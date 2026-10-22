#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/resource.h>

#ifndef SYS_timer_create
#define SYS_timer_create 107
#endif
#ifndef SYS_timer_settime
#define SYS_timer_settime 110
#endif

#define CLK_PROC_CPU 2

int main(void)
{
    struct sigevent ev;
    struct itimerspec its;
    timer_t tid;
    struct rlimit rl;
    int ok = 0, fail = 0, firsterr = 0;

    memset(&ev, 0, sizeof ev);
    ev.sigev_notify = SIGEV_SIGNAL;
    ev.sigev_signo = SIGUSR1;
    memset(&its, 0, sizeof its);
    its.it_value.tv_sec = 3600;

    for (int i = 0; i < 500; i++) {
        int r = syscall(SYS_timer_create, CLK_PROC_CPU, &ev, &tid);
        if (r != 0) {
            if (!firsterr) firsterr = errno;
            fail++;
            if (fail > 3) break;
            continue;
        }
        if (syscall(SYS_timer_settime, tid, 0, &its, NULL) != 0)
            fail++;
        ok++;
    }
    fprintf(stderr, "timer_create ok=%d fail=%d firsterrno=%d (%s)\n",
            ok, fail, firsterr, strerror(firsterr));

    if (getrlimit(RLIMIT_SIGPENDING, &rl) == 0)
        fprintf(stderr, "RLIMIT_SIGPENDING cur=%lld max=%lld\n",
                (long long)rl.rlim_cur, (long long)rl.rlim_max);
    if (getrlimit(RLIMIT_NPROC, &rl) == 0)
        fprintf(stderr, "RLIMIT_NPROC cur=%lld max=%lld\n",
                (long long)rl.rlim_cur, (long long)rl.rlim_max);

    struct timespec ts;
    if (clock_getres(CLK_PROC_CPU, &ts) == 0)
        fprintf(stderr, "CLK_PROC_CPU res=%ld.%09ld\n", (long)ts.tv_sec, ts.tv_nsec);
    else
        fprintf(stderr, "clock_getres failed errno=%d\n", errno);

    return 0;
}
