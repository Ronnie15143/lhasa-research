/*
 * binder_probe.c - is /dev/binder actually *usable* from a plain shell, or just
 * openable? A BINDER_VERSION success only proves the dispatcher answers; the
 * write/read sweep below tells us which encoding the driver accepts and whether
 * our commands actually execute, which is the precondition for auditing it.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>

#define BINDER_SET_MAX_THREADS 0x40046205UL
#define BINDER_VERSION         0xC0046209UL
#define BC_ENTER_LOOPER        0x0c

struct binder_write_read {
    uint64_t write_size, write_consumed, write_buffer;
    uint64_t read_size,  read_consumed,  read_buffer;
};
struct binder_version { int32_t protocol_version; };

int main(void)
{
    printf("=== binder usability ===\n");
    int fd = open("/dev/binder", O_RDWR | O_CLOEXEC);
    if (fd < 0) { printf("open failed: %s\n", strerror(errno)); return 1; }
    printf("  open            OK fd=%d\n", fd);

    void *map = mmap(NULL, 128 * 1024, PROT_READ, MAP_PRIVATE | MAP_NORESERVE, fd, 0);
    if (map == MAP_FAILED) {
        printf("  mmap 128K       FAILED: %s\n", strerror(errno));
        close(fd);
        return 1;
    }
    printf("  mmap 128K       OK @ %p\n", map);

    struct binder_version ver;
    memset(&ver, 0, sizeof ver);
    int r;
    errno = 0;
    r = ioctl(fd, BINDER_VERSION, &ver);
    printf("  BINDER_VERSION  ret=%d errno=%s protocol=%d\n",
           r, r ? strerror(errno) : "-", ver.protocol_version);

    uint32_t maxthreads = 4;
    errno = 0;
    r = ioctl(fd, BINDER_SET_MAX_THREADS, &maxthreads);
    printf("  SET_MAX_THREADS ret=%d errno=%s\n", r, r ? strerror(errno) : "-");

    /* sweep encodings: EINVAL from the dispatcher means "command not
     * recognised", so finding an accepted one is the real test */
    static const unsigned long cmds[] = { 0xC0306201UL, 0xC0186201UL,
                                          0x40186201UL, 0xC0206201UL };
    static const int rd[] = { 0, 512 };
    uint32_t wbuf[1] = { BC_ENTER_LOOPER };
    unsigned char rbuf[512];
    int live = 0;
    for (int c = 0; c < 4 && !live; c++) {
        for (int k = 0; k < 2; k++) {
            struct binder_write_read bwr;
            memset(&bwr, 0, sizeof bwr);
            memset(rbuf, 0, sizeof rbuf);
            bwr.write_size = sizeof wbuf;
            bwr.write_buffer = (uint64_t)(uintptr_t)wbuf;
            bwr.read_size = rd[k];
            bwr.read_buffer = rd[k] ? (uint64_t)(uintptr_t)rbuf : 0;
            errno = 0;
            r = ioctl(fd, cmds[c], &bwr);
            printf("  WRITE_READ %#010lx rd=%-3d ret=%-3d errno=%-16s wc=%llu rc=%llu\n",
                   cmds[c], rd[k], r, r ? strerror(errno) : "-",
                   (unsigned long long)bwr.write_consumed,
                   (unsigned long long)bwr.read_consumed);
            if (r == 0) { live = 1; break; }
        }
    }

    printf("\n  VERDICT: %s\n",
           live ? "binder protocol is LIVE for uid 2000 (full attack surface)"
                : "opened but write/read cycle failed");
    munmap(map, 128 * 1024);
    close(fd);
    return 0;
}
