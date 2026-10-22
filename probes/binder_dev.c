/*
 * binder_dev.c - is the write-path rejection specific to /dev/binder, or does
 * every binder device behave the same? A per-device difference points at the
 * device's context (e.g. no context manager), a uniform one points at a policy
 * or hardening check that applies to the shell domain.
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

#define BINDER_WRITE_READ 0xC0306201UL
#define BINDER_SET_MAX_THREADS 0x40046205UL
#define BC_ENTER_LOOPER 0x0c
#define BC_INCREFS      0x01
#define BC_ACQUIRE      0x02

struct bwr {
    uint64_t write_size, write_consumed, write_buffer;
    uint64_t read_size,  read_consumed,  read_buffer;
};

static void probe(const char *path)
{
    printf("\n=== %s ===\n", path);
    int fd = open(path, O_RDWR | O_CLOEXEC);
    if (fd < 0) { printf("  open: %s\n", strerror(errno)); return; }
    void *m = mmap(NULL, 128 * 1024, PROT_READ, MAP_PRIVATE | MAP_NORESERVE, fd, 0);
    if (m == MAP_FAILED) { printf("  mmap: %s\n", strerror(errno)); close(fd); return; }
    printf("  open+mmap OK\n");

    static unsigned char rb[512];
    static unsigned char wb[64];

    struct bwr b;
    memset(&b, 0, sizeof b); memset(rb, 0, sizeof rb);
    b.read_size = sizeof rb; b.read_buffer = (uint64_t)(uintptr_t)rb;
    errno = 0; int r = ioctl(fd, BINDER_WRITE_READ, &b);
    printf("  read-only        ret=%-3d %-14s rc=%llu",
           r, r ? strerror(errno) : "OK", (unsigned long long)b.read_consumed);
    if (b.read_consumed >= 4) printf(" BR=%#x", *(uint32_t *)rb);
    printf("\n");

    uint32_t cmds[] = { BC_ENTER_LOOPER, BC_INCREFS, BC_ACQUIRE, 0xdeadbeef };
    for (int i = 0; i < 4; i++) {
        memset(wb, 0, sizeof wb);
        *(uint32_t *)wb = cmds[i];
        memset(&b, 0, sizeof b);
        b.write_size = 4;
        b.write_buffer = (uint64_t)(uintptr_t)wb;
        errno = 0; r = ioctl(fd, BINDER_WRITE_READ, &b);
        printf("  write cmd %#010x ret=%-3d %-14s wc=%llu\n",
               cmds[i], r, r ? strerror(errno) : "OK",
               (unsigned long long)b.write_consumed);
    }

    uint32_t mt = 4;
    errno = 0; r = ioctl(fd, BINDER_SET_MAX_THREADS, &mt);
    printf("  SET_MAX_THREADS  ret=%-3d %s\n", r, r ? strerror(errno) : "OK");

    munmap(m, 128 * 1024);
    close(fd);
}

int main(void)
{
    probe("/dev/binder");
    probe("/dev/hwbinder");
    probe("/dev/vndbinder");
    return 0;
}
