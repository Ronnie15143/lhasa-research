/*
 * binder_step2.c - which half of BINDER_WRITE_READ is being refused?
 *
 * Every non-empty *write* got EINVAL with write_consumed=0 while the empty call
 * succeeded, so test the read half on its own and test whether the write buffer
 * has to live inside the mmap'd region (some hardened implementations do that).
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
#define BC_ENTER_LOOPER   0x0c

struct bwr {
    uint64_t write_size, write_consumed, write_buffer;
    uint64_t read_size,  read_consumed,  read_buffer;
};

static int fd;
static unsigned char *map;

static void run(const char *label, uint64_t wsz, void *wbuf,
                uint64_t rsz, void *rbuf)
{
    struct bwr b;
    memset(&b, 0, sizeof b);
    b.write_size = wsz;
    b.write_buffer = (uint64_t)(uintptr_t)wbuf;
    b.read_size = rsz;
    b.read_buffer = (uint64_t)(uintptr_t)rbuf;
    errno = 0;
    int r = ioctl(fd, BINDER_WRITE_READ, &b);
    printf("  %-46s ret=%-3d %-14s wc=%-4llu rc=%llu",
           label, r, r ? strerror(errno) : "OK",
           (unsigned long long)b.write_consumed,
           (unsigned long long)b.read_consumed);
    if (b.read_consumed >= 4 && rbuf) {
        uint32_t c = *(uint32_t *)rbuf;
        printf(" BR=%#x", c);
    }
    printf("\n");
}

int main(void)
{
    printf("=== binder: isolate read vs write ===\n");
    fd = open("/dev/binder", O_RDWR | O_CLOEXEC);
    if (fd < 0) { printf("open: %s\n", strerror(errno)); return 1; }
    map = mmap(NULL, 128 * 1024, PROT_READ, MAP_PRIVATE | MAP_NORESERVE, fd, 0);
    if (map == MAP_FAILED) { printf("mmap: %s\n", strerror(errno)); return 1; }

    static unsigned char heap[512];
    memset(heap, 0, sizeof heap);

    run("read only, 512B", 0, NULL, 512, heap);
    *(uint32_t *)heap = BC_ENTER_LOOPER;
    run("write BC_ENTER_LOOPER, buffer on stack", 4, heap, 0, NULL);
    run("write BC_ENTER_LOOPER, buffer in mmap", 4, map + 0x1000, 0, NULL);
    run("write BC_ENTER_LOOPER in mmap, read 512", 4, map + 0x1000, 512, heap);
    run("write 8 zero bytes", 8, heap, 0, NULL);
    run("write 1 byte", 1, heap, 0, NULL);

    munmap(map, 128 * 1024);
    close(fd);
    return 0;
}
