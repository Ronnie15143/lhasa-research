/*
 * binder_step.c - bisect where BINDER_WRITE_READ starts rejecting us.
 *
 * Zero-size write/read already returns 0, so the transport works. Sending a
 * BC_TRANSACTION with data_size=64 returned EINVAL with write_consumed=0, which
 * means binder_thread_write() bailed. This walks up in small steps so the exact
 * failing shape is identified instead of guessed.
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
#define BC_TRANSACTION    0x00
#define BC_FREE_BUFFER    0x03

struct bwr {
    uint64_t write_size, write_consumed, write_buffer;
    uint64_t read_size,  read_consumed,  read_buffer;
};
struct txn {
    uint64_t target;
    uint64_t cookie;
    uint32_t code;
    uint32_t flags;
    int32_t  sender_pid;
    int32_t  sender_euid;
    uint64_t data_size;
    uint64_t offsets_size;
    uint64_t buffer;
    uint64_t offsets;
};

static int fd;

static void run(const char *label, void *wbuf, uint64_t wsize, uint64_t rsize)
{
    struct bwr b;
    static unsigned char rbuf[512];
    memset(&b, 0, sizeof b);
    memset(rbuf, 0, sizeof rbuf);
    b.write_size = wsize;
    b.write_buffer = (uint64_t)(uintptr_t)wbuf;
    b.read_size = rsize;
    b.read_buffer = rsize ? (uint64_t)(uintptr_t)rbuf : 0;
    errno = 0;
    int r = ioctl(fd, BINDER_WRITE_READ, &b);
    printf("  %-40s ret=%-3d errno=%-12s wc=%-4llu rc=%llu",
           label, r, r ? strerror(errno) : "-",
           (unsigned long long)b.write_consumed,
           (unsigned long long)b.read_consumed);
    if (b.read_consumed >= 4 && rsize)
        printf(" firstBR=%#x", *(uint32_t *)rbuf);
    printf("\n");
}

int main(void)
{
    printf("=== binder write-path bisect ===\n");
    fd = open("/dev/binder", O_RDWR | O_CLOEXEC);
    if (fd < 0) { printf("open: %s\n", strerror(errno)); return 1; }
    void *m = mmap(NULL, 128 * 1024, PROT_READ, MAP_PRIVATE | MAP_NORESERVE, fd, 0);
    if (m == MAP_FAILED) { printf("mmap: %s\n", strerror(errno)); return 1; }

    static unsigned char w[512];
    static unsigned char payload[64];
    memset(payload, 0x41, sizeof payload);

    run("write_size=0 read_size=0", w, 0, 0);
    *(uint32_t *)w = BC_ENTER_LOOPER;
    run("BC_ENTER_LOOPER (4B)", w, 4, 0);
    run("BC_ENTER_LOOPER (4B) + read", w, 4, 512);

    *(uint32_t *)w = BC_FREE_BUFFER;
    *(uint64_t *)(w + 4) = 0x4141414141414141ULL;
    run("BC_FREE_BUFFER bogus ptr", w, 12, 0);

    /* transaction with no payload at all */
    struct txn t;
    *(uint32_t *)w = BC_TRANSACTION;
    memset(&t, 0, sizeof t);
    t.target = 0;
    t.code = 0x1234;
    memcpy(w + 4, &t, sizeof t);
    run("BC_TRANSACTION tr only (data_size=0)", w, 4 + sizeof t, 0);

    /* transaction with small payload */
    t.data_size = 8;
    t.buffer = (uint64_t)(uintptr_t)payload;
    memcpy(w + 4, &t, sizeof t);
    run("BC_TRANSACTION data_size=8", w, 4 + sizeof t, 0);

    /* with a valid offsets array of one entry pointing at a flat_binder_object */
    static unsigned char pay2[32];
    memset(pay2, 0, sizeof pay2);
    t.data_size = 32;
    t.offsets_size = 8;                 /* one binder_size_t = 8 bytes */
    t.buffer = (uint64_t)(uintptr_t)pay2;
    t.offsets = (uint64_t)(uintptr_t)pay2;  /* points at the object offset 0 */
    memcpy(w + 4, &t, sizeof t);
    run("BC_TRANSACTION data=32 offsets=1", w, 4 + sizeof t, 0);

    /* same but also try to read the reply */
    run("BC_TRANSACTION data=32 offsets=1 + read", w, 4 + sizeof t, 512);

    munmap(m, 128 * 1024);
    close(fd);
    return 0;
}
