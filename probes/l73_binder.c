/*
 * l73_binder.c - re-verify the binder write path from uid 2000.
 *
 * HANDOVER_2 claimed the write buffer had to live inside binder's own VMA
 * (EINVAL outside it).  The audit says that was a measurement artefact: the
 * command word must carry the ioctl encoding (_IO('c', nr)), not the bare nr,
 * otherwise binder_thread_write() falls into "unknown command" and returns
 * -EINVAL before touching the buffer.
 *
 * This tool sends properly encoded commands and prints write_consumed, which is
 * the definitive answer: consumed != 0 means the command was parsed and handled.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>

#define BINDER_WRITE_READ 0xC0306201UL
#define BINDER_VERSION    0xC0046209UL

struct binder_write_read {
    uint64_t write_size, write_consumed;   /* binder_size_t is __u64 on 64-bit */
    uint64_t write_buffer;
    uint64_t read_size, read_consumed;
    uint64_t read_buffer;
};

/* _IO('c', 12) etc. */
#define BC_ENTER_LOOPER 0x0000630c
#define BC_EXIT_LOOPER  0x0000630d
#define BC_INCREFS      0x00007200
#define BC_ACQUIRE      0x00007203
#define BC_TRANSACTION  0x40406300
#define BC_FREE_BUFFER  0x00007209

struct binder_transaction_data {
    uint32_t handle;
    uint32_t code;
    uint32_t flags;
    uint32_t sender_pid;   /* not sent by user, but keeps the struct size right */
    uint32_t sender_euid;
    uint64_t data_size;
    uint64_t offsets_size;
    union {
        struct { uint64_t buffer; uint64_t offsets; } ptr;
        uint8_t buf[8];
    } data;
};

static int fd;

static void bwr(const char *label, void *wbuf, uint64_t wsz, int *consumed)
{
    struct binder_write_read b;
    memset(&b, 0, sizeof b);
    b.write_size = wsz;
    b.write_buffer = (uint64_t)(uintptr_t)wbuf;
    errno = 0;
    int r = ioctl(fd, BINDER_WRITE_READ, &b);
    if (consumed) *consumed = (int)b.write_consumed;
    printf("  %-42s ret=%-3d %-24s write_consumed=%u\n",
           label, r, r ? strerror(errno) : "OK", b.write_consumed);
    errno = 0;
}

int main(void)
{
    printf("=== l73 binder write-path probe (uid=%d) ===\n", (int)getuid());
    fd = open("/dev/binder", O_RDWR | O_CLOEXEC);
    if (fd < 0) { printf("open /dev/binder: errno=%d (%s)\n", errno, strerror(errno)); return 1; }

    void *map = mmap(NULL, 128 * 1024, PROT_READ, MAP_PRIVATE | MAP_NORESERVE, fd, 0);
    printf("  binder mmap=%p (errno=%d)\n", map == MAP_FAILED ? NULL : map, errno);

    struct { uint32_t cmd; uint32_t arg; } w;
    int consumed = 0;

    w.cmd = BC_ENTER_LOOPER; w.arg = 0;
    bwr("BC_ENTER_LOOPER (0x0000630c)", &w, 4, &consumed);

    w.cmd = 0x0c; w.arg = 0;
    bwr("bare 0x0c (HANDOVER_2's mistake)", &w, 4, &consumed);

    w.cmd = BC_EXIT_LOOPER; w.arg = 0;
    bwr("BC_EXIT_LOOPER (0x0000630d)", &w, 4, &consumed);

    /* a transaction with handle 0 (context manager) and zero payload */
    struct { uint32_t cmd; struct binder_transaction_data t; } tr;
    memset(&tr, 0, sizeof tr);
    tr.cmd = BC_TRANSACTION;
    tr.t.handle = 0;
    tr.t.code = 1;
    tr.t.data_size = 0;
    tr.t.offsets_size = 0;
    bwr("BC_TRANSACTION handle=0 size=0", &tr, (uint32_t)(4 + sizeof(struct binder_transaction_data)), &consumed);

    /* transaction pointing at a buffer inside the mapping */
    memset(&tr, 0, sizeof tr);
    tr.cmd = BC_TRANSACTION;
    tr.t.handle = 0;
    tr.t.code = 2;
    tr.t.data_size = 64;
    tr.t.offsets_size = 0;
    tr.t.data.ptr.buffer = (uint64_t)(uintptr_t)map;
    tr.t.data.ptr.offsets = (uint64_t)(uintptr_t)map + 0x1000;
    bwr("BC_TRANSACTION handle=0 size=64 (in VMA)", &tr, (uint32_t)(4 + sizeof(struct binder_transaction_data)), &consumed);

    close(fd);
    return 0;
}
