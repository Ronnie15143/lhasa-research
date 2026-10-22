/*
 * binder_txn.c - can a shell process actually execute a transaction?
 *
 * BINDER_WRITE_READ with all-zero args already returns 0, so the encoding is
 * known. The remaining question for auditing is whether we can reach
 * binder_transaction() with attacker-controlled data. Sending BC_TRANSACTION
 * with target.handle = 0 runs the full parse/copy path before the node lookup
 * fails, so a BR_FAILED_REPLY / BR_DEAD_REPLY on the read side proves the
 * transaction path executed.
 *
 * Also probes BINDER_SET_CONTEXT_MGR on each binder device, since being the
 * context manager would give us a real node and a complete binder surface.
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

#define BINDER_WRITE_READ       0xC0306201UL
#define BINDER_SET_CONTEXT_MGR  0x40046207UL
#define BINDER_SET_MAX_THREADS  0x40046205UL
#define BC_TRANSACTION          0x00
#define BR_FAILED_REPLY         0x721b
#define BR_DEAD_REPLY           0x7219
#define BR_ERROR                0x7f00

struct binder_write_read {
    uint64_t write_size, write_consumed, write_buffer;
    uint64_t read_size,  read_consumed,  read_buffer;
};

struct txn_data {
    uint64_t target;          /* handle in low 32 bits */
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

static const char *why(int e)
{
    switch (e) {
    case 0: return "OK";
    case 16: return "EBUSY(already has mgr)";
    case 1: return "EPERM";
    case 13: return "EACCES";
    case 22: return "EINVAL";
    case 25: return "ENOTTY";
    case 8: return "ENOEXEC";
    default: return "other";
    }
}

static void probe(const char *path)
{
    printf("\n=== %s ===\n", path);
    int fd = open(path, O_RDWR | O_CLOEXEC);
    if (fd < 0) { printf("  open: %s\n", strerror(errno)); return; }
    void *map = mmap(NULL, 128 * 1024, PROT_READ, MAP_PRIVATE | MAP_NORESERVE, fd, 0);
    if (map == MAP_FAILED) { printf("  mmap: %s\n", strerror(errno)); close(fd); return; }

    int32_t mgr = 0;
    errno = 0;
    int r = ioctl(fd, BINDER_SET_CONTEXT_MGR, &mgr);
    printf("  SET_CONTEXT_MGR ret=%d %s\n", r, r ? why(errno) : "OK (we are ctx mgr!)");

    /* craft one transaction: handle 0, 64 bytes of controlled payload */
    static unsigned char payload[64];
    memset(payload, 0x41, sizeof payload);

    static unsigned char wbuf[4 + sizeof(struct txn_data)];
    static unsigned char rbuf[1024];
    struct txn_data tr;
    memset(&tr, 0, sizeof tr);
    tr.target = 0;                     /* context manager handle */
    tr.code = 0x1234;
    tr.data_size = sizeof payload;
    tr.offsets_size = 0;
    tr.buffer = (uint64_t)(uintptr_t)payload;

    *(uint32_t *)wbuf = BC_TRANSACTION;
    memcpy(wbuf + 4, &tr, sizeof tr);

    struct binder_write_read bwr;
    memset(&bwr, 0, sizeof bwr);
    memset(rbuf, 0, sizeof rbuf);
    bwr.write_size = sizeof wbuf;
    bwr.write_buffer = (uint64_t)(uintptr_t)wbuf;
    bwr.read_size = sizeof rbuf;
    bwr.read_buffer = (uint64_t)(uintptr_t)rbuf;

    errno = 0;
    r = ioctl(fd, BINDER_WRITE_READ, &bwr);
    printf("  BC_TRANSACTION  ret=%d %s wc=%llu rc=%llu\n",
           r, r ? why(errno) : "-",
           (unsigned long long)bwr.write_consumed,
           (unsigned long long)bwr.read_consumed);
    for (uint64_t i = 0; i + 4 <= bwr.read_consumed && i < 64; i += 4) {
        uint32_t cmd = *(uint32_t *)(rbuf + i);
        printf("    BR cmd %#06x%s\n", cmd,
               cmd == BR_FAILED_REPLY ? "  <== binder_transaction RAN (failed reply)" :
               cmd == BR_DEAD_REPLY   ? "  <== dead reply" :
               cmd == BR_ERROR        ? "  <== error" : "");
    }
    munmap(map, 128 * 1024);
    close(fd);
}

int main(void)
{
    probe("/dev/binder");
    probe("/dev/hwbinder");
    probe("/dev/vndbinder");
    return 0;
}
