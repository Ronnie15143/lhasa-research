/*
 * binder_where.c - discriminate why every binder write returns EINVAL.
 *
 * Same 4-byte command (BC_ENTER_LOOPER), only the *location/attributes* of the
 * write buffer change. The error code pattern tells us whether the driver does
 * a range check against the mmap region, a plain copy_from_user failure, or
 * something else entirely.
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
static unsigned char *bmap;

static void t(const char *label, void *wbuf, uint64_t wsz)
{
    struct bwr b;
    memset(&b, 0, sizeof b);
    b.write_size = wsz;
    b.write_buffer = (uint64_t)(uintptr_t)wbuf;
    errno = 0;
    int r = ioctl(fd, BINDER_WRITE_READ, &b);
    printf("  %-46s ret=%-3d %-22s wc=%llu\n",
           label, r, r ? strerror(errno) : "OK",
           (unsigned long long)b.write_consumed);
}

int main(void)
{
    printf("=== where must the binder write buffer live? ===\n");
    fd = open("/dev/binder", O_RDWR | O_CLOEXEC);
    if (fd < 0) return 1;
    bmap = mmap(NULL, 128 * 1024, PROT_READ, MAP_PRIVATE | MAP_NORESERVE, fd, 0);
    if (bmap == MAP_FAILED) { printf("binder mmap failed\n"); return 1; }

    /* a normal anonymous buffer we can write into, page aligned */
    unsigned char *anon = mmap(NULL, 8192, PROT_READ | PROT_WRITE,
                               MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    anon[0] = BC_ENTER_LOOPER;
    static unsigned char bss[64];
    bss[0] = BC_ENTER_LOOPER;

    printf("  binder map @ %p   anon @ %p   bss @ %p\n", bmap, anon, bss);

    t("anon RW page (aligned)", anon, 4);
    t("bss (static, aligned)", bss, 4);
    t("binder map + 0", bmap, 4);
    t("binder map + 0x1000", bmap + 0x1000, 4);
    t("binder map + 0x1FFF0 (last bytes)", bmap + 0x1FFF0, 4);
    t("binder map + 0x20000 (just past end)", bmap + 0x20000, 4);
    t("NULL buffer, size 4", NULL, 4);
    t("write_size=4, buffer anon+1 (unaligned)", anon + 1, 4);
    t("write_size=0x10000 from anon (overrun)", anon, 0x10000);

    munmap(anon, 8192);
    munmap(bmap, 128 * 1024);
    close(fd);
    return 0;
}
