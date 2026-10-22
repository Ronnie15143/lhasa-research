/*
 * ioctl_probe.c - does the SELinux ioctl rule actually let us reach these
 * drivers' ioctl handlers, or is the open() the only thing that works?
 *
 * Distinguishing ENOTTY/EINVAL (request reached the driver -> real attack
 * surface) from EACCES/EPERM (SELinux blocked the ioctl) is the whole point:
 * the handover claims /dev/mali0's ioctl is blocked by SELinux, but open()
 * now succeeds, so the claim needs re-testing.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

static const char *nm(int e)
{
    switch (e) {
    case 0: return "OK";
    case 1: return "EPERM(SELinux)";
    case 9: return "EBADF";
    case 13: return "EACCES(SELinux)";
    case 14: return "EFAULT";
    case 22: return "EINVAL(reached driver)";
    case 25: return "ENOTTY(reached driver)";
    case 19: return "ENODEV";
    case 38: return "ENOSYS";
    default: return "other";
    }
}

static void t(const char *path, unsigned long req)
{
    int fd = open(path, O_RDWR | O_CLOEXEC);
    if (fd < 0) {
        printf("  %-22s open failed: %s\n", path, strerror(errno));
        return;
    }
    char buf[256];
    memset(buf, 0, sizeof buf);
    errno = 0;
    long r = ioctl(fd, req, buf);
    printf("  %-22s req=%#010lx ret=%-4ld %s\n", path, req, r, nm(errno));
    close(fd);
}

int main(void)
{
    printf("=== ioctl reachability ===\n");
    /* binder: BINDER_VERSION = _IOWR('b', 9, struct binder_version) */
    t("/dev/binder", 0xC0046209);
    t("/dev/binder", 0);
    /* uhid: UHID_GET_REPORT = _IOWR('H', 0x04, ...), UHID_CREATE2 = _IOW('H', 0x0b, ...) */
    t("/dev/uhid", 0x80044804);
    t("/dev/uhid", 0x4004480b);
    t("/dev/uhid", 0);
    /* mali: probe several plausible type chars, plus cmd 0 */
    t("/dev/mali0", 0);
    t("/dev/mali0", 0xC0000000);
    t("/dev/mali0", 0x80000000);
    /* dma heap: DMA_HEAP_IOCTL_ALLOC = _IOWR('H', 0, ...) */
    t("/dev/dma_heap/system", 0xC0184800);
    t("/dev/ptmx", 0);
    return 0;
}
