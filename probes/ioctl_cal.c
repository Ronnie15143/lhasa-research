/*
 * ioctl_cal.c - calibrate ioctl encodings by brute-forcing the _IOC_SIZE field.
 *
 * Why this works for binder: binder_ioctl_write_read() starts with
 *     if (size != sizeof(struct binder_write_read)) return -EINVAL;
 * and with an all-zero argument (write_size == read_size == 0) a correctly
 * encoded BINDER_WRITE_READ returns 0. So exactly one size byte in the ioctl
 * number yields success - that is the encoding the driver was compiled with.
 *
 * For uhid the discriminator is the opposite: the default ioctl path returns
 * ENOTTY, so anything that is not ENOTTY reached a real handler.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#define DIR_WR  1
#define DIR_RW  3
#define BUF     4096

static const char *why(int e)
{
    switch (e) {
    case 0:  return "OK";
    case 1:  return "EPERM";
    case 9:  return "EBADF";
    case 13: return "EACCES";
    case 14: return "EFAULT";
    case 22: return "EINVAL";
    case 25: return "ENOTTY";
    default: return "other";
    }
}

static void sweep(const char *path, unsigned char type, int nr_lo, int nr_hi,
                  int silent_when)
{
    int fd = open(path, O_RDWR | O_CLOEXEC);
    if (fd < 0) {
        printf("%s: open failed (%s)\n", path, strerror(errno));
        return;
    }
    static unsigned char buf[BUF];
    printf("\n=== %s  type='%c'(%#x) ===\n", path, type, type);
    for (int nr = nr_lo; nr <= nr_hi; nr++) {
        for (int dir = 0; dir < 2; dir++) {
            unsigned long d = dir ? DIR_RW : DIR_WR;
            for (int sz = 0; sz <= 64; sz++) {
                unsigned long cmd = (d << 30) | ((unsigned long)sz << 16)
                                    | ((unsigned long)type << 8) | nr;
                memset(buf, 0, BUF);
                errno = 0;
                long r = ioctl(fd, cmd, buf);
                int e = errno;
                if (e == silent_when)
                    continue;
                printf("  nr=%#04x dir=%d sz=%-3d cmd=%#010lx ret=%-4ld %s\n",
                       nr, dir, sz, cmd, r, why(e));
            }
        }
    }
    close(fd);
}

int main(void)
{
    /* binder: want the size that returns OK */
    sweep("/dev/binder", 'b', 1, 1, 22 /* skip EINVAL */);
    /* uhid: ENOTTY means "no handler", so print everything else */
    sweep("/dev/uhid", 'H', 0, 0x10, 25 /* skip ENOTTY */);
    return 0;
}
