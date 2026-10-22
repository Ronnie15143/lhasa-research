/*
 * l74_tango_compat.c - does /dev/tango32 let uid 2000 reach another file's
 * compat_ioctl (and does that bypass the SELinux ioctl gate that makes
 * /dev/mali0 unusable)?
 *
 * tango32 is not a device driver: it is a 32-bit translator shim.  Command
 * 0x400c74a3 (_IOW size 0xc) takes {fd, cmd, arg}, sets TIF_32BIT on the
 * caller, and forwards to the target file's ->compat_ioctl().  The audit says
 * it calls security_file_ioctl() (the native hook) instead of
 * security_file_ioctl_compat(), which may change the LSM verdict.
 *
 * We only send commands the target driver does not implement, so the expected
 * answers are ENOTTY (forwarded, driver rejected) vs EPERM/EACCES (blocked
 * before the driver).  Nothing is executed.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#define TANGO_COMPAT_IOCTL 0x400c74a3UL

struct tango_compat_req {
    int32_t fd;
    uint32_t cmd;
    uint32_t arg;
};

static int tango_fd = -1;

static void try_forward(const char *path, uint32_t cmd)
{
    int fd = open(path, O_RDWR | O_CLOEXEC | O_NONBLOCK);
    if (fd < 0) {
        printf("  %-18s open failed errno=%d (%s)\n", path, errno, strerror(errno));
        return;
    }

    /* baseline: the same command straight on the device */
    errno = 0;
    long direct = ioctl(fd, cmd, 0);
    int de = errno;

    /* forwarded through tango32 as a 32-bit task */
    struct tango_compat_req req;
    req.fd = fd;
    req.cmd = cmd;
    req.arg = 0;
    errno = 0;
    long via = ioctl(tango_fd, TANGO_COMPAT_IOCTL, &req);
    int ve = errno;

    printf("  %-18s cmd=%#010x  direct: rc=%ld errno=%d(%s)   via tango32: rc=%ld errno=%d(%s)%s\n",
           path, cmd, direct, de, strerror(de), via, ve, strerror(ve),
           (de == EPERM || de == EACCES) && ve != de ? "   <== GATE CHANGED" : "");
    close(fd);
    errno = 0;
}

int main(void)
{
    printf("=== l74 tango32 compat_ioctl forwarding (uid=%d) ===\n", (int)getuid());
    tango_fd = open("/dev/tango32", O_RDWR | O_CLOEXEC);
    if (tango_fd < 0) { printf("open /dev/tango32: errno=%d (%s)\n", errno, strerror(errno)); return 1; }

    /* unimplemented commands: expect ENOTTY when the call really reaches the driver */
    try_forward("/dev/mali0", 0x00008005);      /* kbase type 0x80, nr 5, no size */
    try_forward("/dev/mali0", 0x0000803f);
    try_forward("/dev/uhid", 0x00004805);       /* uhid, unimplemented */
    try_forward("/dev/binder", 0x00006305);     /* binder, unimplemented BC */
    try_forward("/dev/xr_fbt", 0x00007405);
    try_forward("/dev/uinput", 0x00005505);

    /* sanity: a real tango32 command (0x800474a0 = _IOR 4) */
    {
        uint32_t out = 0;
        errno = 0;
        long rc = ioctl(tango_fd, 0x800474a0, &out);
        printf("  tango 0x800474a0     rc=%ld errno=%d(%s) out=%#x\n", rc, errno, strerror(errno), out);
    }

    close(tango_fd);
    return 0;
}
