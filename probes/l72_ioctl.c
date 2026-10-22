/*
 * l72_ioctl.c - is the ioctl() path on a vendor char device actually reachable
 * for uid 2000, or does SELinux stop it at the file level?
 *
 * open() succeeding means nothing: /dev/mali0 opens but every kbase ioctl comes
 * back EPERM.  A dummy command that the driver does not implement returns
 * ENOTTY(25) when the call reaches the driver, and EACCES/EPERM when SELinux
 * refuses the ioctl class.  That single errno decides whether a vendor driver is
 * worth the OTA download + static audit at all.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

static void probe(const char *path)
{
    int fd = open(path, O_RDWR | O_CLOEXEC);
    if (fd < 0) { printf("  open  %-24s errno=%d (%s)\n", path, errno, strerror(errno)); return; }

    uint8_t buf[256];
    memset(buf, 0, sizeof buf);

    /* _IOW/_IOR/_IOWR with a bogus type/nr/size: unimplemented -> ENOTTY */
    unsigned long cmds[] = {
        0x00000000UL,                        /* _IO(0,0)        */
        _IOW('x', 0, uint32_t),
        _IOR('x', 1, uint32_t),
        _IOWR('x', 2, uint32_t),
        _IOW('x', 0xff, uint32_t),
    };
    printf("  %s\n", path);
    for (unsigned i = 0; i < sizeof cmds / sizeof cmds[0]; i++) {
        errno = 0;
        long rc = ioctl(fd, cmds[i], buf);
        printf("    cmd=%#010lx rc=%ld errno=%d (%s)%s\n",
               cmds[i], rc, errno, strerror(errno),
               errno == ENOTTY ? "   <== ioctl reached the driver" : "");
        errno = 0;
    }
    close(fd);
}

int main(int argc, char **argv)
{
    printf("=== l72 ioctl reachability (uid=%d) ===\n", (int)getuid());
    if (argc > 1) {
        for (int i = 1; i < argc; i++) probe(argv[i]);
        return 0;
    }
    probe("/dev/xr_fbt");
    probe("/dev/tango32");
    probe("/dev/mali0");
    probe("/dev/ashmem_unpinning_enable");
    probe("/dev/ashmem_ignore_unset_prot_read");
    return 0;
}
