/*
 * l71_mali.c - identify the kbase build behind /dev/mali0 on lhasa.
 *
 * /dev/mali0 is 0666 (u:object_r:gpu_device) and uid 2000 can open it, so the
 * Mali kernel driver is part of the no-capability attack surface.  The driver
 * answers KBASE_IOCTL_VERSION_CHECK with its r-release, which is what decides
 * whether the known kbase LPEs even apply.  Only query ioctls are issued here.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#define KBASE_IOCTL_TYPE 0x80

struct kbase_ioctl_version_check {
    uint16_t major;
    uint16_t minor;
};

struct kbase_ioctl_set_flags {
    uint32_t create_flags;
};

static void show(const char *what, int rc, int e)
{
    if (rc == 0)
        printf("  OK    %s\n", what);
    else
        printf("  FAIL  %-34s errno=%d (%s)\n", what, e, strerror(e));
    errno = 0;
}

int main(void)
{
    int fd = open("/dev/mali0", O_RDWR | O_CLOEXEC);
    if (fd < 0) { printf("open /dev/mali0: errno=%d (%s)\n", errno, strerror(errno)); return 1; }
    printf("=== l71 mali probe (uid=%d) ===\n", (int)getuid());

    struct kbase_ioctl_version_check vc;
    memset(&vc, 0, sizeof vc);
    errno = 0;
    int rc = ioctl(fd, _IOWR(KBASE_IOCTL_TYPE, 0, struct kbase_ioctl_version_check), &vc);
    int e = errno;
    show("KBASE_IOCTL_VERSION_CHECK", rc, e);
    printf("        -> kernel kbase major=%u minor=%u  (userspace said %u.%u)\n",
           vc.major, vc.minor, 0, 0);

    /* Some builds only report the version once SET_FLAGS has been accepted. */
    struct kbase_ioctl_set_flags sf;
    memset(&sf, 0, sizeof sf);
    errno = 0;
    rc = ioctl(fd, _IOW(KBASE_IOCTL_TYPE, 1, struct kbase_ioctl_set_flags), &sf);
    e = errno;
    show("KBASE_IOCTL_SET_FLAGS(0)", rc, e);

    memset(&vc, 0, sizeof vc);
    errno = 0;
    rc = ioctl(fd, _IOWR(KBASE_IOCTL_TYPE, 0, struct kbase_ioctl_version_check), &vc);
    e = errno;
    show("VERSION_CHECK after SET_FLAGS", rc, e);
    printf("        -> major=%u minor=%u\n", vc.major, vc.minor);

    /* Legacy KBASE_IOCTL_GET_VERSION_INFO-ish probe: nr 54 is not used by us. */
    close(fd);
    return 0;
}
