/*
 * sysmap.c - reachability map for an unprivileged shell (uid 2000) on lhasa.
 *
 * Any new exploitation primitive has to start from something reachable, so this
 * probes, with benign arguments, which interesting syscalls and device nodes a
 * plain shell can actually touch, and records the exact errno for each. The
 * table is the input to the audit: EPERM/ENOSYS rows are dead, anything that
 * returns 0 (or a sane fd) is live attack surface.
 *
 * Nothing here writes to a partition, flashes anything, or changes device state
 * beyond creating fds it immediately closes.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

static const char *ename(int e)
{
    switch (e) {
    case 0: return "OK";
    case 1: return "EPERM";
    case 2: return "ENOENT";
    case 13: return "EACCES";
    case 22: return "EINVAL";
    case 38: return "ENOSYS";
    case 95: return "EOPNOTSUPP";
    case 19: return "ENODEV";
    default: return "other";
    }
}

#define T(label, expr)                                          \
    do {                                                        \
        errno = 0;                                              \
        long r_ = (long)(expr);                                 \
        int e_ = errno;                                         \
        printf("  %-26s ret=%-12ld %s\n", label, r_,             \
               e_ ? ename(e_) : "OK");                          \
        if (r_ >= 0 && r_ < 4096 && strstr(label, "fd"))        \
            close((int)r_);                                     \
    } while (0)

int main(void)
{
    char buf[256];
    struct { void *p; } dummy = { 0 };
    (void)dummy;

    printf("=== syscall reachability (uid %d) ===\n", getuid());

    T("io_uring_setup fd", syscall(425, 8, buf));
    T("userfaultfd fd", syscall(282, O_CLOEXEC));
    T("perf_event_open", syscall(241, buf, 0, -1, -1, 0));
    T("bpf(map_create)", syscall(280, 0, buf, sizeof buf));
    T("add_key", syscall(217, "user", "d", "v", 1, -2));
    T("keyctl", syscall(219, 0 /*GET_KEYRING_ID*/, -2, 0, 0));
    T("memfd_create fd", syscall(279, "m", 0));
    T("pidfd_open fd", syscall(434, getpid(), 0));
    T("signalfd4 fd", syscall(74, -1, buf, 8, 0));
    T("timerfd_create fd", syscall(85, 1, 0));
    T("epoll_create1 fd", syscall(20, 0));
    T("inotify_init1 fd", syscall(26, 0));
    T("eventfd2 fd", syscall(19, 0, 0));
    T("seccomp(GET_ACTION_AVAIL)", syscall(277, 2, 0, 0));
    T("clone3", syscall(435, 0, 0));
    T("mseal", syscall(462, 0, 0, 0));
    T("process_vm_readv", syscall(270, getpid(), 0, 0, 0, 0, 0));
    T("ptrace(TRACEME)", syscall(117, 0, 0, 0, 0));
    T("kcmp(self)", syscall(272, getpid(), getpid(), 0, 0, 0));
    T("open_tree", syscall(428, -100, "/data/local/tmp", 0));
    T("fsopen", syscall(430, "tmpfs", 0));
    T("landlock_create_ruleset", syscall(444, 0, 0, 0));
    T("fanotify_init fd", syscall(262, 0, 0));
    T("quotactl", syscall(60, 0, "/data", 0, 0));
    T("io_uring_register", syscall(427, -1, 0, 0, 0));
    T("msgget", syscall(186, 0, 0666));
    T("shmget", syscall(194, 0, 4096, 0666));
    T("mq_open", syscall(180, "/t", 0));
    T("swapoff", syscall(225, 0));
    T("init_module", syscall(105, 0, 0, 0));
    T("kexec_load", syscall(104, 0, 0, 0, 0));
    T("sched_setattr", syscall(274, 0, 0, 0));
    T("ioprio_set", syscall(30, 1, 0, 7));

    printf("\n=== device nodes ===\n");
    static const char *devs[] = {
        "/dev/uhid", "/dev/binder", "/dev/hwbinder", "/dev/vndbinder",
        "/dev/ashmem", "/dev/kgsl-3d0", "/dev/mali0", "/dev/ion",
        "/dev/dma_heap/system", "/dev/dri/renderD128", "/dev/video0",
        "/dev/ptmx", "/dev/net/tun", "/dev/fuse", "/dev/kmsg",
        "/dev/diag", "/dev/msm_dsps", "/dev/block/by-name/misc",
        "/dev/gpu/", "/dev/__properties__", NULL
    };
    for (int i = 0; devs[i]; i++) {
        errno = 0;
        int fd = open(devs[i], O_RDWR | O_CLOEXEC);
        int e1 = errno;
        errno = 0;
        int fd2 = open(devs[i], O_RDONLY | O_CLOEXEC);
        int e2 = errno;
        printf("  %-30s RDWR=%-4s RDONLY=%s\n", devs[i],
               fd >= 0 ? "open" : ename(e1), fd2 >= 0 ? "open" : ename(e2));
        if (fd >= 0) close(fd);
        if (fd2 >= 0) close(fd2);
    }
    return 0;
}
