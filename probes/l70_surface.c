/*
 * l70_surface.c - what can uid 2000 actually reach on lhasa?
 *
 * The 64560 route is closed (see research/64560_DEAD_ON_LHASA.md), so the next
 * kernel-write route has to start from a real inventory of reachable surfaces
 * instead of a guess.  This prints, for a fixed list of device nodes and
 * syscalls, the exact errno a plain shell process gets.  Nothing here writes to
 * the device: opens are O_RDWR|O_NONBLOCK and closed immediately, sockets are
 * created and closed, io_uring is set up and torn down.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/io_uring.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/timerfd.h>
#include <unistd.h>

static void rep(const char *what, long rc)
{
    int e = errno;
    if (rc >= 0) {
        printf("  OK    %-46s (fd/rc=%ld)\n", what, rc);
        if (rc > 2) close((int)rc);
    } else {
        printf("  %-5s %-46s errno=%d (%s)\n", "DENY", what, e, strerror(e));
    }
    errno = 0;
}

static void try_path(const char *p)
{
    char buf[160];
    snprintf(buf, sizeof buf, "open %s", p);
    rep(buf, open(p, O_RDWR | O_CLOEXEC | O_NONBLOCK));
}

static void try_path_ro(const char *p)
{
    char buf[160];
    snprintf(buf, sizeof buf, "open(RO) %s", p);
    rep(buf, open(p, O_RDONLY | O_CLOEXEC | O_NONBLOCK));
}

int main(int argc, char **argv)
{
    if (argc > 1) {
        /* l70 <path...> : probe just these nodes */
        printf("=== l70 path probe (uid=%d, %d paths) ===\n", (int)getuid(), argc - 1);
        for (int i = 1; i < argc; i++) try_path(argv[i]);
        return 0;
    }
    printf("=== l70 surface probe (uid=%d) ===\n", (int)getuid());

    printf("-- device nodes --\n");
    try_path("/dev/uhid");
    try_path("/dev/binder");
    try_path("/dev/binderfs/binder");
    try_path("/dev/ashmem");
    try_path("/dev/ashmem_ignore_unset_prot_exec");
    try_path("/dev/dm-user");
    try_path("/dev/device-mapper");
    try_path("/dev/fuse");
    try_path("/dev/ufs-bsg0");
    try_path("/dev/block/by-name/android_esp_a");
    try_path("/dev/block/by-name/misc");
    try_path("/dev/dma_heap/system");
    try_path("/dev/dma_heap/system-uncached");
    try_path("/dev/dri/card0");
    try_path("/dev/ppp");
    try_path("/dev/net/tun");
    try_path_ro("/proc/kallsyms");
    try_path_ro("/proc/slabinfo");

    printf("-- syscalls --\n");
    {
        struct io_uring_params p;
        memset(&p, 0, sizeof p);
        rep("io_uring_setup(8)", syscall(__NR_io_uring_setup, 8, &p));
        memset(&p, 0, sizeof p);
        rep("io_uring_setup(with SQPOLL)",
            syscall(__NR_io_uring_setup, 8, &(struct io_uring_params){ .flags = IORING_SETUP_SQPOLL }));
    }
    rep("memfd_create", syscall(__NR_memfd_create, "s", 0));
    rep("userfaultfd(O_CLOEXEC)", syscall(__NR_userfaultfd, O_CLOEXEC | O_NONBLOCK));
    rep("pidfd_open(self)", syscall(__NR_pidfd_open, getpid(), 0));
    rep("pidfd_getfd(self,0)", syscall(__NR_pidfd_getfd, getpid(), 0, 0));
    rep("timerfd_create", timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC | TFD_NONBLOCK));
    rep("epoll_create1", epoll_create1(EPOLL_CLOEXEC));
    rep("eventfd", eventfd(0, EFD_CLOEXEC));
    rep("signalfd", signalfd(-1, NULL, SFD_CLOEXEC | SFD_NONBLOCK));
    rep("socket(AF_UNIX,SOCK_DGRAM)", socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0));
    rep("socket(AF_INET,SOCK_DGRAM)", socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0));
    rep("socket(AF_INET,SOCK_RAW)", socket(AF_INET, SOCK_RAW | SOCK_CLOEXEC, 0));
    rep("socket(AF_PACKET)", socket(AF_PACKET, SOCK_RAW | SOCK_CLOEXEC, 0));
    rep("socket(AF_NETLINK,ROUTE)", socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, 0));
    rep("socket(AF_VSOCK)", socket(AF_VSOCK, SOCK_STREAM | SOCK_CLOEXEC, 0));
    rep("socket(AF_XDP-ish AF_KEY?)", socket(15 /*AF_KEY*/, SOCK_RAW | SOCK_CLOEXEC, 0));
    {
        char buf[16];
        memset(buf, 0, sizeof buf);
        rep("bpf(BPF_MAP_CREATE)", syscall(__NR_bpf, 0 /*BPF_MAP_CREATE*/, buf, sizeof buf));
    }
    rep("add_key(user)", syscall(__NR_add_key, "user", "k", "v", 1, (int)-2 /*KEY_SPEC_SESSION_KEYRING*/));
    rep("keyctl(KEYCTL_GET_KEYRING_ID)", syscall(__NR_keyctl, 0, (int)-2, 0, 0, 0));
    rep("fsopen(tmpfs)", syscall(__NR_fsopen, "tmpfs", 0));
    rep("open_tree(/sdcard)", syscall(__NR_open_tree, AT_FDCWD, "/data/local/tmp", 0));
    rep("perf_event_open(sw cpu clock,self)",
        syscall(__NR_perf_event_open,
                &(struct { uint32_t type, size; uint64_t config; }){ 1 /*PERF_TYPE_SOFTWARE*/, 16, 0 /*CPU_CLOCK*/ },
                0, -1, -1, 0));
    rep("sched_setattr(self,OTHER)", syscall(__NR_sched_setattr, 0, &(struct { uint32_t size, sched_flags; int32_t nice; uint32_t prio; }[1]){ { 48, 0, 0, 0 } }, 0));
    return 0;
}
