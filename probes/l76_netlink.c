/*
 * l76_netlink.c - which netlink protocols can uid 2000 open?
 *
 * Vendor modules on Xiaomi devices often register private netlink families.
 * A shell process can usually create AF_NETLINK sockets regardless of the
 * protocol number, and those parsers are rarely fuzzed.  This just enumerates
 * what is actually reachable; nothing is sent.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int main(void)
{
    printf("=== l76 netlink protocol probe (uid=%d) ===\n", (int)getuid());
    const char *names[32] = {
        "ROUTE", "UNUSED1", "USERSOCK", "FIREWALL", "SOCK_DIAG", "NFLOG",
        "XFRM", "SELINUX", "ISCSI", "AUDIT", "FIB_LOOKUP", "CONNECTOR",
        "NETFILTER", "IP6_FW", "DNRTMSG", "KOBJECT_UEVENT", "GENERIC",
        "SCSITRANSPORT", "ECRYPTFS", "RDMA", "CRYPTO", "SMC", "SMC_DIAG",
        "XDP", "PMCNTR", "NVME", "NETDEV", "AUDIT_?",
    };
    int ok = 0;
    for (int p = 0; p <= 31; p++) {
        int fd = socket(AF_NETLINK, SOCK_RAW, p);
        if (fd >= 0) {
            printf("  OK   proto=%-2d %-14s\n", p, p < 28 ? names[p] : "");
            close(fd);
            ok++;
        } else {
            errno = 0;
        }
        errno = 0;
    }
    printf("openable netlink protos: %d/32\n", ok);

    /* the three that matter for us */
    int fd = socket(AF_NETLINK, SOCK_RAW, 2 /*USERSOCK*/);
    printf("  USERSOCK(2)  fd=%d errno=%d\n", fd, errno);
    if (fd >= 0) close(fd);
    errno = 0;
    fd = socket(AF_NETLINK, SOCK_RAW, 15 /*KOBJECT_UEVENT*/);
    printf("  KOBJECT_UEVENT(15) fd=%d errno=%d\n", fd, errno);
    if (fd >= 0) close(fd);
    return 0;
}
