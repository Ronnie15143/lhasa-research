/*
 * l77_sockets.c - which local unix sockets can uid 2000 connect to?
 *
 * Every vendor daemon that listens on /dev/socket/<name> is a privileged
 * process; if shell's SELinux domain may connectto that socket, its protocol
 * parser becomes reachable attack surface (the classic confused-deputy shape).
 * This only connects and immediately disconnects - nothing is sent.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

static void probe(const char *path, int type, const char *tname)
{
    int fd = socket(AF_UNIX, type | SOCK_CLOEXEC, 0);
    if (fd < 0) { printf("  socket(%s) failed errno=%d\n", tname, errno); return; }

    struct sockaddr_un sa;
    memset(&sa, 0, sizeof sa);
    sa.sun_family = AF_UNIX;
    snprintf(sa.sun_path, sizeof sa.sun_path, "%s", path);

    errno = 0;
    int rc = connect(fd, (struct sockaddr *)&sa, sizeof sa);
    int e = errno;
    if (rc == 0)
        printf("  OK    %-46s [%s]\n", path, tname);
    else
        printf("  DENY  %-46s [%s] errno=%d (%s)\n", path, tname, e, strerror(e));
    close(fd);
    errno = 0;
}

int main(int argc, char **argv)
{
    printf("=== l77 socket reachability (uid=%d) ===\n", (int)getuid());
    for (int i = 1; i < argc; i++) {
        probe(argv[i], SOCK_STREAM, "STREAM");
        probe(argv[i], SOCK_SEQPACKET, "SEQPACKET");
        probe(argv[i], SOCK_DGRAM, "DGRAM");
    }
    return 0;
}
