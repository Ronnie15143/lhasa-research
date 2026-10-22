/*
 * order_probe.c - does an 8 KB AF_UNIX send consume kmalloc-8k objects (i.e.
 * an order-1 slab page, which is what the reclaim needs), or does it come from
 * the per-cpu page_frag pool (order-3) where it can never match a
 * posix_timers_cache slab?
 *
 * /proc/buddyinfo is not readable on this device, but /proc/slabinfo is, and it
 * answers the same question: if the frag is a kmalloc-8k object then that
 * cache's active_objs rises by ~N.
 *
 * usage: order_probe <nfrag>
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define FRAG 8192UL

static const char *CACHES[] = {
    "kmalloc-4k", "kmalloc-8k", "kmalloc-16k", "kmalloc-32k",
    "kmalloc-cg-8k", "kmalloc-rcl-8k", "kmalloc-cg-4k", NULL
};

static void snap(const char *tag)
{
    FILE *f = fopen("/proc/slabinfo", "re");
    char line[256];
    printf("--- %s ---\n", tag);
    if (!f) { printf("  slabinfo unreadable\n"); return; }
    while (fgets(line, sizeof line, f)) {
        for (int i = 0; CACHES[i]; i++) {
            size_t n = strlen(CACHES[i]);
            if (!strncmp(line, CACHES[i], n) && line[n] == ' ') {
                printf("  %s", line);
                break;
            }
        }
    }
    fclose(f);
}

int main(int argc, char **argv)
{
    int N = argc > 1 ? atoi(argv[1]) : 4000;
    unsigned char *buf = malloc(FRAG);
    memset(buf, 0x41, FRAG);

    snap("before");
    int *fd = calloc(N, sizeof(int));
    int nf = 0;
    for (int i = 0; i < N; i++) {
        int sv[2];
        if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sv) != 0) break;
        if (send(sv[0], buf, FRAG, MSG_NOSIGNAL) != (ssize_t)FRAG) {
            close(sv[0]); close(sv[1]); break;
        }
        close(sv[0]);
        fd[nf++] = sv[1];
    }
    snap("after");
    printf("sprayed %d frags of %lu bytes (%d MB)\n", nf, FRAG, (int)(nf * 8 / 1024));
    printf("expect active_objs of kmalloc-8k to rise by ~%d if the frag is a\n"
           "kmalloc-8k object (= one order-1 slab page)\n", nf);
    for (int i = 0; i < nf; i++) close(fd[i]);
    return 0;
}
