/*
 * l81_pi_sanity.c - does the PI-futex path actually behave the way our race
 * harness assumes?  Checks: (1) LOCK_PI writes the owner TID into the word,
 * (2) a second task's TRYLOCK_PI returns EBUSY, (3) the blocked LOCK_PI is
 * released by the owner's UNLOCK_PI.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <linux/futex.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

static uint32_t *g_word;

static int fp(int op)
{
    return (int)syscall(SYS_futex, g_word, op | FUTEX_PRIVATE_FLAG, 0, NULL, NULL, 0);
}

int main(void)
{
    g_word = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    *g_word = 0;
    printf("=== l81 PI futex sanity (uid=%d) ===\n", (int)getuid());

    pid_t c = fork();                      /* fork: separate mm is fine for sanity */
    if (c == 0) {
        int rc = fp(FUTEX_LOCK_PI);
        printf("  child  LOCK_PI   rc=%d errno=%d  word=%u  mytid=%d\n",
               rc, errno, *g_word, (int)syscall(SYS_gettid));
        sleep(1);
        rc = fp(FUTEX_UNLOCK_PI);
        printf("  child  UNLOCK_PI rc=%d errno=%d word=%u\n", rc, errno, *g_word);
        _exit(0);
    }

    usleep(200000);
    errno = 0;
    int rc = fp(FUTEX_TRYLOCK_PI);
    printf("  parent TRYLOCK   rc=%d errno=%d (%s) word=%u\n", rc, errno, strerror(errno), *g_word);

    errno = 0;
    rc = fp(FUTEX_LOCK_PI);
    printf("  parent LOCK_PI   rc=%d errno=%d word=%u  (blocks until child unlocks)\n",
           rc, errno, *g_word);
    fp(FUTEX_UNLOCK_PI);
    waitpid(c, NULL, 0);
    printf("done\n");
    return 0;
}
