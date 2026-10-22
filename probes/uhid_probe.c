/*
 * uhid_probe.c - is /dev/uhid actually usable from a plain shell?
 *
 * uhid's control plane is write(), not ioctl:
 *   write(UHID_CREATE2) -> kernel parses our HID report descriptor
 *   read()             -> UHID_START / UHID_OPEN / UHID_GET_REPORT ...
 *   write(UHID_INPUT2) -> kernel copies our report into the input subsystem
 *
 * Layout comes from the device's own BTF and is *packed*: uhid_event is 4380
 * bytes with the union at offset 4 (not 8), uhid_create2_req is 4372 and
 * uhid_input2_req is 4098. uhid_char_write() requires count to equal
 * sizeof(struct uhid_event) exactly, so a flat buffer is used to avoid any
 * compiler-layout ambiguity.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#define UHID_DESTROY 1
#define UHID_CREATE2 11
#define UHID_INPUT2  12
#define BUS_USB      0x03

#define EVENT_SIZE 4380
#define CREATE2_OFF 4
#define CREATE2_SIZE 4372
#define INPUT2_OFF 4
#define INPUT2_SIZE 4098

static const uint8_t RDESC[] = {
    0x06, 0x00, 0xFF, 0x09, 0x01, 0xA1, 0x01,
    0x15, 0x00, 0x26, 0xFF, 0x00, 0x75, 0x08,
    0x95, 0x08, 0x09, 0x01, 0x81, 0x02, 0xC0
};

static uint8_t ev[EVENT_SIZE];

static void drain(int fd)
{
    for (int i = 0; i < 6; i++) {
        uint8_t r[EVENT_SIZE];
        ssize_t n = read(fd, r, sizeof r);
        if (n <= 0) {
            printf("  read: n=%zd (%s)\n", n, n < 0 ? strerror(errno) : "eof");
            return;
        }
        uint32_t t = *(uint32_t *)r;
        printf("  event type=%u len=%zd\n", t, n);
    }
}

static int send_event(int fd, uint32_t type, const void *body, size_t bodylen)
{
    memset(ev, 0, sizeof ev);
    *(uint32_t *)ev = type;
    if (body && bodylen)
        memcpy(ev + 4, body, bodylen > EVENT_SIZE - 4 ? EVENT_SIZE - 4 : bodylen);
    errno = 0;
    ssize_t w = write(fd, ev, sizeof ev);
    printf("  write type=%u -> %zd (%s)\n", type, w, w < 0 ? strerror(errno) : "OK");
    return w < 0 ? -1 : 0;
}

int main(void)
{
    printf("=== uhid usability (packed layout, %d bytes) ===\n", EVENT_SIZE);
    int fd = open("/dev/uhid", O_RDWR | O_CLOEXEC | O_NONBLOCK);
    if (fd < 0) { printf("open: %s\n", strerror(errno)); return 1; }
    printf("  open /dev/uhid OK fd=%d\n", fd);

    /* build uhid_create2_req at offset 4 */
    uint8_t c2[CREATE2_SIZE];
    memset(c2, 0, sizeof c2);
    snprintf((char *)c2, 128, "lhprobe");
    *(uint16_t *)(c2 + 256) = sizeof RDESC;   /* rd_size */
    *(uint16_t *)(c2 + 258) = BUS_USB;        /* bus */
    *(uint32_t *)(c2 + 260) = 0x1234;         /* vendor */
    *(uint32_t *)(c2 + 264) = 0x5678;         /* product */
    *(uint32_t *)(c2 + 268) = 1;              /* version */
    memcpy(c2 + 276, RDESC, sizeof RDESC);    /* rd_data */

    if (send_event(fd, UHID_CREATE2, c2, sizeof c2) == 0)
        drain(fd);

    /* report body: uint16 size + data */
    uint8_t in2[INPUT2_SIZE];
    memset(in2, 0, sizeof in2);
    *(uint16_t *)in2 = 8;
    memset(in2 + 2, 0x41, 8);
    send_event(fd, UHID_INPUT2, in2, sizeof in2);
    drain(fd);

    send_event(fd, UHID_DESTROY, NULL, 0);
    close(fd);
    return 0;
}
