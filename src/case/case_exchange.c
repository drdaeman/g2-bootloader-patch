/* SPDX-License-Identifier: MIT */
/* Append-only extension of the pinned 1720-byte case read bridge. All stock
 * initialization, seated-route checks and YHM restoration stay in that image.
 * Interrupts are already masked by its entry. No case flash writes.
 */
#include <stdint.h>
#define W(a) (*(volatile uint32_t *)(uintptr_t)(a))
#define RESULT ((volatile uint32_t *)0x20011a00u)
#define CAPTURE ((volatile uint8_t *)0x20011a56u)
#define HOST_SEND ((void (*)(const void *, unsigned))0x20010349u)
#define TEMPLE_SEND ((unsigned (*)(const void *, unsigned, unsigned))0x2001057du)
#define RX_PROFILE ((void (*)(void))0x08006c81u)
#define TX_PROFILE ((void (*)(void))0x08006cf9u)
#define ISR W(0x4000481cu)
#define RDR W(0x40004824u)

static int receive(uint8_t *p, unsigned limit) {
    unsigned at = 0;
    for (unsigned polls = 0; polls < 64000000u; polls++) {
        unsigned flags = ISR;
        if (flags & 15u) {
            RESULT[13] |= flags & 15u;
            return 0;
        }
        if (flags & 32u) {
            unsigned b = RDR;
            p[at] = (uint8_t)b;
            CAPTURE[at++] = (uint8_t)b;
            RESULT[11] = RESULT[12] = at;
            if (at == limit)
                return 1;
        }
    }
    return 0;
}

static int host_read(uint8_t *p, unsigned n) {
    unsigned at = 0;
    for (unsigned polls = 0; polls < 64000000u; polls++) {
        unsigned flags = W(0x4001381cu);
        if (flags & 15u)
            return 0;
        if (flags & 32u) {
            p[at++] = (uint8_t)W(0x40013824u);
            if (at == n)
                return 1;
        }
    }
    return 0;
}
static unsigned relay_receive(uint8_t *p) {
    unsigned at = 0, needed = 4;
    for (unsigned polls = 0; polls < 64000000u; polls++) {
        unsigned flags = ISR;
        if (flags & 15u) {
            RESULT[13] |= flags & 15u;
            return 0;
        }
        if (!(flags & 32u))
            continue;
        p[at] = (uint8_t)RDR;
        CAPTURE[at] = p[at];
        at++;
        if (at == 4) {
            if (p[0] != 0x5a || p[1] != 0xa5 || p[2] != 255 ||
                (p[3] != 8 && p[3] != 16 && p[3] != 24 && p[3] != 27))
                return 0;
            needed = p[3] + 5u;
        }
        if (at == needed)
            return at;
    }
    return 0;
}

void exchange(void) {
    if (!reset_claim())
        return;
    /* Console packets G2TX,len,data,sum; G2EX exits. One temple reply per
     * operation, so callback DATA/ACK never races a second output frame. */
    uint8_t p[33], console[39], head[5];
    RESULT[10] = RESULT[11] = RESULT[12] = RESULT[13] = 0;
    HOST_SEND("G2RAM_READY\n", 12);
    while (host_read(head, 4)) {
        if (head[0] != 'G' || head[1] != '2')
            break;
        if (head[2] == 'E' && head[3] == 'X')
            break;
        if (head[2] != 'T' || head[3] != 'X' || !host_read(head + 4, 1))
            break;
        unsigned n = head[4], status = 0;
        if (n != 0 && n != 9 && n != 25 && n != 32)
            break;
        if (!host_read(p, n + 1))
            break;
        unsigned sum = 0;
        for (unsigned i = 0; i < 5; i++)
            sum += head[i];
        for (unsigned i = 0; i < n; i++)
            sum += p[i];
        if (p[n] != (uint8_t)sum)
            break;
        if (n) {
            if (p[0] != 0x7e || p[1] != 0 || p[2] != 1 || p[3] != n - 5u)
                break;
            TX_PROFILE();
            __asm__ volatile("cpsid i" ::: "memory");
            RESULT[10] = TEMPLE_SEND(p, n, 100);
            if (RESULT[10] != n)
                status = 1;
        }
        RX_PROFILE();
        __asm__ volatile("cpsid i" ::: "memory");
        n = status ? 0 : relay_receive(p);
        if (!n && !status)
            status = 2;
        console[0] = 'G';
        console[1] = '2';
        console[2] = 'R';
        console[3] = 'X';
        console[4] = (uint8_t)status;
        console[5] = (uint8_t)n;
        sum = 0;
        for (unsigned i = 0; i < n; i++)
            console[6 + i] = p[i];
        for (unsigned i = 0; i < n + 6; i++)
            sum += console[i];
        console[n + 6] = (uint8_t)sum;
        HOST_SEND(console, n + 7);
    }
    RESULT[11] = RESULT[12] = 0;
}
