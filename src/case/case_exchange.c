/* SPDX-License-Identifier: MIT */
/* Append-only extension of the pinned 1720-byte case read bridge. All stock
 * initialization, seated-route checks and YHM restoration stay in that image.
 * Interrupts are already masked by its entry. No case flash writes.
 */
#include <stdint.h>
#include "../wire.h"
#define W(a) (*(volatile uint32_t *)(uintptr_t)(a))
#define RESULT ((volatile uint32_t *)0x20011a00u)
#define CAPTURE ((volatile uint8_t *)0x20011a56u)
#define HOST_SEND ((void (*)(const void *, unsigned))0x20010349u)
#define TEMPLE_SEND ((unsigned (*)(const void *, unsigned, unsigned))0x2001057du)
#define RX_PROFILE ((void (*)(void))0x08006c81u)
#define TX_PROFILE ((void (*)(void))0x08006cf9u)
#define ISR W(0x4000481cu)
#define RDR W(0x40004824u)
#define CASE_TIM2 0x40000000u
#define CASE_APB_ENABLE 0x4002103cu
#define CASE_APB_RESET 0x4002102cu

/* TIM2 is unused in the pinned stock case. Own it only while clock-gated off
 * at entry; never borrow an active stock timer. At the stock 64 MHz timer
 * clock, /64000 gives a free-running 32-bit millisecond count without IRQs.
 * Register layout: ST cmsis-device-g0 Include/stm32g0b1xx.h.
 */
__attribute__((used, noinline)) static int case_watchdog_start(void) {
    if ((W(CASE_APB_ENABLE) & 1u) || (W(CASE_APB_RESET) & 1u))
        return 0;
    W(CASE_APB_ENABLE) |= 1u;
    (void)W(CASE_APB_ENABLE);
    W(CASE_APB_RESET) |= 1u;
    W(CASE_APB_RESET) &= ~1u;
    W(CASE_TIM2 + 0x28u) = 63999u;
    W(CASE_TIM2 + 0x2cu) = 0xffffffffu;
    W(CASE_TIM2 + 0x14u) = 1u; /* UG loads the prescaler; DIER stays reset. */
    W(CASE_TIM2 + 0x10u) = 0;
    W(CASE_TIM2) = 1u;
    return 1;
}

__attribute__((used, noinline)) static void case_watchdog_stop(void) {
    W(CASE_TIM2) = 0;
    W(CASE_APB_RESET) |= 1u;
    W(CASE_APB_RESET) &= ~1u;
    W(CASE_APB_ENABLE) &= ~1u;
}

/* Stock 1.2.57 PB2 external-watchdog pulse. The stock wrapper uses .data
 * pointers that are not valid after ROM-loader entry. Use the configured pin
 * directly and only the hash-pinned, RAM-independent busy-delay leaf.
 * Run between complete packets: its low pulse must not block UART reception.
 */
__attribute__((used, noinline)) static int case_watchdog_feed(void) {
    if ((W(0x50000400u) & 0x30u) != 0x10u)
        return 0;
    W(0x50000418u) = 4u;
    ((void (*)(unsigned))0x0800a795u)(350u);
    W(0x50000418u) = 4u << 16;
    for (unsigned i = 0; i < 40u; i++)
        ((void (*)(unsigned))0x0800a795u)(350u);
    W(0x50000418u) = 4u;
    return 1;
}

/* One feed immediately, then at most once per five seconds, regardless of
 * packet count. Read again after the pulse so its cost cannot shorten the gap.
 */
__attribute__((used, noinline)) static int case_watchdog_service(uint32_t *last) {
    uint32_t now = W(CASE_TIM2 + 0x24u);
    if ((uint32_t)(now - *last) < 5000u)
        return 1;
    if (!case_watchdog_feed())
        return 0;
    *last = W(CASE_TIM2 + 0x24u);
    return 1;
}

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
        if (at < 32u)
            CAPTURE[at] = p[at];
        at++;
        if (at == 4) {
            if (p[0] == 'B' && p[1] == 'L' && p[2] == 'K' && p[3] == '2') {
                needed = 8;
            } else if (p[0] == 0x5a && p[1] == 0xa5 && p[2] == 255 &&
                       (p[3] == 8 || p[3] == 16 || p[3] == 24 || p[3] == 27)) {
                needed = p[3] + 5u;
            } else {
                return 0;
            }
        }
        if (at == 8 && p[0] == 'B') {
            unsigned n = (unsigned)p[6] | (unsigned)p[7] << 8;
            if (n > WIRE_BLOCK_DATA)
                return 0;
            needed = n + 12u;
        }
        if (at == needed)
            return at;
    }
    return 0;
}

void exchange(void) {
    if (!reset_claim())
        return;
    if (!case_watchdog_start())
        return;
    uint32_t last_feed = W(CASE_TIM2 + 0x24u) - 5000u;
    /* Console packets G2TX,len16,data,sum; G2EX exits. One temple reply per
     * operation, so callback DATA/ACK never races a second output frame. */
    uint8_t p[WIRE_BLOCK_MAX + 1u], console[WIRE_BLOCK_MAX + 8u], head[6];
    RESULT[10] = RESULT[11] = RESULT[12] = RESULT[13] = 0;
    HOST_SEND("G2RAM_READY\n", 12);
    while (host_read(head, 4)) {
        if (head[0] != 'G' || head[1] != '2')
            break;
        if (head[2] == 'E' && head[3] == 'X')
            break;
        if (head[2] != 'T' || head[3] != 'X' || !host_read(head + 4, 2))
            break;
        unsigned n = (unsigned)head[4] | (unsigned)head[5] << 8, status = 0;
        if (n != 0 && n != 9 && n != 25 && n != 32 && (n < 12u || n > WIRE_BLOCK_MAX))
            break;
        if (!host_read(p, n + 1))
            break;
        unsigned sum = 0;
        for (unsigned i = 0; i < 6; i++)
            sum += head[i];
        for (unsigned i = 0; i < n; i++)
            sum += p[i];
        if (p[n] != (uint8_t)sum)
            break;
        if (!case_watchdog_service(&last_feed))
            break;
        if (n) {
            int block = p[0] == 'B' && p[1] == 'L' && p[2] == 'K' && p[3] == '2';
            if (block ? (n < 12u || n != 12u + ((unsigned)p[6] | (unsigned)p[7] << 8))
                      : (p[0] != 0x7e || p[1] != 0 || p[2] != 1 || p[3] != n - 5u))
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
        console[6] = (uint8_t)(n >> 8);
        sum = 0;
        for (unsigned i = 0; i < n; i++)
            console[7 + i] = p[i];
        for (unsigned i = 0; i < n + 7; i++)
            sum += console[i];
        console[n + 7] = (uint8_t)sum;
        HOST_SEND(console, n + 8);
    }
    RESULT[11] = RESULT[12] = 0;
    case_watchdog_stop();
}
