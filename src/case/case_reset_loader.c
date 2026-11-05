/* SPDX-License-Identifier: MIT */
/* Keep reset, claim and the loader on one running case MCU instance. */
#include <string.h>

static int reset_claim(void);
#include "case_exchange.c"
#include "case_reset.h"

static int reset_claim(void) {
    uint8_t beacon[21];
    RESULT[10] = RESULT[11] = RESULT[12] = RESULT[13] = 0;
    RX_PROFILE();
    __asm__ volatile("cpsid i" ::: "memory");
    uint32_t registers[4] = {W(0x40004800u), W(0x40004804u), W(0x4000480cu), ISR};
    HOST_SEND(registers, sizeof(registers));
    HOST_SEND("G2U2_ARMED\n", 11);
    if (!case_reset_selected() || !receive(beacon, sizeof(beacon)))
        return 0;
    HOST_SEND(beacon, sizeof(beacon));
    return 1;
}
