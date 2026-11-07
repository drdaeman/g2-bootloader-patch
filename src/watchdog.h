/* SPDX-License-Identifier: MIT */
#pragma once
/* nPM1300 watchdog service for the observed stock bootloader bus state.
 * IOM7 is initially off; GPIO22/23 already select its I2C pins. Do not touch
 * unpowered IOM registers or borrow a controller another thread has enabled.
 * Only WATCHDOGKICK is written: timer mode/reload, rails and charging stay put.
 */
#define PMIC_IOM 0x40057000u
#define PMIC_POLLS 32768u
#define PMIC_CYCLES 250000u
#define WATCHDOG_DEMCR 0xe000edfcu
#define WATCHDOG_DWT_CTRL 0xe0001000u
#define WATCHDOG_DWT_CYCLES 0xe0001004u

typedef struct {
    uint32_t start, remaining;
} watchdog_budget;

/* One shared budget for power readiness and all I2C commands. CYCCNT does not
 * need interrupts. A frozen/unavailable counter still has the finite poll
 * fallback. Preserve the caller's debug enables; never reset CYCCNT itself.
 * CMSIS Core/Include/core_cm55.h defines TRCENA, NOCYCCNT and CYCCNTENA.
 */
static int watchdog_expired(watchdog_budget *budget) {
    return !budget->remaining-- ||
           (uint32_t)(W(WATCHDOG_DWT_CYCLES) - budget->start) >= PMIC_CYCLES;
}

static int watchdog_command(watchdog_budget *budget, uint32_t command) {
    W(PMIC_IOM + 0x208) = 0xffffffffu;
    W(PMIC_IOM + 0x120) = command;
    while (!watchdog_expired(budget)) {
        uint32_t status = W(PMIC_IOM + 0x204);
        if (status & 0x270u)
            return 0;
        if (status & 1u)
            return 1;
    }
    return 0;
}

__attribute__((used, noinline)) static int boot_watchdog_feed(void) {
    uint32_t mask;
    __asm__ volatile("mrs %0,primask\n cpsid i" : "=r"(mask)::"memory");
    uint32_t power = W(0x40021004u);
    int ok = 0;
    if ((power & 0x1e0u) || W(0x40010058u) != 0x4200u || W(0x4001005cu) != 0x4200u)
        goto done;
    uint32_t demcr = W(WATCHDOG_DEMCR);
    W(WATCHDOG_DEMCR) = demcr | (1u << 24);
    uint32_t dwt = W(WATCHDOG_DWT_CTRL);
    if (!(dwt & (1u << 25)))
        W(WATCHDOG_DWT_CTRL) = dwt | 1u;
    watchdog_budget budget = {W(WATCHDOG_DWT_CYCLES), PMIC_POLLS};
    W(0x40021004u) = power | 0x100u;
    for (;;) {
        if (watchdog_expired(&budget))
            goto power_down;
        if (W(0x40021008u) & 0x100u)
            break;
    }
    W(PMIC_IOM + 0x11c) = 0;
    W(PMIC_IOM + 0x118) = 0x3b1d2301u; /* HFRC24, 400 kHz */
    W(PMIC_IOM + 0x2c0) = 0x0003f270u; /* AmbiqSuite 5.1 timing */
    W(PMIC_IOM + 0x2c4) = 0x6bu;
    W(PMIC_IOM + 0x110) = 0;
    W(PMIC_IOM + 0x110) = 2;
    W(PMIC_IOM + 0x11c) = 0x10u;
    /* Validate TIMERCONFIG and target bytes on every feed. TIMERSTATUS and the
     * reserved byte are not configuration. Known profile: watchdog reset,
     * 2 ms prescaler, target 0x003c00 -> 30.72 s. Never rewrite the profile. */
    W(PMIC_IOM + 0x10c) = 0x0507u;
    if (!watchdog_command(&budget, 0x281u) || !watchdog_command(&budget, 0x602u) ||
        ((W(PMIC_IOM + 0x100) >> 16) & 255u) < 6u)
        goto shutdown;
    uint32_t lo = W(PMIC_IOM + 0x108), hi = W(PMIC_IOM + 0x108);
    if ((lo & 0xff0000ffu) != 0x0au || (hi & 0xffffu) != 0x003cu)
        goto shutdown;
    /* The completed pointer/read transaction has drained both FIFOs. A second
     * FIFO reset here stalls the next write on real Apollo510; reuse the FIFO
     * state for the kick (right-temple RAM-only A/B validated). */
    W(PMIC_IOM + 0x10c) = 0x00010407u;      /* register 07 04, value 01 */
    ok = watchdog_command(&budget, 0x301u); /* three-byte write, STOP */
shutdown:
    W(PMIC_IOM + 0x11c) = 0;
    W(PMIC_IOM + 0x118) = 0;
power_down:
    W(0x40021004u) = power;
    W(WATCHDOG_DWT_CTRL) = dwt;
    W(WATCHDOG_DEMCR) = demcr;
done:
    __asm__ volatile("msr primask,%0" ::"r"(mask) : "memory");
    return ok;
}

/* Called by the higher-priority manager, not the worker executing RAM code.
 * Retry failed/temporarily busy bus ownership after one second. Unsigned tick
 * subtraction handles wraparound. All scheduling state stays on its stack.
 */
static void boot_watchdog_hold(session *s) {
    uint32_t last = TICK, interval = 0;
    while (s->held) {
        uint32_t now = TICK;
        if (!s->receiving && (uint32_t)(now - last) >= interval) {
            interval = boot_watchdog_feed() ? 5120u : 1024u;
            last = TICK;
        }
        DELAY(1);
    }
}
