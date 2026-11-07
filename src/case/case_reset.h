/* SPDX-License-Identifier: MIT */
/* Volatile case-SRAM reset while the pinned bridge owns the selected route.
 * The selected YHM image matches stock left/right reset routing. Keep that
 * selection for reception; the outer pinned bridge restores the saved route.
 * No case flash writes and no RTOS services while interrupts are masked.
 */
#define CASE_GPIO_INIT ((void (*)(uint32_t, const uint32_t *))0x08004d31u)
#define CASE_GPIOB 0x50000400u
#define CASE_PB9 (1u << 9)
#define CASE_SELECTED_YHM ((const volatile uint8_t *)0x20011a42u)
#define CASE_SPIN ((void (*)(uint32_t))0x20010625u)
#define CASE_RESET_WAVEFORM ((void (*)(void))0x20011401u)

__attribute__((used, noinline)) void
case_reset_delay_ms(uint32_t ms) { /* Pinned delay is SUBS/BNE: about three
                                      cycles/iteration at 64 MHz. */
    CASE_SPIN(ms * 21334u);
}

__attribute__((used, noinline)) static int case_reset_selected(void) {
    const volatile uint8_t *route = CASE_SELECTED_YHM;
    unsigned side = RESULT[3]; /* Pinned bridge: left=0, right=1. */
    if (side > 1 || route[3 + side] != 0xa6 || route[5] != 3 || route[6] != 0xc1 ||
        route[7] != 3 + 2 * side)
        return 0;
    uint32_t gpio[5];
    gpio[0] = CASE_PB9;
    gpio[1] = 1;
    gpio[2] = 0;
    gpio[3] = 3;
    gpio[4] = 0;
    CASE_GPIO_INIT(CASE_GPIOB, gpio);
    case_reset_delay_ms(30);
    CASE_RESET_WAVEFORM();
    gpio[1] = 0;
    CASE_GPIO_INIT(CASE_GPIOB, gpio);
    RX_PROFILE();
    __asm__ volatile("cpsid i" ::: "memory");
    return 1;
}
