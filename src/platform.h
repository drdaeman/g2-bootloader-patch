/* SPDX-License-Identifier: MIT */
#pragma once
#include <stdint.h>

/* Absolute bindings for the hash-pinned Even bootloader 2.3.2.14 only.
 * Function entries include the Thumb bit. SLOT means an address in driver RAM;
 * the value stored there is read at runtime, not another fixed hardware address.
 */
#define W(address) (*(volatile uint32_t *)(uintptr_t)(address))

enum {
    STOCK_TICK_COUNT_ENTRY = 0x004160e9u,
    STOCK_THREAD_DELAY_ENTRY = 0x00416379u,
    STOCK_THREAD_NEW_ENTRY = 0x004160ffu,
    STOCK_TASK_DELETE_ENTRY = 0x00417f0bu,
    STOCK_GPIO_FUNCTION_ENTRY = 0x0041d92du,
    STOCK_UART_WAKE_ENTRY = 0x0041f847u,
    STOCK_UART_SLEEP_ENTRY = 0x0041f8bbu,
    STOCK_UPDATE_FLAG_ENTRY = 0x0042e56du,
    /* Sets VTOR, loads MSP from the table and branches to its reset vector. */
    STOCK_VECTOR_HANDOFF_ENTRY = 0x0042dfd9u,

    BOOT_UART2_HANDLE_SLOT = 0x20000494u,
    BOOT_UART2_PIN_TABLE_SLOT = 0x20000498u,
    BOOT_UART2_AWAKE_SLOT = 0x200004a8u,
    BOOT_UART2_RX_CALLBACK_SLOT = 0x200004a4u,
    BOOT_UART2_EXPECTED_PIN_TABLE = 0x00434210u,
    BOOT_POWER_PRE_CALLBACK_SLOT = 0x20026e44u,
    BOOT_POWER_POST_CALLBACK_SLOT = 0x20026e48u,
    /* Three words of DTCM below the stock MSPLIM (0x2007d000). The stock image's
     * static RAM ends at 0x200271c8 and no stock literal addresses this gap. */
    BOOT_SELECTION_SLOT = 0x2007cff0u,

    MAIN_APPLICATION_BASE = 0x00438000u,
    MAIN_APPLICATION_END = 0x007fe000u,
    /* Stock init copies code to ITCM 0x40..0x6c and calls it until handoff. No
     * other stock literal addresses ITCM, so boot images may use later pages. */
    ITCM_BOOT_BASE = 0x00001000u,
    ITCM_END = 0x00040000u,

    UART2_BASE = 0x4003b000u,
    UART2_DATA = UART2_BASE,
    UART2_ERROR_CLEAR = UART2_BASE + 0x04u,
    UART2_FLAGS = UART2_BASE + 0x18u,
    UART_FLAG_BUSY = 0x08u,
    UART_FLAG_RX_EMPTY = 0x10u,
    UART_FLAG_TX_FULL = 0x20u,
    UART_DATA_ERROR_MASK = 0x0f00u,
    UART_CLEAR_ALL_ERRORS = 0xffu,
    UART2_MODULE = 2u,
    UART2_IRQ_MASK = 1u << 17,
    GPIO_PARK_FUNCTION = 3u,

    PWRCTRL_DEVICE_POWER_STATUS = 0x40021008u,
    PWRCTRL_UART2_POWERED = 0x800u,
    NVIC_IRQ0_SET_ENABLE = 0xe000e100u,
    NVIC_IRQ0_CLEAR_ENABLE = 0xe000e180u,
    NVIC_IRQ0_CLEAR_PENDING = 0xe000e280u
};

#define TICK (((uint32_t (*)(void))STOCK_TICK_COUNT_ENTRY)())
#define DELAY(ticks) (((int32_t (*)(uint32_t))STOCK_THREAD_DELAY_ENTRY)(ticks))
#define GPIO ((uint32_t (*)(uint32_t, uint32_t))STOCK_GPIO_FUNCTION_ENTRY)
#define WAKE ((uint32_t (*)(uint32_t))STOCK_UART_WAKE_ENTRY)
#define SLEEP ((uint32_t (*)(uint32_t))STOCK_UART_SLEEP_ENTRY)
#define NEW ((void *(*)(void (*)(void *), void *, const void *))STOCK_THREAD_NEW_ENTRY)
#define DELETE ((void (*)(void *))STOCK_TASK_DELETE_ENTRY)
#define ORIGINAL_FLAG ((uint32_t (*)(void))STOCK_UPDATE_FLAG_ENTRY)
typedef void handoff_function(uint32_t vectors) __attribute__((noreturn));
#define HANDOFF ((handoff_function *)STOCK_VECTOR_HANDOFF_ENTRY)
