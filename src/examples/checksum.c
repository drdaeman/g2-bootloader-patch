/* SPDX-License-Identifier: MIT */
#include "../ram_api.h"

/* Return the CRC-32 of a memory range. The host supplies the start address
 * and byte count; a zero-length range returns 0. No callback data is sent.
 * The entire range must be readable; invalid addresses can fault the CPU.
 */
uint32_t entry(const ram_api *api, uint32_t address, uint32_t length) {
    (void)api;

    const volatile uint8_t *p = (const void *)address;
    uint32_t c = 0xffffffffu;
    while (length--) {
        c ^= *p++;
        for (unsigned i = 0; i < 8; i++)
            c = (c >> 1) ^ (0xedb88320u & (0u - (c & 1u)));
    }
    return ~c;
}
