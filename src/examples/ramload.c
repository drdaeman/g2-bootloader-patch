/* SPDX-License-Identifier: MIT */
#include <stdint.h>
#include "../ram_api.h"

/* Receive a boot image into ITCM while this program stays resident in RAM.
 * arg0 is the destination and arg1 the byte count, both multiples of 16, within
 * [0x1000, 0x40000); the first ITCM page holds stock bootloader code. Each
 * 256-byte block, and the final partial one, produces a little-endian uint32_t
 * cumulative count. A zero-length call checks API support without writing.
 * Return 0 on success, 1 for invalid bounds/alignment, 4 when RAM API version 2
 * is required, and 5 for incomplete input or callback failure.
 */
uint32_t entry(const ram_api *api, uint32_t address, uint32_t length) {
    if (api->version < 2)
        return 4;
    if (!length)
        return 0;
    if (address < 0x1000u || address >= 0x40000u || length > 0x40000u - address ||
        ((address | length) & 15u))
        return 1;
    uint8_t *out = (uint8_t *)(uintptr_t)address;
    uint32_t done = 0;
    while (done < length) {
        uint32_t end = length - done > 256u ? done + 256u : length;
        while (done < end) {
            int n = api->recv(api->context, out + done, end - done);
            if (n <= 0)
                return 5;
            done += (uint32_t)n;
        }
        if (api->send(api->context, &done, sizeof(done)))
            return 5;
    }
    __asm__ volatile("dsb sy\n isb sy" ::: "memory");
    return 0;
}
