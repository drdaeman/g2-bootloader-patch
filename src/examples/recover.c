/* SPDX-License-Identifier: MIT */
#include <stdint.h>
#include "../ram_api.h"

/* Receive and program MRAM while this program stays resident in RAM. arg0 is
 * the destination and arg1 the byte count, both multiples of 16. Each verified
 * block produces a little-endian uint32_t progress count. A zero-length call
 * checks API support without programming. Only stock bootloader 2.3.2.14 is
 * supported; ROM determines programming permissions within physical MRAM.
 */
uint32_t entry(const ram_api *api, uint32_t address, uint32_t length) {
    if (api->version < 2)
        return 4;
    if (!length)
        return 0;
    if (address < 0x00400000u || address >= 0x00800000u ||
        length > 0x00800000u - address || ((address | length) & 15u))
        return 1;
    uint32_t block[64], done = 0;
    while (done < length) {
        unsigned size = length - done;
        if (size > sizeof(block))
            size = sizeof(block);
        unsigned filled = 0;
        while (filled < size) {
            int n = api->recv(api->context, (uint8_t *)block + filled, size - filled);
            if (n <= 0)
                return 5;
            filled += (unsigned)n;
        }
        uint32_t status =
            ((uint32_t (*)(uint32_t, const void *, uint32_t, uint32_t))0x0042e83du)(
                0x12344321u, block, address + done, size / 4);
        if (status)
            return status;
        __asm__ volatile("dsb sy" ::: "memory");
        /* ROM programming leaves previously read MRAM lines in the CPU cache. */
        for (uint32_t line = (address + done) & ~31u; line < address + done + size;
             line += 32u)
            *(volatile uint32_t *)0xe000ef5cu = line;
        __asm__ volatile("dsb sy\n isb sy" ::: "memory");
        const volatile uint32_t *actual = (const void *)(uintptr_t)(address + done);
        for (unsigned i = 0; i < size / 4; i++)
            if (actual[i] != block[i])
                return 3;
        done += size;
        if (api->send(api->context, &done, sizeof(done)))
            return 5;
    }
    return 0;
}
