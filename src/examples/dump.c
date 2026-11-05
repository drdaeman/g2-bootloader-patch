/* SPDX-License-Identifier: MIT */
#include "../ram_api.h"

/* Send a memory range to the host in chunks of up to 128 bytes. The host
 * supplies the start address and byte count. boot.py saves the received bytes
 * in callback.bin. Return 0 on completion, or 1 if a send fails. A zero-length
 * range sends nothing. The entire range must be readable; invalid addresses
 * can fault the CPU.
 */
uint32_t entry(const ram_api *api, uint32_t address, uint32_t length) {
    while (length) {
        uint32_t n = length > 128u ? 128u : length;
        if (api->send(api->context, (const void *)(uintptr_t)address, n))
            return 1;
        address += n;
        length -= n;
    }
    return 0;
}
