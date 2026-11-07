/* SPDX-License-Identifier: MIT */
#include "../ram_api.h"

/* Send a memory range to the host. The transport chooses block boundaries. The host
 * supplies the start address and byte count. boot.py saves the received bytes
 * in callback.bin. Return 0 on completion, or 1 if a send fails. A zero-length
 * range sends nothing. The entire range must be readable; invalid addresses
 * can fault the CPU.
 */
uint32_t entry(const ram_api *api, uint32_t address, uint32_t length) {
    return length && api->send(api->context, (const void *)(uintptr_t)address, length)
               ? 1
               : 0;
}
