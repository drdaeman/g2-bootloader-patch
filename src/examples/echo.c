/* SPDX-License-Identifier: MIT */
#include "../ram_api.h"

/* Send a 12-byte message to the host: ASCII "HEY!", followed by the two
 * host-supplied arguments as little-endian uint32_t values. Return 0 if the
 * host acknowledges the message, or 1 if sending fails. This demonstrates
 * argument passing and the loader's output callback.
 */
uint32_t entry(const ram_api *api, uint32_t arg0, uint32_t arg1) {
    const uint32_t words[3] = {0x21594548u, arg0, arg1}; /* HEY! */
    return api->send(api->context, words, sizeof(words)) ? 1u : 0u;
}
