/* SPDX-License-Identifier: MIT */
#pragma once
#include "bearssl_hmac.h"
#include "wire.h"
#include "auth_key.h"

/* HMAC input: G2BOOT | version LE32 | challenge LE32 | direction marker. */
static void auth_tag(const char *marker, uint32_t challenge, uint8_t tag[16]) {
    static const uint8_t key[64] = AUTH_KEY_PAD;
    uint8_t message[18] = {'G', '2', 'B', 'O', 'O', 'T'};
    for (unsigned i = 0; i < 4; i++) {
        message[6 + i] = (uint8_t)(WIRE_VERSION >> (8 * i));
        message[10 + i] = (uint8_t)(challenge >> (8 * i));
        message[14 + i] = (uint8_t)marker[i];
    }
    br_hmac_key_context kc;
    br_hmac_context ctx;
    br_hmac_key_init(&kc, &br_sha256_vtable, key, sizeof(key));
    br_hmac_init(&ctx, &kc, 16);
    br_hmac_update(&ctx, message, sizeof(message));
    br_hmac_out(&ctx, tag);
}
static int auth_equal(const uint8_t *a, const uint8_t *b, unsigned size) {
    unsigned difference = 0;
    for (unsigned i = 0; i < size; i++)
        difference |= a[i] ^ b[i];
    return difference == 0;
}
