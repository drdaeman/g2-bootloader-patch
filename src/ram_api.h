/* SPDX-License-Identifier: MIT */
#pragma once
#include <stdint.h>

/* ABI version 1. Pointers are borrowed for this call only. send() synchronously
 * transmits chunks and waits for host acknowledgements. It returns 0 on success, -1 on
 * transport failure. Code must be Thumb PIC, <=512 bytes, return normally, and leave SP
 * valid.
 */
typedef struct {
    uint32_t version;
    int (*send)(void *context, const void *data, uint32_t size);
    void *context;
} ram_api;
