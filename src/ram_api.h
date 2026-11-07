/* SPDX-License-Identifier: MIT */
#pragma once
#include <stdint.h>

/* ABI version 3; fields retain the version-2 layout and version-1 prefix. Pointers are
 * borrowed for this call only. send() synchronously transmits chunks and waits for host
 * acknowledgements. It returns 0 on success, -1 on transport failure. Code must be
 * Thumb PIC, <=512 bytes, return normally, and leave SP valid. recv() returns one input
 * chunk of at most min(size, 1024) bytes, 0 for end-of-stream (or size 0), and -1 on
 * transport failure.
 */
typedef struct {
    uint32_t version;
    int (*send)(void *context, const void *data, uint32_t size);
    void *context;
    int (*recv)(void *context, void *data, uint32_t size);
} ram_api;
