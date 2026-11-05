/* SPDX-License-Identifier: MIT */
#include <string.h>

void *memcpy(void *to, const void *from, size_t size) {
    unsigned char *d = to;
    const unsigned char *s = from;
    while (size--)
        *d++ = *s++;
    return to;
}
void *memset(void *to, int value, size_t size) {
    unsigned char *d = to;
    while (size--)
        *d++ = (unsigned char)value;
    return to;
}

/* ARM compiler runtime support. No C library is linked. */
__attribute__((used)) void __aeabi_memcpy(void *to, const void *from, unsigned size) {
    (void)memcpy(to, from, size);
}
