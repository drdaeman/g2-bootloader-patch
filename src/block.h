/* SPDX-License-Identifier: MIT */
#pragma once
/* Version-2 streaming frames: BLK2, kind u16, length u16, bytes, CRC32.
 * One outstanding block; CRC validates the complete header and data before
 * delivery, including the declared length.
 */
static int block_send(unsigned kind, const uint8_t *data, unsigned n) {
    uint8_t packet[WIRE_BLOCK_HEADER];
    packet[0] = 'B';
    packet[1] = 'L';
    packet[2] = 'K';
    packet[3] = '2';
    packet[4] = (uint8_t)kind;
    packet[5] = 0;
    packet[6] = (uint8_t)n;
    packet[7] = (uint8_t)(n >> 8);
    DELAY(6);
    return transmit_frame(packet, sizeof(packet), data, n, 1);
}

__attribute__((used, noinline)) static unsigned
block_receive(uint8_t *packet, unsigned capacity, unsigned kind) {
    unsigned at = 0, needed = 8, discarding = 0;
    uint32_t start = TICK, last = start;
    for (;;) {
        uint32_t now = TICK;
        if ((uint32_t)(now - start) >= IO_WAIT_TICKS ||
            ((at || discarding) && (uint32_t)(now - last) >= 128u))
            return 0;
        if (W(UART2_FLAGS) & UART_FLAG_RX_EMPTY) {
            continue;
        }
        uint32_t dr = W(UART2_DATA);
        last = now;
        if (dr & UART_DATA_ERROR_MASK) {
            W(UART2_ERROR_CLEAR) = UART_CLEAR_ALL_ERRORS;
            discarding = 1;
        }
        /* A rejected header can understate the frame length. Drain until the
         * inter-byte timeout before turning the half-duplex line around. */
        if (discarding)
            continue;
        packet[at++] = (uint8_t)dr;
        if (at == 8) {
            unsigned n = u16(packet + 6);
            if (packet[0] != 'B' || packet[1] != 'L' || packet[2] != 'K' ||
                packet[3] != '2' || u16(packet + 4) != kind || n > capacity ||
                n > WIRE_BLOCK_DATA) {
                discarding = 1;
                continue;
            }
            needed = n + 12u;
        }
        if (at == needed) {
            if (crc32(packet, needed - 4) == u32(packet + needed - 4))
                return needed;
            discarding = 1;
        }
    }
}
