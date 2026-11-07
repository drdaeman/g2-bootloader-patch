/* SPDX-License-Identifier: MIT */
/* Stock 2.3.2.14 only. The manager owns UART setup/cleanup. A lower-priority
 * worker owns the wire protocol. They share one session: the worker publishes
 * the selected boot target before it clears held.
 */
/* Shared UART power-domain status is not UART2 ownership. */
#define PROBE_WAIT_TICKS 512u
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "platform.h"
#include "wire.h"
#include "auth.h"
#define IO_WAIT_TICKS 2048u
#define SELECTION_MAGIC 0x544f4231u /* "1BOT" */
enum { LOAD = 1, DATA, RUN, OUTPUT_ACK, INPUT_DATA, BOOT };
enum { ACK, OUTPUT, RESULT, READY, ERROR, INPUT };
enum { UNAVAILABLE = 1, BAD_REQUEST, BAD_CRC, ABORTED, IO_ERROR, BAD_TARGET };

typedef struct {
    uint16_t length, entry;
    uint32_t arg0, arg1;
} program;
typedef struct {
    volatile uint32_t held, target, claimed;
} session;
typedef struct {
    const char *name;
    uint32_t bits;
    void *cb;
    uint32_t cb_bytes;
    void *stack;
    uint32_t stack_bytes, priority, tz, reserved;
} thread_attributes;
_Static_assert(sizeof(thread_attributes) == 36, "stock thread ABI");

#include "ram_invoke.h"
#include "watchdog.h"

static uint32_t u32(const uint8_t *p) {
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 |
           (uint32_t)p[3] << 24;
}
static unsigned u16(const uint8_t *p) { return (unsigned)p[0] | (unsigned)p[1] << 8; }
static void put32(uint8_t *p, uint32_t n) {
    for (unsigned i = 0; i < 4; i++)
        p[i] = (uint8_t)(n >> (8 * i));
}
static uint32_t crc32(const uint8_t *p, unsigned n) {
    uint32_t c = 0xffffffffu;
    while (n--) {
        c ^= *p++;
        for (unsigned i = 0; i < 8; i++)
            c = (c >> 1) ^ (0xedb88320u & (0u - (c & 1u)));
    }
    return ~c;
}
/* An alternate image must be 4 KiB-aligned inside the main-application MRAM
 * region or ITCM above its first page, and start with a plausible vector table:
 * an 8-byte-aligned SRAM stack pointer and a Thumb reset vector after the table
 * base, inside the same region. */
static int boot_target_valid(uint32_t vectors) {
    uint32_t end;
    if (vectors >= MAIN_APPLICATION_BASE && vectors < MAIN_APPLICATION_END)
        end = MAIN_APPLICATION_END;
    else if (vectors >= ITCM_BOOT_BASE && vectors < ITCM_END)
        end = ITCM_END;
    else
        return 0;
    if (vectors & 0xfffu)
        return 0;
    uint32_t sp = W(vectors), reset = W(vectors + 4u);
    return !(sp & 7u) && sp > 0x20000000u && sp <= 0x20400000u && (reset & 1u) &&
           (reset & ~1u) >= vectors + 8u && reset < end;
}
/* One-shot record from the manager's hook to the DFU task's handoff. */
static void boot_select(uint32_t vectors) {
    volatile uint32_t *record = (volatile uint32_t *)(uintptr_t)BOOT_SELECTION_SLOT;
    record[0] = vectors ? SELECTION_MAGIC : 0;
    record[1] = vectors;
    record[2] = ~vectors;
    __asm__ volatile("dsb sy" ::: "memory");
}
/* Replaces both stock DFU-task calls of the handoff leaf, which always pass the
 * stock main application. The selection is consumed before any jump, so it
 * applies to one boot only; a missing or no longer valid target boots stock. */
__attribute__((used, noinline, noreturn)) void boot_handoff(uint32_t vectors) {
    volatile uint32_t *record = (volatile uint32_t *)(uintptr_t)BOOT_SELECTION_SLOT;
    uint32_t target = record[1];
    int armed = record[0] == SELECTION_MAGIC && record[2] == ~target;
    boot_select(0);
    if (armed && boot_target_valid(target))
        vectors = target;
    HANDOFF(vectors);
}
static void direction(unsigned tx) {
    const uint32_t *p = (const uint32_t *)(uintptr_t)W(BOOT_UART2_PIN_TABLE_SLOT);
    GPIO(p[tx ? 1 : 0], GPIO_PARK_FUNCTION);
    GPIO(p[tx ? 0 : 1], p[tx ? 2 : 3]);
}
/* The finite per-send bound is local. No session deadline or IRQ completion. */
static int transmit(const uint8_t *p, unsigned n) {
    uint32_t start = TICK;
    int ok = 0;
    direction(1);
    for (unsigned i = 0; i < n; i++) {
        while (W(UART2_FLAGS) & UART_FLAG_TX_FULL) {
            if ((uint32_t)(TICK - start) >= 21u)
                goto done;
            DELAY(1);
        }
        W(UART2_DATA) = p[i];
    }
    while (W(UART2_FLAGS) & UART_FLAG_BUSY) {
        if ((uint32_t)(TICK - start) >= 21u)
            goto done;
        DELAY(1);
    }
    ok = 1;
done:

    direction(0);
    return ok;
}
static void continue_request(uint8_t *p) {
    p[0] = 0x7e;
    p[1] = 0;
    p[2] = 1;
    p[3] = 4;
    for (unsigned i = 0; i < 4; i++)
        p[4 + i] = (uint8_t)WIRE_CONT[i];
    unsigned sum = 9 + 0x7d;
    for (unsigned i = 0; i < 8; i++)
        sum += p[i];
    p[8] = (uint8_t)sum;
}
static void announcement(uint8_t *p, const char *marker, const uint8_t *data,
                         unsigned bytes) {
    p[0] = 0x5a;
    p[1] = 0xa5;
    p[2] = 255;
    p[3] = (uint8_t)(8 + bytes);
    p[4] = 0;
    p[5] = 1;
    p[6] = 3;
    p[7] = (uint8_t)(4 + bytes);
    for (unsigned i = 0; i < 4; i++)
        p[8 + i] = (uint8_t)marker[i];
    for (unsigned i = 0; i < bytes; i++)
        p[12 + i] = data[i];
    unsigned sum = 6 + bytes;
    for (unsigned i = 4; i < 12 + bytes; i++)
        sum += p[i];
    p[12 + bytes] = (uint8_t)sum;
}
/* Zero means idle wait without an overall timeout. Once a frame starts, an
 * inter-byte timeout/error aborts it; callers never resume an ambiguous LOAD. */
static unsigned receive(uint8_t *p, uint32_t timeout) {
    unsigned at = 0, needed = 0;
    uint32_t start = TICK, last = start;
    for (;;) {
        uint32_t now = TICK;
        if ((timeout && (uint32_t)(now - start) >= timeout) ||
            (at && (uint32_t)(now - last) >= 128u))
            return 0;
        if (W(UART2_FLAGS) & UART_FLAG_RX_EMPTY) {
            DELAY(1);
            continue;
        }
        uint32_t dr = W(UART2_DATA);
        if (dr & UART_DATA_ERROR_MASK) {
            W(UART2_ERROR_CLEAR) = UART_CLEAR_ALL_ERRORS;
            return 0;
        }
        uint8_t b = (uint8_t)dr;
        last = now;
        if (!at) {
            if (b == 0x7e)
                p[at++] = b;
            continue;
        }
        if ((at == 1 && b != 0) || (at == 2 && b != 1) ||
            (at == 3 && b != 4 && b != 20 && b != 27))
            return 0;
        p[at++] = b;
        if (at == 4)
            needed = b + 5u;
        if (at != needed)
            continue;
        unsigned sum = needed + 0x7d;
        for (unsigned i = 0; i < needed - 1; i++)
            sum += p[i];
        return p[needed - 1] == (uint8_t)sum ? needed : 0;
    }
}
static int command(const uint8_t *p, unsigned got, unsigned op) {
    return got == 32 && p[4] == WIRE_RQST[0] && p[5] == WIRE_RQST[1] &&
           p[6] == WIRE_RQST[2] && p[7] == WIRE_RQST[3] && p[8] == op;
}
static int reply(unsigned kind, unsigned status, const uint8_t *data, unsigned n) {
    uint8_t p[32] = {0x5a, 0xa5,         255,          27,           0,           1, 3,
                     23,   WIRE_RESP[0], WIRE_RESP[1], WIRE_RESP[2], WIRE_RESP[3]};
    p[12] = (uint8_t)kind;
    p[13] = (uint8_t)status;
    for (unsigned i = 0; i < n; i++)
        p[14 + i] = data[i];
    unsigned sum = 25;
    for (unsigned i = 4; i < 31; i++)
        sum += p[i];
    p[31] = (uint8_t)sum;
    DELAY(6);
    return transmit(p, sizeof(p));
}
/* Blocking LOAD: cursor/expected CRC live only in this call. On success publish
 * the header last. 0 means a definite rejection; -1 means abort the session. */
static int load(uint8_t *code, program *available, uint8_t *p) {
    available->length = 0;
    program header;
    header.length = (uint16_t)u16(p + 9);
    header.entry = (uint16_t)u16(p + 11);
    header.arg0 = u32(p + 13);
    header.arg1 = u32(p + 17);
    uint32_t expected = u32(p + 21);
    if (header.length < 2 || header.length > 512 || header.entry >= header.length ||
        ((header.length | header.entry) & 1u))
        return reply(ERROR, BAD_REQUEST, 0, 0) ? 0 : -1;
    if (!reply(ACK, 0, 0, 0))
        return -1;
    unsigned cursor = 0;
    while (cursor < header.length) {
        unsigned got = receive(p, IO_WAIT_TICKS), n = p[9];
        if (!command(p, got, DATA))
            return -1;
        if (!n || n > 16 || n > header.length - cursor)
            return reply(ERROR, BAD_REQUEST, 0, 0) ? 0 : -1;
        for (unsigned i = 0; i < n; i++)
            code[cursor + i] = p[10 + i];
        cursor += n;
        if (cursor < header.length && !reply(ACK, 0, 0, 0))
            return -1;
    }
    if (crc32(code, header.length) != expected)
        return reply(ERROR, BAD_CRC, 0, 0) ? 0 : -1;
    *available = header;
    if (!reply(READY, 0, 0, 0)) {
        available->length = 0;
        return -1;
    }
    return 1;
}
__attribute__((used, noinline)) static int send_output(void *context, const void *data,
                                                       uint32_t size) {
    int *failed = context;
    const uint8_t *p = data;
    if (*failed)
        return -1;
    while (size) {
        unsigned n = size > 16u ? 16u : size;
        if (!reply(OUTPUT, n, p, n))
            goto error;
        uint8_t ack[32];
        unsigned got = receive(ack, IO_WAIT_TICKS);
        if (!command(ack, got, OUTPUT_ACK))
            goto error;
        p += n;
        size -= n;
    }
    return 0;
error:
    *failed = 1;
    return -1;
}
__attribute__((used, noinline)) static int recv_input(void *context, void *data,
                                                      uint32_t size) {
    int *failed = context;
    if (*failed)
        return -1;
    if (!size)
        return 0;
    unsigned capacity = size > 16u ? 16u : size;
    if (!reply(INPUT, capacity, 0, 0))
        goto error;
    uint8_t packet[32];
    unsigned got = receive(packet, IO_WAIT_TICKS), n = packet[9];
    if (!command(packet, got, INPUT_DATA) || n > capacity ||
        crc32(packet + 10, n) != u32(packet + 26))
        goto error;
    uint8_t *out = data;
    for (unsigned i = 0; i < n; i++)
        out[i] = packet[10 + i];
    return (int)n;
error:
    *failed = 1;
    return -1;
}
static int is_continue(const uint8_t *p, unsigned got) {
    uint8_t expected[9];
    continue_request(expected);
    if (got != 9)
        return 0;
    for (unsigned i = 0; i < 9; i++)
        if (p[i] != expected[i])
            return 0;
    return 1;
}
/* Every release publishes the boot target first; the manager reads it once
 * held is clear. */
static __attribute__((always_inline)) inline void finish_session(session *s,
                                                                 uint32_t target) {
    uint8_t acknowledgement[13];
    announcement(acknowledgement, WIRE_RLSD, 0, 0);
    DELAY(6);
    (void)transmit(acknowledgement, sizeof(acknowledgement));
    s->target = target;
    s->held = 0;
}
static __attribute__((always_inline)) inline void continue_only(session *s) {
    uint8_t packet[32];
    for (;;) {
        unsigned got = receive(packet, 0);
        if (is_continue(packet, got))
            break;
    }
    finish_session(s, 0);
}
/* The boot selection stays local until a CONTINUE in this loop. Every failure
 * path, including an unacknowledged BOOT, discards it. */
static void commands(session *s) {
    uint8_t code[512] __attribute__((aligned(32))), p[32];
    program available;
    available.length = 0;
    uint32_t selected = 0;
    for (;;) {
        unsigned got = receive(p, 0);
        if (is_continue(p, got)) {
            finish_session(s, selected);
            return;
        }
        if (!got)
            goto aborted;
        if (command(p, got, LOAD)) {
            if (load(code, &available, p) < 0)
                goto aborted;
        } else if (command(p, got, RUN)) {
            if (!available.length) {
                if (!reply(ERROR, UNAVAILABLE, 0, 0))
                    goto aborted;
                continue;
            }
            program header = available;
            available.length = 0;
            int failed = 0;
            uintptr_t send, recv;
            __asm__ volatile("adr %0, send_output\n orr %0,%0,#1" : "=r"(send));
            __asm__ volatile("adr %0, recv_input\n orr %0,%0,#1" : "=r"(recv));
            ram_api api = {2, (void *)send, &failed, (void *)recv};
            boot_ram_call call = {((uintptr_t)code + header.entry) | 1u, &api,
                                  header.arg0, header.arg1, 0};
            boot_ram_sync(code, header.length);
            boot_ram_invoke(&call);
            uint8_t result[4];
            put32(result, call.result);
            if (!reply(RESULT, failed ? IO_ERROR : 0, result, 4) || failed)
                goto wait_continue;
        } else if (command(p, got, BOOT)) {
            /* Every BOOT first clears the selection; target 0 only clears it. */
            uint32_t target = u32(p + 9);
            selected = 0;
            if (target && !boot_target_valid(target)) {
                if (!reply(ERROR, BAD_TARGET, 0, 0))
                    goto aborted;
                continue;
            }
            if (!reply(ACK, 0, 0, 0))
                goto aborted;
            selected = target;
        } else if (!reply(ERROR, BAD_REQUEST, 0, 0))
            goto aborted;
    }
aborted:
    /* No retries/resume after uncertainty. Only explicit continue is accepted. */
    available.length = 0;
    (void)reply(ERROR, ABORTED, 0, 0);
wait_continue:
    continue_only(s);
}
__attribute__((used, noinline)) uint32_t boot_task_checkpoint(volatile uint32_t *held) {
    return *held;
}
__attribute__((used, noinline)) void boot_probe_wait(void) { DELAY(PROBE_WAIT_TICKS); }
__attribute__((used, noinline)) static void uart2_worker(void *argument) {
    session *s = argument;
    uint32_t challenge = TICK ^ 0x32524c47u;
    uint8_t p[32],
        expected[25] = {0x7e,         0,           1, 20, WIRE_HOLD[0], WIRE_HOLD[1],
                        WIRE_HOLD[2], WIRE_HOLD[3]};
    auth_tag(WIRE_HOLD, challenge, expected + 8);
    unsigned sum = 25 + 0x7d;
    for (unsigned i = 0; i < 24; i++)
        sum += expected[i];
    expected[24] = (uint8_t)sum;
    uint8_t hello[8];
    put32(hello, WIRE_VERSION);
    put32(hello + 4, challenge);
    announcement(p, WIRE_HELO, hello, sizeof(hello));
    if (!transmit(p, 21))
        goto park;
    for (;;) {
        if (receive(p, 0) != sizeof(expected) ||
            !auth_equal(p, expected, sizeof(expected)))
            continue;
        s->claimed = 1;
        s->held = 1;
        uint8_t tag[16];
        auth_tag(WIRE_OKAY, challenge, tag);
        announcement(p, WIRE_OKAY, tag, sizeof(tag));
        DELAY(6);
        if (transmit(p, 29))
            commands(s);
        else
            continue_only(s);
        break;
    }
park:
    for (;;)
        DELAY(0xffffffffu);
}
uint32_t boot_task_then_flag(void) {
    uint64_t stack[512], cb[14];
    session s;
    s.held = 0;
    s.target = 0;
    s.claimed = 0;
    /* RAM can survive a reset; never inherit a previous boot's selection. */
    boot_select(0);
    if (!W(BOOT_UART2_HANDLE_SLOT) ||
        W(BOOT_UART2_PIN_TABLE_SLOT) != BOOT_UART2_EXPECTED_PIN_TABLE ||
        (W(BOOT_UART2_AWAKE_SLOT) & 0xffu) || W(BOOT_UART2_RX_CALLBACK_SLOT) ||
        W(BOOT_POWER_PRE_CALLBACK_SLOT) || W(BOOT_POWER_POST_CALLBACK_SLOT))
        return ORIGINAL_FLAG();
    uint32_t enabled = W(NVIC_IRQ0_SET_ENABLE) & UART2_IRQ_MASK;
    W(NVIC_IRQ0_CLEAR_ENABLE) = UART2_IRQ_MASK;
    __asm__ volatile("dsb sy\n isb sy" ::: "memory");
    uint32_t wake_result = WAKE(UART2_MODULE);
    if (wake_result == 0 && (W(PWRCTRL_DEVICE_POWER_STATUS) & PWRCTRL_UART2_POWERED)) {
        thread_attributes a;
        a.name = "u2-minimal";
        a.bits = 0;
        a.cb = cb;
        a.cb_bytes = sizeof(cb);
        a.stack = stack;
        a.stack_bytes = sizeof(stack);
        a.priority = 47;
        a.tz = 0;
        a.reserved = 0;
        uintptr_t worker;
        __asm__ volatile("adr %0, uart2_worker\n orr %0,%0,#1" : "=r"(worker));
        void *thread = NEW((void (*)(void *))worker, (void *)&s, &a);
        if (thread) {
            boot_probe_wait();
            if (boot_task_checkpoint(&s.held))
                boot_watchdog_hold(&s);
            DELETE(thread);
            /* Includes a session released before the first checkpoint. The
             * worker is gone, so it can no longer own the PMIC bus. Never
             * delay release indefinitely if this best-effort kick fails. */
            if (s.claimed)
                (void)boot_watchdog_feed();
        }
    }
    (void)SLEEP(UART2_MODULE);
    W(NVIC_IRQ0_CLEAR_PENDING) = UART2_IRQ_MASK;
    if (enabled)
        W(NVIC_IRQ0_SET_ENABLE) = UART2_IRQ_MASK;
    /* A pending stock update installs and boots the stock slot; it may also
     * overwrite the selected image, so the selection is dropped. */
    uint32_t pending = ORIGINAL_FLAG();
    if (!pending && s.target)
        boot_select(s.target);
    return pending;
}
