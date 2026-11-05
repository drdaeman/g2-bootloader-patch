/* SPDX-License-Identifier: MIT */
/* Payloads must return normally with a valid stack and execution context.
 * The UART send callback is synchronous and uses stop-and-wait.
 */
#include "ram_api.h"
enum {
    CORTEXM_DCACHE_CLEAN_MVA_TO_POU = 0xe000ef64u,
    CORTEXM_ICACHE_INVALIDATE_ALL_TO_POU = 0xe000ef50u,
    CORTEXM_CACHE_LINE_BYTES = 32u
};
typedef struct {
    uintptr_t entry;
    const ram_api *api;
    uint32_t arg0, arg1, result;
} boot_ram_call;

__attribute__((naked, noinline)) void boot_ram_invoke(boot_ram_call *call) {
    __asm__ volatile(
#ifdef __clang__
        ".cpu cortex-m55\n"
#else
        ".arch armv8.1-m.main\n .arch_extension mve\n"
#endif
        "push.w {r0-r12,lr}\n"
        "mrs r1,apsr\n mrs r2,primask\n mrs r3,basepri\n"
        "mrs r4,faultmask\n mrs r5,control\n vmrs r6,fpscr\n"
        "vmrs r7,vpr\n mrs r8,psplim\n mrs r9,msplim\n"
        "push.w {r1-r10}\n vpush {s0-s31}\n"
        "ldr r4,[sp,#168]\n ldr r12,[r4]\n ldr r0,[r4,#4]\n"
        "ldr r1,[r4,#8]\n ldr r2,[r4,#12]\n blx r12\n"
        "ldr r4,[sp,#168]\n str r0,[r4,#16]\n"
        "vpop {s0-s31}\n pop.w {r1-r10}\n"
        "msr psplim,r8\n msr msplim,r9\n vmsr vpr,r7\n vmsr fpscr,r6\n"
        "msr control,r5\n isb\n msr faultmask,r4\n"
        "msr basepri,r3\n msr primask,r2\n msr APSR_nzcvqg,r1\n"
        "pop.w {r0-r12,lr}\n bx lr\n"
        ".cpu cortex-m4\n");
}

static void boot_ram_sync(void *code, unsigned size) {
    for (uintptr_t p = (uintptr_t)code; p < (uintptr_t)code + size;
         p += CORTEXM_CACHE_LINE_BYTES)
        W(CORTEXM_DCACHE_CLEAN_MVA_TO_POU) = (uint32_t)p;
    __asm__ volatile("dsb sy" ::: "memory");
    W(CORTEXM_ICACHE_INVALIDATE_ALL_TO_POU) = 0;
    __asm__ volatile("dsb sy\n isb sy" ::: "memory");
}
