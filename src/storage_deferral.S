/* SPDX-License-Identifier: MIT */
/* Even 2.3.2.14 only. Preserve the existing API bytes and fixed addresses.
 * Latch this boot's startup path before a held RAM program can change it.
 * If storage already ran on this boot, do not initialize it a second time.
 */
.syntax unified
.thumb
.section .hook.storage_startup,"ax",%progbits
/* External B.N relocations are widened by the assembler. Fix this reviewed
 * encoding explicitly; the linker checks the target equation below. */
.inst.n 0xe004
.section .storage_deferral,"ax",%progbits
.global boot_storage_then_flag
.thumb_func
boot_storage_then_flag:
    push {r4,r5,r6,lr}
    ldr r4,.Lsite
    ldrh r4,[r4]
    bl boot_task_then_flag
    mov r5,r0
    lsls r4,r4,#19
    bmi .Ldone
    bl nor
    bl fs
.Ldone:
    mov r0,r5
    pop {r4,r5,r6,pc}
.balign 4
.Lsite:
    .word 0x0041b89e
