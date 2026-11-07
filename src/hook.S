/* SPDX-License-Identifier: MIT */
.syntax unified
.thumb
/* Manager: replaces the stock pending-update flag call. */
.section .hook,"ax",%progbits
bl boot_task_then_flag
/* DFU task: replace both calls of the stock vector handoff leaf. */
.section .hook.handoff_update,"ax",%progbits
bl boot_handoff
.section .hook.handoff_boot,"ax",%progbits
bl boot_handoff
