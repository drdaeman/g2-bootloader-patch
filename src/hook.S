/* SPDX-License-Identifier: MIT */
.syntax unified
.thumb
.section .hook,"ax",%progbits
bl boot_task_then_flag
