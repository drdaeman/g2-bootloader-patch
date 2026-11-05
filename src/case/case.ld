/* SPDX-License-Identifier: MIT */
/* Reviewed case 1.2.57 SRAM bridge layout. */
SECTIONS {
  .bridge 0x20010000 : { *(.bridge) }
  .text 0x20010700 : { *(.text) }
  .rodata : { *(.rodata*) }
  ASSERT(. <= 0x20011400, "case extension overlaps reset waveform")
  .waveform 0x20011400 : { *(.waveform) }
  .data : { *(.data*) *(.bss*) *(COMMON) }
  /DISCARD/ : { *(.ARM.exidx*) *(.ARM.extab*) *(.comment) *(.note*) }
  ASSERT(SIZEOF(.bridge) == 1720, "case bridge size changed")
  ASSERT(SIZEOF(.data) == 0, "case extension cannot have writable globals")
  ASSERT(. < 0x200119f0, "case extension overlaps retained result")
}
