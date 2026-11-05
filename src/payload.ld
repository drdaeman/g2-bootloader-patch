/* SPDX-License-Identifier: MIT */
SECTIONS {
  . = DEFINED(IMAGE_BASE) ? IMAGE_BASE : 0;
  .text : { *(.text) }
  .rodata : { *(.rodata*) }
  .data : { *(.data*) *(.bss*) *(COMMON) }
  /DISCARD/ : { *(.ARM.exidx*) *(.ARM.extab*) *(.comment) *(.note*) }
  ASSERT(SIZEOF(.data) == 0, "payload cannot have writable globals")
  ASSERT(SIZEOF(.text) + SIZEOF(.rodata) <= 512, "payload exceeds RAM loader")
}
