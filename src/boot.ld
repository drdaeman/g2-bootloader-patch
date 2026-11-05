/* SPDX-License-Identifier: MIT */
/* Even 2.3.2.14: one replacement call and code appended after stock bytes. */
SECTIONS {
  .hook 0x0042e656 : { KEEP(*(.hook)) }
  .text 0x00434900 : { KEEP(*(.text)) *(.text.*) }
  .rodata : { *(.rodata*) }
  .data : { *(.data*) *(.bss*) *(COMMON) }
  /DISCARD/ : { *(.ARM.exidx*) *(.ARM.extab*) *(.comment) *(.note*) }
  ASSERT(SIZEOF(.hook) == 4, "boot hook must be one BL")
  ASSERT(SIZEOF(.data) == 0, "patch cannot have writable globals")
  ASSERT(. <= 0x00438000, "patch overlaps main application")
}
