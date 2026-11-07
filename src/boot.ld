/* SPDX-License-Identifier: MIT */
/* Even 2.3.2.14: three replacement calls and code appended after stock bytes. */
SECTIONS {
  .hook 0x0042e656 : { KEEP(*(.hook)) }
  .hook.handoff_update 0x0042e3d4 : { KEEP(*(.hook.handoff_update)) }
  .hook.handoff_boot 0x0042e440 : { KEEP(*(.hook.handoff_boot)) }
  .text 0x00434900 : { KEEP(*(.text)) *(.text.*) }
  .rodata : { *(.rodata*) }
  .data : { *(.data*) *(.bss*) *(COMMON) }
  /DISCARD/ : { *(.ARM.exidx*) *(.ARM.extab*) *(.comment) *(.note*) }
  ASSERT(SIZEOF(.hook) == 4, "boot hook must be one BL")
  ASSERT(SIZEOF(.hook.handoff_update) == 4, "update handoff hook must be one BL")
  ASSERT(SIZEOF(.hook.handoff_boot) == 4, "boot handoff hook must be one BL")
  ASSERT(SIZEOF(.data) == 0, "patch cannot have writable globals")
  ASSERT(. <= 0x00438000, "patch overlaps main application")
}
