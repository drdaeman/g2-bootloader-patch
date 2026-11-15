/* SPDX-License-Identifier: MIT */
/* Even 2.3.2.14: three replacement calls, a startup branch and appended code. */
SECTIONS {
  .hook.storage_startup 0x0041b89e : { KEEP(*(.hook.storage_startup)) }
  .hook 0x0042e656 : { KEEP(*(.hook)) }
  .hook.handoff_update 0x0042e3d4 : { KEEP(*(.hook.handoff_update)) }
  .hook.handoff_boot 0x0042e440 : { KEEP(*(.hook.handoff_boot)) }
  .text 0x00434900 : { KEEP(*(.text)) *(.text.*) }
  .rodata : { *(.rodata*) }
  .data : { *(.data*) *(.bss*) *(COMMON) }
  ASSERT(. <= 0x004364a8, "existing patch overlaps fixed storage wrapper")
  .storage_deferral 0x004364a8 : { KEEP(*(.storage_deferral)) }
  /DISCARD/ : { *(.ARM.exidx*) *(.ARM.extab*) *(.comment) *(.note*) }
  ASSERT(SIZEOF(.hook) == 4, "boot hook must be one BL")
  ASSERT(SIZEOF(.hook.handoff_update) == 4, "update handoff hook must be one BL")
  ASSERT(SIZEOF(.hook.handoff_boot) == 4, "boot handoff hook must be one BL")
  ASSERT(SIZEOF(.data) == 0, "patch cannot have writable globals")
  ASSERT(SIZEOF(.storage_deferral) == 32,
         "storage wrapper must be exactly 32 bytes")
  ASSERT(SIZEOF(.hook.storage_startup) == 2,
         "storage startup branch and wrapper must be installed together")
  ASSERT(. <= 0x00438000, "patch overlaps main application")
}
nor = 0x004204af;
fs = 0x00421559;
storage_startup_tail = 0x0041b8aa;
ASSERT(storage_startup_tail == 0x0041b89e + 4 + 8, "startup B.N encoding target")
