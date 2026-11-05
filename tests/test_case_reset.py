# SPDX-License-Identifier: MIT
"""Execute the case reset wrapper for both routes (optional Unicorn dependency)."""

import json
import struct
import unittest
from pathlib import Path

try:
    import unicorn as u
except ImportError:
    u = None

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(u, "install Unicorn to execute the ARM reset-wrapper checks")
class ResetRoutes(unittest.TestCase):
    def test_only_selected_stock_reset_route_emits_waveform(self):
        # The class is skipped when Unicorn is absent.
        assert u is not None
        from unicorn.arm_const import (
            UC_ARM_REG_LR,
            UC_ARM_REG_PC,
            UC_ARM_REG_R0,
            UC_ARM_REG_R1,
            UC_ARM_REG_SP,
        )
        from unicorn.unicorn import Uc

        image = (ROOT / "build/case.bin").read_bytes()
        meta = json.loads((ROOT / "build/case.json").read_text())
        entry = meta["base"] + meta["functions"]["case_reset_selected"]["offset"]
        for side, selected, valid in (
            (0, bytes.fromhex("81010ca6af03c10322ff"), True),
            (1, bytes.fromhex("81010cafa603c10522ff"), True),
            (0, bytes.fromhex("81010cafa603c10522ff"), False),
            (1, bytes.fromhex("81010ca6af03c10322ff"), False),
            (2, bytes.fromhex("81010cafa603c10522ff"), False),
        ):
            with self.subTest(side=side, selected=selected.hex()):
                cpu = Uc(u.UC_ARCH_ARM, u.UC_MODE_THUMB | u.UC_MODE_MCLASS)
                cpu.mem_map(0x20000000, 0x20000)
                cpu.mem_map(0x08000000, 0x10000)
                cpu.mem_write(0x20010000, image)
                cpu.mem_write(0x20011A0C, struct.pack("<I", side))
                cpu.mem_write(0x20011A42, selected)
                cpu.reg_write(UC_ARM_REG_SP, 0x2001FF00)
                cpu.reg_write(UC_ARM_REG_LR, 0x2001F101)
                events = []

                def call(c, address, size, data, events=events):
                    if address == 0x08004D30:
                        events.append(
                            (
                                "gpio",
                                c.reg_read(UC_ARM_REG_R0),
                                struct.unpack(
                                    "<5I", c.mem_read(c.reg_read(UC_ARM_REG_R1), 20)
                                ),
                            )
                        )
                    elif address == 0x20010624:
                        events.append(("delay", c.reg_read(UC_ARM_REG_R0)))
                    elif address == 0x20011400:
                        events.append(("waveform",))
                    elif address == 0x08006C80:
                        events.append(("receive",))
                    else:
                        return
                    c.reg_write(UC_ARM_REG_PC, c.reg_read(UC_ARM_REG_LR))

                cpu.hook_add(u.UC_HOOK_CODE, call)
                cpu.emu_start(entry | 1, 0x2001F100, count=30000)
                self.assertEqual(cpu.reg_read(UC_ARM_REG_PC), 0x2001F100)
                self.assertEqual(cpu.reg_read(UC_ARM_REG_R0), int(valid))
                expected = (
                    [
                        ("gpio", 0x50000400, (512, 1, 0, 3, 0)),
                        ("delay", 640020),
                        ("waveform",),
                        ("gpio", 0x50000400, (512, 0, 0, 3, 0)),
                        ("receive",),
                    ]
                    if valid
                    else []
                )
                self.assertEqual(events, expected)


if __name__ == "__main__":
    unittest.main()
