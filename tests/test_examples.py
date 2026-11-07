# SPDX-License-Identifier: MIT
"""Execute compiled examples and compare their results with host implementations."""

import struct
import unittest
import zlib
from pathlib import Path

import unicorn as u
from unicorn.arm_const import (
    UC_ARM_REG_LR,
    UC_ARM_REG_PC,
    UC_ARM_REG_R0,
    UC_ARM_REG_R1,
    UC_ARM_REG_R2,
    UC_ARM_REG_SP,
)
from unicorn.unicorn import Uc

ROOT = Path(__file__).resolve().parents[1]


class Examples(unittest.TestCase):
    def run_example(self, name, arg0, arg1, data=b"", fail_at=None):
        cpu = Uc(u.UC_ARCH_ARM, u.UC_MODE_THUMB | u.UC_MODE_MCLASS)
        cpu.mem_map(0x10000, 0x10000)
        cpu.mem_map(0x20000000, 0x10000)
        cpu.mem_write(0x10000, (ROOT / f"build/{name}.bin").read_bytes())
        cpu.mem_write(0x20000000, struct.pack("<III", 1, 0x11001, 0x1234))
        if data:
            cpu.mem_write(0x20001000, data)
        cpu.reg_write(UC_ARM_REG_R0, 0x20000000)
        cpu.reg_write(UC_ARM_REG_R1, arg0)
        cpu.reg_write(UC_ARM_REG_R2, arg1)
        cpu.reg_write(UC_ARM_REG_SP, 0x2000FFF0)
        cpu.reg_write(UC_ARM_REG_LR, 0x12001)
        output = []

        def send(c, address, size, user_data):
            if address != 0x11000:
                return
            self.assertEqual(c.reg_read(UC_ARM_REG_R0), 0x1234)
            output.append(
                bytes(c.mem_read(c.reg_read(UC_ARM_REG_R1), c.reg_read(UC_ARM_REG_R2)))
            )
            c.reg_write(UC_ARM_REG_R0, 0xFFFFFFFF if len(output) == fail_at else 0)
            c.reg_write(UC_ARM_REG_PC, c.reg_read(UC_ARM_REG_LR))

        hook = cpu.hook_add(u.UC_HOOK_CODE, send)
        try:
            cpu.emu_start(0x10001, 0x12000, count=1000000)
            self.assertEqual(cpu.reg_read(UC_ARM_REG_PC), 0x12000)
            return cpu.reg_read(UC_ARM_REG_R0), output
        finally:
            cpu.hook_del(hook)

    def test_echo(self):
        for fail_at, expected in ((None, 0), (1, 1)):
            result, output = self.run_example("echo", 7, 8, fail_at=fail_at)
            self.assertEqual(result, expected)
            self.assertEqual(output, [b"HEY!" + struct.pack("<II", 7, 8)])

    def test_checksum_arbitrary_readable_range(self):
        for data in (b"", b"123456789", bytes(range(256)) * 3):
            result, output = self.run_example("checksum", 0x20001000, len(data), data)
            self.assertEqual(result, zlib.crc32(data))
            self.assertEqual(output, [])

    def test_dump(self):
        for size in (0, 1, 128, 129, 300):
            data = bytes(i & 255 for i in range(size))
            result, output = self.run_example("dump", 0x20001000, size, data)
            self.assertEqual(result, 0)
            self.assertEqual(b"".join(output), data)
            self.assertEqual(output, [data] if data else [])

    def test_dump_stops_on_send_failure(self):
        data = bytes(range(256)) * 2
        result, output = self.run_example(
            "dump", 0x20001000, len(data), data, fail_at=1
        )
        self.assertEqual(result, 1)
        self.assertEqual(output, [data])
