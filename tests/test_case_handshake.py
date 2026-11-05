# SPDX-License-Identifier: MIT
"""Check emitted case code against the host's handshake codec."""

import json
import struct
import sys
import unittest
from collections import deque
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from g2patch.handshake import hello, hold, okay

try:
    import unicorn as u
except ImportError:
    u = None

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(u, "install Unicorn to execute the case handshake checks")
class CaseHandshake(unittest.TestCase):
    def exchange(self, beacon, acknowledgement):
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
        entry = meta["base"] + meta["functions"]["exchange"]["offset"]
        cpu = Uc(u.UC_ARCH_ARM, u.UC_MODE_THUMB | u.UC_MODE_MCLASS)
        cpu.mem_map(0x20000000, 0x20000)
        cpu.mem_map(0x08000000, 0x10000)
        cpu.mem_map(0x40004000, 0x1000)
        cpu.mem_map(0x40013000, 0x1000)
        cpu.mem_write(0x20010000, image)
        cpu.mem_write(0x20011A0C, struct.pack("<I", 1))
        cpu.mem_write(0x20011A42, bytes.fromhex("81010cafa603c10522ff"))
        cpu.reg_write(UC_ARM_REG_SP, 0x2001FF00)
        cpu.reg_write(UC_ARM_REG_LR, 0x2001F101)
        incoming = deque(beacon + acknowledgement)
        request = hold(0x32524C45)
        command = b"G2TX" + bytes([len(request)]) + request
        outgoing = deque(command + bytes([sum(command) & 255]))
        sent, console = [], []

        def read(c, access, address, size, value, data):
            if address == 0x4001381C:
                c.mem_write(address, struct.pack("<I", 32 if outgoing else 0))
            elif address == 0x40013824:
                c.mem_write(address, struct.pack("<I", outgoing.popleft()))
            elif address == 0x4000481C:
                c.mem_write(address, struct.pack("<I", 32 if incoming else 0))
            elif address == 0x40004824:
                c.mem_write(address, struct.pack("<I", incoming.popleft()))

        def call(c, address, size, data):
            if address in (0x20010348, 0x2001057C):
                packet = bytes(
                    c.mem_read(c.reg_read(UC_ARM_REG_R0), c.reg_read(UC_ARM_REG_R1))
                )
                if address == 0x20010348:
                    console.append(packet)
                    if packet.startswith(b"G2RX"):
                        c.emu_stop()
                        return
                else:
                    sent.append(packet)
                    c.reg_write(UC_ARM_REG_R0, len(packet))
            elif address not in (
                0x08004D30,
                0x20010624,
                0x20011400,
                0x08006C80,
                0x08006CF8,
            ):
                return
            c.reg_write(UC_ARM_REG_PC, c.reg_read(UC_ARM_REG_LR))

        cpu.hook_add(u.UC_HOOK_MEM_READ, read)
        cpu.hook_add(u.UC_HOOK_CODE, call)
        cpu.emu_start(entry | 1, 0x2001F100, count=1000000)
        ready = b"G2RAM_READY\n" in console
        if not ready:
            self.assertEqual(cpu.reg_read(UC_ARM_REG_PC), 0x2001F100)
        return ready, sent, console

    def test_host_generated_hold_is_forwarded(self):
        challenge = 0x32524C45
        beacon, acknowledgement = hello(challenge), okay(challenge)
        ready, sent, console = self.exchange(beacon, acknowledgement)
        self.assertTrue(ready)
        self.assertEqual(sent, [hold(challenge)])
        self.assertEqual(console[2], beacon)
        reply = console[-1]
        self.assertEqual(reply[:6], b"G2RX" + bytes([0, 29]))
        self.assertEqual(reply[6:-1], acknowledgement)
        self.assertEqual(reply[-1], sum(reply[:-1]) & 255)

    def test_case_leaves_authentication_to_host(self):
        beacon = bytearray(hello(123))
        beacon[-1] ^= 1
        acknowledgement = okay(124)
        ready, _sent, console = self.exchange(bytes(beacon), acknowledgement)
        self.assertTrue(ready)
        self.assertEqual(console[2], beacon)
        self.assertEqual(console[-1][6:-1], acknowledgement)
