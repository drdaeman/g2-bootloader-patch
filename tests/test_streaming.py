# SPDX-License-Identifier: MIT
"""Check framed input, CRC rejection, and the compiled recv callback."""

import io
import json
import struct
import sys
import unittest
from collections import deque
from pathlib import Path
from unittest.mock import Mock

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

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from g2patch import protocol as p

ROOT = Path(__file__).resolve().parents[1]


def input_packet(data, checksum=None):
    frame = p.block(p.BLOCK_INPUT, data)
    return frame if checksum is None else frame[:-4] + struct.pack("<I", checksum)


class HostInput(unittest.TestCase):
    def test_input_output_and_eof(self):
        exchange = Mock(
            side_effect=[
                p.block(p.BLOCK_REQUEST, struct.pack("<H", 2)),
                p.block(p.BLOCK_OUTPUT, b"ab"),
                p.block(p.BLOCK_REQUEST, struct.pack("<H", 16)),
                p.reply(p.RESULT, data=struct.pack("<I", 7)),
            ]
        )
        result, output = p.Client(exchange).execute(source=io.BytesIO(b"ab").read)
        self.assertEqual((result, output), (7, b"ab"))
        self.assertEqual(
            [call.args[0] for call in exchange.call_args_list],
            [
                p.request(p.RUN),
                input_packet(b"ab"),
                p.block(p.BLOCK_ACK),
                input_packet(b""),
            ],
        )

    def test_bad_source_stops_without_sending_or_retrying(self):
        exchange = Mock(return_value=p.block(p.BLOCK_REQUEST, struct.pack("<H", 1)))
        client = p.Client(exchange)
        with self.assertRaises(ValueError):
            client.execute(source=lambda _: b"too large")
        exchange.assert_called_once_with(p.request(p.RUN))
        self.assertTrue(client.failed)

    def test_no_source_sends_eof(self):
        exchange = Mock(
            side_effect=[
                p.block(p.BLOCK_REQUEST, struct.pack("<H", 16)),
                p.reply(p.RESULT),
            ]
        )
        p.Client(exchange).execute()
        self.assertEqual(exchange.call_args.args[0], input_packet(b""))


class NativeRecv(unittest.TestCase):
    def invoke(self, packet, capacity=16, failed=False, again=False):
        meta = json.loads((ROOT / "build/patch.json").read_text())
        functions = {
            name: meta["base"] + value["offset"]
            for name, value in meta["functions"].items()
        }
        cpu = Uc(u.UC_ARCH_ARM, u.UC_MODE_THUMB | u.UC_MODE_MCLASS)
        cpu.mem_map(0x00410000, 0x40000)
        cpu.mem_map(0x20000000, 0x40000)
        cpu.mem_map(0x4003B000, 0x1000)
        cpu.mem_write(meta["base"], (ROOT / "build/patch.bin").read_bytes())
        cpu.mem_write(0x20000100, struct.pack("<II", int(failed), 0x20000120))
        cpu.mem_write(0x20000200, bytes([0xA5]) * p.BLOCK_DATA)
        frames = []
        outgoing = bytearray()
        incoming = deque(packet)
        ticks = 0

        def uart(c, access, address, size, value, user):
            if address == 0x4003B018:
                c.mem_write(address, struct.pack("<I", 0 if incoming else 0x10))
            elif address == 0x4003B000:
                self.assertEqual(struct.unpack("<I", c.mem_read(0x2000012C, 4))[0], 1)
                c.mem_write(address, struct.pack("<I", incoming.popleft()))

        cpu.hook_add(u.UC_HOOK_MEM_READ, uart)

        def sent(c, access, address, size, value, user):
            self.assertEqual(struct.unpack("<I", c.mem_read(0x2000012C, 4))[0], 1)
            outgoing.append(value & 255)
            if (
                len(outgoing) >= 8
                and len(outgoing) == int.from_bytes(outgoing[6:8], "little") + 12
            ):
                frames.append(bytes(outgoing))
                outgoing.clear()

        cpu.hook_add(u.UC_HOOK_MEM_WRITE, sent, begin=0x4003B000, end=0x4003B000)

        def hook(c, address, size, data):
            nonlocal ticks
            if address == functions["direction"]:
                c.reg_write(UC_ARM_REG_R0, 0)
            elif address == 0x4160E8:
                ticks += 1
                c.reg_write(UC_ARM_REG_R0, ticks)
            elif address == 0x416378:
                c.reg_write(UC_ARM_REG_R0, 0)
            else:
                return
            c.reg_write(UC_ARM_REG_PC, c.reg_read(UC_ARM_REG_LR))

        handle = cpu.hook_add(u.UC_HOOK_CODE, hook)
        try:
            for _ in range(2 if again else 1):
                cpu.reg_write(UC_ARM_REG_SP, 0x2003F000)
                cpu.reg_write(UC_ARM_REG_LR, 0x20030001)
                cpu.reg_write(UC_ARM_REG_R0, 0x20000100)
                cpu.reg_write(UC_ARM_REG_R1, 0x20000200)
                cpu.reg_write(UC_ARM_REG_R2, capacity)
                cpu.emu_start(functions["recv_input"] | 1, 0x20030000, count=500000)
                self.assertEqual(cpu.reg_read(UC_ARM_REG_PC), 0x20030000)
                self.assertEqual(struct.unpack("<I", cpu.mem_read(0x2000012C, 4))[0], 0)
            return (
                cpu.reg_read(UC_ARM_REG_R0),
                bytes(cpu.mem_read(0x20000200, p.BLOCK_DATA)),
                struct.unpack("<I", cpu.mem_read(0x20000100, 4))[0],
                frames,
            )
        finally:
            cpu.hook_del(handle)

    def test_chunk_limit_and_short_read(self):
        result, data, failed, frames = self.invoke(input_packet(b"abc"), capacity=100)
        self.assertEqual((result, data[:3], failed), (3, b"abc", 0))
        self.assertEqual(data[3:], bytes([0xA5]) * (p.BLOCK_DATA - 3))
        self.assertEqual(p.decode_transfer_reply(frames[0])[:2], (p.INPUT, 100))
        self.assertEqual(
            p.decode_transfer_reply(self.invoke(input_packet(b"a"), capacity=1)[3][0])[
                :2
            ],
            (p.INPUT, 1),
        )

    def test_zero_capacity_and_eof(self):
        self.assertEqual(self.invoke(b"", capacity=0)[::2], (0, 0))
        self.assertEqual(self.invoke(b"", capacity=0)[3], [])
        self.assertEqual(self.invoke(input_packet(b""))[0], 0)

    def test_maximum_input_and_truncated_frames(self):
        data = bytes(i & 255 for i in range(p.BLOCK_DATA))
        result, actual, failed, frames = self.invoke(input_packet(data), capacity=10000)
        self.assertEqual((result, actual, failed), (len(data), data, 0))
        self.assertEqual(
            p.decode_transfer_reply(frames[0])[:2], (p.INPUT, p.BLOCK_DATA)
        )
        frame = input_packet(b"abc")
        for cut in (1, 7, 8, len(frame) - 1):
            with self.subTest(cut=cut):
                result, actual, failed, _ = self.invoke(frame[:cut], capacity=16)
                self.assertEqual((result, failed), (0xFFFFFFFF, 1))
                self.assertEqual(actual, bytes([0xA5]) * p.BLOCK_DATA)

    def test_crc_count_command_timeout_and_failure_latch(self):
        for packet, capacity in (
            (input_packet(b"abc", checksum=0), 16),
            (input_packet(b"abc"), 2),
            (p.request(p.OUTPUT_ACK), 16),
            (b"", 16),
            ([0x100], 16),
        ):
            result, data, failed, frames = self.invoke(
                packet, capacity=capacity, again=True
            )
            self.assertEqual((result, failed), (0xFFFFFFFF, 1))
            self.assertEqual(data, bytes([0xA5]) * p.BLOCK_DATA)
            self.assertEqual(len(frames), 1)
        self.assertEqual(self.invoke(input_packet(b"abc"), failed=True)[3], [])


class WriterStreaming(unittest.TestCase):
    def test_whole_range_uses_one_upload(self):
        from g2patch.recovery import APP_BASE, Recovery

        data = bytes(range(256)) * 3
        client = Mock()
        received = bytearray()

        def execute(callback, source):
            for count in range(256, len(data) + 1, 256):
                for _ in range(16):
                    received.extend(source(16))
                callback(struct.pack("<I", count))
            return 0, b""

        client.execute.side_effect = execute
        progress = []
        Recovery(client, {"recover": b"writer"}).write(APP_BASE, data, progress.append)
        client.upload.assert_called_once_with(b"writer", arg0=APP_BASE, arg1=len(data))
        self.assertEqual(received, data)
        self.assertEqual(progress, [256, 512, 768])
