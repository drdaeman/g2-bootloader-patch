# SPDX-License-Identifier: MIT
"""Version-2 framing and compiled callback timing."""

import struct
import unittest
from collections import deque
from unittest.mock import Mock

import unicorn as u
from g2patch import protocol as p
from test_altboot import DELAY, RETURN, TICK, Native
from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_R2, UC_ARM_REG_R3


class BlockCodec(unittest.TestCase):
    def test_golden_frame_and_boundaries(self):
        self.assertEqual(
            p.block(p.BLOCK_OUTPUT, b"abc").hex(), "424c4b320100030061626382d6b8d1"
        )
        for size in (1, 16, 255, 256, 1000, p.BLOCK_DATA):
            data = bytes(i & 255 for i in range(size))
            frame = p.block(p.BLOCK_OUTPUT, data)
            self.assertEqual(p.decode_block(frame), (p.BLOCK_OUTPUT, data))
            self.assertEqual(len(frame), size + 12)
        self.assertEqual(len(p.block(p.BLOCK_OUTPUT, bytes(p.BLOCK_DATA))), 1036)
        self.assertEqual(p.decode_block(p.block(p.BLOCK_INPUT)), (p.BLOCK_INPUT, b""))
        self.assertEqual(p.decode_block(p.block(p.BLOCK_ACK)), (p.BLOCK_ACK, b""))

    def test_invalid_shapes_lengths_and_crc(self):
        good = p.block(p.BLOCK_OUTPUT, b"abc")
        bad_length = bytearray(good)
        struct.pack_into("<H", bad_length, 6, 65535)
        for frame in (
            b"",
            good[:7],
            good[:-1],
            good + b"x",
            bytes(bad_length),
            good[:-1] + bytes([good[-1] ^ 1]),
        ):
            with self.subTest(frame=frame), self.assertRaises(ValueError):
                p.decode_block(frame)
        for kind, data in (
            (0, b""),
            (5, b""),
            (p.BLOCK_OUTPUT, b""),
            (p.BLOCK_ACK, b"x"),
            (p.BLOCK_INPUT, bytes(1025)),
            (p.BLOCK_REQUEST, b"\0\0"),
            (p.BLOCK_REQUEST, b"\xff\xff"),
        ):
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                p.block(kind, data)

    def test_one_acknowledgement_per_output_block(self):
        chunks = [bytes(p.BLOCK_DATA), b"last"]
        exchange = Mock(
            side_effect=[
                *[p.block(p.BLOCK_OUTPUT, d) for d in chunks],
                p.reply(p.RESULT, data=struct.pack("<I", 7)),
            ]
        )
        result, data = p.Client(exchange).execute()
        self.assertEqual((result, data), (7, b"".join(chunks)))
        self.assertEqual(
            [c.args[0] for c in exchange.call_args_list],
            [p.request(p.RUN), p.block(p.BLOCK_ACK), p.block(p.BLOCK_ACK)],
        )

    def test_crc_failure_is_latched_before_callback_or_ack(self):
        good = p.block(p.BLOCK_OUTPUT, bytes(p.BLOCK_DATA))
        bad = good[:-1] + bytes([good[-1] ^ 1])
        exchange = Mock(return_value=bad)
        callback = Mock()
        client = p.Client(exchange)
        with self.assertRaisesRegex(ValueError, "CRC"):
            client.execute(callback)
        callback.assert_not_called()
        exchange.assert_called_once_with(p.request(p.RUN))
        with self.assertRaises(RuntimeError):
            client.execute()
        self.assertEqual(exchange.call_count, 1)

    def test_full_input_and_eof(self):
        source = Mock(side_effect=[bytes(p.BLOCK_DATA), b""])
        wanted = p.block(p.BLOCK_REQUEST, struct.pack("<H", p.BLOCK_DATA))
        exchange = Mock(side_effect=[wanted, wanted, p.reply(p.RESULT)])
        self.assertEqual(p.Client(exchange).execute(source=source), (0, b""))
        self.assertEqual(
            [c.args[0] for c in exchange.call_args_list],
            [
                p.request(p.RUN),
                p.block(p.BLOCK_INPUT, bytes(p.BLOCK_DATA)),
                p.block(p.BLOCK_INPUT),
            ],
        )
        self.assertEqual([c.args for c in source.call_args_list], [(p.BLOCK_DATA,)] * 2)


class NativeReceiveTurnaround(unittest.TestCase):
    def receive_then_reply(self, frame, error_at=None):
        native = Native()
        cpu = native.cpu
        cpu.mem_map(0x4003B000, 0x1000)
        context, destination = 0x20000100, 0x20001000
        cpu.mem_write(context, bytes(8))
        sentinel = bytes([0xA5]) * p.BLOCK_DATA
        cpu.mem_write(destination, sentinel)
        byte_ns = 10_000  # 1 Mbaud, 8N1.
        now = 0
        wire_start = None
        consumed = 0
        reply_started = None

        def tick(c):
            nonlocal now
            now += byte_ns
            return now * 1024 // 1_000_000_000

        def delay(c):
            nonlocal now
            now += (c.reg_read(UC_ARM_REG_R0) * 1_000_000_000 + 1023) // 1024
            return 0

        def direction(c):
            nonlocal wire_start, reply_started
            if not c.reg_read(UC_ARM_REG_R0) and wire_start is None:
                wire_start = now + 100_000
            elif c.reg_read(UC_ARM_REG_R0) and wire_start is not None:
                reply_started = now
            return 0

        def uart(c, access, address, size, value, user):
            nonlocal consumed
            if address == 0x4003B018:
                ready = (
                    wire_start is not None
                    and consumed < len(frame)
                    and now >= wire_start + (consumed + 1) * byte_ns
                )
                c.mem_write(address, struct.pack("<I", 0 if ready else 0x10))
            elif address == 0x4003B000:
                value = frame[consumed] | (0x100 if consumed == error_at else 0)
                c.mem_write(address, struct.pack("<I", value))
                consumed += 1

        cpu.hook_add(u.UC_HOOK_MEM_READ, uart)
        native.stubs.update(
            {native.functions["direction"]: direction, TICK: tick, DELAY: delay}
        )
        cpu.reg_write(UC_ARM_REG_R2, p.BLOCK_DATA)
        result, pc = native.call("recv_input", context, destination)
        self.assertEqual((result, pc), (0xFFFFFFFF, RETURN))
        self.assertEqual(native.read(destination, p.BLOCK_DATA), sentinel)
        self.assertEqual(native.words(context, 1), (1,))
        cpu.reg_write(UC_ARM_REG_R2, 0)
        cpu.reg_write(UC_ARM_REG_R3, 0)
        _, pc = native.call("reply", p.RESULT, p.IO_ERROR)
        self.assertEqual(pc, RETURN)
        self.assertEqual(consumed, len(frame))
        self.assertIsNotNone(reply_started)
        self.assertGreaterEqual(reply_started, wire_start + len(frame) * byte_ns)
        self.assertLess(reply_started - wire_start, 2_100_000_000)

    def test_rejected_full_frames_finish_before_the_error_reply(self):
        frame = p.block(p.BLOCK_INPUT, bytes(p.BLOCK_DATA))
        for offset, value in (
            (0, 0),
            (4, p.BLOCK_ACK),
            (7, 0),
            (7, 0xFF),
            (-1, frame[-1] ^ 1),
        ):
            bad = bytearray(frame)
            bad[offset] = value
            with self.subTest(offset=offset):
                self.receive_then_reply(bytes(bad))

    def test_uart_error_at_start_or_mid_frame_drains_the_remainder(self):
        frame = p.block(p.BLOCK_INPUT, bytes(p.BLOCK_DATA))
        for position in (0, 500):
            with self.subTest(position=position):
                self.receive_then_reply(frame, error_at=position)

    def test_truncated_rejected_frame_has_a_bounded_wait(self):
        frame = bytearray(p.block(p.BLOCK_INPUT, bytes(p.BLOCK_DATA)))
        frame[4] = p.BLOCK_ACK
        self.receive_then_reply(bytes(frame[:8]))


class NativeOutput(unittest.TestCase):
    def invoke(self, data, acknowledgements, again=False, tx_flags=0):
        native = Native()
        cpu = native.cpu
        cpu.mem_map(0x4003B000, 0x1000)
        cpu.mem_write(0x20000100, bytes(4))
        if data:
            cpu.mem_write(0x20001000, data)
        incoming = deque(acknowledgements)
        frames = []
        outgoing = bytearray()
        directions = []
        ticks = 0

        def uart(c, access, address, size, value, user):
            if address == 0x4003B018:
                c.mem_write(
                    address, struct.pack("<I", tx_flags | (0 if incoming else 0x10))
                )
            elif address == 0x4003B000:
                c.mem_write(address, struct.pack("<I", incoming.popleft()))

        def sent(c, access, address, size, value, user):
            outgoing.append(value & 255)
            if (
                len(outgoing) >= 8
                and len(outgoing) == int.from_bytes(outgoing[6:8], "little") + 12
            ):
                frames.append(bytes(outgoing))
                outgoing.clear()

        def tick(c):
            nonlocal ticks
            ticks += 1
            return ticks

        def delay(c):
            nonlocal ticks
            ticks += c.reg_read(UC_ARM_REG_R0)
            return 0

        cpu.hook_add(u.UC_HOOK_MEM_READ, uart)
        cpu.hook_add(u.UC_HOOK_MEM_WRITE, sent, begin=0x4003B000, end=0x4003B000)
        native.stubs.update(
            {
                native.functions["direction"]: lambda c: (
                    directions.append(c.reg_read(UC_ARM_REG_R0)) or 0
                ),
                TICK: tick,
                DELAY: delay,
            }
        )
        for _ in range(2 if again else 1):
            cpu.reg_write(UC_ARM_REG_R2, len(data))
            result, pc = native.call(
                "send_output", 0x20000100, 0x20001000, count=2_000_000
            )
            self.assertEqual(pc, RETURN)
        if directions:
            self.assertEqual(directions[-1], 0)
        return result, frames, native.words(0x20000100, 1)[0]

    def test_full_or_busy_transmitter_times_out_and_returns_to_receive(self):
        for flags, count in ((0x20, 0), (0x08, 1)):
            with self.subTest(flags=flags):
                result, frames, failed = self.invoke(
                    b"data", b"", again=True, tx_flags=flags
                )
                self.assertEqual((result, failed), (0xFFFFFFFF, 1))
                self.assertEqual(len(frames), count)

    def test_output_is_split_at_the_frame_limit(self):
        data = bytes(i & 255 for i in range(3 * p.BLOCK_DATA + 17))
        result, frames, failed = self.invoke(data, p.block(p.BLOCK_ACK) * 4)
        self.assertEqual((result, failed), (0, 0))
        self.assertEqual([len(f) for f in frames], [1036, 1036, 1036, 29])
        chunks = [p.decode_block(f)[1] for f in frames]
        self.assertEqual(b"".join(chunks), data)
        self.assertEqual(self.invoke(b"", b"")[:2], (0, []))

    def test_invalid_or_missing_ack_stops_output_and_latches_failure(self):
        ack = p.block(p.BLOCK_ACK)
        bad = ack[:-1] + bytes([ack[-1] ^ 1])
        for reply in (b"", ack[:7], bad, p.block(p.BLOCK_INPUT, b"x")):
            with self.subTest(reply=reply):
                result, frames, failed = self.invoke(bytes(2048), reply, again=True)
                self.assertEqual((result, failed), (0xFFFFFFFF, 1))
                self.assertEqual(len(frames), 1)
                self.assertEqual(len(frames[0]), 1036)
