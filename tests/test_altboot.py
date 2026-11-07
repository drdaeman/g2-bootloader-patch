# SPDX-License-Identifier: MIT
"""One-boot alternate image selection: wire command, arming, and handoff."""

import json
import struct
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

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
from g2patch import firmware, link, protocol
from g2patch import recovery as r
from g2patch.handshake import cont, hello, hold, okay, released

ROOT = Path(__file__).resolve().parents[1]
RECORD = 0x2007CFF0
MAGIC = 0x544F4231
STOCK_TARGET = 0x00438000
HANDOFF = 0x0042DFD8
TARGET = 0x007C0000
VECTORS = struct.pack("<II", 0x2007FB00, TARGET + 0x201)
ITCM_TARGET = 0x00001000
ITCM_VECTORS = struct.pack("<II", 0x2007FB00, ITCM_TARGET + 0x201)
RETURN = 0x20030000
TICK, DELAY, NEW, DELETE = 0x4160E8, 0x416378, 0x4160FE, 0x417F0A
WAKE, SLEEP, FLAG = 0x41F846, 0x41F8BA, 0x42E56C


def record(target, magic=MAGIC, check=None):
    return struct.pack(
        "<3I", magic, target, (~target if check is None else check) & 0xFFFFFFFF
    )


class Native:
    """Run compiled patch functions with stock bindings replaced by hooks."""

    def __init__(self, vectors=()):
        meta = json.loads((ROOT / "build/patch.json").read_text())
        self.functions = {
            name: meta["base"] + value["offset"]
            for name, value in meta["functions"].items()
        }
        self.cpu = Uc(u.UC_ARCH_ARM, u.UC_MODE_THUMB | u.UC_MODE_MCLASS)
        self.cpu.mem_map(0x00000000, 0x40000)
        self.cpu.mem_map(0x00400000, 0x400000)
        self.cpu.mem_map(0x20000000, 0x80000)
        self.cpu.mem_map(0x40021000, 0x1000)
        self.cpu.mem_map(0xE000E000, 0x1000)
        self.cpu.mem_write(meta["base"], (ROOT / "build/patch.bin").read_bytes())
        self.cpu.mem_write(TARGET, VECTORS)
        self.cpu.mem_write(ITCM_TARGET, ITCM_VECTORS)
        for address, data in vectors:
            self.cpu.mem_write(address, data)
        self.stubs = {}

    def read(self, address, size):
        return bytes(self.cpu.mem_read(address, size))

    def words(self, address, count):
        return struct.unpack(f"<{count}I", self.read(address, 4 * count))

    def call(self, function, *args, count=2_000_000):
        def hook(c, address, size, data):
            if address == RETURN:
                return
            stub = self.stubs.get(address)
            if stub is None:
                return
            result = stub(c)
            if result is StopIteration:
                c.emu_stop()
                return
            if result is not None:
                c.reg_write(UC_ARM_REG_R0, result & 0xFFFFFFFF)
            c.reg_write(UC_ARM_REG_PC, c.reg_read(UC_ARM_REG_LR))

        cpu = self.cpu
        handle = cpu.hook_add(u.UC_HOOK_CODE, hook)
        try:
            cpu.reg_write(UC_ARM_REG_SP, 0x2007F000)
            cpu.reg_write(UC_ARM_REG_LR, RETURN | 1)
            for register, value in zip((UC_ARM_REG_R0, UC_ARM_REG_R1), args):
                cpu.reg_write(register, value)
            cpu.emu_start(self.functions[function] | 1, RETURN, count=count)
            return cpu.reg_read(UC_ARM_REG_R0), cpu.reg_read(UC_ARM_REG_PC)
        finally:
            cpu.hook_del(handle)


class Handoff(unittest.TestCase):
    def handoff(self, stored, vectors=()):
        native = Native(vectors)
        native.cpu.mem_write(RECORD, stored)
        targets = []

        def leaf(c):
            targets.append(c.reg_read(UC_ARM_REG_R0))
            return StopIteration

        native.stubs[HANDOFF] = leaf
        native.call("boot_handoff", STOCK_TARGET)
        self.assertEqual(native.words(RECORD, 3), (0, 0, 0xFFFFFFFF))
        self.assertEqual(len(targets), 1)
        return targets[0]

    def test_selected_valid_target_is_consumed_and_used(self):
        self.assertEqual(self.handoff(record(TARGET)), TARGET)

    def test_absent_or_damaged_record_boots_stock(self):
        for stored in (
            bytes(12),
            record(0, magic=0),
            record(TARGET, magic=MAGIC ^ 1),
            record(TARGET, check=TARGET),
        ):
            with self.subTest(stored=stored.hex()):
                self.assertEqual(self.handoff(stored), STOCK_TARGET)

    def test_invalid_target_or_vectors_boot_stock(self):
        bad_vectors = (
            struct.pack("<II", 0xFFFFFFFF, 0xFFFFFFFF),
            struct.pack("<II", 0x2007FB04, TARGET + 0x201),
            struct.pack("<II", 0x20000000, TARGET + 0x201),
            struct.pack("<II", 0x20400008, TARGET + 0x201),
            struct.pack("<II", 0x2007FB00, TARGET + 0x200),
            struct.pack("<II", 0x2007FB00, TARGET + 0x5),
            struct.pack("<II", 0x2007FB00, 0x007FE001),
            struct.pack("<II", 0x2007FB00, 0x00410001),
        )
        for vectors in bad_vectors:
            with self.subTest(vectors=vectors.hex()):
                self.assertEqual(
                    self.handoff(record(TARGET), [(TARGET, vectors)]), STOCK_TARGET
                )
        for target in (TARGET + 0x100, 0x00437000, 0x007FE000, 0x20000000):
            with self.subTest(target=hex(target)):
                self.assertEqual(
                    self.handoff(record(target), [(target, VECTORS)]), STOCK_TARGET
                )

    def test_itcm_target_above_the_stock_page_is_used(self):
        self.assertEqual(self.handoff(record(ITCM_TARGET)), ITCM_TARGET)
        top = 0x0003F000
        vectors = struct.pack("<II", 0x2007FB00, 0x0003FFF1)
        self.assertEqual(self.handoff(record(top), [(top, vectors)]), top)

    def test_itcm_rules(self):
        for target, vectors in (
            (0x00000000, struct.pack("<II", 0x2007FB00, 0x201)),
            (0x00040000, struct.pack("<II", 0x2007FB00, 0x40201)),
            (ITCM_TARGET, struct.pack("<II", 0x2007FB00, 0x00040001)),
            (ITCM_TARGET, struct.pack("<II", 0x2007FB00, TARGET + 0x201)),
            (ITCM_TARGET, struct.pack("<II", 0x2007FB00, ITCM_TARGET + 1)),
        ):
            with self.subTest(target=hex(target), vectors=vectors.hex()):
                memory = [(target, vectors)] if target < 0x40000 else []
                self.assertEqual(self.handoff(record(target), memory), STOCK_TARGET)

    def test_stock_main_application_slot_is_accepted(self):
        vectors = struct.pack("<II", 0x2007FB00, 0x005E4233)
        self.assertEqual(
            self.handoff(record(STOCK_TARGET), [(STOCK_TARGET, vectors)]),
            STOCK_TARGET,
        )


CHALLENGE = 0x32524C47  # TICK stubbed to 0


class Worker(unittest.TestCase):
    """The compiled worker from HELO through RLSD with scripted UART frames."""

    def session(self, requests, failed_transmit=None):
        native = Native()
        script = [hold(CHALLENGE), *requests]
        frames = []

        def receive(c):
            if not script:
                self.fail("worker waited for another frame")
            packet = script.pop(0)
            c.mem_write(c.reg_read(UC_ARM_REG_R0), packet)
            return len(packet)

        def transmit(c):
            frame = native.read(c.reg_read(UC_ARM_REG_R0), c.reg_read(UC_ARM_REG_R1))
            frames.append(frame)
            return 0 if frame == failed_transmit else 1

        def delay(c):
            return StopIteration if c.reg_read(UC_ARM_REG_R0) == 0xFFFFFFFF else 0

        native.stubs.update(
            {
                TICK: lambda c: 0,
                DELAY: delay,
                native.functions["receive"]: receive,
                native.functions["transmit"]: transmit,
            }
        )
        session = 0x20000100
        native.cpu.mem_write(session, struct.pack("<II", 0, 0xA5A5A5A5))
        native.call("uart2_worker", session)
        self.assertEqual(script, [])
        self.assertEqual(frames[:2], [hello(CHALLENGE), okay(CHALLENGE)])
        self.assertEqual(frames[-1], released())
        held, target = native.words(session, 2)
        self.assertEqual(held, 0)
        return target, [protocol.decode_reply(f)[:2] for f in frames[2:-1]]

    @staticmethod
    def boot(address):
        return protocol.request(protocol.BOOT, struct.pack("<I", address))

    def test_acknowledged_selection_is_published_on_continue(self):
        target, replies = self.session([self.boot(TARGET), cont()])
        self.assertEqual(target, TARGET)
        self.assertEqual(replies, [(protocol.ACK, 0)])

    def test_itcm_selection_is_accepted(self):
        self.assertEqual(
            self.session([self.boot(ITCM_TARGET), cont()]),
            (ITCM_TARGET, [(protocol.ACK, 0)]),
        )

    def test_no_selection_publishes_zero(self):
        self.assertEqual(self.session([cont()]), (0, []))

    def test_invalid_target_is_rejected_and_clears_selection(self):
        for address in (TARGET + 0x10, 0x00800000, TARGET + 0x1000):
            with self.subTest(address=hex(address)):
                target, replies = self.session(
                    [self.boot(TARGET), self.boot(address), cont()]
                )
                self.assertEqual(target, 0)
                self.assertEqual(
                    replies,
                    [(protocol.ACK, 0), (protocol.ERROR, protocol.BAD_TARGET)],
                )

    def test_zero_clears_and_last_selection_wins(self):
        self.assertEqual(self.session([self.boot(TARGET), self.boot(0), cont()])[0], 0)
        target, _ = self.session([self.boot(0), self.boot(TARGET), cont()])
        self.assertEqual(target, TARGET)

    def test_abort_or_lost_acknowledgement_discards_selection(self):
        target, replies = self.session([self.boot(TARGET), b"", cont()])
        self.assertEqual(target, 0)
        self.assertEqual(
            replies, [(protocol.ACK, 0), (protocol.ERROR, protocol.ABORTED)]
        )
        target, replies = self.session(
            [self.boot(TARGET), cont()], failed_transmit=protocol.reply(protocol.ACK)
        )
        self.assertEqual(target, 0)
        self.assertEqual(
            replies, [(protocol.ACK, 0), (protocol.ERROR, protocol.ABORTED)]
        )


class Manager(unittest.TestCase):
    """boot_task_then_flag publishes the worker's selection unless OTA is pending."""

    def run_manager(self, target, pending, usable=True):
        native = Native()
        native.cpu.mem_write(RECORD, record(0x12345000))
        for address, value in (
            (0x20000494, 1 if usable else 0),
            (0x20000498, 0x00434210),
            (0x40021008, 0x800),
        ):
            native.cpu.mem_write(address, struct.pack("<I", value))
        calls = []

        def checkpoint(c):
            # The worker has finished: it published target, then cleared held.
            native.cpu.mem_write(
                c.reg_read(UC_ARM_REG_R0) + 4, struct.pack("<I", target)
            )
            return 0

        def flag(c):
            calls.append("flag")
            self.assertEqual(native.words(RECORD, 3), (0, 0, 0xFFFFFFFF))
            return int(pending)

        native.stubs.update(
            {
                DELAY: lambda c: 0,
                WAKE: lambda c: 0,
                SLEEP: lambda c: 0,
                NEW: lambda c: 1,
                DELETE: lambda c: None,
                FLAG: flag,
                native.functions["boot_task_checkpoint"]: checkpoint,
            }
        )
        result, pc = native.call("boot_task_then_flag")
        self.assertEqual((pc, calls), (RETURN, ["flag"]))
        self.assertEqual(result, int(pending))
        return native.words(RECORD, 3)

    def test_selection_is_armed_only_without_pending_update(self):
        self.assertEqual(
            self.run_manager(TARGET, pending=False),
            (MAGIC, TARGET, ~TARGET & 0xFFFFFFFF),
        )
        self.assertEqual(self.run_manager(TARGET, pending=True), (0, 0, 0xFFFFFFFF))
        self.assertEqual(self.run_manager(0, pending=False), (0, 0, 0xFFFFFFFF))

    def test_stale_record_is_cleared_when_uart_is_unavailable(self):
        self.assertEqual(
            self.run_manager(TARGET, pending=False, usable=False), (0, 0, 0xFFFFFFFF)
        )


@unittest.skipUnless(
    (ROOT / "build/official-2.3.2.14.bin").exists(), "official bundle not downloaded"
)
class StockBindings(unittest.TestCase):
    def test_handoff_hooks_replace_calls_of_the_stock_vector_leaf(self):
        stock, _ = firmware.extract_stock(
            (ROOT / "build/official-2.3.2.14.bin").read_bytes()
        )
        for name, offset, call in firmware.HOOKS:
            self.assertEqual(stock[offset : offset + 4], call)
        for name, offset, call in firmware.HOOKS[1:]:
            with self.subTest(hook=name):
                self.assertEqual(
                    firmware.bl_target(offset, call), HANDOFF - firmware.BASE
                )
        leaf = HANDOFF - firmware.BASE
        # movw/movt r1, VTOR; str r0,[r1]; ldr sp,[r0]; ldr r1,[r0,#4]; bx r1
        self.assertEqual(
            stock[leaf : leaf + 18].hex(), "4ef60851cef200010860d0f800d041680847"
        )


class RamLoader(unittest.TestCase):
    """The compiled ITCM loader with stubbed recv/send callbacks."""

    def invoke(self, address, length, data=None, version=2, fail_send=False):
        code = r.load_program("ramload")
        cpu = Uc(u.UC_ARCH_ARM, u.UC_MODE_THUMB | u.UC_MODE_MCLASS)
        cpu.mem_map(0x00000000, 0x40000)
        cpu.mem_map(0x20000000, 0x40000)
        cpu.mem_write(0, bytes([0xA5]) * 0x40000)
        cpu.mem_write(0x20010000, code)
        cpu.mem_write(
            0x20000000, struct.pack("<4I", version, 0x20030001, 0x1234, 0x20030011)
        )
        source = bytes(i * 7 & 255 for i in range(length)) if data is None else data
        cursor, progress = 0, []

        def hook(c, pc, size, user_data):
            nonlocal cursor
            if pc == 0x20030010:
                n = min(16, c.reg_read(UC_ARM_REG_R2), len(source) - cursor)
                c.mem_write(c.reg_read(UC_ARM_REG_R1), source[cursor : cursor + n])
                cursor += n
                c.reg_write(UC_ARM_REG_R0, n)
            elif pc == 0x20030000:
                progress.append(
                    struct.unpack("<I", c.mem_read(c.reg_read(UC_ARM_REG_R1), 4))[0]
                )
                c.reg_write(UC_ARM_REG_R0, 0xFFFFFFFF if fail_send else 0)
            else:
                return
            c.reg_write(UC_ARM_REG_PC, c.reg_read(UC_ARM_REG_LR))

        handle = cpu.hook_add(u.UC_HOOK_CODE, hook)
        try:
            cpu.reg_write(UC_ARM_REG_R0, 0x20000000)
            cpu.reg_write(UC_ARM_REG_R1, address)
            cpu.reg_write(UC_ARM_REG_R2, length)
            cpu.reg_write(UC_ARM_REG_SP, 0x2003F000)
            cpu.reg_write(UC_ARM_REG_LR, 0x20020001)
            cpu.emu_start(0x20010001, 0x20020000, count=2_000_000)
            itcm = bytes(cpu.mem_read(0, 0x40000))
            return cpu.reg_read(UC_ARM_REG_R0), progress, itcm, source
        finally:
            cpu.hook_del(handle)

    def test_load_and_progress(self):
        result, progress, itcm, source = self.invoke(ITCM_TARGET, 528)
        self.assertEqual((result, progress), (0, [256, 512, 528]))
        self.assertEqual(itcm[ITCM_TARGET : ITCM_TARGET + 528], source)
        untouched = itcm[:ITCM_TARGET] + itcm[ITCM_TARGET + 528 :]
        self.assertEqual(set(untouched), {0xA5})

    def test_bounds_api_and_failures(self):
        for address, length in (
            (0x0, 16),
            (0xFF0, 32),
            (ITCM_TARGET + 8, 16),
            (ITCM_TARGET, 17),
            (0x3FFF0, 32),
            (0x40000, 16),
            (0xFFFFFFF0, 32),
        ):
            with self.subTest(address=hex(address), length=length):
                result, progress, itcm, _ = self.invoke(address, length)
                self.assertEqual((result, progress), (1, []))
                self.assertEqual(set(itcm), {0xA5})
        self.assertEqual(self.invoke(ITCM_TARGET, 0)[0], 0)
        self.assertEqual(self.invoke(ITCM_TARGET, 16, version=1)[0], 4)
        self.assertEqual(self.invoke(ITCM_TARGET, 32, data=bytes(20))[0], 5)
        self.assertEqual(self.invoke(ITCM_TARGET, 32, fail_send=True)[:2], (5, [32]))


class FakeClient:
    def __init__(self, memory, boot_error=None):
        self.memory = memory
        self.boot_error = boot_error
        self.selected = []
        self.pending = None

    def upload(self, code, arg0=0, arg1=0):
        self.pending = (arg0, arg1)

    def execute(self, callback=None, source=None):
        address, length = self.pending
        data = self.memory.get(address, bytes(length))[:length]
        if callback:
            callback(data)
        return 0, data

    def select_boot(self, address):
        if self.boot_error is not None:
            raise protocol.RemoteError(self.boot_error)
        self.selected.append(address)


class HostSelection(unittest.TestCase):
    def memory(self, flag=b"\xff" * 4, vectors=VECTORS):
        return {r.UPDATE_FLAG: flag, TARGET: vectors}

    def test_wire_request(self):
        sent = []
        protocol.Client(
            lambda packet: sent.append(packet) or protocol.reply(protocol.ACK)
        ).select_boot(TARGET)
        self.assertEqual(sent, [protocol.request(6, struct.pack("<I", TARGET))])

    def test_checks_flag_and_vectors_before_selecting(self):
        report = {}
        client = FakeClient(self.memory())
        r.Recovery(client, {"dump": b"d"}).select_boot(TARGET, report)
        self.assertEqual(client.selected, [TARGET])
        self.assertEqual(report["boot_selection"], "acknowledged")
        self.assertEqual(report["boot_vectors"], VECTORS.hex())
        for memory, error in (
            (self.memory(flag=r.PENDING_UPDATE), "pending"),
            (self.memory(vectors=b"\xff" * 8), "stack"),
        ):
            client = FakeClient(memory)
            with self.subTest(error=error), self.assertRaisesRegex(Exception, error):
                r.Recovery(client, {"dump": b"d"}).select_boot(TARGET, {})
            self.assertEqual(client.selected, [])

    def test_address_rules_match_the_bootloader(self):
        for address in (
            TARGET + 0x800,
            r.APP_BASE - 0x1000,
            r.APP_END,
            0x0,
            0x1800,
            r.ITCM_END,
        ):
            with self.subTest(address=hex(address)), self.assertRaises(ValueError):
                r.check_boot_address(address)
        for address in (r.APP_BASE, ITCM_TARGET, r.ITCM_END - 0x1000):
            r.check_boot_address(address)
        r.check_boot_vectors(ITCM_TARGET, ITCM_VECTORS)
        with self.assertRaisesRegex(ValueError, "reset"):
            r.check_boot_vectors(ITCM_TARGET, VECTORS)

    def test_remote_rejections_are_explained(self):
        for status, message in (
            (protocol.BAD_REQUEST, "no BOOT command"),
            (protocol.BAD_TARGET, "rejected"),
        ):
            report = {}
            with (
                self.subTest(status=status),
                self.assertRaisesRegex(RuntimeError, message),
            ):
                r.Recovery(
                    FakeClient(self.memory(), boot_error=status), {"dump": b"d"}
                ).select_boot(TARGET, report)
            self.assertEqual(report["boot_selection"], "rejected")

    def test_boot_once_releases_even_after_rejection(self):
        with tempfile.TemporaryDirectory() as directory:
            case = link.CaseLink("unused", Path(directory) / "run")
            with (
                patch.object(link.CaseLink, "__enter__", lambda self: self),
                patch.object(link.CaseLink, "close"),
                patch.object(case, "continue_boot") as release,
                patch.object(
                    r.Recovery,
                    "select_boot",
                    side_effect=RuntimeError("rejected"),
                ),
                self.assertRaises(RuntimeError),
            ):
                r.boot_once(case, TARGET, {"dump": b"d"})
            release.assert_called_once_with()
            self.assertFalse(case.report["success"])

    def test_boot_ram_loads_verifies_selects_and_releases(self):
        image = ITCM_VECTORS + bytes(20)
        order = []
        padded = image + bytes(4)

        class Engine:
            def __init__(self, client, programs):
                pass

            def check_api(self, program):
                order.append(("api", program))

            def read(self, address, length, callback=None):
                order.append(("read", address))
                return b"\xff" * length

            def load_ram(self, address, data, progress=None):
                order.append(("load", address, data))
                progress(len(data))

            def checksum(self, address, length):
                import zlib

                order.append(("checksum", address, length))
                return zlib.crc32(padded)

            def select_boot(self, address, report):
                order.append(("select", address))

        with tempfile.TemporaryDirectory() as directory:
            case = link.CaseLink("unused", Path(directory) / "run")
            with (
                patch.object(link.CaseLink, "__enter__", lambda self: self),
                patch.object(link.CaseLink, "close"),
                patch.object(case, "continue_boot", lambda: order.append("release")),
                patch.object(r, "Recovery", Engine),
            ):
                r.boot_ram(case, ITCM_TARGET, image, {})
            self.assertTrue(case.report["image_verified"])
        self.assertEqual(
            order,
            [
                ("api", "ramload"),
                ("read", r.UPDATE_FLAG),
                ("load", ITCM_TARGET, padded),
                ("checksum", ITCM_TARGET, len(padded)),
                ("select", ITCM_TARGET),
                "release",
            ],
        )
        for address, data in ((TARGET, VECTORS), (ITCM_TARGET, VECTORS)):
            with self.subTest(address=hex(address)), self.assertRaises(ValueError):
                r.boot_ram(None, address, data, {})

    def test_boot_ram_releases_after_crc_mismatch_without_selecting(self):
        class Engine:
            def __init__(self, client, programs):
                pass

            def check_api(self, program):
                pass

            def read(self, address, length, callback=None):
                return b"\xff" * length

            def load_ram(self, address, data, progress=None):
                pass

            def checksum(self, address, length):
                return 0

            def select_boot(self, address, report):
                raise AssertionError("must not select an unverified image")

        with tempfile.TemporaryDirectory() as directory:
            case = link.CaseLink("unused", Path(directory) / "run")
            with (
                patch.object(link.CaseLink, "__enter__", lambda self: self),
                patch.object(link.CaseLink, "close"),
                patch.object(case, "continue_boot") as release,
                patch.object(r, "Recovery", Engine),
                self.assertRaisesRegex(RuntimeError, "CRC"),
            ):
                r.boot_ram(case, ITCM_TARGET, ITCM_VECTORS + bytes(8), {})
            release.assert_called_once_with()

    def test_recover_boot_selects_after_verification(self):
        image = VECTORS + bytes(8)
        order = []

        class Engine:
            def __init__(self, client, programs):
                pass

            def preflight(self):
                order.append("preflight")
                return b"\xff" * 4

            def check_api(self):
                pass

            def read(self, address, length, callback=None):
                callback(bytes(length))
                return bytes(length)

            def checksum(self, address, length):
                import zlib

                return zlib.crc32(bytes(length))

            def install(self, *args, **kwargs):
                order.append("install")

            def select_boot(self, address, report):
                order.append(("select", address))

        with tempfile.TemporaryDirectory() as directory:
            case = link.CaseLink("unused", Path(directory) / "run")
            with (
                patch.object(link.CaseLink, "__enter__", lambda self: self),
                patch.object(link.CaseLink, "close"),
                patch.object(case, "continue_boot", lambda: order.append("release")),
                patch.object(r, "Recovery", Engine),
            ):
                r.recover(
                    case, image, {}, address=TARGET, vectors_last=False, boot=True
                )
        self.assertEqual(order, ["preflight", "install", ("select", TARGET), "release"])
        with self.assertRaises(ValueError):
            r.recover(None, b"\xff" * 16, {}, address=TARGET, boot=True)


if __name__ == "__main__":
    unittest.main()
