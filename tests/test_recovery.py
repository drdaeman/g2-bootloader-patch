# SPDX-License-Identifier: MIT
"""Recovery validation, write ordering, and native pinned-bootloader MRAM calls.

ROM programming and power controls are modeled; these are not hardware tests.
"""

import json
import struct
import sys
import tempfile
import unittest
import zlib
from pathlib import Path
from unittest.mock import Mock, patch

import unicorn as u
from unicorn.arm_const import (
    UC_ARM_REG_LR,
    UC_ARM_REG_PC,
    UC_ARM_REG_PRIMASK,
    UC_ARM_REG_R0,
    UC_ARM_REG_R1,
    UC_ARM_REG_R2,
    UC_ARM_REG_R3,
    UC_ARM_REG_SP,
)
from unicorn.unicorn import Uc

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from g2patch import firmware
from g2patch.link import CaseLink
from g2patch.recovery import (
    APP_BASE,
    APP_END,
    MRAM_BASE,
    MRAM_END,
    Recovery,
    application,
    load_program,
    recover,
)

ROOT = Path(__file__).resolve().parents[1]


def image(size=600):
    data = bytearray(i & 255 for i in range(size))
    struct.pack_into("<II", data, 0, 0x2007FF00, APP_BASE + 17)
    return bytes(data)


def bundle(data):
    preamble = struct.pack("<8I", len(data) + 32, 0, 0, 0, 0, APP_BASE, 0, 0)
    payload = bytearray(preamble + data)
    struct.pack_into("<I", payload, 4, zlib.crc32(payload[8:]))
    crc = firmware.crc32c_msb(payload)
    header = bytearray(128)
    struct.pack_into("<II", header, 8, len(payload), crc)
    name = b"ota/s200_firmware_ota.bin"
    header[48 : 48 + len(name)] = name
    table = b"EVENOTA\0" + struct.pack("<I", 1) + bytes(52)
    table += struct.pack("<4I", 0, 80, len(payload) + 128, crc)
    return table + header + payload


class ApplicationInput(unittest.TestCase):
    def test_raw_and_bundle(self):
        data = image()
        self.assertEqual(application(data), data)
        self.assertEqual(application(bundle(data)), data)

    def test_invalid_vectors_and_bounds(self):
        for data in (b"", bytes(16), image(APP_END - APP_BASE + 1)):
            with self.assertRaises(ValueError):
                application(data)
        for stack, reset in (
            (0x2007FF01, APP_BASE + 17),
            (0, APP_BASE + 17),
            (0x2007FF00, APP_BASE + 16),
            (0x2007FF00, APP_BASE - 1),
        ):
            data = bytearray(image())
            struct.pack_into("<II", data, 0, stack, reset)
            with self.assertRaises(ValueError):
                application(data)

    def test_corrupt_bundle(self):
        valid = bundle(image())
        for offset in (8, 68, 72, 76, 88, 92, len(valid) - 1):
            data = bytearray(valid)
            data[offset] ^= 0x80
            with self.assertRaises(ValueError):
                application(data)


class WriteOrdering(unittest.TestCase):
    def setUp(self):
        self.image = image()
        self.before = bytes([0xA5]) * 608
        self.memory = bytearray(self.before)
        self.writes = []
        self.recovery = Recovery(Mock(), {})

        def write(address, data, progress=None):
            offset = address - APP_BASE
            self.memory[offset : offset + len(data)] = data
            self.writes.append((address, data))

        self.recovery.write = Mock(side_effect=write)
        self.recovery.checksum = Mock(
            side_effect=lambda address, length: zlib.crc32(
                self.memory[address - APP_BASE : address - APP_BASE + length]
            )
        )

    def test_vectors_last_and_tail_preserved(self):
        self.recovery.install(self.image, self.before, lambda _: None)
        self.assertEqual(self.memory, self.image + self.before[len(self.image) :])
        self.assertEqual(self.writes[-1], (APP_BASE, self.image[:16]))
        self.assertTrue(
            all(address >= APP_BASE + 16 for address, _ in self.writes[:-1])
        )

    def test_body_mismatch_does_not_commit_vectors(self):
        self.recovery.checksum = Mock(return_value=0)
        with self.assertRaisesRegex(RuntimeError, "body CRC"):
            self.recovery.install(self.image, self.before, lambda _: None)
        self.assertEqual(self.memory[:16], self.before[:16])

    def test_raw_flag_write_preserves_neighboring_bytes(self):
        before = bytes(range(16))
        memory = bytearray(before)
        writes = []

        def write(address, data, progress=None):
            writes.append((address, data))
            memory[address - APP_END : address - APP_END + len(data)] = data

        self.recovery.write = Mock(side_effect=write)
        self.recovery.checksum = Mock(
            side_effect=lambda address, length: zlib.crc32(
                memory[address - APP_END : address - APP_END + length]
            )
        )
        self.recovery.install(
            bytes(4), before, lambda _: None, address=APP_END + 4, vectors_last=False
        )
        self.assertEqual(memory, before[:4] + bytes(4) + before[8:])
        self.assertEqual(len(writes), 1)

    def test_failed_write_is_not_retried(self):
        self.recovery.write = Mock(side_effect=TimeoutError("lost reply"))
        with self.assertRaises(TimeoutError):
            self.recovery.install(self.image, self.before, lambda _: None)
        self.recovery.write.assert_called_once()


@unittest.skipUnless(
    (ROOT / "build/official-2.3.2.14.bin").exists(),
    "stock bundle needed for native MRAM wrapper test",
)
class NativeWriter(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.stock, _ = firmware.extract_stock(
            (ROOT / "build/official-2.3.2.14.bin").read_bytes()
        )
        cls.writer = load_program("recover")

    def invoke(
        self,
        address=APP_BASE,
        length=256,
        rom_status=0,
        corrupt=False,
        pending=False,
        mask=0,
        api_version=2,
        eof_after=None,
    ):
        cpu = Uc(u.UC_ARCH_ARM, u.UC_MODE_THUMB | u.UC_MODE_MCLASS)
        cpu.mem_map(0x00400000, 0x400000)
        cpu.mem_map(0x20000000, 0x80000)
        cpu.mem_map(0x02000000, 0x10000)
        cpu.mem_map(0x40014000, 0x1000)
        cpu.mem_map(0xE000E000, 0x1000)
        cpu.mem_write(firmware.BASE, self.stock)
        cpu.mem_write(APP_END, struct.pack("<I", 0x55555555 if pending else 0xFFFFFFFF))
        data = bytes(i & 255 for i in range(min(length, 1024)))
        if eof_after is not None:
            data = data[:eof_after]
        cursor = 0
        cpu.mem_write(
            0x20000000, struct.pack("<4I", api_version, 0x20030001, 0x1234, 0x20030011)
        )
        code = self.writer
        cpu.mem_write(0x20010000, code)
        cpu.reg_write(UC_ARM_REG_R0, 0x20000000)
        cpu.reg_write(UC_ARM_REG_R1, address)
        cpu.reg_write(UC_ARM_REG_R2, length)
        cpu.reg_write(UC_ARM_REG_SP, 0x2007F000)
        cpu.reg_write(UC_ARM_REG_LR, 0x20020001)
        cpu.reg_write(UC_ARM_REG_PRIMASK, mask)
        calls = []
        invalidations = []

        def hook(c, pc, size, user_data):
            nonlocal cursor
            if pc == 0x20030010:
                self.assertEqual(c.reg_read(UC_ARM_REG_R0), 0x1234)
                n = min(16, c.reg_read(UC_ARM_REG_R2), len(data) - cursor)
                if n:
                    c.mem_write(c.reg_read(UC_ARM_REG_R1), data[cursor : cursor + n])
                cursor += n
                c.reg_write(UC_ARM_REG_R0, n)
            elif pc == 0x20030000:
                self.assertEqual(c.reg_read(UC_ARM_REG_R2), 4)
                count = struct.unpack("<I", c.mem_read(c.reg_read(UC_ARM_REG_R1), 4))[0]
                self.assertEqual(count, sum(len(block) for _, block in calls))
                c.reg_write(UC_ARM_REG_R0, 0)
            elif pc == 0x41B8EC:
                c.reg_write(UC_ARM_REG_R0, c.reg_read(UC_ARM_REG_PRIMASK))
                c.reg_write(UC_ARM_REG_PRIMASK, 1)
            elif pc in (0x41BD92, 0x41BDE4):
                c.reg_write(UC_ARM_REG_R0, 0)
            elif pc == 0x0200FF20:
                self.assertEqual(c.reg_read(UC_ARM_REG_PRIMASK), 1)
                self.assertEqual(c.reg_read(UC_ARM_REG_R0), 0x12344321)
                self.assertEqual(c.reg_read(UC_ARM_REG_R1), 1)
                destination = 0x400000 + 4 * c.reg_read(UC_ARM_REG_R3)
                count = (
                    4 * struct.unpack("<I", c.mem_read(c.reg_read(UC_ARM_REG_SP), 4))[0]
                )
                source = bytes(c.mem_read(c.reg_read(UC_ARM_REG_R2), count))
                calls.append((destination, source))
                if not rom_status:
                    c.mem_write(destination, source)
                    if corrupt:
                        c.mem_write(destination, bytes([source[0] ^ 1]))
                c.reg_write(UC_ARM_REG_R0, rom_status)
            else:
                return
            c.reg_write(UC_ARM_REG_PC, c.reg_read(UC_ARM_REG_LR))

        def cache_write(c, access, address, size, value, data):
            if address == 0xE000EF5C:
                invalidations.append(value)

        cache_handle = cpu.hook_add(u.UC_HOOK_MEM_WRITE, cache_write)
        handle = cpu.hook_add(u.UC_HOOK_CODE, hook)
        try:
            cpu.emu_start(0x20010001, 0x20020000, count=100000)
            self.assertEqual(cpu.reg_read(UC_ARM_REG_PC), 0x20020000)
            self.assertEqual(cpu.reg_read(UC_ARM_REG_PRIMASK), mask)
            expected_lines = (
                [
                    line
                    for address, block in calls
                    for line in range(address & ~31, address + len(block), 32)
                ]
                if not rom_status
                else []
            )
            self.assertEqual(invalidations, expected_lines)
            return cpu.reg_read(UC_ARM_REG_R0), calls
        finally:
            cpu.hook_del(handle)
            cpu.hook_del(cache_handle)

    def test_native_stock_programming_and_interrupt_restore(self):
        for mask in (0, 1):
            result, calls = self.invoke(mask=mask)
            self.assertEqual(result, 0)
            self.assertEqual(calls, [(APP_BASE, bytes(range(256)))])

    def test_native_rom_error_and_readback_mismatch(self):
        self.assertEqual(self.invoke(rom_status=7)[0], 0x08000107)
        self.assertEqual(self.invoke(corrupt=True)[0], 3)

    def test_physical_bounds_and_pending_ota(self):
        for address, length in (
            (MRAM_BASE - 16, 16),
            (MRAM_END, 16),
            (MRAM_END - 16, 32),
            (APP_BASE + 1, 16),
            (APP_BASE, 17),
            (0xFFFFFFF0, 32),
        ):
            result, calls = self.invoke(address, length)
            self.assertEqual(result, 1)
            self.assertEqual(calls, [])
        self.assertEqual(self.invoke(pending=True)[0], 0)
        self.assertEqual(self.invoke(address=APP_END, length=16, pending=True)[0], 0)

    def test_multiple_blocks_and_early_eof(self):
        result, calls = self.invoke(length=512)
        self.assertEqual(result, 0)
        self.assertEqual(
            calls, [(APP_BASE, bytes(range(256))), (APP_BASE + 256, bytes(range(256)))]
        )
        self.assertEqual(self.invoke(eof_after=15), (5, []))
        result, calls = self.invoke(length=512, eof_after=270)
        self.assertEqual(result, 5)
        self.assertEqual(len(calls), 1)

    def test_api_probe_and_old_api_rejection(self):
        self.assertEqual(self.invoke(length=0), (0, []))
        self.assertEqual(self.invoke(api_version=1), (4, []))


class TransactionJournal(unittest.TestCase):
    def test_streamed_transactions_do_not_accumulate(self):
        with tempfile.TemporaryDirectory() as directory:
            link = CaseLink(
                "unused", Path(directory) / "audit", stream_transactions=True
            )
            link.port = Mock()
            frame = bytes.fromhex("5aa5ff0800010304524c534443")
            header = b"G2RX" + bytes([0, len(frame)])
            tail = frame + bytes([sum(header + frame) & 255])
            with patch("g2patch.link.read_exact", side_effect=[header, tail] * 100):
                for _ in range(100):
                    self.assertEqual(link.exchange(bytes(9)), frame)
            self.assertEqual(link.report["transactions"], [])
            self.assertEqual(link.report["transaction_count"], 100)
            events = [
                json.loads(line)
                for line in (link.out / "transactions.jsonl").read_text().splitlines()
            ]
            self.assertEqual(len(events), 200)
            self.assertEqual(events[-1]["sequence"], 100)
            self.assertIn("reply", events[-1])


class RecoveryWorkflow(unittest.TestCase):
    def run_workflow(self, failure=None):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        link = Mock()
        link.__enter__ = Mock(return_value=link)
        link.__exit__ = Mock(return_value=False)
        link.out = Path(directory.name)
        link.report = {}
        engine = Mock()
        before = bytes([0xA5]) * 608

        def read(address, size, callback):
            self.assertEqual((address, size), (APP_BASE, 608))
            callback(before)
            return before

        engine.read.side_effect = read
        engine.checksum.return_value = zlib.crc32(before)
        if failure == "api":
            engine.check_api.side_effect = RuntimeError("old API")
        elif failure == "backup":
            engine.checksum.return_value ^= 1
        elif failure == "write":
            engine.install.side_effect = TimeoutError("lost write reply")
        elif failure == "preflight":
            engine.preflight.side_effect = ValueError("unsupported bootloader")
        with patch("g2patch.recovery.Recovery", return_value=engine):
            if failure:
                with self.assertRaises((RuntimeError, TimeoutError, ValueError)):
                    recover(link, image(), {})
                link.continue_boot.assert_not_called()
                if failure in ("backup", "preflight", "api"):
                    engine.install.assert_not_called()
                    self.assertFalse(link.report["writes_started"])
            else:
                recover(link, image(), {})
                link.continue_boot.assert_called_once()
                self.assertTrue(link.report["image_verified"])
                self.assertTrue(link.report["success"])
        if failure not in ("preflight", "api"):
            self.assertEqual((link.out / "before.bin").read_bytes(), before)
        return link

    def test_success_releases_after_verified_install(self):
        self.run_workflow()

    def test_preflight_backup_and_write_failures_keep_boot_held(self):
        for failure in ("preflight", "api", "backup", "write"):
            with self.subTest(failure=failure):
                self.run_workflow(failure)

    def test_preflight_rejects_wrong_stock_before_reading_flag(self):
        recovery = Recovery(Mock(), {})
        recovery.read = Mock(return_value=bytes(firmware.STOCK_BYTES))
        with self.assertRaisesRegex(ValueError, "supported stock"):
            recovery.preflight()
        recovery.read.assert_called_once()


class AddressAcknowledgement(unittest.TestCase):
    def test_cli_acknowledgement_only_outside_application(self):
        import contextlib
        import io

        import recover as cli

        for address, acknowledged, allowed in (
            (APP_BASE + 1, False, True),
            (APP_END - 4, False, True),
            (APP_END - 3, False, False),
            (APP_END, False, False),
            (APP_BASE - 1, False, False),
            (APP_END, True, True),
        ):
            with (
                self.subTest(address=address, acknowledged=acknowledged),
                tempfile.TemporaryDirectory() as directory,
            ):
                source = Path(directory) / "data.bin"
                source.write_bytes(bytes(4))
                args = [
                    "recover.py",
                    str(source),
                    "--write",
                    "unused",
                    "--side",
                    "right",
                    "--address",
                    hex(address),
                ]
                if acknowledged:
                    args.append("--i-verified-the-addresses")
                with (
                    patch.object(sys, "argv", args),
                    patch.object(cli, "load_program", return_value=bytes(2)),
                    patch.object(cli, "load_case_image"),
                    patch.object(cli, "CaseLink"),
                    patch.object(cli, "recover") as run,
                    contextlib.redirect_stdout(io.StringIO()),
                    contextlib.redirect_stderr(io.StringIO()),
                ):
                    if allowed:
                        cli.main()
                        run.assert_called_once()
                    else:
                        with self.assertRaises(SystemExit) as error:
                            cli.main()
                        self.assertEqual(error.exception.code, 2)
                        run.assert_not_called()
