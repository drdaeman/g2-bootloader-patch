# SPDX-License-Identifier: MIT
"""Execute compiled watchdog paths, including faults and held-session timing."""

import json
import struct
import unittest
from pathlib import Path

import unicorn as u
from test_altboot import (
    DELAY,
    DELETE,
    FLAG,
    NEW,
    RECORD,
    RETURN,
    SLEEP,
    TICK,
    WAKE,
    Native,
)
from unicorn.arm_const import (
    UC_ARM_REG_LR,
    UC_ARM_REG_PC,
    UC_ARM_REG_PRIMASK,
    UC_ARM_REG_R0,
    UC_ARM_REG_SP,
)

ROOT = Path(__file__).resolve().parents[1]
IOM = 0x40057000
POWER = 0x40021004
TIMER_PROFILE = bytes.fromhex("0a0200003c00")


class PmicWatchdog(unittest.TestCase):
    def run_feed(
        self,
        power=0x800,
        pins=0x4200,
        ready=True,
        status=1,
        masked=0,
        profile=TIMER_PROFILE,
        fifo_count=6,
        cycle_step=0,
        cycle_start=0,
        fail_command=None,
    ):
        native = Native()
        cpu = native.cpu
        cpu.mem_map(0x40010000, 0x1000)
        cpu.mem_map(IOM, 0x1000)
        cpu.mem_map(0xE0001000, 0x1000)
        for addr, value in (
            (POWER, power),
            (POWER + 4, 0x100 if ready else 0),
            (0x40010058, pins),
            (0x4001005C, pins),
            (IOM + 0x204, status),
            (IOM + 0x100, fifo_count << 16),
            (0xE000EDFC, 0x100),
            (0xE0001000, 0x40000000),
        ):
            cpu.mem_write(addr, struct.pack("<I", value))
        cpu.reg_write(UC_ARM_REG_PRIMASK, masked)
        writes, reads = [], []
        fifo = [
            int.from_bytes(profile[:4], "little"),
            int.from_bytes(profile[4:], "little"),
        ]
        command = None
        read_completed = False
        reset_after_read = False
        cycles = cycle_start

        def access(c, kind, addr, size, value, data):
            nonlocal command, read_completed, reset_after_read
            if kind == u.UC_MEM_WRITE:
                writes.append((addr, value))
                if addr == IOM + 0x120:
                    command = value
                elif addr == IOM + 0x110 and read_completed:
                    reset_after_read = True
            else:
                reads.append(addr)
                if addr == IOM + 0x108:
                    c.mem_write(addr, struct.pack("<I", fifo.pop(0)))
                    read_completed = not fifo
                elif addr == IOM + 0x204:
                    c.mem_write(
                        addr,
                        struct.pack(
                            "<I",
                            0
                            if reset_after_read
                            else (0x10 if command == fail_command else status),
                        ),
                    )
            if IOM <= addr < IOM + 0x1000:
                self.assertTrue(native.words(POWER, 1)[0] & 0x100)

        cpu.hook_add(
            u.UC_HOOK_MEM_READ | u.UC_HOOK_MEM_WRITE,
            access,
            begin=0x40000000,
            end=0x400FFFFF,
        )

        def cycle_read(c, kind, addr, size, value, data):
            nonlocal cycles
            c.mem_write(addr, struct.pack("<I", cycles & 0xFFFFFFFF))
            cycles += cycle_step

        cpu.hook_add(u.UC_HOOK_MEM_READ, cycle_read, begin=0xE0001004, end=0xE0001004)
        result, pc = native.call("boot_watchdog_feed", count=4_000_000)
        self.assertEqual(pc, RETURN, "polling did not terminate")
        self.assertEqual(native.words(POWER, 1)[0], power)
        self.assertEqual(cpu.reg_read(UC_ARM_REG_PRIMASK), masked)
        self.assertEqual(native.words(0xE000EDFC, 1), (0x100,))
        self.assertEqual(native.words(0xE0001000, 1), (0x40000000,))
        return result, writes, reads

    def test_only_kick_register_is_written_and_state_is_restored(self):
        for masked in (0, 1):
            result, writes, _ = self.run_feed(masked=masked)
            self.assertEqual(result, 1)
            self.assertEqual(
                [v for a, v in writes if a == IOM + 0x10C], [0x0507, 0x10407]
            )
            self.assertEqual(
                [v for a, v in writes if a == IOM + 0x120], [0x281, 0x602, 0x301]
            )

    def test_profile_status_is_informational_but_mode_and_target_must_match(self):
        self.assertEqual(self.run_feed(profile=bytes.fromhex("0a00ff003c00"))[0], 1)
        for profile in ("020200003c00", "0a0200013c00", "0a0200002000", "0a0200003c01"):
            with self.subTest(profile=profile):
                result, writes, _ = self.run_feed(profile=bytes.fromhex(profile))
                self.assertEqual(result, 0)
                self.assertNotIn((IOM + 0x10C, 0x10407), writes)
        self.assertEqual(self.run_feed(fifo_count=5)[0], 0)

    def test_errors_at_each_command_restore_state_and_stop(self):
        for command in (0x281, 0x602, 0x301):
            with self.subTest(command=command):
                result, writes, _ = self.run_feed(fail_command=command)
                self.assertEqual(result, 0)
                self.assertEqual(
                    [v for a, v in writes if a == IOM + 0x120][-1], command
                )

    def test_shared_cycle_deadline_expires_across_successful_commands_and_wrap(self):
        for start in (0, 0xFFFF0000):
            with self.subTest(start=start):
                result, writes, reads = self.run_feed(
                    cycle_step=100000, cycle_start=start
                )
                self.assertEqual(result, 0)
                self.assertNotIn((IOM + 0x10C, 0x10407), writes)
                self.assertLess(len(reads), 50)

    def test_busy_bus_or_changed_pins_are_not_touched(self):
        for kwargs in ({"power": 0x900}, {"power": 0x820}, {"pins": 3}):
            result, writes, reads = self.run_feed(**kwargs)
            self.assertEqual((result, writes), (0, []))
            self.assertFalse(any(IOM <= a < IOM + 0x1000 for a in reads))

    def test_power_timeout_never_accesses_iom(self):
        result, writes, reads = self.run_feed(ready=False)
        self.assertEqual(result, 0)
        self.assertEqual(writes, [(POWER, 0x900), (POWER, 0x800)])
        self.assertFalse(any(IOM <= a < IOM + 0x1000 for a in reads))

    def test_bus_error_and_completion_timeout_are_bounded(self):
        for status in (0, 0x10, 0x20, 0x40, 0x200, 0x11):
            with self.subTest(status=status):
                result, writes, _ = self.run_feed(status=status)
                self.assertEqual(result, 0)
                self.assertIn((IOM + 0x11C, 0), writes)
                self.assertIn((IOM + 0x118, 0), writes)


class HeldSession(unittest.TestCase):
    def test_manager_feeds_for_long_session_retries_and_handles_tick_wrap(self):
        for start, fail_first in ((0, False), (0xFFFFF000, True)):
            with self.subTest(start=start, fail_first=fail_first):
                self.run_session(start, fail_first)

    def test_final_feed_is_bounded_best_effort_and_also_covers_early_release(self):
        self.run_session(0, False, early=True, fail_final=True)
        self.run_session(0, False, fail_final=True)

    def run_session(self, start, fail_first, early=False, fail_final=False):
        native = Native()
        for addr, value in (
            (0x20000494, 1),
            (0x20000498, 0x434210),
            (0x40021008, 0x800),
        ):
            native.cpu.mem_write(addr, struct.pack("<I", value))
        elapsed, held, feeds = 0, None, []
        deleted = False

        def checkpoint(c):
            nonlocal held
            held = c.reg_read(UC_ARM_REG_R0)
            c.mem_write(held, struct.pack("<3I", int(not early), 0, 1))
            return int(not early)

        def delay(c):
            nonlocal elapsed
            if held is not None:
                elapsed += 512
                if elapsed >= 40960:
                    c.mem_write(held, bytes(4))
            return 0

        def feed(c):
            feeds.append(elapsed)
            self.assertEqual(deleted, early or elapsed == 40960)
            return int(
                not ((fail_first and len(feeds) == 1) or (fail_final and deleted))
            )

        def delete(c):
            nonlocal deleted
            deleted = True

        native.stubs.update(
            {
                TICK: lambda c: (start + elapsed) & 0xFFFFFFFF,
                DELAY: delay,
                WAKE: lambda c: 0,
                SLEEP: lambda c: 0,
                NEW: lambda c: 1,
                DELETE: delete,
                FLAG: lambda c: 0,
                native.functions["boot_task_checkpoint"]: checkpoint,
                native.functions["boot_watchdog_feed"]: feed,
            }
        )
        _, pc = native.call("boot_task_then_flag")
        self.assertEqual(pc, RETURN)
        expected = (
            [0, *range(1024, 40960, 5120)]
            if fail_first
            else list(range(0, 40960, 5120))
        )
        self.assertEqual(feeds, [0] if early else expected + [40960])
        self.assertEqual(native.words(RECORD, 3), (0, 0, 0xFFFFFFFF))


class CaseWatchdog(unittest.TestCase):
    def test_rate_limit_first_feed_bursts_long_gaps_and_wrap(self):
        for start in (0, 0xFFFFF000):
            with self.subTest(start=start):
                self.run_rate_limit(start)

    def run_rate_limit(self, start):
        meta = json.loads((ROOT / "build/case.json").read_text())
        functions = {
            n: meta["base"] + f["offset"] for n, f in meta["functions"].items()
        }
        cpu = u.Uc(u.UC_ARCH_ARM, u.UC_MODE_THUMB | u.UC_MODE_MCLASS)
        cpu.mem_map(0x20000000, 0x20000)
        cpu.mem_map(0x40000000, 0x1000)
        cpu.mem_map(0x40021000, 0x1000)
        cpu.mem_write(meta["base"], (ROOT / "build/case.bin").read_bytes())
        state, stop = 0x2001F000, 0x2001F100
        cpu.mem_write(state, struct.pack("<I", (start - 5000) & 0xFFFFFFFF))
        feeds = []
        now = start

        def feed(c, address, size, data):
            feeds.append(now)
            c.reg_write(UC_ARM_REG_R0, 1)
            c.reg_write(UC_ARM_REG_PC, c.reg_read(UC_ARM_REG_LR))

        cpu.hook_add(
            u.UC_HOOK_CODE,
            feed,
            begin=functions["case_watchdog_feed"],
            end=functions["case_watchdog_feed"],
        )

        def call(name):
            cpu.reg_write(UC_ARM_REG_R0, state)
            cpu.reg_write(UC_ARM_REG_SP, 0x2001FF00)
            cpu.reg_write(UC_ARM_REG_LR, stop | 1)
            cpu.emu_start(functions[name] | 1, stop, count=1000)
            self.assertEqual(cpu.reg_read(UC_ARM_REG_PC), stop)
            return cpu.reg_read(UC_ARM_REG_R0)

        # An active timer must not be reset or borrowed.
        cpu.mem_write(0x4002103C, struct.pack("<I", 0x101))
        self.assertEqual(call("case_watchdog_start"), 0)
        cpu.mem_write(0x4002103C, struct.pack("<I", 0x100))
        self.assertEqual(call("case_watchdog_start"), 1)
        self.assertEqual(struct.unpack("<I", cpu.mem_read(0x40000028, 4))[0], 63999)
        for offset in [*range(5000), 5000, 5001, 9999, 10000, 80000, 80001]:
            now = (start + offset) & 0xFFFFFFFF
            cpu.mem_write(0x40000024, struct.pack("<I", now))
            self.assertEqual(call("case_watchdog_service"), 1)
        self.assertEqual(
            feeds, [(start + n) & 0xFFFFFFFF for n in (0, 5000, 10000, 80000)]
        )
        call("case_watchdog_stop")
        self.assertEqual(struct.unpack("<I", cpu.mem_read(0x4002103C, 4))[0], 0x100)
        self.assertEqual(struct.unpack("<I", cpu.mem_read(0x40000000, 4))[0], 0)

    def test_guard_and_stock_pulse(self):
        for mode in (0, 0x10, 0x20, 0x30):
            with self.subTest(mode=mode):
                self.run_mode(mode)

    def run_mode(self, mode):
        meta = json.loads((ROOT / "build/case.json").read_text())
        entry = meta["base"] + meta["functions"]["case_watchdog_feed"]["offset"]
        cpu = u.Uc(u.UC_ARCH_ARM, u.UC_MODE_THUMB | u.UC_MODE_MCLASS)
        for addr, length in (
            (0x20000000, 0x20000),
            (0x08000000, 0x10000),
            (0x50000000, 0x1000),
        ):
            cpu.mem_map(addr, length)
        cpu.mem_write(meta["base"], (ROOT / "build/case.bin").read_bytes())
        cpu.mem_write(0x50000400, struct.pack("<I", mode))
        cpu.reg_write(UC_ARM_REG_SP, 0x2001FF00)
        cpu.reg_write(UC_ARM_REG_LR, 0x2001F101)
        events = []

        def delay(c, addr, size, data):
            events.append(("delay", c.reg_read(UC_ARM_REG_R0)))
            c.reg_write(UC_ARM_REG_PC, c.reg_read(UC_ARM_REG_LR))

        cpu.hook_add(u.UC_HOOK_CODE, delay, begin=0x0800A794, end=0x0800A794)
        cpu.hook_add(
            u.UC_HOOK_MEM_WRITE,
            lambda c, k, a, s, v, d: events.append(("gpio", v)),
            begin=0x50000418,
            end=0x50000418,
        )
        cpu.emu_start(entry | 1, 0x2001F100, count=10000)
        self.assertEqual(cpu.reg_read(UC_ARM_REG_PC), 0x2001F100)
        self.assertEqual(cpu.reg_read(UC_ARM_REG_R0), int(mode == 0x10))
        expected = (
            [
                ("gpio", 4),
                ("delay", 350),
                ("gpio", 4 << 16),
                *[("delay", 350)] * 40,
                ("gpio", 4),
            ]
            if mode == 0x10
            else []
        )
        self.assertEqual(events, expected)
