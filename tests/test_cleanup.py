# SPDX-License-Identifier: MIT
"""Release held sessions after aborts and check verification inputs before OTA."""

import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import flash
from g2patch import link, protocol
from g2patch.handshake import cont, released


class ReleaseTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.link = link.CaseLink("unused", Path(self.directory.name) / "run")
        self.continue_packet = cont()
        self.released = released()

    def test_callback_exception_aborts_then_releases_without_replaying_run(self):
        def callback(_data):
            raise ValueError("consumer failed")

        with patch.object(
            self.link,
            "exchange",
            side_effect=[
                protocol.block(protocol.BLOCK_OUTPUT, b"abc"),
                protocol.reply(protocol.RESULT, 5),
                self.released,
            ],
        ) as exchange:
            with self.assertRaisesRegex(ValueError, "consumer failed"):
                try:
                    protocol.Client(self.link.exchange).execute(callback)
                finally:
                    self.link.continue_boot()
            self.assertEqual(
                [call.args[0] for call in exchange.call_args_list],
                [
                    protocol.request(protocol.RUN),
                    self.continue_packet,
                    self.continue_packet,
                ],
            )
        self.assertTrue(self.link.report["continued"])

    def test_pending_load_reply_and_abort_are_drained_before_release(self):
        with patch.object(
            self.link,
            "exchange",
            side_effect=[
                protocol.reply(protocol.ACK),
                protocol.reply(protocol.ERROR, 4),
                self.released,
            ],
        ) as exchange:
            self.link.continue_boot()
            self.assertEqual(exchange.call_count, 3)
        self.assertTrue(self.link.report["continued"])

    def test_uncertain_or_invalid_transport_is_not_retried(self):
        for reply in (TimeoutError("lost transport"), b"bad reply"):
            with (
                self.subTest(reply=reply),
                patch.object(self.link, "exchange", side_effect=[reply]) as exchange,
            ):
                with self.assertRaises((TimeoutError, ValueError)):
                    self.link.continue_boot()
                self.assertEqual(exchange.call_count, 1)
        self.assertNotIn("continued", self.link.report)

    def test_release_attempts_are_bounded(self):
        with patch.object(
            self.link,
            "exchange",
            return_value=protocol.block(protocol.BLOCK_OUTPUT, b"x"),
        ) as exchange:
            with self.assertRaisesRegex(RuntimeError, "release unconfirmed"):
                self.link.continue_boot()
            self.assertEqual(exchange.call_count, 3)
        self.assertNotIn("continued", self.link.report)


class VerificationPreflightTests(unittest.IsolatedAsyncioTestCase):
    async def test_missing_or_invalid_local_inputs_prevent_ble_connection(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            build = root / "build"
            build.mkdir()
            args = SimpleNamespace(verify_port="unused")
            cases = ("checksum.bin", "case.bin", "case.json", "tampered-case")
            for missing in cases:
                with self.subTest(missing=missing):
                    for path in build.iterdir():
                        path.unlink()
                    if missing != "checksum.bin":
                        (build / "checksum.bin").write_bytes(bytes(2))
                    if missing != "case.bin":
                        (build / "case.bin").write_bytes(bytes(2))
                    if missing != "case.json":
                        (build / "case.json").write_text(json.dumps({"sha256": "bad"}))
                    with (
                        patch.object(flash, "ROOT", root),
                        patch.object(link, "ROOT", root),
                        patch.object(flash, "StockOta") as device,
                        self.assertRaises((FileNotFoundError, ValueError)),
                    ):
                        await flash.transfer(args, b"", b"")
                    device.assert_not_called()
