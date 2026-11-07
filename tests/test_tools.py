# SPDX-License-Identifier: MIT
"""Input bounds, golden wire data, failure semantics and stock-only OTA."""

import hashlib
import json
import struct
import sys
import unittest
from pathlib import Path
from unittest.mock import patch as mock_patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import flash
import patch as patcher
from g2patch import firmware, protocol
from g2patch.auth import DEFAULT_KEY, key_bytes, key_id
from g2patch.ble_ota import CTRL, DATA, StockOta, crc16
from g2patch.handshake import (
    check_okay,
    cont,
    decode_hello,
    hello,
    hold,
    okay,
    released,
)

ROOT = Path(__file__).resolve().parents[1]


class ChecksumTests(unittest.TestCase):
    def test_wire_crc_variants(self):
        self.assertEqual(crc16(b""), bytes.fromhex("ffff"))
        self.assertEqual(crc16(b"123456789"), bytes.fromhex("b129"))
        self.assertEqual(firmware.crc32c_msb(b""), 0)
        self.assertEqual(firmware.crc32c_msb(b"123456789"), 0xC052A8C8)


class FirmwareTests(unittest.TestCase):
    def setUp(self):
        self.stock = bytearray(firmware.STOCK_BYTES)
        self.stock[:8] = struct.pack("<II", 0x2007FB00, 0x432CA3)
        for _name, offset, call in firmware.HOOKS:
            self.stock[offset : offset + 4] = call
        digest = firmware.sha(self.stock)
        self.a = mock_patch.object(firmware, "STOCK_SHA", digest)
        self.a.start()
        self.b = mock_patch.object(patcher, "STOCK_SHA", digest)
        self.b.start()
        self.addCleanup(self.a.stop)
        self.addCleanup(self.b.stop)
        self.blob = (ROOT / "build/patch.bin").read_bytes()
        self.hooks = patcher.load_hooks()

    def test_patch_preserves_vectors_code_and_captured_tail(self):
        source = bytes(self.stock) + b"\xa5" * (firmware.PART_BYTES - len(self.stock))
        result, raw = patcher.patch(source, self.blob, self.hooks)
        self.assertEqual(result[:8], source[:8])
        changed = [i for i in range(firmware.STOCK_BYTES) if result[i] != source[i]]
        hooked = {
            offset + i
            for _name, offset, call in firmware.HOOKS
            for i in range(4)
            if self.hooks[_name][i] != call[i]
        }
        self.assertEqual(set(changed), hooked)
        for name, offset, _call in firmware.HOOKS:
            self.assertEqual(result[offset : offset + 4], self.hooks[name])
            target = firmware.bl_target(offset, self.hooks[name])
            self.assertTrue(firmware.STOCK_BYTES <= target < raw)
        self.assertEqual(result[raw:], source[raw : len(result)])
        self.assertEqual(len(result) % 4096, 0)
        self.assertEqual(firmware.validate_image(result), result)

    def test_missing_padding_is_explicitly_filled_not_taken_from_other_components(self):
        result, raw = patcher.patch(bytes(self.stock), self.blob, self.hooks)
        self.assertEqual(result[raw:], b"\xff" * (len(result) - raw))

    def test_wrong_version_out_of_partition_and_bad_hook_rejected(self):
        changed = bytearray(self.stock)
        changed[10] ^= 1
        with self.assertRaises(ValueError):
            patcher.patch(changed, self.blob, self.hooks)
        with self.assertRaises(ValueError):
            patcher.patch(self.stock, bytes(firmware.PART_BYTES), self.hooks)
        with self.assertRaises(ValueError):
            patcher.patch(self.stock, self.blob, {"hook": self.hooks["hook"]})
        image, _ = patcher.patch(self.stock, self.blob, self.hooks)
        for _name, offset, _call in firmware.HOOKS:
            changed = bytearray(image)
            changed[offset : offset + 4] = bytes(4)
            with self.subTest(hook=_name), self.assertRaises(ValueError):
                firmware.component(changed)

    def test_partially_hooked_image_is_rejected(self):
        image, _ = patcher.patch(self.stock, self.blob, self.hooks)
        for _name, offset, call in firmware.HOOKS:
            changed = bytearray(image)
            changed[offset : offset + 4] = call
            with (
                self.subTest(hook=_name),
                self.assertRaisesRegex(ValueError, "only some"),
            ):
                firmware.validate_image(changed)

    def test_raw_partition_and_full_mram_detection(self):
        source = bytes(self.stock) + b"\xa5" * (firmware.PART_BYTES - len(self.stock))
        self.assertEqual(firmware.extract_stock(source), (source, 0))
        self.assertEqual(
            firmware.extract_stock(bytes(0x10000) + source), (source, 0x10000)
        )

    def test_container_bounds_and_component_crc(self):
        header, payload = firmware.component(self.stock)
        data = bytearray(0x100) + header + payload
        data[:8] = b"EVENOTA\0"
        struct.pack_into("<I", data, 8, 1)
        struct.pack_into(
            "<4I", data, 64, 1, 0x100, 128 + len(payload), firmware.crc32c_msb(payload)
        )
        self.assertEqual(firmware.extract_stock(data)[0], payload)
        data[-1] ^= 1
        with self.assertRaisesRegex(ValueError, "CRC"):
            firmware.extract_stock(data)

    def test_only_bootloader_type_path_and_storage_are_built(self):
        header, payload = firmware.component(self.stock)
        self.assertEqual(len(header), 128)
        self.assertEqual(struct.unpack_from("<II", header, 36), (1, 3))
        self.assertEqual(header[48:].split(b"\0")[0], b"ota/s200_bootloader.bin")
        self.assertEqual(
            struct.unpack_from("<II", header, 8),
            (len(payload), firmware.crc32c_msb(payload)),
        )


class BuildPins(unittest.TestCase):
    def test_pinned_artifacts_reproduce(self):
        # Reproducible default-key build pins.
        pins = {
            "patch": "8d3836ae656dd70dd2b711381784e0f5b2a536696557253cced41b55446974bf",
            "case": "004ce36d9cf8d77e2931e27574f34f34a219a92699b9b44e09c8b0e9f93225a9",
            "echo": "50e2d81ef7b26978ab8be1c722a27924b06217945ae7c4cd9c92beb39a9590dc",
        }
        for name, expected in pins.items():
            with self.subTest(name=name):
                if name == "patch" and key_bytes() != DEFAULT_KEY.encode():
                    manifest = json.loads((ROOT / f"build/{name}.json").read_text())
                    self.assertEqual(manifest["auth_key_sha256"], key_id())
                    expected = manifest["sha256"]
                self.assertEqual(
                    hashlib.sha256(
                        (ROOT / f"build/{name}.bin").read_bytes()
                    ).hexdigest(),
                    expected,
                )


class ProtocolTests(unittest.TestCase):
    def test_handshake_wire_vector(self):
        frame = bytes.fromhex("5aa5ff100001030c48454c4f02000000454c52325d")
        self.assertEqual(frame[12:16], bytes.fromhex("02000000"))
        challenge = decode_hello(frame)
        self.assertEqual(frame, hello(challenge))
        self.assertEqual(len(hold(challenge)), 25)
        self.assertEqual(len(okay(challenge)), 29)
        check_okay(okay(challenge), challenge)

    def test_unsupported_hello_version_is_rejected(self):
        for version in (1, 3, 0x00000101, 0x00010001, 0x01000001):
            with self.subTest(version=version):
                frame = bytearray(hello(123))
                struct.pack_into("<I", frame, 12, version)
                frame[-1] = (14 + sum(frame[4:-1])) & 255
                with self.assertRaisesRegex(ValueError, "unsupported protocol version"):
                    decode_hello(frame)

    def test_old_markers_are_rejected(self):
        old = bytes.fromhex("5aa5ff0c0001030847325231454c523227")
        with self.assertRaises(ValueError):
            decode_hello(old)
        old = bytes.fromhex("5aa5ff0c0001030847324431454c523219")
        with self.assertRaises(ValueError):
            check_okay(old, 0x32524C45)

    def test_loader_words_and_release_have_no_challenge(self):
        self.assertEqual(protocol.request(protocol.RUN)[4:8], b"RQST")
        self.assertEqual(protocol.reply(protocol.RESULT)[8:12], b"RESP")
        self.assertEqual(hold(123)[4:8], b"HOLD")
        self.assertEqual(cont(), bytes.fromhex("7e000104434f4e543d"))
        self.assertEqual(released(), bytes.fromhex("5aa5ff0800010304524c534443"))

    def test_run_is_not_repeated_after_ambiguous_failure(self):
        sent = []

        def exchange(packet):
            sent.append(packet)
            raise TimeoutError("lost reply")

        client = protocol.Client(exchange)
        with self.assertRaises(TimeoutError):
            client.execute()
        with self.assertRaises(RuntimeError):
            client.execute()
        self.assertEqual(sent, [protocol.request(protocol.RUN)])

    def test_callback_crc_error_stops_without_ack_or_retry(self):
        sent = []
        bad = bytearray(protocol.block(protocol.BLOCK_OUTPUT, b"abc"))
        bad[-1] ^= 1

        def exchange(packet):
            sent.append(packet)
            return bytes(bad)

        with self.assertRaises(ValueError):
            protocol.Client(exchange).execute()
        self.assertEqual(sent, [protocol.request(protocol.RUN)])


class StockBleTests(unittest.IsolatedAsyncioTestCase):
    async def test_verification_target_mismatch_stops_before_begin(self):
        from types import SimpleNamespace

        class Device:
            end_status = None
            side = "left"

            def __init__(self, *args):
                pass

            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                pass

            async def install(self, *args):
                raise AssertionError("must not start OTA")

        args = SimpleNamespace(
            address="left", side="right", adapter=None, pair=False, verify_port="/case"
        )
        with (
            mock_patch.object(flash, "StockOta", Device),
            self.assertRaisesRegex(ValueError, "does not match"),
        ):
            await flash.transfer(args, bytes(128), bytes(4096))

    async def test_left_verification_uses_advertised_side(self):
        from types import SimpleNamespace

        class Device:
            end_status = None
            side = "left"

            def __init__(self, *args):
                pass

            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                pass

            async def install(self, *args):
                return 8

        args = SimpleNamespace(
            address="left", side="left", adapter=None, pair=False, verify_port="/case"
        )
        with mock_patch.object(flash, "StockOta", Device):
            self.assertEqual(await flash.transfer(args, bytes(128), bytes(4096)), 8)
        self.assertEqual(args.side, "left")

    async def test_post_end_reconnection_never_repeats_install(self):
        from types import SimpleNamespace

        events = []

        class Device:
            end_status = None
            side = "right"

            def __init__(self, *args):
                pass

            async def __aenter__(self):
                events.append("authenticate")
                return self

            async def __aexit__(self, *args):
                events.append("disconnect")

            async def install(self, *args):
                events.append("install")
                self.end_status = 8
                raise TimeoutError("first post-copy reply lost")

        args = SimpleNamespace(
            address="right", adapter=None, pair=False, verify_port=None
        )
        with mock_patch.object(flash, "StockOta", Device):
            self.assertEqual(await flash.transfer(args, bytes(128), bytes(4096)), 8)
        self.assertEqual(
            events,
            ["authenticate", "install", "disconnect", "authenticate", "disconnect"],
        )

    async def test_stock_ota_packet_flow_without_any_faceclaw_endpoint(self):
        device = StockOta("test")
        bodies = []
        fragments = {}
        block_sequence = None

        def note(channel, sid, body):
            frame = (
                bytes((0xAA, 0x12, 1, len(body) + 2, 1, 1, sid, 0)) + body + crc16(body)
            )
            device.notes.put_nowait((channel, frame))

        class Client:
            async def write_gatt_char(self, channel, frame, response=False):
                nonlocal block_sequence
                sid = frame[6]
                key = (channel, sid, frame[2])
                parts = fragments.setdefault(key, bytearray())
                parts.extend(frame[8:])
                self_test.assertEqual(frame[3], len(frame) - 8)
                if frame[5] != frame[4]:
                    return
                body = bytes(fragments.pop(key))
                self_test.assertEqual(body[-2:], crc16(body[:-2]))
                body = body[:-2]
                bodies.append((sid, body, frame[2]))
                if sid == 0x80:
                    # Stock command 4, echoed magic, empty result message.
                    prefix = body[: body.index(b"\x1a")]
                    note(CTRL[1], 0x80, prefix + b"\x1a\0")
                elif sid == 0xC0:
                    if body[0] == 2:
                        block_sequence = frame[2]
                    else:
                        note(DATA[1], 0xC0, bytes((body[0], 8 if body[0] == 3 else 0)))
                elif sid == 0xC1:
                    self_test.assertEqual(frame[2], block_sequence)
                    note(DATA[1], 0xC0, b"\x02\0")
                else:
                    self_test.fail(f"non-stock SID {sid:#x}")

        self_test = self
        payload = bytes(range(256)) * 32
        header = bytes(128)
        with mock_patch.object(device, "client", Client()):
            self.assertEqual(await device.install(header, payload), 8)
        self.assertEqual(
            b"".join(body for sid, body, seq in bodies if sid == 0xC1), payload
        )
        self.assertEqual(
            [body[0] for sid, body, seq in bodies if sid == 0xC0], [0, 1, 2, 2, 3]
        )
        self.assertEqual({sid for sid, body, seq in bodies}, {0x80, 0xC0, 0xC1})
        self.assertEqual(device.end_status, 8)

    async def test_ota_nak_is_terminal(self):
        device = StockOta("test")

        async def rejected(*args, **kwargs):
            return 1

        device.command = rejected
        with self.assertRaisesRegex(RuntimeError, "BEGIN"):
            await device.install(bytes(128), bytes(4096))
        self.assertIsNone(device.end_status)


if __name__ == "__main__":
    unittest.main()
