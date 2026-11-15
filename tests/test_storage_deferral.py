# SPDX-License-Identifier: MIT
"""Reproduce the hardware-tested storage deferral and enforce image identity."""

import importlib.util
import sys
import unittest
from pathlib import Path
from unittest.mock import Mock, call

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from g2patch import firmware as F
from g2patch.recovery import Recovery

ROOT = Path(__file__).resolve().parents[1]


class StorageDeferral(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location(
            "patcher_storage", ROOT / "tools/patch.py"
        )
        patcher = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(patcher)
        build = ROOT / "build"
        stock, _ = F.extract_stock((build / "official-2.3.2.14.bin").read_bytes())
        cls.image, _ = patcher.patch(
            stock, (build / "patch.bin").read_bytes(), patcher.load_patches(build)
        )
        # Reconstruct the previous hardware-tested release as a test fixture.
        previous = bytearray(cls.image)
        previous[0xB89E:0xB8A0] = bytes.fromhex("04f0")
        previous[0x1E656:0x1E658] = bytes.fromhex("06f0")
        previous[0x264A8:0x264C8] = b"\xff" * 32
        cls.previous = bytes(previous)

    def test_hardware_tested_image_and_existing_api_bytes(self):
        self.assertIn(F.sha(self.image), F.KNOWN_BOOTLOADER_SHAS)
        self.assertEqual(len(self.image), 159744)
        # Preserve all pre-existing probe, authentication and RAM API code.
        self.assertEqual(
            F.sha(self.image[149760:155876]),
            "8d3836ae656dd70dd2b711381784e0f5b2a536696557253cced41b55446974bf",
        )

    def test_linked_startup_branch_and_manager_wrapper(self):
        self.assertEqual(self.image[0xB89E:0xB8A0], bytes.fromhex("04e0"))
        self.assertEqual(
            F.BASE + F.bl_target(0x1E656, self.image[0x1E656:0x1E65A]), 0x4364A8
        )
        self.assertEqual(self.image[0x264C4:0x264C8], bytes.fromhex("9eb84100"))

    def test_validation_accepts_known_images_and_erased_partition_tail(self):
        self.assertEqual(
            {F.sha(self.image), F.sha(self.previous)}, F.KNOWN_BOOTLOADER_SHAS
        )
        for image in [self.image, self.previous]:
            self.assertEqual(F.validate_image(image), image)
            partition = image + b"\xff" * (F.PART_BYTES - len(image))
            self.assertEqual(F.validate_image(partition), partition)
            with self.assertRaises(ValueError):
                F.validate_image(image + b"\x00")

    def test_validation_rejects_changed_or_truncated_images(self):
        for at in [0, 4, 0xB89C, 0x1E654, 0x24900, 0x264A8, len(self.image) - 1]:
            bad = bytearray(self.image)
            bad[at] ^= 1
            with self.subTest(at=at), self.assertRaises(ValueError):
                F.validate_image(bad)
        with self.assertRaises(ValueError):
            F.validate_image(self.image[:-4])

    def test_recovery_accepts_each_known_image_before_reading_pending(self):
        for image in [self.image, self.previous]:
            recovery = Recovery(Mock(), {})
            pending = bytes.fromhex("55555555")
            recovery.read = Mock(side_effect=[image, pending])
            self.assertEqual(recovery.preflight(), pending)
            self.assertEqual(
                recovery.read.call_args_list,
                [call(F.BASE, F.PATCHED_BYTES), call(0x7FE000, 4)],
            )

    def test_recovery_refuses_partial_or_changed_new_image(self):
        for image in [self.image[:-4], self.image[:-1] + b"\x00"]:
            recovery = Recovery(Mock(), {})
            recovery.read = Mock(return_value=image)
            with self.subTest(length=len(image)), self.assertRaises(ValueError):
                recovery.preflight()
            recovery.read.assert_called_once_with(F.BASE, F.PATCHED_BYTES)
