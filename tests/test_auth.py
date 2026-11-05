# SPDX-License-Identifier: MIT
"""Check software SHA-256/HMAC against RFC 4231 and Python's implementations."""

import ctypes
import hashlib
import hmac
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from g2patch import auth
from g2patch.artifacts import write_auth_key
from g2patch.handshake import check_okay, cont, hello, hold, okay, released
from g2patch.link import CaseLink, load_case_image

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(
    shutil.which("clang"), "Clang is required for portable crypto checks"
)
class CryptoVectors(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory()
        path = Path(cls.directory.name)
        source = path / "crypto.c"
        source.write_text("""#include "bearssl_hmac.h"
void test_sha(const unsigned char *p,unsigned n,unsigned char out[32]) {
 br_sha256_context s;br_sha256_init(&s);
 unsigned half=n/2;br_sha256_update(&s,p,half);br_sha256_update(&s,p+half,n-half);br_sha256_out(&s,out);
}
void test_hmac(const unsigned char *k,unsigned kn,const unsigned char *p,unsigned n,unsigned char out[32]) {
 br_hmac_key_context kc; br_hmac_context ctx;
 br_hmac_key_init(&kc,&br_sha256_vtable,k,kn);
 br_hmac_init(&ctx,&kc,32);br_hmac_update(&ctx,p,n);br_hmac_out(&ctx,out);
}
""")
        lib = path / "crypto.so"
        subprocess.run(
            [
                "clang",
                "-shared",
                "-fPIC",
                "-nostdlib",
                "-ffreestanding",
                "-fno-builtin",
                "-fuse-ld=lld",
                "-O2",
                "-I" + str(ROOT / "src"),
                "-I" + str(ROOT / "vendor/bearssl/inc"),
                "-I" + str(ROOT / "vendor/bearssl/src"),
                *[
                    str(ROOT / "vendor/bearssl/src" / f)
                    for f in (
                        "hash/sha2small.c",
                        "mac/hmac.c",
                        "codec/dec32be.c",
                        "codec/enc32be.c",
                    )
                ],
                str(source),
                "-o",
                str(lib),
            ],
            check=True,
        )
        cls.lib = ctypes.CDLL(str(lib))
        cls.lib.test_sha.argtypes = [ctypes.c_char_p, ctypes.c_uint, ctypes.c_void_p]
        cls.lib.test_hmac.argtypes = [
            ctypes.c_char_p,
            ctypes.c_uint,
            ctypes.c_char_p,
            ctypes.c_uint,
            ctypes.c_void_p,
        ]

    @classmethod
    def tearDownClass(cls):
        cls.directory.cleanup()

    def mac(self, key, message):
        result = ctypes.create_string_buffer(32)
        self.lib.test_hmac(key, len(key), message, len(message), result)
        return result.raw

    def test_rfc4231_case1(self):
        expected = bytes.fromhex(
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        )
        self.assertEqual(self.mac(bytes([0x0B]) * 20, b"Hi There"), expected)

    def test_hmac_key_and_block_boundaries(self):
        for key_length in (0, 16, 20, 32, 64, 65, 131):
            key = bytes(i & 255 for i in range(key_length))
            for length in (0, 3, 55, 56, 63, 64, 65, 1024):
                message = bytes(i & 255 for i in range(length))
                with self.subTest(key_length=key_length, length=length):
                    self.assertEqual(
                        self.mac(key, message), hmac.digest(key, message, "sha256")
                    )

    def test_sha_padding_and_multiblock(self):
        for length in (0, 3, 55, 56, 63, 64, 65, 1024):
            message = bytes(i & 255 for i in range(length))
            result = ctypes.create_string_buffer(32)
            self.lib.test_sha(message, length, result)
            self.assertEqual(result.raw, hashlib.sha256(message).digest())


class KeyAndHandshake(unittest.TestCase):
    def test_direction_challenge_and_key_are_bound(self):
        self.assertNotEqual(hold(123)[8:24], okay(123)[12:28])
        with self.assertRaises(ValueError):
            check_okay(okay(123), 124)
        with patch.dict(os.environ, {"G2_BOOT_KEY": "test-other-key"}):
            other = okay(123)
        with self.assertRaises(ValueError):
            check_okay(other, 123)

    def test_empty_key_is_rejected(self):
        with patch.dict(os.environ, {"G2_BOOT_KEY": ""}), self.assertRaises(ValueError):
            auth.key_bytes()

    def test_generated_header_changes_only_when_key_changes(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "key.h"
            with patch.dict(os.environ, {"G2_BOOT_KEY": "first-test-key"}):
                write_auth_key(target)
                content, modified = target.read_bytes(), target.stat().st_mtime_ns
                write_auth_key(target)
                self.assertEqual(target.stat().st_mtime_ns, modified)
                self.assertEqual(target.stat().st_mode & 0o777, 0o600)
            with patch.dict(os.environ, {"G2_BOOT_KEY": "second-test-key"}):
                write_auth_key(target)
                self.assertNotEqual(target.read_bytes(), content)

    def test_case_image_is_independent_of_host_key(self):
        with patch.dict(os.environ, {"G2_BOOT_KEY": "different-host-key"}):
            _, manifest, _ = load_case_image()
            self.assertNotIn("auth_key_sha256", manifest)


class HostClaim(unittest.TestCase):
    def test_host_computes_hold_and_checks_okay(self):
        with tempfile.TemporaryDirectory() as directory:
            link = CaseLink("unused", Path(directory) / "run")
            with (
                patch.object(link, "exchange", return_value=okay(123)) as exchange,
                patch("g2patch.link.time.sleep"),
            ):
                link.claim(hello(123))
                exchange.assert_called_once_with(hold(123))
            self.assertEqual(
                link.report["handshake"], (hello(123) + hold(123) + okay(123)).hex()
            )

    def test_invalid_hello_is_rejected_before_transmission(self):
        for offset in (12, 20):
            beacon = bytearray(hello(123))
            beacon[offset] ^= 1
            with tempfile.TemporaryDirectory() as directory:
                link = CaseLink("unused", Path(directory) / "run")
                with (
                    patch.object(link, "exchange") as exchange,
                    self.assertRaises(ValueError),
                ):
                    link.claim(bytes(beacon))
                exchange.assert_not_called()

    def test_wrong_okay_releases_boot_without_repeating_hold(self):
        with tempfile.TemporaryDirectory() as directory:
            link = CaseLink("unused", Path(directory) / "run")
            with (
                patch.object(
                    link, "exchange", side_effect=[okay(124), released()]
                ) as exchange,
                patch("g2patch.link.time.sleep"),
                self.assertRaises(ValueError),
            ):
                link.claim(hello(123))
            self.assertEqual(
                [call.args[0] for call in exchange.call_args_list], [hold(123), cont()]
            )
            self.assertNotIn("handshake", link.report)
