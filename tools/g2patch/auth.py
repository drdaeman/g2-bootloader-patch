# SPDX-License-Identifier: MIT
"""Shared handshake key; the default is public and does not restrict access."""

import hashlib
import hmac
import os
import struct

DEFAULT_KEY = "DEFAULTNOTSECRET"


def key_bytes():
    key = os.environ.get("G2_BOOT_KEY", DEFAULT_KEY).encode("utf-8")
    if not key:
        raise ValueError("G2_BOOT_KEY must not be empty")
    return key


def key_block():
    key = key_bytes()
    if len(key) > 64:
        key = hashlib.sha256(key).digest()
    return key.ljust(64, b"\0")


def key_id():
    return hashlib.sha256(key_block()).hexdigest()


def tag(marker, version, challenge):
    message = b"G2BOOT" + struct.pack("<II", version, challenge) + marker
    return hmac.digest(key_bytes(), message, "sha256")[:16]
