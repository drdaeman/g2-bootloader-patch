# SPDX-License-Identifier: MIT
"""Version-bound boot partition layout and stock OTA component construction."""

import hashlib
import struct

from crc import Calculator, Configuration

BASE = 0x00410000
APP_BASE = 0x00438000
PART_BYTES = APP_BASE - BASE
STOCK_BYTES = 149760
STOCK_SHA = "22a2b98e606b4d296e957a3a8b600a2158497638d79485c817c2025536329ba7"
# (build artifact, partition offset, stock Thumb BL). The manager's update-flag
# call, then the DFU task's two calls of the vector handoff leaf at 0x42DFD8.
HOOKS = (
    ("hook", 0x0042E656 - BASE, bytes.fromhex("fff789ff")),
    ("hook_handoff_update", 0x0042E3D4 - BASE, bytes.fromhex("fff700fe")),
    ("hook_handoff_boot", 0x0042E440 - BASE, bytes.fromhex("fff7cafd")),
)
HOOK, OLD_CALL = HOOKS[0][1:]
PAGE_BYTES = 4096
FILENAME = "ota/s200_bootloader.bin"
# EvenOTA uses the Castagnoli polynomial without reflection or final XOR.
_CRC32 = Calculator(
    Configuration(
        width=32,
        polynomial=0x1EDC6F41,
        init_value=0,
        final_xor_value=0,
        reverse_input=False,
        reverse_output=False,
    ),
    optimized=True,
)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def crc32c_msb(data):
    return _CRC32.checksum(data)


def extract_stock(data):
    """Raw boot/partition, MRAM starting 0x410000/0x400000, or EVENOTA."""
    if data[:8] == b"EVENOTA\0":
        if len(data) < 64:
            raise ValueError("truncated EVENOTA header")
        count = struct.unpack_from("<I", data, 8)[0]
        if not 1 <= count <= 64 or 64 + 16 * count > len(data):
            raise ValueError("bad EVENOTA table")
        found = []
        for i in range(count):
            _, offset, size, crc = struct.unpack_from("<4I", data, 64 + 16 * i)
            if offset < 64 + 16 * count or size < 128 or offset + size > len(data):
                raise ValueError("invalid EVENOTA component bounds")
            header = data[offset : offset + 128]
            if header[48:].split(b"\0")[0] != FILENAME.encode():
                continue
            length = struct.unpack_from("<I", header, 8)[0]
            payload = data[offset + 128 : offset + 128 + length]
            if (
                length > size - 128
                or crc32c_msb(payload) != crc
                or struct.unpack_from("<I", header, 12)[0] != crc
            ):
                raise ValueError("boot component CRC mismatch")
            found.append(payload)
        if len(found) != 1:
            raise ValueError("expected one bootloader component")
        data = found[0]
    for offset in (0, 0x10000):
        if sha(data[offset : offset + STOCK_BYTES]) == STOCK_SHA:
            return data[offset : offset + PART_BYTES], offset
    raise ValueError(
        "only the stock Even 2.3.2.14 bootloader is supported (SHA256 "
        + STOCK_SHA
        + ")"
    )


def restore_hooks(image):
    """Copy of the stock-length prefix with every reviewed hook reverted."""
    prefix = bytearray(image[:STOCK_BYTES])
    for _name, offset, call in HOOKS:
        prefix[offset : offset + 4] = call
    return prefix


def bl_target(offset, call):
    first, second = struct.unpack("<HH", call)
    if first & 0xF800 != 0xF000 or second & 0xD000 != 0xD000:
        raise ValueError("hook is not a Thumb BL")
    s = (first >> 10) & 1
    delta = (
        (s << 24)
        | ((~((second >> 13) ^ s) & 1) << 23)
        | ((~((second >> 11) ^ s) & 1) << 22)
        | ((first & 1023) << 12)
        | ((second & 2047) << 1)
    )
    if s:
        delta -= 1 << 25
    return offset + 4 + delta


def validate_image(image):
    if not STOCK_BYTES <= len(image) <= PART_BYTES:
        raise ValueError("boot image exceeds its partition or is truncated")
    if sha(restore_hooks(image)) != STOCK_SHA:
        raise ValueError("stock code/vectors changed outside the reviewed hooks")
    patched = [image[offset : offset + 4] != call for _name, offset, call in HOOKS]
    if any(patched) and not all(patched):
        raise ValueError("only some of the reviewed hooks are installed")
    for _name, offset, call in HOOKS:
        if image[offset : offset + 4] != call:
            target = bl_target(offset, image[offset : offset + 4])
            if not STOCK_BYTES <= target < len(image):
                raise ValueError("hook target lies outside appended code")
    return image + b"\xff" * ((-len(image)) % PAGE_BYTES)


def component(image):
    payload = validate_image(image)
    if len(payload) > PART_BYTES:
        raise ValueError("rounded image overlaps main application")
    header = struct.pack(
        "<12I",
        0,
        0,
        len(payload),
        crc32c_msb(payload),
        0,
        0x4E455645,
        0xFFFFFFFF,
        0xFFFFFFFF,
        0,
        1,
        3,
        0xFFFFFFFF,
    ) + FILENAME.encode().ljust(80, b"\0")
    return header, payload
