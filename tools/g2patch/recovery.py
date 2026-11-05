# SPDX-License-Identifier: MIT
"""Main-application recovery through the existing bootloader RAM interface."""

import hashlib
import io
import json
import os
import struct
import zlib
from pathlib import Path

from . import firmware
from .protocol import Client

APP_BASE = firmware.APP_BASE
APP_END = 0x007FE000
UPDATE_FLAG = APP_END
MRAM_BASE = 0x00400000
MRAM_END = 0x00800000
BLOCK_BYTES = 256
APP_FILENAME = b"ota/s200_firmware_ota.bin"
ROOT = Path(__file__).resolve().parents[2]


def application(data):
    """Accept a raw vector-table image or extract the main app from EVENOTA."""
    if data.startswith(b"EVENOTA\0"):
        if len(data) < 64:
            raise ValueError("truncated EVENOTA header")
        count = struct.unpack_from("<I", data, 8)[0]
        if not 1 <= count <= 64 or 64 + 16 * count > len(data):
            raise ValueError("invalid EVENOTA table")
        found = []
        for i in range(count):
            _, offset, size, crc = struct.unpack_from("<4I", data, 64 + 16 * i)
            if offset < 64 + 16 * count or size < 128 or offset + size > len(data):
                raise ValueError("invalid EVENOTA component bounds")
            header = data[offset : offset + 128]
            if header[48:].split(b"\0")[0] != APP_FILENAME:
                continue
            length, header_crc = struct.unpack_from("<II", header, 8)
            if length < 40 or length > size - 128:
                raise ValueError("invalid application component size")
            payload = data[offset + 128 : offset + 128 + length]
            if firmware.crc32c_msb(payload) != crc or crc != header_crc:
                raise ValueError("application component CRC mismatch")
            declared, checksum = struct.unpack_from("<II", payload)
            if declared & 0xFFFFFF != length or zlib.crc32(payload[8:]) != checksum:
                raise ValueError("application preamble length/CRC mismatch")
            if struct.unpack_from("<I", payload, 20)[0] != APP_BASE:
                raise ValueError("application has the wrong load address")
            found.append(payload[32:])
        if len(found) != 1:
            raise ValueError("expected exactly one application component")
        data = found[0]
    if not 16 <= len(data) <= APP_END - APP_BASE:
        raise ValueError(
            "application image is empty, truncated, or outside its partition"
        )
    stack, reset = struct.unpack_from("<II", data)
    if stack & 7 or not 0x20000000 < stack <= 0x20400000:
        raise ValueError("application has an invalid initial stack pointer")
    if not reset & 1 or not APP_BASE <= (reset & ~1) < APP_BASE + len(data):
        raise ValueError("application reset vector is outside the supplied image")
    return data


def load_program(name):
    code = (ROOT / f"build/{name}.bin").read_bytes()
    manifest = json.loads((ROOT / f"build/{name}.json").read_text())
    if (
        not 2 <= len(code) <= 512
        or len(code) & 1
        or manifest["bytes"] != len(code)
        or manifest["sha256"] != hashlib.sha256(code).hexdigest()
        or manifest["functions"]["entry"]["offset"] != 0
    ):
        raise ValueError(f"invalid {name} build; run make")
    return code


def memory_range(address, length):
    if length < 1 or not MRAM_BASE <= address < MRAM_END or length > MRAM_END - address:
        raise ValueError("write range is outside physical MRAM")
    base = address & ~15
    return base, (address - base + length + 15) & ~15


class Recovery:
    def __init__(self, client, programs):
        self.client = client
        self.programs = programs

    def read(self, address, length, callback=None):
        self.client.upload(self.programs["dump"], arg0=address, arg1=length)
        result, data = self.client.execute(callback)
        if result or len(data) != length:
            raise RuntimeError("memory read failed or returned an incorrect length")
        return data

    def checksum(self, address, length):
        self.client.upload(self.programs["checksum"], arg0=address, arg1=length)
        result, data = self.client.execute()
        if data:
            raise RuntimeError("unexpected checksum callback")
        return result

    def preflight(self):
        prefix = bytearray(self.read(firmware.BASE, firmware.STOCK_BYTES))
        prefix[firmware.HOOK : firmware.HOOK + 4] = firmware.OLD_CALL
        if firmware.sha(prefix) != firmware.STOCK_SHA:
            raise ValueError("temple does not contain the supported stock bootloader")
        flag = self.read(UPDATE_FLAG, 4)
        return flag

    def check_api(self):
        self.client.upload(self.programs["recover"], arg0=0, arg1=0)
        result, output = self.client.execute()
        if result or output:
            raise RuntimeError(
                "streaming recovery requires bootloader RAM API version 2"
            )

    def write(self, address, data, progress=None):
        memory_range(address, len(data))
        if (address | len(data)) & 15:
            raise ValueError("MRAM programming requires 16-byte alignment")
        self.client.upload(self.programs["recover"], arg0=address, arg1=len(data))
        count = 0

        def checked(chunk):
            nonlocal count
            if len(chunk) != 4:
                raise RuntimeError("invalid writer progress")
            actual = struct.unpack("<I", chunk)[0]
            if actual != min(count + BLOCK_BYTES, len(data)):
                raise RuntimeError("unexpected writer progress")
            count = actual
            if progress:
                progress(count)

        source = io.BytesIO(data)
        result, _output = self.client.execute(checked, source=source.read)
        if result or count != len(data) or source.tell() != len(data):
            raise RuntimeError(
                f"MRAM write/readback failed at {address:#x}: {result:#x}"
            )

    def install(self, image, before, progress, address=APP_BASE, vectors_last=True):
        base, size = memory_range(address, len(image))
        if len(before) != size:
            raise ValueError("backup has the wrong length")
        leading = address - base
        target = before[:leading] + image + before[leading + len(image) :]
        first = 16 if vectors_last else 0
        if vectors_last and address != APP_BASE:
            raise ValueError("vector-last order requires the application base")
        if size > first:
            self.write(base + first, target[first:], progress)
        if self.checksum(base + first, size - first) != zlib.crc32(target[first:]):
            raise RuntimeError(
                "application body CRC mismatch; vectors were not committed"
                if vectors_last
                else "written range CRC mismatch"
            )
        if vectors_last:
            self.write(base, target[:16])
            if self.checksum(base, size) != zlib.crc32(target):
                raise RuntimeError("final MRAM CRC mismatch")
        progress(size)


def recover(link, image, programs, address=APP_BASE, vectors_last=True, release=True):
    """Leave the temple held on any error. Never replay RUN after uncertainty."""
    base, size = memory_range(address, len(image))
    with link:
        recovery = Recovery(Client(link.exchange), programs)
        link.report.update(
            image_sha256=firmware.sha(image),
            address=address,
            image_bytes=len(image),
            writes_started=False,
        )
        link.save()
        flag = recovery.preflight()
        recovery.check_api()
        link.report["update_flag_before"] = flag.hex()
        if flag == bytes.fromhex("55555555"):
            print(
                "Stock OTA flag is set; its update can run after CONTINUE.", flush=True
            )
        print(f"Backing up {size} MRAM bytes...", flush=True)
        with (link.out / "before.bin").open("xb") as file:
            copied = 0

            def backup(data):
                nonlocal copied
                file.write(data)
                copied += len(data)
                if copied == size or copied % (64 * 1024) == 0:
                    print(f"{copied}/{size} bytes backed up", flush=True)

            before = recovery.read(base, size, backup)
            file.flush()
            os.fsync(file.fileno())
        if recovery.checksum(base, size) != zlib.crc32(before):
            raise RuntimeError("backup CRC mismatch; no writes started")
        link.report.update(backup_sha256=firmware.sha(before), writes_started=True)
        link.save()

        def progress(count):
            link.report["verified_bytes"] = count
            link.save()
            if count == size or count % (64 * 1024) == 0:
                print(f"{count}/{size} bytes written and checked", flush=True)

        recovery.install(
            image, before, progress, address=address, vectors_last=vectors_last
        )
        link.report["image_verified"] = True
        link.save()
        if release:
            link.continue_boot()
    link.report["success"] = True
    link.save()
