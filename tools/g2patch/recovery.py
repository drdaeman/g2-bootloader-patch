# SPDX-License-Identifier: MIT
"""Main-application recovery and one-boot selection through the bootloader RAM interface."""

import hashlib
import io
import json
import os
import struct
import zlib
from pathlib import Path

from . import firmware
from .protocol import BAD_REQUEST, BAD_TARGET, Client, RemoteError

APP_BASE = firmware.APP_BASE
APP_END = 0x007FE000
UPDATE_FLAG = APP_END
PENDING_UPDATE = bytes.fromhex("55555555")
BOOT_ALIGNMENT = 0x1000
# The stock bootloader runs code from ITCM 0x40..0x6C; boot images start above it.
ITCM_BOOT_BASE = 0x00001000
ITCM_END = 0x00040000
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


def boot_region_end(address):
    """End of the boot region holding address, as the bootloader checks it."""
    for base, end in ((APP_BASE, APP_END), (ITCM_BOOT_BASE, ITCM_END)):
        if base <= address < end:
            return end
    return None


def check_boot_address(address):
    if address & (BOOT_ALIGNMENT - 1) or boot_region_end(address) is None:
        raise ValueError(
            "boot address must be 4 KiB-aligned within MRAM "
            f"[{APP_BASE:#x}, {APP_END:#x}) or ITCM [{ITCM_BOOT_BASE:#x}, {ITCM_END:#x})"
        )


def is_itcm(address):
    return ITCM_BOOT_BASE <= address < ITCM_END


def check_boot_vectors(address, vectors):
    """The bootloader's own acceptance rule for an alternate vector table."""
    if len(vectors) < 8:
        raise ValueError("a boot image must start with a vector table")
    stack, reset = struct.unpack_from("<II", vectors)
    if stack & 7 or not 0x20000000 < stack <= 0x20400000:
        raise ValueError(f"no valid initial stack pointer at {address:#x}")
    end = boot_region_end(address)
    if not reset & 1 or end is None or not address + 8 <= (reset & ~1) < end:
        raise ValueError(f"no valid Thumb reset vector at {address:#x}")


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
        prefix = self.read(firmware.BASE, firmware.STOCK_BYTES)
        if firmware.sha(firmware.restore_hooks(prefix)) != firmware.STOCK_SHA:
            raise ValueError("temple does not contain the supported stock bootloader")
        flag = self.read(UPDATE_FLAG, 4)
        return flag

    def select_boot(self, address, report):
        """Check the target as the bootloader will, then select it for one boot.

        report["boot_selection"] becomes "sent" before BOOT and "acknowledged"
        after ACK. A failure while "sent" leaves the temple's choice unknown.
        """
        check_boot_address(address)
        flag = self.read(UPDATE_FLAG, 4)
        report["update_flag"] = flag.hex()
        if flag == PENDING_UPDATE:
            raise RuntimeError(
                "a stock OTA update is pending; the bootloader would install it "
                "and ignore the selection"
            )
        vectors = self.read(address, 8)
        report["boot_vectors"] = vectors.hex()
        check_boot_vectors(address, vectors)
        report["boot_selection"] = "sent"
        try:
            self.client.select_boot(address)
        except RemoteError as error:
            report["boot_selection"] = "rejected"
            if error.status == BAD_REQUEST:
                raise RuntimeError(
                    "this bootloader has no BOOT command; install the current patch"
                ) from error
            if error.status == BAD_TARGET:
                raise RuntimeError(
                    f"the bootloader rejected the vector table at {address:#x}"
                ) from error
            raise
        report["boot_selection"] = "acknowledged"

    def check_api(self, program="recover"):
        self.client.upload(self.programs[program], arg0=0, arg1=0)
        result, output = self.client.execute()
        if result or output:
            raise RuntimeError("streaming writes require bootloader RAM API version 2")

    def write(self, address, data, progress=None):
        memory_range(address, len(data))
        if (address | len(data)) & 15:
            raise ValueError("MRAM programming requires 16-byte alignment")
        self._stream("recover", address, data, progress)

    def load_ram(self, address, data, progress=None):
        if (
            not is_itcm(address)
            or not data
            or len(data) > ITCM_END - address
            or (address | len(data)) & 15
        ):
            raise ValueError(
                f"ITCM loads need 16-byte alignment within [{ITCM_BOOT_BASE:#x}, "
                f"{ITCM_END:#x})"
            )
        self._stream("ramload", address, data, progress)

    def _stream(self, program, address, data, progress):
        """One resident writer upload; per-block progress; no retry after failure."""
        self.client.upload(self.programs[program], arg0=address, arg1=len(data))
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
            raise RuntimeError(f"write/readback failed at {address:#x}: {result:#x}")

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


def boot_once(link, address, programs):
    """Select an alternate image for this boot, then release boot.

    Boot is released on failure too; without an acknowledged selection the
    temple starts the stock application.
    """
    check_boot_address(address)
    with link:
        link.report.update(boot_address=address, boot_selection="none")
        try:
            Recovery(Client(link.exchange), programs).select_boot(address, link.report)
        finally:
            link.save()
            link.continue_boot()
    link.report["success"] = True
    link.save()


def boot_ram(link, address, image, programs):
    """Load image into ITCM, verify it, select it for this boot, and release.

    Nothing persistent changes. Boot is released on failure too; without an
    acknowledged selection the temple starts the stock application.
    """
    if not is_itcm(address):
        raise ValueError("RAM boot images load into ITCM")
    check_boot_address(address)
    check_boot_vectors(address, image)
    padded = image + bytes(-len(image) % 16)
    if len(padded) > ITCM_END - address:
        raise ValueError(f"image does not fit in ITCM at {address:#x}")
    with link:
        link.report.update(
            boot_address=address,
            image_sha256=firmware.sha(image),
            image_bytes=len(image),
            boot_selection="none",
        )
        try:
            recovery = Recovery(Client(link.exchange), programs)
            recovery.check_api("ramload")
            flag = recovery.read(UPDATE_FLAG, 4)
            if flag == PENDING_UPDATE:
                raise RuntimeError(
                    "a stock OTA update is pending; the bootloader would install it "
                    "and ignore the selection"
                )

            def progress(count):
                link.report["loaded_bytes"] = count
                if count == len(padded) or count % (16 * 1024) == 0:
                    print(f"{count}/{len(padded)} bytes loaded", flush=True)

            recovery.load_ram(address, padded, progress)
            if recovery.checksum(address, len(padded)) != zlib.crc32(padded):
                raise RuntimeError("ITCM CRC mismatch after loading")
            link.report["image_verified"] = True
            recovery.select_boot(address, link.report)
        finally:
            link.save()
            link.continue_boot()
    link.report["success"] = True
    link.save()


def recover(
    link,
    image,
    programs,
    address=APP_BASE,
    vectors_last=True,
    release=True,
    boot=False,
):
    """Leave the temple held on any error. Never replay RUN after uncertainty.

    With boot, select the verified image at address for this boot only.
    """
    if boot:
        if not release:
            raise ValueError("boot selection requires releasing boot")
        check_boot_address(address)
        check_boot_vectors(address, image)
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
        if boot:
            link.report.update(boot_address=address, boot_selection="none")
            recovery.select_boot(address, link.report)
            link.save()
        if release:
            link.continue_boot()
    link.report["success"] = True
    link.save()
