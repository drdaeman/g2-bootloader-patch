# SPDX-License-Identifier: MIT
"""Stock G2 BLE authentication and single-component OTA; no private endpoints."""

import asyncio
import re
import sys
import time

from crc import Calculator, Crc16

DATA = ("00002760-08c2-11e1-9073-0e8ac72e0001", "00002760-08c2-11e1-9073-0e8ac72e0002")
CTRL = ("00002760-08c2-11e1-9073-0e8ac72e5401", "00002760-08c2-11e1-9073-0e8ac72e5402")
_CRC16 = Calculator(Crc16.IBM_3740.value, optimized=True)


def crc16(data):
    return _CRC16.checksum(data).to_bytes(2, "little")


def frames(sid, payload, sequence):
    body = payload + crc16(payload)
    count = max(1, (len(body) + 231) // 232)
    return [
        bytes(
            (0xAA, 0x21, sequence, len(body[i : i + 232]), count, i // 232 + 1, sid, 0)
        )
        + body[i : i + 232]
        for i in range(0, len(body), 232)
    ]


def unwrap(frame):
    if (
        len(frame) < 10
        or frame[:2] != b"\xaa\x12"
        or frame[3] != len(frame) - 8
        or crc16(frame[8:-2]) != frame[-2:]
    ):
        return None, b""
    return frame[6], frame[8:-2]


class StockOta:
    def __init__(self, address: str, adapter: str | None = None, pair: bool = False):
        self.address = address
        self.adapter = adapter
        self.pair = pair
        self.sequence = 0
        self.notes = asyncio.Queue()
        self.client = None
        self.end_status = None
        self.side = None

    async def __aenter__(self):
        from bleak import BleakClient, BleakScanner

        adapter = self.adapter if sys.platform.startswith("linux") else None
        device = await BleakScanner.find_device_by_address(
            self.address, timeout=20, bluez={"adapter": adapter} if adapter else {}
        )
        if device is None:
            raise RuntimeError(
                "temple not advertising; release other clients and check the address"
            )
        match = re.search(r"_(L|R)_[0-9a-f]{6}$", device.name or "", re.IGNORECASE)
        self.side = {"L": "left", "R": "right"}.get(match[1].upper()) if match else None
        self.client = BleakClient(
            device,
            pair=self.pair,
            timeout=30,
            bluez={"adapter": adapter} if adapter else {},
        )
        try:
            await self.client.connect()
            if sys.platform.startswith("linux"):
                from bleak.backends.bluezdbus.client import BleakClientBlueZDBus

                backend = self.client._backend
                assert isinstance(backend, BleakClientBlueZDBus)
                await backend._acquire_mtu()
            if self.client.mtu_size < 243:
                raise RuntimeError("stock OTA needs negotiated MTU >=243")
            for ch in (CTRL[1], DATA[1]):
                await self.client.start_notify(
                    ch,
                    lambda sender, data, ch=ch: self.notes.put_nowait(
                        (ch, bytes(data))
                    ),
                )
            await asyncio.sleep(2.5)
            await self.authenticate()
            return self
        except BaseException:
            await self.client.disconnect()
            raise

    async def __aexit__(self, *args):
        if self.client:
            await self.client.disconnect()

    def next_sequence(self):
        self.sequence = (self.sequence + 1) & 255
        return self.sequence

    async def send(self, characteristic, packets):
        client = self.client
        if client is None:
            raise RuntimeError("BLE connection is not open")
        for packet in packets:
            await client.write_gatt_char(characteristic, packet, response=False)

    def drain(self):
        while not self.notes.empty():
            self.notes.get_nowait()

    async def wait(self, channel, predicate, timeout):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            ch, frame = await asyncio.wait_for(
                self.notes.get(), deadline - time.monotonic()
            )
            sid, payload = unwrap(frame)
            if ch == channel and predicate(sid, payload):
                return payload
        raise TimeoutError("stock BLE reply timeout; do not replay the write")

    async def authenticate(self):
        magic = self.next_sequence()
        # Protobuf varint, including when the post-OTA sequence exceeds 127.
        encoded = (
            bytes((magic,)) if magic < 128 else bytes(((magic & 127) | 128, magic >> 7))
        )
        prefix = b"\x08\x04\x10" + encoded
        request = prefix + b"\x1a\x04\x08\x01\x10\x04"
        await self.send(CTRL[0], frames(0x80, request, magic))
        result = await self.wait(
            CTRL[1], lambda sid, p: sid == 0x80 and p.startswith(prefix), 10
        )
        if result != prefix + b"\x1a\0":
            raise RuntimeError("stock authentication rejected")

    async def command(self, operation, data=b"", timeout=10):
        self.drain()
        await self.send(
            DATA[0], frames(0xC0, bytes((operation,)) + data, self.next_sequence())
        )
        reply = await self.wait(
            DATA[1], lambda sid, p: len(p) >= 2 and p[0] == operation, timeout
        )
        return reply[1]

    async def install(self, header, payload):
        if len(header) != 128 or not payload or len(payload) % 4096:
            raise ValueError("expected a page-aligned component")
        if await self.command(0):
            raise RuntimeError("stock BEGIN rejected")
        if await self.command(1, header):
            raise RuntimeError("stock FILE_CHECK rejected")
        for offset in range(0, len(payload), 4096):
            self.drain()
            sequence = self.next_sequence()
            packets = frames(0xC0, b"\x02", sequence) + frames(
                0xC1, payload[offset : offset + 4096], sequence
            )
            await self.send(DATA[0], packets)
            ack = await self.wait(DATA[1], lambda sid, p: len(p) >= 2 and p[0] == 2, 4)
            if ack[1]:
                raise RuntimeError(
                    f"block rejected: status {ack[1]}; no block replay performed"
                )
            print(f"{offset + 4096}/{len(payload)} bytes", flush=True)
        status = await self.command(3, timeout=30)
        if status not in (0, 8, 9):
            raise RuntimeError(f"END rejected: {status}")
        self.end_status = status
        # END is acknowledged before the stock synchronous MRAM copy. A fresh
        # stock request is a liveness check, not an image-readback assertion.
        await self.authenticate()
        return status
