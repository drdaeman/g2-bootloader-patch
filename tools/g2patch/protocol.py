# SPDX-License-Identifier: MIT
"""Sequential, non-retrying LOAD/RUN/BOOT protocol for a held bootloader.

One outstanding block, ordered channel, no reconnect/resume after ambiguity.
The authenticated hold and plain continue exchange is in handshake.py.
"""

import struct
import zlib

LOAD, DATA, RUN, OUTPUT_ACK, INPUT_DATA, BOOT = 1, 2, 3, 4, 5, 6
ACK, OUTPUT, RESULT, READY, ERROR, INPUT = 0, 1, 2, 3, 4, 5
UNAVAILABLE, BAD_REQUEST, BAD_CRC, ABORTED, IO_ERROR, BAD_TARGET = 1, 2, 3, 4, 5, 6


def request(operation, payload=b""):
    if len(payload) > 22:
        raise ValueError("request payload exceeds 22 bytes")
    body = (
        bytes((0x7E, 0, 1, 27))
        + b"RQST"
        + bytes((operation,))
        + payload.ljust(22, b"\0")
    )
    return body + bytes(((32 + 0x7D + sum(body)) & 255,))


def reply(kind, status=0, data=b""):
    if len(data) > 16:
        raise ValueError("reply payload exceeds 16 bytes")
    body = (
        bytes((0, 1, 3, 23))
        + b"RESP"
        + bytes((kind, status))
        + data.ljust(16, b"\0")
        + b"\0"
    )
    return bytes((0x5A, 0xA5, 255, 27)) + body + bytes(((25 + sum(body)) & 255,))


def decode_reply(frame):
    if (
        len(frame) != 32
        or frame[:12] != bytes((0x5A, 0xA5, 255, 27, 0, 1, 3, 23)) + b"RESP"
    ):
        raise ValueError("invalid minimal reply framing")
    if frame[-1] != ((25 + sum(frame[4:-1])) & 255):
        raise ValueError("reply checksum failed")
    kind, status = frame[12:14]
    if kind > INPUT or (kind in (OUTPUT, INPUT) and not 1 <= status <= 16):
        raise ValueError("invalid reply kind or count")
    if kind in (ACK, READY) and status:
        raise ValueError("invalid acknowledgement status")
    return kind, status, frame[14 : 14 + status] if kind == OUTPUT else frame[14:30]


class RemoteError(RuntimeError):
    def __init__(self, status, result=None):
        self.status, self.result = status, result
        super().__init__(f"bootloader error {status}, program result {result}")


class Client:
    def __init__(self, exchange):
        self.exchange = exchange
        self.failed = False

    def _exchange(self, packet):
        if self.failed:
            raise RuntimeError(
                "session failed; use CONTINUE and a fresh boot handshake"
            )
        try:
            kind, status, data = decode_reply(self.exchange(packet))
            if kind == ERROR:
                raise RemoteError(status)
            if kind == RESULT and status:
                raise RemoteError(status, struct.unpack_from("<I", data)[0])
            return kind, status, data
        except BaseException:
            self.failed = True
            raise

    def _expect(self, packet, expected):
        kind, _status, _data = self._exchange(packet)
        if kind != expected:
            self.failed = True
            raise ValueError(f"expected reply {expected}, got {kind}")

    def upload(self, code, entry=0, arg0=0, arg1=0):
        if (
            not 2 <= len(code) <= 512
            or (len(code) | entry) & 1
            or not 0 <= entry < len(code)
        ):
            raise ValueError(
                "expected even 2..512 code bytes and aligned entry inside code"
            )
        self._expect(
            request(
                LOAD,
                struct.pack("<HHIII", len(code), entry, arg0, arg1, zlib.crc32(code)),
            ),
            ACK,
        )
        for offset in range(0, len(code), 16):
            chunk = code[offset : offset + 16]
            self._expect(
                request(DATA, bytes((len(chunk),)) + chunk),
                READY if offset + len(chunk) == len(code) else ACK,
            )

    def select_boot(self, address):
        """Select a vector table for one boot after CONTINUE; 0 clears it.

        Bootloaders without BOOT reply BAD_REQUEST; invalid targets BAD_TARGET.
        """
        if not 0 <= address <= 0xFFFFFFFF:
            raise ValueError("boot address must fit uint32")
        self._expect(request(BOOT, struct.pack("<I", address)), ACK)

    def execute(self, callback=None, source=None):
        output = bytearray()
        try:
            kind, _status, data = self._exchange(request(RUN))
            while kind in (OUTPUT, INPUT):
                if kind == OUTPUT:
                    output.extend(data)
                    if callback:
                        callback(data)
                    packet = request(OUTPUT_ACK)
                else:
                    chunk = source(_status) if source else b""
                    if (
                        not isinstance(chunk, (bytes, bytearray, memoryview))
                        or len(chunk) > _status
                    ):
                        raise ValueError(
                            "input source exceeded the requested chunk size"
                        )
                    chunk = bytes(chunk)
                    packet = request(
                        INPUT_DATA,
                        struct.pack("<B16sI", len(chunk), chunk, zlib.crc32(chunk)),
                    )
                kind, _status, data = self._exchange(packet)
            if kind != RESULT:
                raise ValueError("RUN did not produce a result")
            return struct.unpack_from("<I", data)[0], bytes(output)
        except BaseException:
            self.failed = True
            raise
