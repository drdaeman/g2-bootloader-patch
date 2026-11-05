# SPDX-License-Identifier: MIT
"""Case-shaped handshake frames. Only HELO carries the initial challenge."""

import hmac
import struct

from .auth import tag

VERSION = 1


def _announcement(marker, payload=b""):
    # Stock case command 0 is a no-op, not a forwarding command.
    body = bytes((0, 1, 3, 4 + len(payload))) + marker + payload
    return (
        b"\x5a\xa5\xff"
        + bytes((len(body),))
        + body
        + bytes(((len(body) - 2 + sum(body)) & 255,))
    )


def _request(marker, payload=b""):
    body = bytes((0x7E, 0, 1, 4 + len(payload))) + marker + payload
    return body + bytes(((len(body) + 1 + 0x7D + sum(body)) & 255,))


def hello(challenge):
    return _announcement(b"HELO", struct.pack("<II", VERSION, challenge))


def hold(challenge):
    return _request(b"HOLD", tag(b"HOLD", VERSION, challenge))


def okay(challenge):
    return _announcement(b"OKAY", tag(b"OKAY", VERSION, challenge))


def cont():
    return _request(b"CONT")


def released():
    return _announcement(b"RLSD")


def decode_hello(frame):
    if len(frame) != 21:
        raise ValueError("unexpected HELO length")
    version, challenge = struct.unpack_from("<II", frame, 12)
    if version != VERSION:
        raise ValueError("unsupported protocol version")
    if frame != hello(challenge):
        raise ValueError("invalid HELO framing or checksum")
    return challenge


def check_okay(frame, challenge):
    if not hmac.compare_digest(frame, okay(challenge)):
        raise ValueError("invalid OKAY framing, checksum or HMAC")
