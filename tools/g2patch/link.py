# SPDX-License-Identifier: MIT
"""Selected-temple case-USB path; one SRAM instance per held session."""

import hashlib
import json
import struct
import time
from datetime import datetime, timezone
from pathlib import Path

from .case_rom import (
    go_sram,
    open_rom_loader,
    read_exact,
    read_memory,
    require_expected_identity,
    restore_application,
    write_sram,
)
from .handshake import check_okay, cont, decode_hello, hold, released
from .protocol import Client, decode_reply

ROOT = Path(__file__).resolve().parents[2]


def load_case_image():
    image = (ROOT / "build/case.bin").read_bytes()
    manifest = json.loads((ROOT / "build/case.json").read_text())
    pins = json.loads((Path(__file__).with_name("data") / "case.json").read_text())
    if hashlib.sha256(image).hexdigest() != manifest["sha256"] or len(image) >= 0x19F0:
        raise ValueError("case build identity/bounds mismatch; run make")
    return image, manifest, pins


class CaseLink:
    def __init__(self, port, output, side="right", stream_transactions=False):
        if side not in ("left", "right"):
            raise ValueError("expected left or right temple")
        self.side = side
        self.route = {"left": 0, "right": 1}[side]
        self.device = port
        self.out = Path(output)
        self.out.mkdir(parents=True, exist_ok=False)
        self.stream_transactions = stream_transactions
        self.port = None
        self.touched = self.ready = False
        self.report = {
            "port": port,
            "side": side,
            "transactions": [],
            "success": False,
            "case_flash_writes": False,
        }

    def record_transaction(self, event):
        if self.stream_transactions:
            self.report["transaction_log"] = "transactions.jsonl"
            with (self.out / "transactions.jsonl").open("a") as file:
                file.write(json.dumps(event) + "\n")
        else:
            self.save()

    def save(self):
        (self.out / "result.json").write_text(json.dumps(self.report, indent=2) + "\n")

    def __enter__(self):
        try:
            image, manifest, pins = load_case_image()
            self.report["case_sha256"] = manifest["sha256"]
            self.touched = True
            self.port = open_rom_loader(self.device)
            require_expected_identity(self.port)
            for check in pins["checks"]:
                observed = b"".join(
                    read_memory(
                        self.port,
                        check["address"] + offset,
                        min(256, check["length"] - offset),
                    )
                    for offset in range(0, check["length"], 256)
                )
                if hashlib.sha256(observed).hexdigest() != check["sha256"]:
                    raise ValueError(
                        f"unsupported case firmware at {check['address']:#x}"
                    )
            regions = [(0x20011A00, bytes(160)), (0x20011B00, bytes(8))]
            regions.extend(
                (0x20010000 + i, image[i : i + 256]) for i in range(0, len(image), 256)
            )
            for address, data in regions:
                write_sram(self.port, address, data)
                if read_memory(self.port, address, len(data)) != data:
                    raise ValueError("case SRAM readback mismatch")
            go_sram(self.port)
            if read_exact(self.port, 18, "case banner") != b"G2_POGO_BRIDGE_V1\n":
                raise ValueError("case banner mismatch")
            header = bytearray(b"G2RQ" + bytes((1, 2, self.route, 31, 0, 0)))
            header[9] = sum(header[:9]) & 255
            self.port.write(header[:5])
            self.port.flush()
            time.sleep(0.005)
            self.port.write(header[5:])
            self.port.flush()
            self.port.timeout = 60
            self.report["uart_registers"] = list(
                struct.unpack("<4I", read_exact(self.port, 16, "UART registers"))
            )
            if read_exact(self.port, 11, "arm marker") != b"G2U2_ARMED\n":
                raise ValueError("arm marker mismatch")
            beacon = read_exact(self.port, 21, "boot beacon")
            if read_exact(self.port, 12, "relay ready") != b"G2RAM_READY\n":
                raise ValueError("relay failed to arm")
            self.ready = True
            self.claim(beacon)
            self.save()
            return self
        except BaseException as error:
            self.report["error"] = repr(error)
            self.close()
            raise

    def claim(self, beacon):
        challenge = decode_hello(beacon)
        request = hold(challenge)
        # Allow the temple to switch from beacon TX to RX before HOLD.
        time.sleep(0.03)
        response = self.exchange(request)
        try:
            check_okay(response, challenge)
        except ValueError:
            # HOLD may have succeeded even if its acknowledgement is invalid.
            self.continue_boot()
            raise
        self.report.update(handshake=(beacon + request + response).hex())

    def exchange(self, frame):
        port = self.port
        if port is None:
            raise RuntimeError("case serial connection is not open")
        if len(frame) not in (0, 9, 25, 32):
            raise ValueError("unsupported frame length")
        packet = b"G2TX" + bytes((len(frame),)) + frame
        packet += bytes((sum(packet) & 255,))
        event = {"request": frame.hex()}
        if self.stream_transactions:
            count = self.report.get("transaction_count", 0) + 1
            self.report["transaction_count"] = count
            event["sequence"] = count
        else:
            self.report["transactions"].append(event)
        self.record_transaction(event)
        port.write(packet)
        port.flush()
        head = read_exact(port, 6, "relay response")
        if head[:4] != b"G2RX" or head[5] > 32:
            raise ValueError("invalid relay header")
        tail = read_exact(port, head[5] + 1, "temple response")
        event["reply"] = (head + tail).hex()
        self.record_transaction(event)
        if tail[-1] != (sum(head) + sum(tail[:-1])) & 255:
            raise ValueError("relay checksum mismatch")
        if head[4]:
            raise RuntimeError(
                f"case relay status {head[4]}; command outcome may be unknown"
            )
        return tail[:-1]

    def continue_boot(self):
        # A pending reply can precede an abort reply: CONTINUE during LOAD or
        # OUTPUT_ACK aborts that transaction before another CONTINUE releases it.
        # Advance only on valid replies, never retry a failed transport or RUN.
        for _ in range(3):
            actual = self.exchange(cont())
            if actual == released():
                self.report["continued"] = True
                self.save()
                return
            decode_reply(actual)
        raise RuntimeError("boot release unconfirmed after three CONTINUE exchanges")

    def close(self):
        try:
            if self.ready:
                port = self.port
                if port is None:
                    raise RuntimeError("case relay has no serial connection")
                port.write(b"G2EX")
                port.flush()
                head = read_exact(port, 12, "restoration header")
                if head[:5] != b"G2RS\1" or head[9] > 64:
                    raise ValueError("invalid restoration response")
                tail = read_exact(port, head[9] + 1, "restoration tail")
                self.report["restoration_response"] = (head + tail).hex()
                if (
                    tail[-1] != (sum(head) + sum(tail[:-1])) & 255
                    or head[5:8] != bytes((2, self.route, 31))
                    or head[9]
                    or head[10]
                ):
                    raise ValueError("invalid restoration framing")
                self.report["bridge_exit_status"] = head[8]
                port.close()
                self.port = open_rom_loader(self.device)
                require_expected_identity(self.port)
                retained = read_memory(self.port, 0x20011A00, 160)
                proof = read_memory(self.port, 0x20011B00, 8)
                (self.out / "case-retained.bin").write_bytes(retained)
                words = struct.unpack_from("<14I", retained)
                if (
                    proof != bytes.fromhex("47425250dec0dec0")
                    or words[:5] != (0x47524247, 2, 2, self.route, 31)
                    or words[6:9] != (0x3FF,) * 3
                    or words[9] != 0x1FF
                    or words[13]
                    or retained[56:66] != retained[76:86]
                ):
                    raise ValueError("case route restoration not verified")
                self.report["route_restored"] = True
        except BaseException as error:
            self.report["cleanup_error"] = repr(error)
            raise
        finally:
            if self.port:
                self.port.close()
                self.port = None
            try:
                if self.touched:
                    self.report["case_version"] = restore_application(
                        self.device, expected_version="1.2.57"
                    )
            finally:
                self.save()

    def __exit__(self, kind, error, traceback):
        if error:
            self.report["error"] = repr(error)
        self.close()


def run(
    port,
    code,
    entry=0,
    arg0=0,
    arg1=0,
    callback=None,
    output=None,
    side="right",
    source=None,
):
    """One upload/RUN; explicit release even on failure. Never retry RUN."""
    out = (
        Path(output)
        if output
        else ROOT
        / "build/runs"
        / datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    )
    link = CaseLink(port, out, side)
    print(f"Audit: {out}")
    with link:
        try:
            client = Client(link.exchange)
            client.upload(code, entry, arg0, arg1)
            result, data = client.execute(callback, source=source)
            (out / "callback.bin").write_bytes(data)
            link.report.update(
                program_result=result,
                callback=data.hex(),
                code_sha256=hashlib.sha256(code).hexdigest(),
            )
        finally:
            link.continue_boot()
    link.report["success"] = True
    link.save()
    return result, data, out
