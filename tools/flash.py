#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Flash only the bootloader using the STOCK app's BLE OTA service.

No Faceclaw patches or diagnostic key are needed. Close other glasses clients.
This cannot recover a dead stock app. --verify-port independently checks the
installed image through the new bootloader and charging-case USB serial.
"""

import argparse
import asyncio
import json
import zlib
from pathlib import Path

from g2patch.ble_ota import StockOta
from g2patch.firmware import BASE, component, sha

ROOT = Path(__file__).resolve().parents[1]


def verification_inputs():
    from g2patch.link import load_case_image

    code = (ROOT / "build/checksum.bin").read_bytes()
    if not 2 <= len(code) <= 512 or len(code) & 1:
        raise ValueError("invalid checksum payload; run make")
    load_case_image()
    return code


async def transfer(args, header, payload):
    if args.verify_port:
        verification_inputs()
    device = StockOta(args.address, args.adapter, args.pair)
    try:
        async with device:
            if getattr(args, "side", None) and device.side != args.side:
                raise ValueError(
                    "advertised temple does not match --side; no OTA started"
                )
            if args.verify_port and device.side not in ("left", "right"):
                raise ValueError(
                    "--verify-port needs an identifiable advertised temple; no OTA started"
                )
            args.side = device.side
            status = await device.install(header, payload)
    except Exception:
        if device.end_status is None:
            raise
        # Only read-only connection/authentication is retried after END. The
        # stock copier can stall the first request; never repeat the transfer.
        print("END accepted; reconnecting for stock authentication only.", flush=True)
        async with StockOta(args.address, args.adapter, args.pair):
            pass
        status = device.end_status
    print(
        f"Stock OTA END status {status}; main app responds. No automatic reset or write retry."
    )
    return status


def verify(port, payload, side="right"):
    from datetime import datetime, timezone

    from g2patch.link import CaseLink
    from g2patch.protocol import Client

    out = (
        ROOT
        / "build/runs"
        / datetime.now(timezone.utc).strftime("verify-%Y%m%dT%H%M%S.%fZ")
    )
    code = verification_inputs()
    expected = zlib.crc32(payload)
    link = CaseLink(port, out, side)
    with link:
        try:
            results = []
            client = Client(link.exchange)
            for _ in range(2):
                client.upload(code, arg0=BASE, arg1=len(payload))
                actual, data = client.execute()
                results.append(actual)
                if data or actual != expected:
                    raise RuntimeError("installed bootloader CRC32 differs from input")
            link.report.update(
                image_sha256=sha(payload),
                image_bytes=len(payload),
                readback_crc32=results,
            )
        finally:
            link.continue_boot()
    link.report["success"] = True
    link.save()
    print(
        f"Case {side}-temple bytes matched CRC32 {expected:08x} on two independent reads; boot continued. Audit: {out}"
    )


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("bootloader", type=Path)
    p.add_argument(
        "--address",
        required=True,
        help="temple BLE address/UUID, not the case serial port",
    )
    p.add_argument("--adapter", help="Linux BlueZ controller, e.g. hci0")
    p.add_argument(
        "--side",
        choices=("left", "right"),
        help="require this advertised side before starting OTA",
    )
    p.add_argument(
        "--pair",
        action="store_true",
        help="ask the OS to bond; use an OS pairing agent if required",
    )
    p.add_argument(
        "--verify-port",
        help="USB case containing this same temple; both temples must be seated",
    )
    args = p.parse_args()
    header, payload = component(args.bootloader.read_bytes())
    print(f"Only ota/s200_bootloader.bin: {len(payload)} bytes, SHA256 {sha(payload)}")
    from datetime import datetime, timezone

    out = (
        ROOT
        / "build/runs"
        / datetime.now(timezone.utc).strftime("flash-%Y%m%dT%H%M%S.%fZ")
    )
    out.mkdir(parents=True, mode=0o700)
    report = {
        "address": args.address,
        "bytes": len(payload),
        "sha256": sha(payload),
        "filename": "ota/s200_bootloader.bin",
        "side": args.side,
        "verify_port": args.verify_port,
        "verified": False,
    }
    try:
        report["end_status"] = asyncio.run(transfer(args, header, payload))
        report["side"] = args.side
        if args.verify_port:
            verify(args.verify_port, payload, args.side)
            report["verified"] = True
        else:
            print(
                "Installation contents remain unverified. Add --verify-port CASE_PORT for post-reset readback CRCs."
            )
    except BaseException as error:
        report["error"] = repr(error)
        raise
    finally:
        (out / "result.json").write_text(json.dumps(report, indent=2) + "\n")
        print(f"Audit: {out}")


if __name__ == "__main__":
    main()
