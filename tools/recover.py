#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Program MRAM through a patched bootloader and USB case.

Accepts an EVENOTA bundle or a raw main image beginning with its vector table.
With --address, treats the input as raw bytes for that MRAM address.
Without --write, validates the local files and prints the plan; no device access.
"""

import argparse
from datetime import datetime, timezone
from pathlib import Path

from g2patch import firmware
from g2patch.link import CaseLink, load_case_image
from g2patch.recovery import (
    APP_BASE,
    APP_END,
    application,
    load_program,
    memory_range,
    recover,
)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image", type=Path)

    parser.add_argument("--side", choices=("left", "right"))
    parser.add_argument(
        "--write",
        metavar="PORT",
        help="write the selected temple's MRAM through this USB case serial port",
    )
    parser.add_argument(
        "--output", type=Path, help="new directory for backup and audit"
    )
    parser.add_argument(
        "--address",
        type=lambda value: int(value, 0),
        help="raw-file destination in MRAM; omit for application/bundle recovery",
    )
    parser.add_argument(
        "--i-verified-the-addresses",
        action="store_true",
        help="acknowledge a write outside the main application region",
    )
    parser.add_argument(
        "--hold",
        action="store_true",
        help="leave boot held after successful verification",
    )
    args = parser.parse_args()
    raw = args.address is not None
    address = args.address if raw else APP_BASE
    image = args.image.read_bytes()
    if raw:
        base, size = memory_range(address, len(image))
        if (
            args.write
            and not APP_BASE <= base < base + size <= APP_END
            and not args.i_verified_the_addresses
        ):
            parser.error(
                "writes outside the main application region require --i-verified-the-addresses"
            )
    else:
        image = application(image)
    programs = {name: load_program(name) for name in ("dump", "checksum", "recover")}
    load_case_image()
    print(
        f"MRAM image: {len(image)} bytes at {address:#010x}; SHA256 {firmware.sha(image)}"
    )
    if not args.write:
        print(
            "Local validation passed. No device accessed. Add --write PORT --side SIDE to recover."
        )
        return
    if not args.side:
        parser.error("--write requires --side")
    out = args.output or Path(__file__).resolve().parents[
        1
    ] / "build/runs" / datetime.now(timezone.utc).strftime("recover-%Y%m%dT%H%M%S.%fZ")
    print(f"Backup and audit: {out}", flush=True)
    link = CaseLink(args.write, out, args.side, stream_transactions=True)
    try:
        recover(
            link,
            image,
            programs,
            address=address,
            vectors_last=not raw,
            release=not args.hold,
        )
    except BaseException:
        print(
            "Recovery did not complete. No automatic CONTINUE or write retry. Keep the case connected; rerun recovery to start a new session."
        )
        raise
    print(
        "Image verified and case route restored. "
        + ("Boot remains held." if args.hold else "Boot released.")
    )


if __name__ == "__main__":
    main()
