#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Program MRAM through a patched bootloader and USB case.

Accepts an EVENOTA bundle or a raw main image beginning with its vector table.
With --address, treats the input as raw bytes for that MRAM address; add --boot
to start that image once, instead of the stock application, after verification.
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
    check_boot_address,
    check_boot_vectors,
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
    parser.add_argument(
        "--boot",
        action="store_true",
        help="with --address: boot the written image once after verification",
    )
    args = parser.parse_args()
    raw = args.address is not None
    if args.boot and (not raw or args.hold):
        parser.error("--boot requires --address and cannot be combined with --hold")
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
    if args.boot:
        try:
            check_boot_address(address)
            check_boot_vectors(address, image)
        except ValueError as error:
            parser.error(str(error))
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
            boot=args.boot,
        )
    except BaseException:
        if link.report.get("image_verified"):
            print(
                "The image was written and verified, but boot selection or release "
                "did not complete; boot may still be held. Use tools/altboot.py "
                "for a new session."
            )
            raise
        print(
            "Recovery did not complete. No automatic CONTINUE or write retry. Keep the case connected; rerun recovery to start a new session."
        )
        raise
    print(
        "Image verified and case route restored. "
        + (
            "Boot remains held."
            if args.hold
            else f"Boot released to {address:#010x} for this boot only."
            if args.boot
            else "Boot released."
        )
    )


if __name__ == "__main__":
    main()
