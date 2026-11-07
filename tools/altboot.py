#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Boot an alternate main-application image once through the patched bootloader.

Resets and claims one temple, checks the vector table at ADDRESS and the stock
OTA flag, selects ADDRESS, then releases boot. The bootloader finishes as usual
and hands off to ADDRESS instead of 0x438000. The next boot starts the stock
application. The image must be linked to run at ADDRESS.

ADDRESS may be in MRAM [0x438000, 0x7FE000), for an image written earlier (see
tools/recover.py --address ... --boot), or in ITCM [0x1000, 0x40000) with
--load IMAGE, which loads IMAGE into ITCM in the same session. ITCM loses its
contents on power loss, so an ITCM test image leaves no persistent change.
"""

import argparse
from datetime import datetime, timezone
from pathlib import Path

from g2patch.link import CaseLink, load_case_image
from g2patch.recovery import (
    ITCM_END,
    boot_once,
    boot_ram,
    check_boot_address,
    check_boot_vectors,
    is_itcm,
    load_program,
)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("address", type=lambda value: int(value, 0))
    parser.add_argument("--port", required=True, help="USB case serial port")
    parser.add_argument("--side", choices=("left", "right"), required=True)
    parser.add_argument(
        "--load", type=Path, metavar="IMAGE", help="raw ITCM image to load first"
    )
    parser.add_argument("--output", type=Path, help="new audit directory")
    args = parser.parse_args()
    image = None
    try:
        check_boot_address(args.address)
        if is_itcm(args.address) != (args.load is not None):
            raise ValueError(
                "ITCM addresses require --load; MRAM images are written with "
                "tools/recover.py --address ADDRESS --boot"
            )
        if args.load:
            image = args.load.read_bytes()
            check_boot_vectors(args.address, image)
            if len(image) > ITCM_END - args.address:
                raise ValueError("image does not fit in ITCM at this address")
    except ValueError as error:
        parser.error(str(error))
    names = ("dump", "checksum", "ramload") if image else ("dump",)
    programs = {name: load_program(name) for name in names}
    load_case_image()
    out = args.output or Path(__file__).resolve().parents[
        1
    ] / "build/runs" / datetime.now(timezone.utc).strftime("altboot-%Y%m%dT%H%M%S.%fZ")
    print(f"Audit: {out}", flush=True)
    link = CaseLink(args.port, out, args.side, stream_transactions=image is not None)
    try:
        if image is None:
            boot_once(link, args.address, programs)
        else:
            boot_ram(link, args.address, image, programs)
    except BaseException:
        if link.report.get("boot_selection") == "sent":
            print(
                "The BOOT reply was lost; the temple may still start the alternate image."
            )
        elif link.report.get("continued"):
            print(
                "No alternate image selected. Boot released to the stock application."
            )
        raise
    print(f"Selected {args.address:#010x} for this boot only. Boot released.")


if __name__ == "__main__":
    main()
