#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Reset/claim one temple, run one PIC binary through case USB, then CONTINUE.

Requires the patched bootloader. The ordinary case MCU firmware is unchanged.
"""

import argparse
from contextlib import ExitStack
from pathlib import Path


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("program", type=Path)
    p.add_argument("--port", required=True)
    p.add_argument("--side", choices=("left", "right"), default="right")
    p.add_argument(
        "--input",
        type=Path,
        help="file supplied to the program through recv (RAM API 2)",
    )
    p.add_argument("--entry", type=lambda x: int(x, 0), default=0)
    p.add_argument("--arg0", type=lambda x: int(x, 0), default=0)
    p.add_argument("--arg1", type=lambda x: int(x, 0), default=0)
    p.add_argument(
        "--output", type=Path, help="new audit directory; includes callback.bin"
    )
    a = p.parse_args()
    code = a.program.read_bytes()
    if (
        not 2 <= len(code) <= 512
        or (len(code) | a.entry) & 1
        or not 0 <= a.entry < len(code)
    ):
        p.error("expected even 2..512-byte code and an aligned entry inside it")
    if any(not 0 <= n <= 0xFFFFFFFF for n in (a.arg0, a.arg1)):
        p.error("arguments must fit uint32")
    from g2patch.link import run

    with ExitStack() as files:
        source = files.enter_context(a.input.open("rb")).read if a.input else None
        result, data, _out = run(
            a.port,
            code,
            a.entry,
            a.arg0,
            a.arg1,
            output=a.output,
            side=a.side,
            source=source,
        )
    print(f"Result: {result:#010x}; callback: {data.hex()}; boot continued")


if __name__ == "__main__":
    main()
