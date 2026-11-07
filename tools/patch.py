#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Patch the fixed 2.3.2.14 bootloader; Make uses the artifact options below."""

import argparse
import json
import subprocess
from pathlib import Path

from g2patch import artifacts
from g2patch.auth import key_id
from g2patch.firmware import (
    APP_BASE,
    BASE,
    HOOKS,
    PAGE_BYTES,
    STOCK_BYTES,
    STOCK_SHA,
    extract_stock,
    sha,
    validate_image,
)

ROOT = Path(__file__).resolve().parents[1]


def load_hooks(build=ROOT / "build"):
    return {name: (build / f"{name}.bin").read_bytes() for name, _, _ in HOOKS}


def patch(stock, blob, hooks):
    if sha(stock[:STOCK_BYTES]) != STOCK_SHA:
        raise ValueError("stock bootloader identity mismatch")
    if set(hooks) != {name for name, _, _ in HOOKS}:
        raise ValueError("expected exactly the reviewed hooks")
    image = bytearray(stock[:STOCK_BYTES])
    for name, offset, call in HOOKS:
        if len(hooks[name]) != 4:
            raise ValueError(f"{name} must be one linked Thumb BL")
        if image[offset : offset + 4] != call:
            raise ValueError("stock call mismatch")
        image[offset : offset + 4] = hooks[name]
    image.extend(blob)
    image.extend(bytes(-len(image) % 4))
    raw_bytes = len(image)
    end = (raw_bytes + PAGE_BYTES - 1) & -PAGE_BYTES
    if end > APP_BASE - BASE:
        raise ValueError("patch overlaps main application")
    image.extend(stock[raw_bytes:end])
    image.extend(b"\xff" * (end - len(image)))
    validate_image(image)
    return bytes(image), raw_bytes


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("firmware", nargs="?", type=Path)
    p.add_argument("-o", "--output", type=Path)
    actions = p.add_mutually_exclusive_group()
    actions.add_argument(
        "--auth-key-header",
        action="store_true",
        help="prepare the build's handshake key",
    )
    actions.add_argument(
        "--describe",
        type=Path,
        metavar="ELF",
        help="write an artifact manifest (used by Make)",
    )
    actions.add_argument(
        "--prepare-case",
        action="store_true",
        help="prepare case assembly input (used by Make)",
    )
    p.add_argument("--base", type=lambda x: int(x, 0), default=0)
    p.add_argument(
        "--case-firmware",
        type=Path,
        help="reviewed raw case 1.2.57 image; read only, never bundled",
    )
    a = p.parse_args()
    if a.describe or a.prepare_case or a.auth_key_header:
        if a.firmware or not a.output:
            p.error(
                "artifact operations require -o and no firmware positional argument"
            )
        if a.auth_key_header:
            artifacts.write_auth_key(a.output)
        elif a.describe:
            artifacts.describe(a.describe, a.output, a.base)
        else:
            artifacts.prepare_case(a.output, a.case_firmware)
        return
    if not a.firmware:
        p.error("supply a vanilla firmware dump")
    output = a.output or ROOT / "build/bootloader.bin"
    if a.firmware.resolve() == output.resolve():
        p.error("input and output must differ")
    stock, offset = extract_stock(a.firmware.read_bytes())
    subprocess.run(["make", "-C", str(ROOT), "build/patch.bin"], check=True)
    image, raw_bytes = patch(
        stock, (ROOT / "build/patch.bin").read_bytes(), load_hooks()
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(image)
    receipt = {
        "stock_sha256": STOCK_SHA,
        "source_offset": offset,
        "base": BASE,
        "hooks": {name: BASE + offset for name, offset, _ in HOOKS},
        "raw_bytes": raw_bytes,
        "raw_sha256": sha(image[:raw_bytes]),
        "bytes": len(image),
        "sha256": sha(image),
        "auth_key_sha256": key_id(),
    }
    output.with_suffix(".json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(json.dumps(receipt, indent=2))


if __name__ == "__main__":
    main()
