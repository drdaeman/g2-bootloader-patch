# SPDX-License-Identifier: MIT
"""Hash/symbol reports and assembly inputs for the fixed case SRAM layout."""

import hashlib
import json
import os
import subprocess
import tempfile
from pathlib import Path

from .auth import key_block, key_id

ROOT = Path(__file__).resolve().parents[2]
DATA = Path(__file__).with_name("data")


def write_auth_key(output):
    output = Path(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    values = ",".join(f"0x{byte:02x}" for byte in key_block())
    text = (
        "/* Generated from G2_BOOT_KEY. Do not commit. */\n#define AUTH_KEY_PAD {"
        + values
        + "}\n"
    )
    if output.exists() and output.read_text() == text:
        output.chmod(0o600)
        return
    with tempfile.NamedTemporaryFile(mode="w", dir=output.parent, delete=False) as file:
        file.write(text)
        temporary = Path(file.name)
    temporary.replace(output)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def describe(elf, output, base):
    output = Path(output)
    binary = output.with_suffix(".bin")
    blob = binary.read_bytes()
    table = subprocess.check_output(
        [
            os.environ.get("NM", "llvm-nm"),
            "--defined-only",
            "--print-size",
            "--format=posix",
            str(elf),
        ],
        text=True,
    )
    functions = {}
    for line in table.splitlines():
        columns = line.split()
        if len(columns) >= 3 and columns[1] in ("t", "T"):
            address = int(columns[2], 16) & ~1
            if base <= address < base + len(blob):
                functions[columns[0]] = {
                    "offset": address - base,
                    "bytes": int(columns[3], 16) if len(columns) > 3 else 0,
                }
    result = {
        "bytes": len(blob),
        "sha256": sha(blob),
        "functions": functions,
        "base": base,
    }
    if base == 0x434900:
        result["auth_key_sha256"] = key_id()
    output.write_text(json.dumps(result, indent=2) + "\n")
    print(f"{binary}: {len(blob)} bytes, SHA256 {result['sha256']}")


def prepare_case(output, firmware=None):
    """Extract privately supplied reset code; let the assembler/linker relocate it."""
    output = Path(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    meta = json.loads((DATA / "case.json").read_text())
    bridge = DATA / "case_bridge.bin"
    wave = ROOT / "build/reset_waveform.bin"
    if firmware:
        data = Path(firmware).read_bytes()
        if sha(data) != meta["source_case_firmware_sha256"]:
            raise ValueError("expected the reviewed raw case firmware 1.2.57")
        wave.write_bytes(data[0xB678:0xB7EC])
    if not wave.exists():
        raise ValueError(
            "supply CASE_FIRMWARE=/path/to/firmware_box.raw.bin; vendor code is not bundled"
        )
    raw = wave.read_bytes()
    if (
        sha(raw) != meta["waveform_sha256"]
        or sha(bridge.read_bytes()) != meta["base_sha256"]
    ):
        raise ValueError("case input identity mismatch")
    # Fixed spans come from the reviewed binary; branch destinations are
    # architectural addresses. No ELF parsing or instruction rewriting here.
    lines = [
        ".syntax unified",
        ".thumb",
        '.section .bridge,"ax",%progbits',
        f".incbin {json.dumps(str(bridge))},0,368",
        "bl exchange",
        ".short 0xe012",
        f".incbin {json.dumps(str(bridge))},374,1346",
        '.section .waveform,"ax",%progbits',
    ]
    previous = 0
    calls = 0
    for at in range(0, len(raw) - 3, 2):
        a = int.from_bytes(raw[at : at + 2], "little")
        b = int.from_bytes(raw[at + 2 : at + 4], "little")
        if a & 0xF800 != 0xF000 or b & 0xD000 != 0xD000:
            continue
        sign = (a >> 10) & 1
        displacement = (
            (sign << 24)
            | ((1 ^ ((b >> 13) & 1) ^ sign) << 23)
            | ((1 ^ ((b >> 11) & 1) ^ sign) << 22)
            | ((a & 1023) << 12)
            | ((b & 2047) << 1)
        )
        if sign:
            displacement -= 1 << 25
        target = 0x0800B678 + at + 4 + displacement
        name = {
            0x08004E9E: "reset_gpio",
            0x0800A7A2: "reset_spin",
            0x0800A7B0: "case_reset_delay_ms",
        }.get(target)
        if name is None:
            raise ValueError(f"unexpected reset call target {target:#x}")
        if at > previous:
            lines.append(f".incbin {json.dumps(str(wave))},{previous},{at - previous}")
        lines.append("bl " + name)
        previous = at + 4
        calls += 1
    if calls != 39:
        raise ValueError("reset call coverage changed")
    if previous < len(raw):
        lines.append(
            f".incbin {json.dumps(str(wave))},{previous},{len(raw) - previous}"
        )
    for name, address in (("reset_gpio", 0x08004E9F), ("reset_spin", 0x0800A7A3)):
        lines += [
            ".balign 4",
            ".thumb_func",
            name + ":",
            "ldr r3,[pc,#0]",
            "bx r3",
            f".word {address}",
        ]
    output.write_text("\n".join(lines) + "\n")
