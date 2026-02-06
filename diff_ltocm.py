#!/usr/bin/env python3
"""
Diff two LTO-CM dumps with colored hex output and region labels.

Compares two LTO-CM dump files byte-by-byte and prints differing regions with
colored hex (and ASCII). Uses ECMA-319 Annex D layout: 32-byte blocks; known
regions (Block 0, Cartridge Manufacturer, Init Data, etc.) are labeled.

Usage:
  diff_ltocm.py <file_a> <file_b> [-c N] [--no-color]

Options:
  -c, --context N   Bytes of context around each diff (default: full block).
  --no-color        Disable ANSI colors (e.g. for pipes).
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

# ANSI colors
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
BLUE = "\033[34m"
MAGENTA = "\033[35m"
CYAN = "\033[36m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"

BLOCK_SIZE = 32
# Known regions (start_byte, end_byte, label) — end exclusive
REGIONS = [
    (0, 32, "Block 0 (LTO CM MFG)"),
    (32, 64, "Block 1 (Write-inhibit, Protected PT)"),
    (64, 128, "Cartridge Manufacturer (64)"),
    (128, 192, "Media Manufacturer (128)"),
    (192, 256, "Init Data (192) / Tape Write Pass"),
    (256, 320, "Tape Directory / EOD"),
    (320, 352, "Cartridge Status (0x105)"),
    (352, 416, "Usage 0 (0x108)"),
    (416, 480, "Usage 1 (0x109)"),
    (480, 544, "Usage 2 (0x10A)"),
    (544, 608, "Usage 3 (0x10B)"),
]


def region_at(offset: int) -> str | None:
    for start, end, label in REGIONS:
        if start <= offset < end:
            return label
    return None


def hex_line(data: bytes, base: int, width: int = 16) -> str:
    parts = []
    ascii_parts = []
    for i in range(width):
        if base + i < len(data):
            b = data[base + i]
            parts.append(f"{b:02x}")
            ascii_parts.append(chr(b) if 32 <= b < 127 else ".")
        else:
            parts.append("  ")
            ascii_parts.append(" ")
    return " ".join(parts) + "  |" + "".join(ascii_parts) + "|"


def diff_bytes(a: bytes, b: bytes) -> list[tuple[int, int, int]]:
    """Return list of (offset, byte_a, byte_b) for differing bytes."""
    out = []
    n = max(len(a), len(b))
    for i in range(n):
        ba = a[i] if i < len(a) else None
        bb = b[i] if i < len(b) else None
        if ba is None or bb is None or ba != bb:
            out.append((i, ba if ba is not None else -1, bb if bb is not None else -1))
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description="Diff two LTO-CM dumps with colored hex")
    ap.add_argument("file_a", type=Path, help="First dump (e.g. FA8XBTd068_original.bin)")
    ap.add_argument("file_b", type=Path, help="Second dump (e.g. 2091207173_original.bin)")
    ap.add_argument("-c", "--context", type=int, default=0,
                    help="Bytes of context around each diff (default: full block)")
    ap.add_argument("--no-color", action="store_true", help="Disable colors")
    args = ap.parse_args()

    if args.no_color:
        global RED, GREEN, YELLOW, BLUE, MAGENTA, CYAN, BOLD, DIM, RESET
        RED = GREEN = YELLOW = BLUE = MAGENTA = CYAN = BOLD = DIM = RESET = ""

    data_a = args.file_a.read_bytes()
    data_b = args.file_b.read_bytes()

    diffs = diff_bytes(data_a, data_b)
    if not diffs:
        print(f"{GREEN}Aucune différence entre les deux dumps.{RESET}")
        return 0

    # Build set of offsets that differ
    diff_offsets = {o for o, _, _ in diffs}
    blocks_with_diffs = sorted({o // BLOCK_SIZE for o, _, _ in diffs})
    n = max(len(data_a), len(data_b))

    # Show summary
    print(f"{BOLD}Diff LTO-CM: {args.file_a.name} vs {args.file_b.name}{RESET}")
    print(f"  Taille: {len(data_a)} vs {len(data_b)} octets | {len(diffs)} octet(s) différent(s)\n")

    for block in blocks_with_diffs:
        block_start = block * BLOCK_SIZE
        end = min(block_start + BLOCK_SIZE, n)
        label = region_at(block_start)
        if label:
            print(f"{CYAN}{DIM}# {label} (bloc {block}, offset {block_start}-{end - 1}){RESET}")

        for base in range(block_start, end, 16):
            line_a = []
            line_b = []
            ascii_a = []
            ascii_b = []
            for k in range(16):
                pos = base + k
                if pos >= n:
                    break
                va = data_a[pos] if pos < len(data_a) else None
                vb = data_b[pos] if pos < len(data_b) else None
                is_diff = pos in diff_offsets
                if va is not None:
                    seg = f"{va:02x}"
                    line_a.append(f"{RED}{seg}{RESET}" if is_diff else seg)
                    ascii_a.append(chr(va) if 32 <= va < 127 else ".")
                else:
                    line_a.append(f"{RED}??{RESET}" if is_diff else "  ")
                    ascii_a.append(" ")
                if vb is not None:
                    seg = f"{vb:02x}"
                    line_b.append(f"{GREEN}{seg}{RESET}" if is_diff else seg)
                    ascii_b.append(chr(vb) if 32 <= vb < 127 else ".")
                else:
                    line_b.append(f"{GREEN}??{RESET}" if is_diff else "  ")
                    ascii_b.append(" ")

            addr = f"{base:04x}"
            print(f"  {DIM}{addr}{RESET}  " + " ".join(line_a) + "  |" + "".join(ascii_a) + "|  A")
            print(f"  {DIM}{addr}{RESET}  " + " ".join(line_b) + "  |" + "".join(ascii_b) + "|  B")
        print()

    # Legend
    print(f"{BOLD}Légende:{RESET} {RED}rouge = {args.file_a.name}{RESET}  {GREEN}vert = {args.file_b.name}{RESET}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
