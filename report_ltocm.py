#!/usr/bin/env python3
"""
LTO-CM report script: page-by-page report or diff of one or two dumps.

Reads one or two LTO-CM dumps (from files and/or from NFC via nfc-ltocm) and either:
  - One dump: prints a full page-by-page report with clear-text fields (per ECMA-319)
    and optional hex remainder. Missing pages are shown as "not found".
  - Two dumps (or one file + --read): prints a side-by-side diff of the two dumps.

Usage:
  report_ltocm.py [options] [input_file [input_file]]
  report_ltocm.py --read [input_file]   # diff file vs device

Options:
  -o, --output FILE   Write report to FILE instead of stdout.
  --no-hex            Omit hex dump of remainder in each page.
  --check-crc / --no-check-crc   Verify CRCs (default: on).

Standalone: no imports from other project files. ECMA-319 Annex D.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import tempfile
from pathlib import Path

# --- Diff colors (character-level; disabled if NO_COLOR) -----------------------
def _color_enabled() -> bool:
    return os.environ.get("NO_COLOR", "").strip() == ""

def _red(s: str) -> str:
    return f"\033[31m{s}\033[0m" if _color_enabled() else s

def _green(s: str) -> str:
    return f"\033[32m{s}\033[0m" if _color_enabled() else s

def _color_diff_per_char(left_val: str, right_val: str, width: int = 48) -> tuple[str, str]:
    """Per-character coloring: red for left-only diffs, green for right."""
    l_pad = (left_val[: width - 3] + "..." if len(left_val) > width else left_val).ljust(width)
    r_pad = (right_val[: width - 3] + "..." if len(right_val) > width else right_val).ljust(width)
    l_out, r_out = [], []
    for i in range(width):
        lc, rc = l_pad[i], r_pad[i]
        if lc != rc:
            l_out.append(_red(lc))
            r_out.append(_green(rc))
        else:
            l_out.append(lc)
            r_out.append(rc)
    return ("".join(l_out), "".join(r_out))

# --- GF(256) and ECMA-319 Section 13.2 CRC (standalone) -----------------------
def _gf256_build_tables() -> tuple[list[int], list[int]]:
    exp = [0] * 512
    log = [0] * 256
    x = 1
    for i in range(255):
        exp[i] = x
        log[x] = i
        x <<= 1
        if x & 0x100:
            x ^= 0x11d
    for i in range(255, 512):
        exp[i] = exp[i % 255]
    return exp, log

_GF256_EXP, _GF256_LOG = _gf256_build_tables()

def _gf256_mul(a: int, b: int) -> int:
    if a == 0 or b == 0:
        return 0
    return _GF256_EXP[_GF256_LOG[a] + _GF256_LOG[b]]

def _gf256_add(a: int, b: int) -> int:
    return a ^ b

def ecma319_crc4(data: bytes) -> bytes:
    """4-byte CRC per ECMA-319 section 13.2. Returns (CRC3, CRC2, CRC1, CRC0)."""
    g3 = _GF256_EXP[201 % 255]
    g2 = _GF256_EXP[246 % 255]
    g1 = _GF256_EXP[201 % 255]
    r0, r1, r2, r3 = 0, 0, 0, 0
    for d in data:
        t = _gf256_add(d, r3)
        r3 = _gf256_add(r2, _gf256_mul(g3, t))
        r2 = _gf256_add(r1, _gf256_mul(g2, t))
        r1 = _gf256_add(r0, _gf256_mul(g1, t))
        r0 = t
    return bytes([r3, r2, r1, r0])

# --- Constants (ECMA-319 Annex D) ----------------------------------------------
BLOCK_SIZE = 32
ADDR_PROTECTED_PTABLE = 36
PAGE_DESCRIPTOR_SIZE = 4
PAGE_ID_EOPT = 0xFFF
TYPE_TO_BLOCKS = {0x0001: 127, 0x0002: 255, 0x0003: 511}

PAGE_NAMES: dict[int | None, str] = {
    None: "LTO CM Manufacturer's Information (Block 0)",
    0x001: "Cartridge Manufacturer's Information",
    0x002: "Media Manufacturer's Information",
    0x101: "Initialisation Data",
    0x102: "Tape Write Pass",
    0x103: "Tape Directory",
    0x104: "EOD Information",
    0x105: "Cartridge Status and Tape Alert Flags",
    0x106: "Mechanism Related",
    0x107: "Suspended Append Writes",
    0x108: "Usage Information 0",
    0x109: "Usage Information 1",
    0x10A: "Usage Information 2",
    0x10B: "Usage Information 3",
    0x200: "Application Specific Data",
    0xFFC: "Pad",
    0xFFD: "Defect",
    0xFFE: "Empty",
}

# Documented pages that always get a report section (if missing from dump, show "not found")
DOCUMENTED_PAGE_IDS = (
    0x001, 0x002, 0x101, 0x102, 0x103, 0x104, 0x105, 0x106, 0x107,
    0x108, 0x109, 0x10A, 0x10B, 0x200,
)

# Field: (offset_in_page, length, name, format)
# format: ascii, hex, uint8, uint16_le, uint16_be, uint32_le, uint32_be, uint64_le, uint64_be, cart_type, cartridge_status, validity_eod
BLOCK0_FIELDS = [
    (0, 4, "LTO CM Serial Number", "hex"),
    (4, 1, "CM Serial Number Check Byte", "hex"),
    (5, 1, "CM Size", "uint8"),
    (6, 2, "Type", "uint16_be"),
    (8, 24, "Manufacturer's Information", "hex"),
]

BLOCK1_FIELDS = [
    (0, 1, "Last Write-Inhibited Block Number", "uint8"),
    (1, 1, "Block 1 Protection Flag", "uint8"),
    (2, 2, "Reserved", "hex"),
]

CART_MFG_FIELDS = [
    (0, 2, "Page Id", "uint16_be"),
    (2, 2, "Page Length", "uint16_be"),
    (4, 8, "Cartridge Manufacturer", "ascii"),
    (12, 10, "Serial Number", "ascii"),
    (22, 2, "Cartridge Type", "cart_type"),
    (24, 8, "Date of Manufacture", "ascii"),
    (32, 2, "Tape Length", "uint16_be"),
    (34, 2, "Tape Thickness", "uint16_be"),
    (36, 2, "Empty Reel Inertia", "uint16_be"),
    (38, 2, "Hub Radius", "uint16_be"),
    (40, 2, "Full Reel Pack Radius", "uint16_be"),
    (42, 2, "Maximum Media Speed", "uint16_be"),
    (44, 4, "License Code", "ascii"),
    (48, 12, "Cartridge Manufacturer's Use", "hex"),
    (60, 4, "CRC", "hex"),
]

MEDIA_MFG_FIELDS = [
    (0, 2, "Page Id", "uint16_be"),
    (2, 2, "Page Length", "uint16_be"),
    (4, 48, "Servowriter Manufacturer", "ascii"),
    (52, 8, "Reserved", "hex"),
    (60, 4, "CRC", "hex"),
]

INIT_DATA_FIELDS = [
    (0, 2, "Page Id", "uint16_be"),
    (2, 2, "Page Length", "uint16_be"),
    (4, 8, "Initialising Drive Manufacturer", "ascii"),
    (12, 10, "Drive Id", "ascii"),
    (22, 2, "Format Type", "uint16_be"),
    (24, 4, "LP1 Position", "uint32_be"),
    (28, 4, "LP2 Position", "uint32_be"),
    (32, 4, "LP3 Position", "uint32_be"),
    (36, 4, "LP4 Position", "uint32_be"),
    (40, 4, "LP5 Position", "uint32_be"),
    (44, 4, "LP6 Position", "uint32_be"),
    (48, 12, "Reserved", "hex"),
    (60, 4, "CRC", "hex"),
]

TAPE_WRITE_PASS_FIELDS = [
    (0, 2, "Page Id", "uint16_be"),
    (2, 2, "Page Length", "uint16_be"),
    (4, 12, "Reserved", "hex"),
    (16, 4, "Write Pass Field 0", "uint32_be"),
    (20, 4, "Write Pass Field 1", "uint32_be"),
    (24, 4, "Write Pass Field 2", "uint32_be"),
    (28, 4, "Write Pass Field 3", "uint32_be"),
    (32, 4, "Write Pass Field 4", "uint32_be"),
    (36, 4, "Write Pass Field 5", "uint32_be"),
    (40, 4, "Write Pass Field 6", "uint32_be"),
    (44, 4, "Write Pass Field 7", "uint32_be"),
]

TAPE_DIR_FIELDS = [
    (0, 2, "Page Id", "uint16_be"),
    (2, 2, "Page Length", "uint16_be"),
    (4, 4, "FID Tape Write Pass", "uint32_be"),
    (8, 8, "Reserved", "hex"),
] + [(16 + i * 16, 16, f"Wrap Section {i}", "hex") for i in range(96)]

EOD_INFO_FIELDS = [
    (0, 2, "Page Id", "uint16_be"),
    (2, 2, "Page Length", "uint16_be"),
    (4, 4, "Tape Write Pass for last written EOD", "uint32_be"),
    (8, 4, "Thread Count", "uint32_be"),
    (12, 6, "Record count at EOD", "uint48_be"),
    (18, 6, "File Mark Count at EOD", "uint48_be"),
    (24, 4, "EOD Data Set Number", "uint32_be"),
    (28, 4, "Wrap Section Number of EOD", "uint32_be"),
    (32, 2, "Validity of EOD", "validity_eod"),
    (34, 2, "First CQ Set Number", "uint16_be"),
    (36, 4, "Physical Position of EOD", "uint32_be"),
    (40, 20, "Reserved", "hex"),
    (60, 4, "CRC", "hex"),
]

CARTRIDGE_STATUS_FIELDS = [
    (0, 2, "Page Id", "uint16_be"),
    (2, 2, "Page Length", "uint16_be"),
    (4, 8, "Tape Alert Flags", "hex"),
    (12, 4, "Thread Count", "uint32_be"),
    (16, 2, "Cartridge Status", "cartridge_status"),
    (18, 10, "Reserved", "hex"),
    (28, 4, "CRC", "hex"),
]

MECHANISM_FIELDS = [
    (0, 2, "Page Id", "uint16_be"),
    (2, 2, "Page Length", "uint16_be"),
    (4, 8, "Drive Manufacturer Identity", "ascii"),
    (12, 368, "Mechanism related data", "hex"),
    (380, 4, "CRC", "hex"),
]

SUSPENDED_APPEND_FIELDS = [
    (0, 2, "Page Id", "uint16_be"),
    (2, 2, "Page Length", "uint16_be"),
    (4, 4, "Reserved", "hex"),
] + [(8 + i * 8, 8, f"Suspended Append {i}", "hex") for i in range(14)] + [
    (120, 4, "Reserved", "hex"),
    (124, 4, "CRC", "hex"),
]

USAGE_FIELDS = [
    (0, 2, "Page Id", "uint16_be"),
    (2, 2, "Page Length", "uint16_be"),
    (4, 8, "Drive Manufacturer", "ascii"),
    (12, 10, "Drive Id", "ascii"),
    (22, 2, "Suspended Writes at Append", "uint16_le"),
    (24, 4, "Thread Count", "uint32_le"),
    (28, 8, "Total Data Sets Written", "uint64_le"),
    (36, 8, "Total Data Sets Read", "uint64_le"),
    (44, 4, "Total Write Retries", "uint32_le"),
    (48, 4, "Total Read Retries", "uint32_le"),
    (52, 2, "Total Unrecovered Write Errors", "uint16_le"),
    (54, 2, "Total Unrecovered Read Errors", "uint16_le"),
    (56, 2, "Total Number of Suspended Writes", "uint16_le"),
    (58, 2, "Total Number of Fatal Suspended Writes", "uint16_le"),
    (60, 4, "CRC", "hex"),
]

# Application Specific Data (page 0x200): MAM-style layout when signature is "MAM001"
# Offsets 4-10: "MAM001", 10-14: param header (e.g. 08 06 00 20), 14-26: barcode (ASCII, often 8+1 chars + padding)
APP_SPECIFIC_FIELDS = [
    (0, 2, "Page Id", "uint16_be"),
    (2, 2, "Page Length", "uint16_be"),
    (4, 6, "MAM Signature", "ascii"),
    (10, 4, "MAM Parameter Header", "hex"),
    (14, 12, "Barcode", "ascii"),
    (26, 1002, "Application Data (remainder)", "hex"),
    (1028, 24, "Reserved", "hex"),
    (1052, 4, "CRC", "hex"),
]

def get_page_fields(page_id: int | None) -> list[tuple[int, int, str, str]]:
    if page_id is None:
        return BLOCK0_FIELDS
    m = {
        0x001: CART_MFG_FIELDS,
        0x002: MEDIA_MFG_FIELDS,
        0x101: INIT_DATA_FIELDS,
        0x102: TAPE_WRITE_PASS_FIELDS,
        0x103: TAPE_DIR_FIELDS,
        0x104: EOD_INFO_FIELDS,
        0x105: CARTRIDGE_STATUS_FIELDS,
        0x106: MECHANISM_FIELDS,
        0x107: SUSPENDED_APPEND_FIELDS,
        0x108: USAGE_FIELDS,
        0x109: USAGE_FIELDS,
        0x10A: USAGE_FIELDS,
        0x10B: USAGE_FIELDS,
        0x200: APP_SPECIFIC_FIELDS,
    }
    return m.get(page_id, [])

def get_block1_descriptor_fields(dump: bytes) -> list[tuple[int, int, int, str]]:
    """Return list of (offset, page_id, start_addr, label) for protected table then unprotected."""
    out: list[tuple[int, int, int, str]] = []
    off = ADDR_PROTECTED_PTABLE
    n = 0
    while off + PAGE_DESCRIPTOR_SIZE <= len(dump):
        b0, b1, b2, b3 = dump[off], dump[off + 1], dump[off + 2], dump[off + 3]
        page_id = ((b0 & 0x0F) << 8) | b1
        start_addr = (b2 << 8) | b3
        out.append((off, page_id, start_addr, f"Descriptor {n}"))
        n += 1
        if page_id == PAGE_ID_EOPT:
            break
        off += PAGE_DESCRIPTOR_SIZE
    return out

def get_crc_region_for_page(page_id: int | None, page_len: int) -> tuple[int, int] | None:
    """(offset of first CRC byte, length 4) or None if page has no CRC in spec."""
    if page_id is None:
        return None
    if page_id in (0x001, 0x002, 0x101, 0x104, 0x105, 0x106, 0x107, 0x108, 0x109, 0x10A, 0x10B, 0x200):
        return (page_len - 4, 4)
    return None

# --- Helpers ------------------------------------------------------------------
def get_num_blocks(dump: bytes) -> int:
    if len(dump) < 8:
        return 0
    typ = (dump[6] << 8) | dump[7]
    return TYPE_TO_BLOCKS.get(typ, 0) or (len(dump) // BLOCK_SIZE)

def parse_page_descriptor(data: bytes, offset: int) -> tuple[int, int] | None:
    if offset + 4 > len(data):
        return None
    b0, b1, b2, b3 = data[offset], data[offset + 1], data[offset + 2], data[offset + 3]
    page_id = ((b0 & 0x0F) << 8) | b1
    start_addr = (b2 << 8) | b3
    return (page_id, start_addr)

def find_unprotected_table_start(dump: bytes) -> int | None:
    off = ADDR_PROTECTED_PTABLE
    while off + PAGE_DESCRIPTOR_SIZE <= len(dump):
        desc = parse_page_descriptor(dump, off)
        if desc is None:
            break
        page_id, start_addr = desc
        if page_id == PAGE_ID_EOPT:
            return start_addr
        off += PAGE_DESCRIPTOR_SIZE
    return None

def build_page_map(dump: bytes) -> list[tuple[int | None, int, int, bool]]:
    """List of (page_id, start_addr, length, is_protected). Block 0 and Block 1 are not in this list; they are fixed."""
    result: list[tuple[int | None, int, int, bool]] = []
    # Protected table: from 36 until EOPT
    off = ADDR_PROTECTED_PTABLE
    protected_descriptors: list[tuple[int, int]] = []
    while off + PAGE_DESCRIPTOR_SIZE <= len(dump):
        desc = parse_page_descriptor(dump, off)
        if desc is None:
            break
        page_id, start_addr = desc
        protected_descriptors.append((page_id, start_addr))
        if page_id == PAGE_ID_EOPT:
            break
        off += PAGE_DESCRIPTOR_SIZE
    for i, (pid, start) in enumerate(protected_descriptors):
        if pid == PAGE_ID_EOPT:
            break
        next_start = protected_descriptors[i + 1][1] if i + 1 < len(protected_descriptors) else len(dump)
        length = next_start - start
        result.append((pid, start, length, True))
    # Unprotected table
    ustart = find_unprotected_table_start(dump)
    if ustart is None or ustart >= len(dump):
        return result
    off = ustart
    unprotected_descriptors: list[tuple[int, int]] = []
    while off + PAGE_DESCRIPTOR_SIZE <= len(dump):
        desc = parse_page_descriptor(dump, off)
        if desc is None:
            break
        page_id, start_addr = desc
        unprotected_descriptors.append((page_id, start_addr))
        if page_id == PAGE_ID_EOPT:
            break
        off += PAGE_DESCRIPTOR_SIZE
    for i, (pid, start) in enumerate(unprotected_descriptors):
        if pid == PAGE_ID_EOPT:
            break
        next_start = unprotected_descriptors[i + 1][1] if i + 1 < len(unprotected_descriptors) else len(dump)
        length = next_start - start
        result.append((pid, start, length, False))
    return result

def format_field_value(raw: bytes, fmt: str) -> str:
    if fmt == "ascii":
        s = raw.decode("ascii", errors="replace").strip().strip("\x00")
        return s or "(empty)"
    if fmt == "hex":
        return raw.hex()
    if fmt == "uint8":
        return str(raw[0]) if len(raw) >= 1 else ""
    if fmt == "uint16_le":
        return str(int.from_bytes(raw[:2], "little"))
    if fmt == "uint16_be":
        return str(int.from_bytes(raw[:2], "big"))
    if fmt == "uint32_le":
        return str(int.from_bytes(raw[:4], "little"))
    if fmt == "uint32_be":
        return str(int.from_bytes(raw[:4], "big"))
    if fmt == "uint48_be":
        return str(int.from_bytes(raw[:6], "big"))
    if fmt == "uint64_le":
        return str(int.from_bytes(raw[:8], "little"))
    if fmt == "uint64_be":
        return str(int.from_bytes(raw[:8], "big"))
    if fmt == "cart_type":
        if len(raw) < 2:
            return "not found"
        b0, b1 = raw[0], raw[1]
        cleaning = "cleaning cartridge" if (b0 & 0x80) else "data cartridge"
        ultrium = "Ultrium format" if (b1 & 0x01) else "not Ultrium"
        return f"0x{b0:02X}{b1:02X} ({cleaning}, {ultrium})"
    if fmt == "cartridge_status":
        if len(raw) < 2:
            return "not found"
        v = int.from_bytes(raw[:2], "big")
        status = {0: "unloaded normally", 1: "not unloaded normally (drive not writing)", 2: "not unloaded normally (drive was writing)"}
        return f"0x{v:04X} ({status.get(v, 'reserved')})"
    if fmt == "validity_eod":
        if len(raw) < 2:
            return "not found"
        v = int.from_bytes(raw[:2], "big")
        status = {0: "EOD position unknown", 1: "EOD location valid", 2: "Backup in progress (no EOD Data Set)", 3: "Backup failed (EOD not written)"}
        return f"0x{v:04X} ({status.get(v, 'reserved')})"
    return raw.hex()

def format_field(data: bytes, base: int, offset: int, length: int, fmt: str) -> str:
    """Return decoded value or 'not found' if range is outside data."""
    start = base + offset
    end = start + length
    if start < 0 or end > len(data):
        return "not found"
    raw = data[start:end]
    return format_field_value(raw, fmt)

def hex_dump(data: bytes, base_addr: int = 0, bytes_per_line: int = 16) -> str:
    lines = []
    for i in range(0, len(data), bytes_per_line):
        chunk = data[i : i + bytes_per_line]
        addr = base_addr + i
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"  {addr:04x}: {hex_part:<{bytes_per_line * 3 - 1}}  {ascii_part}")
    return "\n".join(lines)

def get_page_slice(dump: bytes, start: int, length: int) -> bytes | None:
    if start < 0 or start + length > len(dump):
        return None
    return dump[start : start + length]

def run_nfc_ltocm(args: list[str], capture_output: bool = True) -> subprocess.CompletedProcess:
    exe = Path(__file__).resolve().parent / "nfc-ltocm"
    if not exe.is_file():
        exe = Path("nfc-ltocm")
    return subprocess.run([str(exe)] + args, capture_output=capture_output, timeout=120)

# --- Report structure (for diff) -----------------------------------------------
# Section = (section_key, title, addr_line, [(label, value), ...])
# section_key is "block0", "block1", or "page_0xXXX" for alignment.
SectionT = tuple[str, str, str, list[tuple[str, str]]]

def _section_block0(dump: bytes, check_crc: bool) -> SectionT:
    addr = "  Address: 0x0000  Length: 32 bytes"
    fields: list[tuple[str, str]] = []
    data = get_page_slice(dump, 0, BLOCK_SIZE)
    if data is None:
        for _, _, name, _ in BLOCK0_FIELDS:
            fields.append((name, "not found"))
    else:
        for off, length, name, fmt in BLOCK0_FIELDS:
            fields.append((name, format_field(dump, 0, off, length, fmt)))
    return ("block0", "Block 0 – LTO CM Manufacturer's Information", addr, fields)

def _section_block1(dump: bytes, show_hex: bool, check_crc: bool) -> SectionT:
    addr = "  Address: 0x0020  Length: 32 bytes"
    fields: list[tuple[str, str]] = []
    block1_start = 32
    block1_len = BLOCK_SIZE
    data = get_page_slice(dump, block1_start, block1_len)
    if data is None:
        for _, _, name, _ in BLOCK1_FIELDS:
            fields.append((name, "not found"))
        fields.append(("Protected page table", "not found"))
    else:
        for off, length, name, fmt in BLOCK1_FIELDS:
            fields.append((name, format_field(dump, block1_start, off, length, fmt)))
        for off, pid, start_addr, label in get_block1_descriptor_fields(dump):
            pid_str = "EOPT" if pid == PAGE_ID_EOPT else f"0x{pid:03X}"
            fields.append((label, f"Page Id {pid_str}, Start Address 0x{start_addr:04X}"))
        ustart = find_unprotected_table_start(dump)
        if ustart is not None and check_crc and ustart >= ADDR_PROTECTED_PTABLE + 4:
            if ustart - ADDR_PROTECTED_PTABLE >= 4:
                table_data = dump[ADDR_PROTECTED_PTABLE : ustart - 4]
                stored_crc = get_page_slice(dump, ustart - 4, 4)
                if stored_crc is not None and len(table_data) > 0:
                    computed = ecma319_crc4(table_data)
                    valid = computed == stored_crc
                    fields.append(("Protected Table CRC", f"{stored_crc.hex()} ({'valid' if valid else 'invalid'})"))
        if show_hex and len(data) > 4:
            fields.append(("Remainder (hex)", f"[{len(data)-4} bytes]"))
    return ("block1", "Block 1 – Write-Inhibit and Protected Page Table", addr, fields)

def _section_page(dump: bytes, page_id: int, start: int, length: int, show_hex: bool, check_crc: bool, name: str) -> SectionT:
    pid_str = f"0x{page_id:03X}"
    title = f"Page {pid_str} – {name}"
    if start < 0:
        addr = "  Address: not in dump  Length: 0 bytes"
    else:
        addr = f"  Address: 0x{start:04X}  Length: {length} bytes"
    fields = []
    data = None if start < 0 else get_page_slice(dump, start, length)
    field_defs = get_page_fields(page_id)
    if data is None:
        for _, _, fname, _ in field_defs:
            fields.append((fname, "not found"))
        if check_crc and get_crc_region_for_page(page_id, 0 if length <= 0 else length) is not None:
            fields.append(("CRC verification", "not found"))
    else:
        for off, flen, fname, fmt in field_defs:
            val = format_field(dump, start, off, flen, fmt) if off + flen <= length else "not found"
            fields.append((fname, val))
        if show_hex:
            covered = set()
            for o, fl, _, _ in field_defs:
                for j in range(o, min(o + fl, length)):
                    covered.add(j)
            remainder_len = sum(1 for i in range(length) if i not in covered)
            if remainder_len:
                fields.append(("Remainder (hex)", f"[{remainder_len} bytes]"))
        if check_crc:
            crc_region = get_crc_region_for_page(page_id, length)
            if crc_region is not None:
                crc_off, crc_len = crc_region
                if crc_off >= 0 and crc_off + crc_len <= length:
                    crc_data = dump[start : start + crc_off]
                    stored = dump[start + crc_off : start + crc_off + 4]
                    valid = ecma319_crc4(crc_data) == stored
                    fields.append(("CRC verification", "valid" if valid else "invalid"))
                else:
                    fields.append(("CRC verification", "not found"))
    return (f"page_{pid_str}", title, addr, fields)

def build_report_structure(dump: bytes, show_hex: bool, check_crc: bool) -> list[SectionT]:
    out: list[SectionT] = []
    out.append(_section_block0(dump, check_crc))
    out.append(_section_block1(dump, show_hex, check_crc))
    page_map = build_page_map(dump)
    present_ids = {p[0] for p in page_map}
    for pid in DOCUMENTED_PAGE_IDS:
        if pid not in present_ids:
            page_map.append((pid, -1, 0, False))
    page_map.sort(key=lambda x: (x[1] if x[1] >= 0 else 0x10000, x[0] or 0))
    for page_id, start, length, _ in page_map:
        name = PAGE_NAMES.get(page_id, f"Page 0x{page_id:03X}" if page_id is not None else "Unknown")
        out.append(_section_page(dump, page_id, start, length, show_hex, check_crc, name))
    return out

def diff_structures(struct_a: list[SectionT], struct_b: list[SectionT], source_a: str, source_b: str, value_width: int = 40) -> list[str]:
    """Produce diff lines with character-level colors. Align by section key."""
    lines = []
    lines.append("LTO-CM Diff (ECMA-319 Annex D)")
    lines.append("=" * 60)
    lines.append(f"  Left:  {source_a}")
    lines.append(f"  Right: {source_b}")
    lines.append("")
    keys_a = {s[0]: s for s in struct_a}
    keys_b = {s[0]: s for s in struct_b}
    all_keys = sorted(set(keys_a) | set(keys_b), key=lambda k: (0 if k == "block0" else 1 if k == "block1" else 2, k))
    for key in all_keys:
        sa = keys_a.get(key)
        sb = keys_b.get(key)
        if sa is None and sb is not None:
            sa = (key, sb[1], sb[2], [])
        if sb is None and sa is not None:
            sb = (key, sa[1], sa[2], [])
        if sa is None or sb is None:
            continue
        _, title_a, addr_a, fields_a = sa
        _, title_b, addr_b, fields_b = sb
        lines.append("")
        lines.append(f"=== {title_a} ===")
        if addr_a != addr_b:
            l_addr, r_addr = _color_diff_per_char(addr_a, addr_b, 50)
            lines.append(f"  Left:  {l_addr}  |  Right: {r_addr}")
        else:
            lines.append(addr_a)
        lines.append("")
        labels_a = {f[0]: f[1] for f in fields_a}
        labels_b = {f[0]: f[1] for f in fields_b}
        all_labels = sorted(set(labels_a) | set(labels_b))
        for lab in all_labels:
            va = labels_a.get(lab, "not found")
            vb = labels_b.get(lab, "not found")
            la, lb = _color_diff_per_char(va, vb, value_width)
            lines.append(f"  {lab:<38}  {la}  |  {lb}")
    return lines

# --- Report sections ----------------------------------------------------------
def report_block0(dump: bytes, lines: list[str], show_hex: bool, check_crc: bool) -> None:
    lines.append("")
    lines.append("=== Block 0 – LTO CM Manufacturer's Information ===")
    lines.append(f"  Address: 0x0000  Length: {BLOCK_SIZE} bytes")
    lines.append("")
    data = get_page_slice(dump, 0, BLOCK_SIZE)
    if data is None:
        for _, _, name, _ in BLOCK0_FIELDS:
            lines.append(f"  {name}: not found")
        return
    for off, length, name, fmt in BLOCK0_FIELDS:
        val = format_field(dump, 0, off, length, fmt)
        lines.append(f"  {name}: {val}")

def report_block1(dump: bytes, lines: list[str], show_hex: bool, check_crc: bool) -> None:
    lines.append("")
    lines.append("=== Block 1 – Write-Inhibit and Protected Page Table ===")
    block1_start = 32
    block1_len = BLOCK_SIZE
    data = get_page_slice(dump, block1_start, block1_len)
    if data is None:
        for _, _, name, _ in BLOCK1_FIELDS:
            lines.append(f"  {name}: not found")
        lines.append("  Protected page table: not found")
        return
    for off, length, name, fmt in BLOCK1_FIELDS:
        val = format_field(dump, block1_start, off, length, fmt)
        lines.append(f"  {name}: {val}")
    # Descriptors
    descs = get_block1_descriptor_fields(dump)
    for off, pid, start_addr, label in descs:
        pid_str = "EOPT" if pid == PAGE_ID_EOPT else f"0x{pid:03X}"
        lines.append(f"  {label}: Page Id {pid_str}, Start Address 0x{start_addr:04X}")
    # CRC of protected table: over bytes from start of table to before CRC (table ends before unprotected start)
    ustart = find_unprotected_table_start(dump)
    if ustart is not None and check_crc and ustart >= ADDR_PROTECTED_PTABLE + 4:
        crc_region_len = ustart - ADDR_PROTECTED_PTABLE
        if crc_region_len >= 4:
            table_data = dump[ADDR_PROTECTED_PTABLE : ustart - 4]
            stored_crc = get_page_slice(dump, ustart - 4, 4)
            if stored_crc is not None and len(table_data) > 0:
                computed = ecma319_crc4(table_data)
                valid = computed == stored_crc
                lines.append(f"  Protected Table CRC: {stored_crc.hex()} ({'valid' if valid else 'invalid'})")
    if show_hex:
        # Remainder is bytes 4-31 (descriptors + table CRC)
        remainder = data[4:] if len(data) > 4 else b""
        if remainder:
            lines.append("  Remainder (hex):")
            lines.append(hex_dump(remainder, block1_start + 4))

def report_page(dump: bytes, page_id: int | None, start: int, length: int, lines: list[str],
                show_hex: bool, check_crc: bool, name: str) -> None:
    lines.append("")
    pid_str = "Block 0" if page_id is None else f"0x{page_id:03X}"
    lines.append(f"=== Page {pid_str} – {name} ===")
    if start < 0:
        lines.append("  Address: not in dump  Length: 0 bytes")
    else:
        lines.append(f"  Address: 0x{start:04X}  Length: {length} bytes")
    lines.append("")
    data = None if start < 0 else get_page_slice(dump, start, length)
    fields = get_page_fields(page_id)
    if data is None:
        for _, _, fname, _ in fields:
            lines.append(f"  {fname}: not found")
        if check_crc and get_crc_region_for_page(page_id, 0 if length <= 0 else length) is not None:
            lines.append("  CRC verification: not found")
        return
    for off, flen, fname, fmt in fields:
        if off + flen <= length:
            val = format_field(dump, start, off, flen, fmt)
        else:
            val = "not found"
        lines.append(f"  {fname}: {val}")
    if show_hex:
        covered = set()
        for off, flen, _, _ in fields:
            for j in range(off, min(off + flen, length)):
                covered.add(j)
        remainder = bytes(b for i, b in enumerate(data) if i not in covered)
        if remainder:
            lines.append("  Remainder (hex):")
            first_uncovered = next((i for i in range(length) if i not in covered), length)
            lines.append(hex_dump(remainder, start + first_uncovered))
    if check_crc:
        crc_region = get_crc_region_for_page(page_id, length)
        if crc_region is not None:
            crc_off, crc_len = crc_region
            if crc_off >= 0 and crc_off + crc_len <= length:
                crc_data = dump[start : start + crc_off]
                stored = dump[start + crc_off : start + crc_off + 4]
                computed = ecma319_crc4(crc_data)
                valid = computed == stored
                lines.append(f"  CRC verification: {'valid' if valid else 'invalid'}")
            else:
                lines.append("  CRC verification: not found")

def _load_dump(path: str | None, from_nfc: bool) -> tuple[bytes, str] | None:
    """Load dump from file or NFC. Return (dump_bytes, source_label) or None on error."""
    if from_nfc:
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as tmp:
            tmp_path = tmp.name
        try:
            if run_nfc_ltocm([tmp_path]).returncode != 0:
                print("Error: failed to read from NFC device (nfc-ltocm).", file=sys.stderr)
                return None
            with open(tmp_path, "rb") as f:
                data = f.read()
        finally:
            try:
                Path(tmp_path).unlink(missing_ok=True)
            except OSError:
                pass
        return (data, "NFC device")
    if path is None:
        return None
    p = Path(path)
    if not p.is_file():
        print(f"Error: file not found: {p}", file=sys.stderr)
        return None
    try:
        with open(p, "rb") as f:
            data = f.read()
    except OSError as e:
        print(f"Error: could not read file: {e}", file=sys.stderr)
        return None
    return (data, str(p))

def _validate_dump(dump: bytes) -> bool:
    num_blocks = get_num_blocks(dump)
    if num_blocks == 0:
        print("Error: invalid dump (could not determine block count from Type or size).", file=sys.stderr)
        return False
    if len(dump) < num_blocks * BLOCK_SIZE:
        print(f"Error: dump too short (expected {num_blocks * BLOCK_SIZE} bytes, got {len(dump)}).", file=sys.stderr)
        return False
    return True

def main() -> int:
    parser = argparse.ArgumentParser(
        description="LTO-CM report: dump file(s) or NFC read, output page-by-page report or diff.",
    )
    parser.add_argument("input_file", nargs="*", help="Input dump file(s) (.bin); one or two for diff")
    parser.add_argument("--read", action="store_true", help="Read one dump from NFC device (use with one file for diff)")
    parser.add_argument("-o", "--output", metavar="FILE", help="Output report file")
    parser.add_argument("--no-hex", action="store_true", help="Do not show hex dump of remainder")
    parser.add_argument("--check-crc", action="store_true", default=True, help="Verify CRCs (default: True)")
    parser.add_argument("--no-check-crc", action="store_false", dest="check_crc", help="Do not verify CRCs")
    args = parser.parse_args()

    files = args.input_file or []
    if len(files) > 2:
        parser.error("At most two input files allowed")
    if args.read and len(files) > 1:
        parser.error("Use --read with at most one input file (file vs device diff)")
    if not args.read and len(files) == 0:
        parser.error("Provide at least one input_file or use --read")

    show_hex = not args.no_hex
    check_crc = args.check_crc

    # Two dumps: diff mode (file vs file, or file vs --read)
    if (args.read and len(files) == 1) or len(files) == 2:
        if args.read:
            left = _load_dump(files[0], from_nfc=False)
            right = _load_dump(None, from_nfc=True)
            source_left = files[0] if left else ""
            source_right = "NFC device" if right else ""
        else:
            left = _load_dump(files[0], from_nfc=False)
            right = _load_dump(files[1], from_nfc=False)
            source_left = files[0] if left else ""
            source_right = files[1] if right else ""
        if left is None or right is None:
            return 1
        dump_a, source_a = left
        dump_b, source_b = right
        if not _validate_dump(dump_a) or not _validate_dump(dump_b):
            return 1
        struct_a = build_report_structure(dump_a, show_hex, check_crc)
        struct_b = build_report_structure(dump_b, show_hex, check_crc)
        diff_lines = diff_structures(struct_a, struct_b, source_a, source_b)
        report_text = "\n".join(diff_lines)
        if args.output:
            try:
                with open(args.output, "w", encoding="utf-8") as f:
                    f.write(report_text)
            except OSError as e:
                print(f"Error: could not write report: {e}", file=sys.stderr)
                return 1
        else:
            print(report_text)
        return 0

    # Single dump: report mode
    if args.read:
        result = _load_dump(None, from_nfc=True)
    else:
        result = _load_dump(files[0], from_nfc=False)
    if result is None:
        return 1
    dump, source = result
    if not _validate_dump(dump):
        return 1
    typ = (dump[6] << 8) | dump[7] if len(dump) >= 8 else 0
    typ_str = str(typ) if typ in (1, 2, 3) else f"0x{typ:04X}"
    num_blocks = get_num_blocks(dump)

    lines: list[str] = []
    lines.append("LTO-CM Report (ECMA-319 Annex D)")
    lines.append("=" * 60)
    lines.append(f"  Source: {source}")
    lines.append(f"  Dump size: {len(dump)} bytes")
    lines.append(f"  LTO-CM type: {typ_str}  Blocks: {num_blocks}")
    lines.append("")

    report_block0(dump, lines, show_hex, check_crc)
    report_block1(dump, lines, show_hex, check_crc)

    page_map = build_page_map(dump)
    present_ids = {p[0] for p in page_map}
    for pid in DOCUMENTED_PAGE_IDS:
        if pid not in present_ids:
            page_map.append((pid, -1, 0, False))
    page_map.sort(key=lambda x: (x[1] if x[1] >= 0 else 0x10000, x[0] or 0))
    for page_id, start, length, _ in page_map:
        name = PAGE_NAMES.get(page_id, f"Page 0x{page_id:03X}" if page_id is not None else "Unknown")
        report_page(dump, page_id, start, length, lines, show_hex, check_crc, name)

    report_text = "\n".join(lines)
    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(report_text)
        except OSError as e:
            print(f"Error: could not write report: {e}", file=sys.stderr)
            return 1
    else:
        print(report_text)
    return 0

if __name__ == "__main__":
    sys.exit(main())
