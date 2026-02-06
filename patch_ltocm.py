#!/usr/bin/env python3
"""
LTO-CM patch script: read dump (file or NFC), apply patches, and optionally write back.

Reads an LTO Cartridge Memory dump from a file or from the NFC device (via nfc-ltocm),
applies one or more patches, and saves the result. With --apply, writes the patched
dump to the cartridge block-by-block and verifies by re-reading.

Patches:
  --init-data          Initialise as data tape (pages 0x101, 0x106, 0x102–0x105, 0x107).
  --init-cleaning      Initialise as cleaning tape (pages 0x101, 0x106, 0x105).
  --set-barcode BARCODE  Set MAM barcode in Application Specific Data (page 0x200); max 32 ASCII chars.
  --set-cleaning-tape  Set Cartridge Type to cleaning (bytes 86–87); recomputes Cartridge Manufacturer CRC.
  --reset-clean-usage  Zero usage counters on cleaning tapes (Cartridge Status 0x105, Usage 0x108–0x10B).

Input: <input_file> or --read (from device). Output: -o <file> (default derived from input).
  --apply              Write patched dump to device (only modified blocks, or all with --full).
  --full               With --apply: write all blocks (use bypass for protected blocks as needed).
  --bypass-write-protection  With --apply: pass to nfc-ltocm to allow writing protected blocks.

Uninitialised cartridges require --init-data or --init-cleaning before other patches.
ECMA-319 Annex D (LTO Cartridge Memory); CRC per section 13.2.
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

# --- GF(256) and ECMA-319 Section 13.2 CRC ------------------------------------
# Field: GF(256) with P(x) = x^8 + x^4 + x^3 + x^2 + 1 (0x11d)
# Primitive element alpha = 0x02
# Generator: G(x) = (x + a^126)(x + a^127)(x + a^128)(x + a^129)
#            = x^4 + a^201 x^3 + a^246 x^2 + a^201 x + 1


def _gf256_build_tables() -> tuple[list[int], list[int]]:
    """Build exp and log tables for GF(256) with primitive 0x11d, generator 0x02."""
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
    """
    Compute 4-byte CRC per ECMA-319 section 13.2 (Protected Record CRC).
    Generator G(x) = x^4 + a^201 x^3 + a^246 x^2 + a^201 x + 1 over GF(256).
    Returns bytes (CRC3, CRC2, CRC1, CRC0) to append in that order.
    """
    g3 = _GF256_EXP[201 % 255]
    g2 = _GF256_EXP[246 % 255]
    g1 = _GF256_EXP[201 % 255]
    # g0 = 1
    r0, r1, r2, r3 = 0, 0, 0, 0
    for d in data:
        t = _gf256_add(d, r3)
        r3 = _gf256_add(r2, _gf256_mul(g3, t))
        r2 = _gf256_add(r1, _gf256_mul(g2, t))
        r1 = _gf256_add(r0, _gf256_mul(g1, t))
        r0 = t
    return bytes([r3, r2, r1, r0])


# --- Dump layout (ECMA-319 Annex D) -------------------------------------------

BLOCK_SIZE = 32
# Block 0: bytes 0-31 (type at 6-7)
# Block 1: bytes 32-63 (write-inhibit at 32, 33)
# Cartridge Manufacturer's Information at address 64 (byte 64); Cartridge Type at offset 22 -> byte 86
ADDR_CART_MFG = 64
OFFSET_CART_TYPE = 22
OFFSET_CART_SERIAL = 12
CART_SERIAL_LEN = 10
CART_MFG_PAGE_SIZE = 64
CART_MFG_CRC_OFFSET = 60  # CRC over bytes 0-59, stored at 60-63
# Protected Page Table at address 36
ADDR_PROTECTED_PTABLE = 36
PAGE_DESCRIPTOR_SIZE = 4
PAGE_ID_EOPT = 0xFFF
PAGE_ID_EMPTY = 0xFFE
PAGE_ID_CARTRIDGE_STATUS = 0x105
PAGE_ID_INIT_DATA = 0x101
PAGE_ID_TAPE_WRITE_PASS = 0x102
PAGE_ID_TAPE_DIRECTORY = 0x103
PAGE_ID_EOD_INFO = 0x104
PAGE_ID_MECHANISM_RELATED = 0x106
PAGE_ID_SUSPENDED_APPEND = 0x107
PAGE_IDS_USAGE = (0x108, 0x109, 0x10A, 0x10B)
PAGE_ID_APP_SPECIFIC = 0x200  # Application Specific Data (MAM barcode)
# MAM barcode in page 0x200: at offset 14, 32 usable ASCII chars (pad 0x20) + 2-byte terminator 0x0FFF = 34 bytes total
MAM_BARCODE_OFFSET = 14
MAM_BARCODE_LEN = 32  # usable characters
MAM_BARCODE_TERMINATOR = bytes([0x0F, 0xFF])
MAM_BARCODE_FIELD_LEN = 32 + len(MAM_BARCODE_TERMINATOR)  # 34
MAM_BARCODE_PAD = 0x20
# Application Specific Data page (0x200) full layout: 1056 bytes, CRC over first 1052 at 1052-1055
APP_SPECIFIC_PAGE_SIZE = 1056
APP_SPECIFIC_CRC_OFFSET = 1052
MAM_SIGNATURE = b"MAM001"
MAM_PARAM_HEADER = bytes([0x08, 0x06, 0x00, 0x20])  # default MAM parameter header
USAGE_PAGE_SIZE = 64
# Cartridge Status and Tape Alert Flags (ECMA-319 D.2.7.2): 32 bytes, CRC over 0-27 at 28-31
CARTRIDGE_STATUS_PAGE_SIZE = 32
CARTRIDGE_STATUS_CRC_OFFSET = 28
CARTRIDGE_STATUS_CRC_LEN = 4
CARTRIDGE_STATUS_DATA_END = 28  # CRC computed over bytes 0-27
# Only zero Tape Alert (4-11), Thread Count (12-15), Cartridge Status (16-17); leave Reserved (18-27) untouched
CARTRIDGE_STATUS_RESET_START = 4
CARTRIDGE_STATUS_RESET_END = 18
# Usage Information page: bytes 0-3 = Page Id, Length; 4-59 = data; 60-63 = CRC
USAGE_DATA_START = 4
USAGE_DATA_END = 60
USAGE_CRC_OFFSET = 60

# LTO-CM type -> number of blocks (from nfc-ltocm.c)
TYPE_TO_BLOCKS = {0x0001: 127, 0x0002: 255, 0x0003: 511}


def get_num_blocks(dump: bytes) -> int:
    """Derive number of blocks from dump size or block 0 type."""
    if len(dump) < 8:
        return 0
    typ = (dump[6] << 8) | dump[7]
    return TYPE_TO_BLOCKS.get(typ, 0) or (len(dump) // BLOCK_SIZE)


def parse_block1(dump: bytes) -> tuple[int, int]:
    """Return (last_write_inhibited_block, block1_protect_flag)."""
    if len(dump) < 34:
        return 0, 0
    return dump[32], dump[33]


def is_block_writable(block: int, last_inhibited: int, block1_protect: int) -> bool:
    """Match nfc-ltocm ltocm_is_block_writable logic."""
    if block <= last_inhibited:
        return False
    if block == 1 and block1_protect == 0x01:
        return False
    return True


def is_cleaning_tape(dump: bytes) -> bool:
    """True if Cartridge Type (byte 86) has bit 7 set (cleaning cartridge)."""
    if len(dump) <= 86:
        return False
    return (dump[ADDR_CART_MFG + OFFSET_CART_TYPE] & 0x80) != 0


def find_page_start(dump: bytes, page_id: int) -> int | None:
    """Return start byte offset of the given page_id (in protected or unprotected table), or None."""
    # Protected table
    off = ADDR_PROTECTED_PTABLE
    while off + PAGE_DESCRIPTOR_SIZE <= len(dump):
        desc = parse_page_descriptor(dump, off)
        if desc is None:
            break
        pid, start_addr = desc
        if pid == page_id:
            return start_addr
        if pid == PAGE_ID_EOPT:
            break
        off += PAGE_DESCRIPTOR_SIZE
    # Unprotected table
    ustart = find_unprotected_table_start(dump)
    if ustart is None or ustart >= len(dump):
        return None
    off = ustart
    while off + PAGE_DESCRIPTOR_SIZE <= len(dump):
        desc = parse_page_descriptor(dump, off)
        if desc is None:
            break
        pid, start_addr = desc
        if pid == page_id:
            return start_addr
        if pid == PAGE_ID_EOPT:
            break
        off += PAGE_DESCRIPTOR_SIZE
    return None


def get_barcode_from_dump(dump: bytes) -> str | None:
    """Extract MAM barcode from Application Specific Data (page 0x200). Reads 34 bytes at offset 14 (32 chars + 0x0FFF terminator), strips trailing 0x20."""
    start = find_page_start(dump, PAGE_ID_APP_SPECIFIC)
    if start is None:
        return None
    sig_start = start + 4
    sig_end = sig_start + 6
    barcode_start = start + MAM_BARCODE_OFFSET
    barcode_end = barcode_start + MAM_BARCODE_FIELD_LEN
    if barcode_end > len(dump):
        return None
    if sig_end <= len(dump) and dump[sig_start:sig_end] != MAM_SIGNATURE:
        return None
    raw = dump[barcode_start:barcode_start + MAM_BARCODE_LEN]
    term = dump[barcode_start + MAM_BARCODE_LEN : barcode_end]
    if term == MAM_BARCODE_TERMINATOR:
        pass
    s = raw.decode("ascii", errors="ignore").rstrip("\x20 ").strip("\x00")
    return s if s else None


def get_file_prefix(dump: bytes) -> str:
    """Filename prefix: barcode (MAM) first, then cartridge serial, then LTO-CM serial in hex."""
    # 1) Barcode from Application Specific Data (page 0x200, MAM)
    barcode = get_barcode_from_dump(dump)
    if barcode:
        s = re.sub(r"[^\w\-]", "_", barcode)
        if s:
            return s[:32]
    # 2) Cartridge Manufacturer's Information at 64; Serial at offset 12, 10 bytes
    start = ADDR_CART_MFG + OFFSET_CART_SERIAL
    end = start + CART_SERIAL_LEN
    if len(dump) >= end:
        raw = dump[start:end]
        s = raw.decode("ascii", errors="ignore").strip().strip("\x00")
        s = re.sub(r"[^\w\-]", "_", s)
        if s:
            return s[:32]
    # 3) Fallback: LTO-CM serial (block 0, bytes 0-3), hex
    if len(dump) >= 4:
        return dump[0:4].hex().upper()
    return "ltocm"


def parse_page_descriptor(data: bytes, offset: int) -> tuple[int, int] | None:
    """Parse 4-byte descriptor: (page_id_12bit, start_address_16bit)."""
    if offset + 4 > len(data):
        return None
    b0, b1, b2, b3 = data[offset], data[offset + 1], data[offset + 2], data[offset + 3]
    page_id = ((b0 & 0x0F) << 8) | b1
    start_addr = (b2 << 8) | b3
    return (page_id, start_addr)


def find_unprotected_table_start(dump: bytes) -> int | None:
    """Return byte offset of Unprotected Page Table (EOPT Start Address in Protected Table)."""
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


def find_usage_page_addresses(dump: bytes) -> dict[int, int]:
    """Return {page_id: start_byte} for Usage Information pages 0x108-0x10B."""
    result = {}
    start = find_unprotected_table_start(dump)
    if start is None or start >= len(dump):
        return result
    off = start
    while off + PAGE_DESCRIPTOR_SIZE <= len(dump):
        desc = parse_page_descriptor(dump, off)
        if desc is None:
            break
        page_id, start_addr = desc
        if page_id == PAGE_ID_EOPT:
            break
        if page_id in PAGE_IDS_USAGE:
            result[page_id] = start_addr
        off += PAGE_DESCRIPTOR_SIZE
    return result


def find_cartridge_status_address(dump: bytes) -> int | None:
    """Return start byte address of Cartridge Status page (0x105) or None."""
    start = find_unprotected_table_start(dump)
    if start is None or start >= len(dump):
        return None
    off = start
    while off + PAGE_DESCRIPTOR_SIZE <= len(dump):
        desc = parse_page_descriptor(dump, off)
        if desc is None:
            break
        page_id, start_addr = desc
        if page_id == PAGE_ID_EOPT:
            break
        if page_id == PAGE_ID_CARTRIDGE_STATUS:
            return start_addr
        off += PAGE_DESCRIPTOR_SIZE
    return None


def is_cartridge_initialised(dump: bytes) -> bool:
    """
    Return True if the cartridge is initialised (ECMA-319 D.2.4).
    Uninitialised cartridge: Unprotected Page Table contains only Empty (0xFFE) and EOPT (0xFFF) descriptors.
    """
    start = find_unprotected_table_start(dump)
    if start is None or start >= len(dump):
        return False
    off = start
    while off + PAGE_DESCRIPTOR_SIZE <= len(dump):
        desc = parse_page_descriptor(dump, off)
        if desc is None:
            break
        page_id, _start_addr = desc
        if page_id == PAGE_ID_EOPT:
            break
        if page_id != PAGE_ID_EMPTY and page_id != PAGE_ID_EOPT:
            return True
        off += PAGE_DESCRIPTOR_SIZE
    return False


# --- Cartridge Status page (0x105) fields for clear-text display (Table D.14) ---
CARTRIDGE_STATUS_FIELDS = [
    (4, 8, "Tape Alert Flags", "hex"),
    (12, 4, "Thread Count", "uint32_be"),
    (16, 2, "Cartridge Status", "uint16_be"),
]


# --- Usage Information fields (Table D.15) for clear-text display --------------
USAGE_FIELDS = [
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
]


def format_usage_field(page: bytes, start: int, length: int, fmt: str) -> str:
    end = start + length
    if end > len(page):
        return "<invalid>"
    raw = page[start:end]
    if fmt == "ascii":
        return raw.decode("ascii", errors="replace").strip().strip("\x00") or "(empty)"
    if fmt == "hex":
        return raw.hex()
    if fmt == "uint16_le":
        return str(int.from_bytes(raw, "little"))
    if fmt == "uint32_le":
        return str(int.from_bytes(raw, "little"))
    if fmt == "uint64_le":
        return str(int.from_bytes(raw, "little"))
    if fmt == "uint16_be":
        return str(int.from_bytes(raw, "big"))
    if fmt == "uint32_be":
        return str(int.from_bytes(raw, "big"))
    return raw.hex()


def format_usage_page_clear(page: bytes) -> list[tuple[str, str]]:
    """Return list of (field_name, value_str) for display."""
    out = []
    for start, length, name, fmt in USAGE_FIELDS:
        out.append((name, format_usage_field(page, start, length, fmt)))
    return out


def format_cartridge_status_clear(page: bytes) -> list[tuple[str, str]]:
    """Return list of (field_name, value_str) for Cartridge Status page display."""
    out = []
    for start, length, name, fmt in CARTRIDGE_STATUS_FIELDS:
        out.append((name, format_usage_field(page, start, length, fmt)))
    return out


def format_cart_type_from_page(page: bytes) -> str:
    """Format Cartridge Type (offset 22, 2 bytes) for display (ECMA-319 D.2.6.1)."""
    if len(page) < 24:
        return "<invalid>"
    b0, b1 = page[22], page[23]
    cleaning = "cleaning cartridge" if (b0 & 0x80) else "data cartridge"
    ultrium = "Ultrium format" if (b1 & 0x01) else "not Ultrium"
    return f"0x{b0:02X}{b1:02X} ({cleaning}, {ultrium})"


# --- Hex diff ------------------------------------------------------------------
# ANSI colors for diff (disabled if NO_COLOR is set)
def _color_enabled() -> bool:
    return os.environ.get("NO_COLOR", "").strip() == ""


def _red(s: str) -> str:
    return f"\033[31m{s}\033[0m" if _color_enabled() else s


def _green(s: str) -> str:
    return f"\033[32m{s}\033[0m" if _color_enabled() else s


def _color_diff_per_char(before_val: str, after_val: str, width: int) -> tuple[str, str]:
    """Build two strings with per-character coloring: red for before chars that differ, green for after."""
    b_pad = (before_val[: width - 3] + "..." if len(before_val) > width else before_val).ljust(width)
    a_pad = (after_val[: width - 3] + "..." if len(after_val) > width else after_val).ljust(width)
    b_out = []
    a_out = []
    for i in range(width):
        bc = b_pad[i]
        ac = a_pad[i]
        if bc != ac:
            b_out.append(_red(bc))
            a_out.append(_green(ac))
        else:
            b_out.append(bc)
            a_out.append(ac)
    return ("".join(b_out), "".join(a_out))


def clear_text_diff_side_by_side(
    before_fields: list[tuple[str, str]],
    after_fields: list[tuple[str, str]],
    name_width: int = 38,
    value_width: int = 28,
) -> str:
    """Format clear-text fields side-by-side with per-character colors: red/green only where values differ."""
    lines = []
    lines.append(f"  {'Field':<{name_width}}  {'Before':<{value_width}}  |  {'After':<{value_width}}")
    lines.append("  " + "-" * (name_width + 2 + value_width) + "  +  " + "-" * value_width)
    for (b_name, b_val), (a_name, a_val) in zip(before_fields, after_fields):
        b_show, a_show = _color_diff_per_char(b_val, a_val, value_width)
        lines.append(f"  {b_name:<{name_width}}  {b_show}  |  {a_show}")
    return "\n".join(lines)


def hex_dump(data: bytes, base_addr: int = 0, bytes_per_line: int = 16) -> str:
    """Produce xxd-style hex dump lines."""
    lines = []
    for i in range(0, len(data), bytes_per_line):
        chunk = data[i : i + bytes_per_line]
        addr = base_addr + i
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{addr:04x}: {hex_part:<{bytes_per_line * 3 - 1}}  {ascii_part}")
    return "\n".join(lines)


def hex_diff_side_by_side(before: bytes, after: bytes, base_addr: int = 0, bytes_per_line: int = 16) -> str:
    """Produce a side-by-side hex diff with colors: red for old bytes, green for new (when different)."""
    lines = []
    width = bytes_per_line * 3 - 1  # width of one hex column "xx xx xx ..."
    for i in range(0, max(len(before), len(after)), bytes_per_line):
        b_chunk = before[i : i + bytes_per_line]
        a_chunk = after[i : i + bytes_per_line]
        addr = base_addr + i
        b_parts = []
        a_parts = []
        for j in range(len(b_chunk)):
            b_byte = b_chunk[j] if j < len(b_chunk) else 0
            a_byte = a_chunk[j] if j < len(a_chunk) else 0
            b_s = f"{b_byte:02x}"
            a_s = f"{a_byte:02x}"
            if b_byte != a_byte:
                b_parts.append(_red(b_s))
                a_parts.append(_green(a_s))
            else:
                b_parts.append(b_s)
                a_parts.append(a_s)
        b_hex = " ".join(b_parts)
        a_hex = " ".join(a_parts)
        lines.append(f"  {addr:04x}:  {b_hex:<{width}}  |  {a_hex:<{width}}")
    return "\n".join(lines) if lines else "(no change)"


def hex_diff(before: bytes, after: bytes, base_addr: int = 0) -> str:
    """Produce a side-by-side hex diff with colors (delegate to hex_diff_side_by_side)."""
    return hex_diff_side_by_side(before, after, base_addr)


# --- Initialisation (ECMA-319 D.2.4, D.2.8) -----------------------------------
INIT_DATA_PAGE_SIZE = 64
TAPE_WRITE_PASS_PAGE_SIZE = 48
TAPE_DIRECTORY_PAGE_SIZE = 1552
EOD_INFO_PAGE_SIZE = 64
MECHANISM_RELATED_PAGE_SIZE = 384  # 2+2+8+368+4 per ECMA-319
SUSPENDED_APPEND_PAGE_SIZE = 128
# Required page IDs for initialised cartridge (RI in D.2.4) and their sizes; 0x103 needs 16-byte alignment.
# Mechanism Related (0x106) required for both; Init Data uses Drive Id / Mfg from reference (e.g. CLNU05CU.bin).
REQUIRED_INIT_PAGES = (
    (PAGE_ID_INIT_DATA, INIT_DATA_PAGE_SIZE, 32),
    (PAGE_ID_MECHANISM_RELATED, MECHANISM_RELATED_PAGE_SIZE, 32),
    (PAGE_ID_TAPE_WRITE_PASS, TAPE_WRITE_PASS_PAGE_SIZE, 32),
    (PAGE_ID_TAPE_DIRECTORY, TAPE_DIRECTORY_PAGE_SIZE, 16),
    (PAGE_ID_EOD_INFO, EOD_INFO_PAGE_SIZE, 32),
    (PAGE_ID_CARTRIDGE_STATUS, CARTRIDGE_STATUS_PAGE_SIZE, 32),
    (PAGE_ID_SUSPENDED_APPEND, SUSPENDED_APPEND_PAGE_SIZE, 32),
)
# Cleaning tapes: only Initialisation Data (0x101), Mechanism Related (0x106), Cartridge Status (0x105).
REQUIRED_INIT_PAGES_CLEANING = (
    (PAGE_ID_INIT_DATA, INIT_DATA_PAGE_SIZE, 32),
    (PAGE_ID_MECHANISM_RELATED, MECHANISM_RELATED_PAGE_SIZE, 32),
    (PAGE_ID_CARTRIDGE_STATUS, CARTRIDGE_STATUS_PAGE_SIZE, 32),
)
INIT_TABLE_SIZE = 64  # bytes; 32-byte aligned
# Reference content from CLNU05CU.bin (Initialisation Data 0x101 and Mechanism Related 0x106), embedded so correct data is written even when the dump file is absent.
REF_INIT_DATA_101 = (
    b"\x01\x01\x00@LTO-UCC1HU10828LM4\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00HP      \x00\x00\x00\x00\xb9\n\x8f\xf5"
)
assert len(REF_INIT_DATA_101) == 64
# Mechanism Related page 0x106 (384 bytes) from CLNU05CU.bin
REF_MECHANISM_106 = bytes.fromhex(
    "01060180485020202020202000000000000000000000000000000000000000000000000000000002"
    "0000004d000001b5000000000000000100000000242023de0000000000000000e2fb80a700000000"
    "00000000000000000000000000000000000000000000000000000000000000000000000000000000"
    "00000000000000000000000000000000000000000000000000000000000000000000000000000000"
    "00000000000000000000000000000000000000000000000000000000000000000000000000000000"
    "00000000000000000000000000000000000000000000000000000000000000020000004e000001c1"
    "000000000000000100000000275e24cf000000000b00000026857bf3000000000000000000000000"
    "00000000000000000000000000000000000000000000000000000000000000000000000000000000"
    "00000000000000000000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000dc7cb7bf"
)
assert len(REF_MECHANISM_106) == 384
INIT_DATA_FORMAT_TYPE_CLEANING = 1  # Format Type at offset 22: 1 for cleaning; 0 for data tape


def _write_page_descriptor(data: bytearray, offset: int, page_id: int, start_addr: int) -> None:
    """Write one 4-byte page descriptor (Table D.7). Version=0."""
    data[offset] = (page_id >> 8) & 0x0F
    data[offset + 1] = page_id & 0xFF
    data[offset + 2] = (start_addr >> 8) & 0xFF
    data[offset + 3] = start_addr & 0xFF


def _parse_unprotected_table(dump: bytes, ustart: int) -> tuple[list[tuple[int, int]], int]:
    """
    Parse Unprotected Page Table. Return (list of (page_id, start_addr) in order, eopt_start).
    Stops at EOPT; eopt_start is the EOPT descriptor's start address (one past last page).
    """
    descriptors: list[tuple[int, int]] = []
    eopt_start = ustart + 64  # fallback
    off = ustart
    while off + PAGE_DESCRIPTOR_SIZE <= len(dump):
        desc = parse_page_descriptor(dump, off)
        if desc is None:
            break
        page_id, start_addr = desc
        descriptors.append((page_id, start_addr))
        if page_id == PAGE_ID_EOPT:
            eopt_start = start_addr
            break
        off += PAGE_DESCRIPTOR_SIZE
    return descriptors, eopt_start


def _write_init_page(
    dump: bytearray,
    page_id: int,
    start: int,
    size: int,
    *,
    init_cleaning: bool = False,
) -> None:
    """Write one initialised page at start. For 0x101 uses embedded REF_INIT_DATA_101 (Drive Id HU10828LM4, Mfg LTO-UCC1) and sets Format Type 1 (cleaning) or 0 (data). For 0x106 uses embedded REF_MECHANISM_106."""
    dump[start : start + 2] = (page_id).to_bytes(2, "big")
    if page_id == PAGE_ID_INIT_DATA:
        dump[start : start + 64] = REF_INIT_DATA_101
        format_type = INIT_DATA_FORMAT_TYPE_CLEANING if init_cleaning else 0
        dump[start + 22 : start + 24] = format_type.to_bytes(2, "big")
        dump[start + 60 : start + 64] = ecma319_crc4(dump[start : start + 60])
    elif page_id == PAGE_ID_TAPE_WRITE_PASS:
        dump[start + 2 : start + 4] = (0x0030).to_bytes(2, "big")
        dump[start + 4 : start + 48] = bytes(44)
    elif page_id == PAGE_ID_TAPE_DIRECTORY:
        dump[start + 2 : start + 4] = (0x0610).to_bytes(2, "big")
        dump[start + 4 : start + 16] = bytes(12)
        for i in range(96):
            off = start + 16 + i * 16
            dump[off : off + 4] = (0xFFFFFFFF).to_bytes(4, "big")
            dump[off + 4 : off + 12] = bytes(8)
            dump[off + 12 : off + 16] = ecma319_crc4(dump[off : off + 12])
    elif page_id == PAGE_ID_EOD_INFO:
        dump[start + 2 : start + 4] = (0x0040).to_bytes(2, "big")
        dump[start + 4 : start + 60] = bytes(56)
        dump[start + 60 : start + 64] = ecma319_crc4(dump[start : start + 60])
    elif page_id == PAGE_ID_CARTRIDGE_STATUS:
        dump[start + 2 : start + 4] = (0x0020).to_bytes(2, "big")
        dump[start + 4 : start + 28] = bytes(24)
        dump[start + 28 : start + 32] = ecma319_crc4(dump[start : start + 28])
    elif page_id == PAGE_ID_SUSPENDED_APPEND:
        dump[start + 2 : start + 4] = (0x0080).to_bytes(2, "big")
        dump[start + 4 : start + 124] = bytes(120)
        dump[start + 124 : start + 128] = ecma319_crc4(dump[start : start + 124])
    elif page_id == PAGE_ID_MECHANISM_RELATED:
        dump[start : start + MECHANISM_RELATED_PAGE_SIZE] = REF_MECHANISM_106


def build_and_apply_init(dump: bytearray, ustart: int, init_cleaning: bool) -> set[int] | None:
    """
    Add only missing required pages; preserve existing pages and manufacturer data.
    init_cleaning: if True use only 0x101, 0x106, 0x105 (cleaning tape); if False use full set (data tape).
    Init Data and Mechanism Related content are taken from embedded reference (CLNU05CU.bin).
    Returns set of block indices modified, or None on failure.
    """
    if ustart + INIT_TABLE_SIZE > len(dump):
        return None
    modified_blocks: set[int] = set()

    required_pages = REQUIRED_INIT_PAGES_CLEANING if init_cleaning else REQUIRED_INIT_PAGES
    descriptors, eopt_start = _parse_unprotected_table(dump, ustart)
    existing_ids = {pid for pid, _ in descriptors if pid not in (PAGE_ID_EMPTY, PAGE_ID_EOPT)}
    # Keep existing (page_id, start_addr) in order, excluding Empty and EOPT
    existing_entries = [(pid, addr) for pid, addr in descriptors if pid not in (PAGE_ID_EMPTY, PAGE_ID_EOPT)]
    required_ids = {pid for pid, _, _ in required_pages}
    missing_ids = required_ids - existing_ids
    if not missing_ids:
        return set()

    # Place missing pages after eopt_start with correct alignment
    next_addr = eopt_start
    new_entries: list[tuple[int, int]] = []
    for page_id, size, align in required_pages:
        if page_id not in missing_ids:
            continue
        next_addr = ((next_addr + align - 1) // align) * align
        if next_addr + size > len(dump):
            return None
        _write_init_page(dump, page_id, next_addr, size, init_cleaning=init_cleaning)
        new_entries.append((page_id, next_addr))
        for b in range(next_addr // BLOCK_SIZE, (next_addr + size + BLOCK_SIZE - 1) // BLOCK_SIZE):
            modified_blocks.add(b)
        next_addr += size
    new_eopt_start = next_addr

    # Build new table: existing entries + new entries + EOPT + Empty padding to 64 bytes + CRC
    all_entries = existing_entries + new_entries
    table_descriptor_count = (INIT_TABLE_SIZE - 4) // 4  # 15 slots; last 4 bytes = CRC
    slot = 0
    for pid, addr in all_entries:
        _write_page_descriptor(dump, ustart + slot * 4, pid, addr)
        slot += 1
    _write_page_descriptor(dump, ustart + slot * 4, PAGE_ID_EOPT, new_eopt_start)
    slot += 1
    while slot < table_descriptor_count:
        _write_page_descriptor(dump, ustart + slot * 4, PAGE_ID_EMPTY, new_eopt_start)
        slot += 1
    crc_len = slot * 4  # 15 slots * 4 = 60 bytes; CRC in last 4 bytes
    crc = ecma319_crc4(dump[ustart : ustart + crc_len])
    dump[ustart + crc_len : ustart + INIT_TABLE_SIZE] = crc
    for b in range(ustart // BLOCK_SIZE, (ustart + INIT_TABLE_SIZE + BLOCK_SIZE - 1) // BLOCK_SIZE):
        modified_blocks.add(b)

    return modified_blocks


# --- Reset clean usage patch ---------------------------------------------------
def patch_reset_cartridge_status(dump: bytearray, addr: int) -> tuple[bytes, bytes] | None:
    """
    Zero Tape Alert, Thread Count, Cartridge Status (bytes 4-17) in Cartridge Status page (0x105).
    Reserved (18-27) are left unchanged. CRC over 0-27 is recomputed. Returns (before, after) or None.
    """
    if addr + CARTRIDGE_STATUS_PAGE_SIZE > len(dump):
        return None
    before = bytes(dump[addr : addr + CARTRIDGE_STATUS_PAGE_SIZE])
    for i in range(CARTRIDGE_STATUS_RESET_START, CARTRIDGE_STATUS_RESET_END):
        dump[addr + i] = 0
    new_crc = ecma319_crc4(dump[addr : addr + CARTRIDGE_STATUS_DATA_END])
    for j, b in enumerate(new_crc):
        dump[addr + CARTRIDGE_STATUS_CRC_OFFSET + j] = b
    after = bytes(dump[addr : addr + CARTRIDGE_STATUS_PAGE_SIZE])
    return (before, after)


def patch_reset_clean_usage(dump: bytearray, usage_addrs: dict[int, int]) -> list[tuple[int, bytes, bytes]]:
    """
    Zero usage data (bytes 4-59) in each Usage Information page and recompute CRC.
    Returns list of (page_id, before_64bytes, after_64bytes) for modified pages.
    """
    modified = []
    for page_id in sorted(usage_addrs.keys()):
        addr = usage_addrs[page_id]
        if addr + USAGE_PAGE_SIZE > len(dump):
            continue
        before = bytes(dump[addr : addr + USAGE_PAGE_SIZE])
        # Keep Page Id and Page Length (0-3), zero 4-59, then CRC
        for i in range(USAGE_DATA_START, USAGE_DATA_END):
            dump[addr + i] = 0
        new_crc = ecma319_crc4(dump[addr : addr + USAGE_DATA_END])
        for j, b in enumerate(new_crc):
            dump[addr + USAGE_CRC_OFFSET + j] = b
        after = bytes(dump[addr : addr + USAGE_PAGE_SIZE])
        modified.append((page_id, before, after))
    return modified


def patch_set_cleaning_tape(dump: bytearray) -> tuple[bytes, bytes] | None:
    """
    Set Cartridge Type (ECMA-319 D.2.6.1) to cleaning tape: bytes 86-87 = 0x80 0x01.
    Recomputes CRC over bytes 0-59 of Cartridge Manufacturer's Information page.
    Returns (before_64bytes, after_64bytes) for the page, or None if dump too short.
    """
    if len(dump) < ADDR_CART_MFG + CART_MFG_PAGE_SIZE:
        return None
    before = bytes(dump[ADDR_CART_MFG : ADDR_CART_MFG + CART_MFG_PAGE_SIZE])
    dump[ADDR_CART_MFG + OFFSET_CART_TYPE] = 0x80
    dump[ADDR_CART_MFG + OFFSET_CART_TYPE + 1] = 0x01
    new_crc = ecma319_crc4(dump[ADDR_CART_MFG : ADDR_CART_MFG + CART_MFG_CRC_OFFSET])
    for j, b in enumerate(new_crc):
        dump[ADDR_CART_MFG + CART_MFG_CRC_OFFSET + j] = b
    after = bytes(dump[ADDR_CART_MFG : ADDR_CART_MFG + CART_MFG_PAGE_SIZE])
    return (before, after)


# --- Application Specific Data (0x200) MAM barcode ---------------------------------
def _barcode_to_bytes(barcode: str) -> bytes:
    """Encode barcode to ASCII, truncate to MAM_BARCODE_LEN (32), pad right with 0x20, then append 0x0FFF terminator."""
    raw = barcode.encode("ascii", errors="replace")
    if len(raw) >= MAM_BARCODE_LEN:
        payload = raw[:MAM_BARCODE_LEN]
    else:
        payload = raw + bytes([MAM_BARCODE_PAD] * (MAM_BARCODE_LEN - len(raw)))
    return payload + MAM_BARCODE_TERMINATOR


def _write_mam_page(dump: bytearray, start: int, barcode: str) -> None:
    """Write full Application Specific Data page (0x200) at start: MAM001, header, barcode (19 bytes, pad 0x20), zeros, CRC."""
    dump[start : start + 2] = (PAGE_ID_APP_SPECIFIC).to_bytes(2, "big")
    dump[start + 2 : start + 4] = (APP_SPECIFIC_PAGE_SIZE).to_bytes(2, "big")
    dump[start + 4 : start + 10] = MAM_SIGNATURE
    dump[start + 10 : start + 14] = MAM_PARAM_HEADER
    dump[start + 14 : start + 14 + MAM_BARCODE_FIELD_LEN] = _barcode_to_bytes(barcode)
    dump[start + 14 + MAM_BARCODE_FIELD_LEN : start + APP_SPECIFIC_CRC_OFFSET] = bytes(
        APP_SPECIFIC_CRC_OFFSET - 14 - MAM_BARCODE_FIELD_LEN
    )
    dump[start + APP_SPECIFIC_CRC_OFFSET : start + APP_SPECIFIC_PAGE_SIZE] = ecma319_crc4(
        dump[start : start + APP_SPECIFIC_CRC_OFFSET]
    )


def patch_set_mam_barcode(dump: bytearray, barcode: str) -> tuple[bytes, bytes] | None:
    """
    Set MAM barcode in Application Specific Data page (0x200) if present. Padding 0x20, max 19 chars.
    Returns (before_slice, after_slice) for barcode region or None if page missing/invalid.
    """
    start = find_page_start(dump, PAGE_ID_APP_SPECIFIC)
    if start is None:
        return None
    if start + APP_SPECIFIC_PAGE_SIZE > len(dump):
        return None
    if dump[start + 4 : start + 10] != MAM_SIGNATURE:
        return None
    barcode_end = start + 14 + MAM_BARCODE_FIELD_LEN
    before = bytes(dump[start + 14 : barcode_end])
    dump[start + 14 : barcode_end] = _barcode_to_bytes(barcode)
    dump[start + APP_SPECIFIC_CRC_OFFSET : start + APP_SPECIFIC_PAGE_SIZE] = ecma319_crc4(
        dump[start : start + APP_SPECIFIC_CRC_OFFSET]
    )
    after = bytes(dump[start + 14 : barcode_end])
    return (before, after)


def ensure_app_specific_page(dump: bytearray, ustart: int, barcode: str) -> set[int] | None:
    """
    If page 0x200 is not in the Unprotected Page Table, add it and write full MAM page at eopt_start.
    Returns set of block indices modified, or None on failure (e.g. no space).
    """
    if ustart + INIT_TABLE_SIZE > len(dump):
        return None
    descriptors, eopt_start = _parse_unprotected_table(dump, ustart)
    existing_ids = {pid for pid, _ in descriptors if pid not in (PAGE_ID_EMPTY, PAGE_ID_EOPT)}
    if PAGE_ID_APP_SPECIFIC in existing_ids:
        return set()
    align = 32
    next_addr = ((eopt_start + align - 1) // align) * align
    if next_addr + APP_SPECIFIC_PAGE_SIZE > len(dump):
        return None
    modified_blocks: set[int] = set()
    _write_mam_page(dump, next_addr, barcode)
    for b in range(
        next_addr // BLOCK_SIZE,
        (next_addr + APP_SPECIFIC_PAGE_SIZE + BLOCK_SIZE - 1) // BLOCK_SIZE,
    ):
        modified_blocks.add(b)
    existing_entries = [(pid, addr) for pid, addr in descriptors if pid not in (PAGE_ID_EMPTY, PAGE_ID_EOPT)]
    new_eopt_start = next_addr + APP_SPECIFIC_PAGE_SIZE
    all_entries = existing_entries + [(PAGE_ID_APP_SPECIFIC, next_addr)]
    table_descriptor_count = (INIT_TABLE_SIZE - 4) // 4
    slot = 0
    for pid, addr in all_entries:
        _write_page_descriptor(dump, ustart + slot * 4, pid, addr)
        slot += 1
    _write_page_descriptor(dump, ustart + slot * 4, PAGE_ID_EOPT, new_eopt_start)
    slot += 1
    while slot < table_descriptor_count:
        _write_page_descriptor(dump, ustart + slot * 4, PAGE_ID_EMPTY, new_eopt_start)
        slot += 1
    crc_len = slot * 4
    crc = ecma319_crc4(dump[ustart : ustart + crc_len])
    dump[ustart + crc_len : ustart + INIT_TABLE_SIZE] = crc
    for b in range(ustart // BLOCK_SIZE, (ustart + INIT_TABLE_SIZE + BLOCK_SIZE - 1) // BLOCK_SIZE):
        modified_blocks.add(b)
    return modified_blocks


# --- nfc-ltocm CLI -------------------------------------------------------------
def run_nfc_ltocm(args: list[str], capture_output: bool = True, verbose: bool = False) -> subprocess.CompletedProcess:
    """Run nfc-ltocm with given args. Prefer executable in same dir as script. If verbose, print the command."""
    exe = Path(__file__).resolve().parent / "nfc-ltocm"
    if not exe.is_file():
        exe = Path("nfc-ltocm")
    cmd = [str(exe)] + args
    if verbose:
        print("  $", " ".join(cmd), flush=True)
    return subprocess.run(cmd, capture_output=capture_output, timeout=120)


def read_dump_from_device(output_path: str | Path, verbose: bool = False) -> bool:
    """Read LTO-CM from device into output_path. Return True on success."""
    r = run_nfc_ltocm([str(output_path)], verbose=verbose)
    if r.returncode != 0:
        if r.stderr:
            sys.stderr.write(r.stderr.decode("utf-8", errors="replace"))
        return False
    return True


def write_block_to_device(
    block: int,
    block_data: bytes,
    verbose: bool = False,
    bypass_write_protection: bool = False,
) -> bool:
    """Write 32-byte block_data to LTO-CM at block index. Return True on success."""
    assert len(block_data) == BLOCK_SIZE
    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
        f.write(block_data)
        path = f.name
    try:
        args = []
        if bypass_write_protection:
            args.append("--bypass-write-protection")
        args.extend(["--write-block", str(block), path])
        r = run_nfc_ltocm(args, verbose=verbose)
        return r.returncode == 0
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def verify_dump_from_device(verbose: bool = False) -> bytes | None:
    """Read full LTO-CM from device into memory. Return bytes or None on failure."""
    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
        path = f.name
    try:
        if not read_dump_from_device(path, verbose=verbose):
            return None
        with open(path, "rb") as f:
            return f.read()
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def _progress_bar(current: int, total: int, width: int = 32, prefix: str = "", use_cr: bool = True) -> str:
    """Return a single progress bar line. use_cr=False for one line per block (no overwrite)."""
    if total <= 0:
        return f"{prefix} 0/0"
    pct = current / total
    filled = min(int(width * pct), width)
    bar = "=" * filled + (">" if filled < width else "") + " " * (width - filled - 1)
    line = f"{prefix}[{bar}] {current}/{total} ({100 * pct:.0f}%)"
    return f"\r{line}" if use_cr else line


# --- Main flow -----------------------------------------------------------------
def main() -> int:
    parser = argparse.ArgumentParser(
        description="Patch LTO-CM dumps: reset clean usage on cleaning tapes, optional write-back with verify.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Examples:\n"
        "  %(prog)s --read --init-cleaning -o out.bin (initialise uninitialised cleaning tape)\n"
        "  %(prog)s dump.bin --init-data --apply     (init data tape then write to device)\n"
        "  %(prog)s --read --reset-clean-usage -o out.bin\n"
        "  %(prog)s CLNU05CU.bin --reset-clean-usage\n"
        "  %(prog)s 2091207173_original.bin --set-cleaning-tape -o 2091207173_patched.bin\n"
        "  %(prog)s dump.bin --set-barcode CLNU05CU -o out.bin\n"
        "  %(prog)s --read --reset-clean-usage --apply\n",
    )
    parser.add_argument("input_file", nargs="?", help="Input dump file (.bin)")
    parser.add_argument("--read", action="store_true", help="Read dump from NFC device instead of file")
    parser.add_argument("--reset-clean-usage", action="store_true", help="Reset usage counters on cleaning tapes")
    parser.add_argument(
        "--set-cleaning-tape",
        action="store_true",
        help="Set Cartridge Type to cleaning tape (ECMA-319 D.2.6.1). Recomputes Cartridge Manufacturer page CRC. Modifies protected blocks 2-3; write with --apply may fail on initialised cartridges.",
    )
    parser.add_argument("-o", "--output", dest="output", metavar="FILE", help="Patched dump output file")
    parser.add_argument("--apply", action="store_true", help="Write patched dump to device and verify")
    parser.add_argument("-v", "--verbose", action="store_true", help="Print each nfc-ltocm command before running")
    parser.add_argument("-f", "--force", action="store_true", help="On --apply: continue writing blocks on error; list failed blocks at end")
    parser.add_argument("--full", action="store_true", help="On --apply: write all writable blocks; default is to write only modified blocks")
    parser.add_argument(
        "--bypass-write-protection",
        action="store_true",
        help="On --apply: ignore write-inhibit and write any block (including protected blocks 0-1 and those below Last Write-Inhibited). Passed to nfc-ltocm.",
    )
    parser.add_argument(
        "--init-data",
        action="store_true",
        help="Initialise as data tape: Unprotected Page Table and pages 0x101, 0x106, 0x102–0x105, 0x107. Init Data and Mechanism Related from embedded reference (CLNU05CU.bin); Format Type 0. Required before other patches if uninitialised.",
    )
    parser.add_argument(
        "--init-cleaning",
        action="store_true",
        help="Initialise as cleaning tape: Unprotected Page Table and pages 0x101, 0x106, 0x105. Init Data and Mechanism Related from embedded reference (CLNU05CU.bin). Required before other patches if uninitialised.",
    )
    parser.add_argument(
        "--set-barcode",
        dest="set_barcode",
        metavar="BARCODE",
        default=None,
        help="Set MAM barcode in Application Specific Data (page 0x200). Up to 32 ASCII chars; padding 0x20, terminator 0x0FFF. Creates page if missing (requires initialised cartridge).",
    )
    args = parser.parse_args()

    if not args.read and not args.input_file:
        parser.error("Either provide input_file or use --read")
    if args.read and args.input_file:
        parser.error("Use either --read or input_file, not both")
    if not args.reset_clean_usage and not args.set_cleaning_tape and not args.apply and not args.init_data and not args.init_cleaning and args.set_barcode is None:
        parser.error("Specify at least one of --reset-clean-usage, --set-cleaning-tape, --init-data, --init-cleaning, --set-barcode, or --apply (with a patched file)")
    if args.init_data and args.init_cleaning:
        parser.error("Specify only one of --init-data or --init-cleaning")
    if args.set_barcode is not None:
        try:
            args.set_barcode.encode("ascii")
        except UnicodeEncodeError:
            parser.error("--set-barcode must be ASCII only")
        if len(args.set_barcode) > MAM_BARCODE_LEN:
            parser.error(f"--set-barcode: max {MAM_BARCODE_LEN} characters")

    # Load dump
    if args.read:
        print("Reading LTO-CM from device...")
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
            tmp_path = f.name
        try:
            if not read_dump_from_device(tmp_path, verbose=args.verbose):
                print("Error: failed to read from device.", file=sys.stderr)
                return 1
            with open(tmp_path, "rb") as f:
                dump = bytearray(f.read())
        finally:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
        prefix = get_file_prefix(dump)
        original_path = f"{prefix}_original.bin"
        if not Path(original_path).exists():
            with open(original_path, "wb") as f:
                f.write(dump)
            print(f"Original saved (never overwritten): {original_path}")
        backup_path = f"{prefix}_backup.bin"
        with open(backup_path, "wb") as f:
            f.write(dump)
        print(f"Backup saved: {backup_path}")
        if not args.output:
            args.output = f"{prefix}_patched.bin"
    else:
        path = Path(args.input_file)
        if not path.is_file():
            print(f"Error: file not found: {path}", file=sys.stderr)
            return 1
        with open(path, "rb") as f:
            dump = bytearray(f.read())
        prefix = get_file_prefix(dump)
        if not args.output:
            args.output = path.stem + "_patched.bin" if path.suffix else str(path) + "_patched.bin"

    num_blocks = get_num_blocks(dump)
    if num_blocks == 0 or len(dump) < num_blocks * BLOCK_SIZE:
        print("Error: invalid or truncated dump (size or type).", file=sys.stderr)
        return 1

    last_inhibited, block1_protect = parse_block1(dump)
    usage_addrs = find_usage_page_addresses(dump)
    cartridge_status_addr = find_cartridge_status_address(dump)
    cleaning = is_cleaning_tape(dump)
    initialised = is_cartridge_initialised(dump)

    if not initialised and not args.init_data and not args.init_cleaning:
        if args.reset_clean_usage or args.set_cleaning_tape or args.apply:
            print(
                "Error: cartridge is uninitialised (no Initialisation Data or other required pages in Unprotected Page Table). "
                "Run with --init-data or --init-cleaning first, then you can apply other patches.",
                file=sys.stderr,
            )
            return 1
        if args.set_barcode is not None and find_page_start(dump, PAGE_ID_APP_SPECIFIC) is None:
            print(
                "Error: cartridge is uninitialised and Application Specific Data (0x200) is missing. "
                "Run with --init-data or --init-cleaning first to create the page table, then --set-barcode.",
                file=sys.stderr,
            )
            return 1

    # Block indices touched by patches (for --apply without --full)
    modified_block_indices: set[int] = set()

    if args.init_data or args.init_cleaning:
        # Build and apply initialisation: Unprotected Page Table + required pages (ECMA-319 D.2.4, D.2.8).
        ustart = find_unprotected_table_start(dump)
        if ustart is None or ustart >= len(dump):
            print("Error: cannot find Unprotected Page Table start; dump may be invalid.", file=sys.stderr)
            return 1
        init_result = build_and_apply_init(dump, ustart, init_cleaning=args.init_cleaning)
        if init_result is None:
            print("Error: initialisation build failed (e.g. dump too short).", file=sys.stderr)
            return 1
        for block_index in init_result:
            modified_block_indices.add(block_index)
        mode = "cleaning tape (0x101, 0x106, 0x105)" if args.init_cleaning else "data tape (0x101–0x105, 0x106, 0x107)"
        print("\n--- Initialisation applied (Unprotected Page Table and required pages for " + mode + ") ---")
        print(f"Modified blocks: {sorted(modified_block_indices)}")

    if args.reset_clean_usage:
        if not cleaning:
            print("Warning: cartridge is not a cleaning tape; skipping reset clean usage.")
        else:
            # Reset Cartridge Status page (0x105): Thread Count and Tape Alert Flags (cleaning "use" count)
            if cartridge_status_addr is not None:
                result = patch_reset_cartridge_status(dump, cartridge_status_addr)
                if result is not None:
                    addr = cartridge_status_addr
                    end = addr + CARTRIDGE_STATUS_PAGE_SIZE
                    for bo in range(addr // BLOCK_SIZE, (end - 1) // BLOCK_SIZE + 1):
                        modified_block_indices.add(bo)
                    before, after = result
                    print("\n--- Cartridge Status and Tape Alert Flags (0x105) (before -> after) ---")
                    print(clear_text_diff_side_by_side(
                        format_cartridge_status_clear(before),
                        format_cartridge_status_clear(after),
                    ))
                    print("Hex diff:")
                    print(hex_diff(before, after))
            # Reset Usage Information pages (0x108-0x10B) if present
            if usage_addrs:
                modified = patch_reset_clean_usage(dump, usage_addrs)
                for page_id, before, after in modified:
                    addr = usage_addrs[page_id]
                    end = addr + USAGE_PAGE_SIZE
                    for bo in range(addr // BLOCK_SIZE, (end - 1) // BLOCK_SIZE + 1):
                        modified_block_indices.add(bo)
                    print(f"\n--- Usage Information page 0x{page_id:03X} (before -> after) ---")
                    print(clear_text_diff_side_by_side(
                        format_usage_page_clear(before),
                        format_usage_page_clear(after),
                    ))
                    print("Hex diff:")
                    print(hex_diff(before, after))
            if cartridge_status_addr is None and not usage_addrs:
                print("Warning: no Cartridge Status (0x105) or Usage Information pages found; nothing to reset.")

    if args.set_cleaning_tape:
        result = patch_set_cleaning_tape(dump)
        if result is not None:
            before_page, after_page = result
            for bo in range(ADDR_CART_MFG // BLOCK_SIZE, (ADDR_CART_MFG + CART_MFG_PAGE_SIZE - 1) // BLOCK_SIZE + 1):
                modified_block_indices.add(bo)
            before_fields = [("Cartridge Type", format_cart_type_from_page(before_page))]
            after_fields = [("Cartridge Type", format_cart_type_from_page(after_page))]
            print("\n--- Cartridge Manufacturer's Information (before -> after) ---")
            print(clear_text_diff_side_by_side(before_fields, after_fields))
            print("Hex diff:")
            print(hex_diff(before_page, after_page, base_addr=ADDR_CART_MFG))
        else:
            print("Warning: dump too short; skipping set cleaning tape.")

    if args.set_barcode is not None:
        app_start = find_page_start(dump, PAGE_ID_APP_SPECIFIC)
        if app_start is not None:
            result = patch_set_mam_barcode(dump, args.set_barcode)
            if result is not None:
                for bo in range(
                    app_start // BLOCK_SIZE,
                    (app_start + APP_SPECIFIC_PAGE_SIZE + BLOCK_SIZE - 1) // BLOCK_SIZE,
                ):
                    modified_block_indices.add(bo)
                before_bc, after_bc = result
                print("\n--- Application Specific Data (0x200) MAM barcode ---")
                print(f"Barcode set to: {args.set_barcode!r}")
                print("Hex diff (barcode field):")
                print(hex_diff(before_bc, after_bc, base_addr=MAM_BARCODE_OFFSET))
            else:
                # Page exists but invalid or too short (e.g. no MAM001, or dump truncated): overwrite with full MAM page
                need_len = app_start + APP_SPECIFIC_PAGE_SIZE
                if need_len > len(dump):
                    dump.extend(bytes(need_len - len(dump)))
                _write_mam_page(dump, app_start, args.set_barcode)
                for bo in range(
                    app_start // BLOCK_SIZE,
                    (app_start + APP_SPECIFIC_PAGE_SIZE + BLOCK_SIZE - 1) // BLOCK_SIZE,
                ):
                    modified_block_indices.add(bo)
                print("\n--- Application Specific Data (0x200) MAM barcode (page rewritten) ---")
                print(f"Barcode set to: {args.set_barcode!r}")
        else:
            ustart = find_unprotected_table_start(dump)
            if ustart is None or ustart >= len(dump):
                print("Error: cannot find Unprotected Page Table; cannot create Application Specific Data page.", file=sys.stderr)
                return 1
            ensure_blocks = ensure_app_specific_page(dump, ustart, args.set_barcode)
            if ensure_blocks is None:
                print("Error: not enough space to add Application Specific Data page (0x200).", file=sys.stderr)
                return 1
            for bo in ensure_blocks:
                modified_block_indices.add(bo)
            print("\n--- Application Specific Data (0x200) created with MAM barcode ---")
            print(f"Barcode set to: {args.set_barcode!r}")
            print(f"Modified blocks: {sorted(ensure_blocks)}")

    # Save patched dump (when --read, output filename has prefix unless already present)
    out_path = args.output
    if args.read and prefix:
        p = Path(out_path)
        if not p.stem.startswith(prefix):
            out_path = str(p.parent / f"{prefix}_{p.stem}.bin")
    with open(out_path, "wb") as f:
        f.write(dump)
    print(f"\nPatched dump saved: {out_path}")

    if args.apply:
        if args.set_cleaning_tape and (2 in modified_block_indices or 3 in modified_block_indices):
            print("Note: --set-cleaning-tape modified protected blocks 2-3; write may fail on initialised cartridges.", file=sys.stderr)
        if args.bypass_write_protection:
            writable = list(range(num_blocks)) if args.full else sorted(modified_block_indices)
            print("Note: --bypass-write-protection enabled; writing may include protected blocks.", file=sys.stderr)
        else:
            writable_all = [
                b
                for b in range(num_blocks)
                if is_block_writable(b, last_inhibited, block1_protect)
            ]
            if args.full:
                writable = list(range(num_blocks))
                protected_count = num_blocks - len(writable_all)
                if protected_count:
                    print("Note: --full writes all blocks including protected; bypass will be used for those.", file=sys.stderr)
            else:
                writable = sorted(set(writable_all) & modified_block_indices)
        if not writable:
            print("No blocks were modified by patches; use --full to write all writable blocks.", file=sys.stderr)
            return 0
        total = len(writable)
        failed_blocks: list[int] = []
        print(f"\nWriting and verifying {total} block{'s' if total != 1 else ''} (write then verify each block)...")
        for idx, block in enumerate(writable):
            sys.stdout.write(_progress_bar(idx, total, prefix="Block   ", use_cr=False))
            print(f" Block {block}/{num_blocks - 1}: Writing...", end=" ", flush=True)
            start = block * BLOCK_SIZE
            block_data = bytes(dump[start : start + BLOCK_SIZE])
            bypass_for_block = args.bypass_write_protection or (
                args.full and not is_block_writable(block, last_inhibited, block1_protect)
            )
            if not write_block_to_device(
                block, block_data, verbose=args.verbose, bypass_write_protection=bypass_for_block
            ):
                print("failed.", file=sys.stderr)
                failed_blocks.append(block)
                if not args.force:
                    print(f"Error: failed to write block {block}.", file=sys.stderr)
                    return 1
                continue
            print("done. Verifying...", end=" ", flush=True)
            read_back = verify_dump_from_device(verbose=args.verbose)
            if read_back is None:
                print("failed.", file=sys.stderr)
                failed_blocks.append(block)
                if not args.force:
                    print("Error: failed to read back from device.", file=sys.stderr)
                    return 1
                continue
            if len(read_back) < (block + 1) * BLOCK_SIZE:
                print("failed.", file=sys.stderr)
                failed_blocks.append(block)
                if not args.force:
                    print("Error: read-back dump too short.", file=sys.stderr)
                    return 1
                continue
            if read_back[block * BLOCK_SIZE : (block + 1) * BLOCK_SIZE] != block_data:
                print("mismatch.", file=sys.stderr)
                failed_blocks.append(block)
                if not args.force:
                    print(f"Error: block {block} verify failed (data differs).", file=sys.stderr)
                    return 1
                continue
            print("done.")
        print(_progress_bar(total, total, prefix="Block   ", use_cr=False))
        if failed_blocks:
            print("Errored blocks:", failed_blocks, file=sys.stderr)
            return 1
        print("Verify OK.")

    return 0


if __name__ == "__main__":
    sys.exit(main())
