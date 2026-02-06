# LTO Cartridge Memory (LTO-CM / MAM) reader and writer for libnfc

Author: Phil Pemberton <philpem@philpem.me.uk>


## Scripts overview

| Script / binary      | Purpose |
|----------------------|--------|
| **nfc-ltocm**        | C program (build with `make`). Reads and writes LTO-CM over NFC: read full dump, write full dump or single block. Respects write-inhibit unless `--bypass-write-protection` is used. |
| **patch_ltocm.py**   | Patch dumps: initialise (data or cleaning tape), set MAM barcode, set cleaning type, reset clean usage. Input from file or `--read`; optional `--apply` to write back to the cartridge with verification. |
| **report_ltocm.py**  | Human-readable report of one dump (page-by-page with clear-text fields and hex), or diff of two dumps (or one file vs device with `--read`). Optional CRC checks. |
| **diff_ltocm.py**    | Byte-level diff of two LTO-CM dump files with colored hex and region labels (Block 0, Cartridge Manufacturer, etc.). |

All Python scripts require Python 3. The C program requires [libnfc](https://github.com/nfc-tools/libnfc/). Layout and CRC follow ECMA-319 Annex D.


## Usage (nfc-ltocm)

  - Place an LTO tape on your NFC reader, with the CM chip (on the label side, opposite the write-protect tab) centred over the aerial.

  - **Read** (default): run `nfc-ltocm` or `nfc-ltocm <output.bin>`. The LTO-CM contents are written to the given file (default: serial-number-based name).
  - **Write full dump**: `nfc-ltocm --write <file.bin>` — writes the file to the LTO-CM block by block (32 bytes per block). Write-inhibit is respected; protected blocks are not written.
  - **Write single block**: `nfc-ltocm --write-block <block> <file.bin>` — writes the first 32 bytes of the file to the specified block index.
  - **Bypass write protection**: `nfc-ltocm --bypass-write-protection --write <file.bin>` — allow writing protected blocks (use with care).

  Feed read output to [LTO-CM-Analyzer](https://github.com/Kevin-Nakamoto/LTO-CM-Analyzer) for analysis.


## Patching LTO-CM (patch_ltocm.py)

The Python script `patch_ltocm.py` reads an LTO-CM dump (from a file or from the device), applies patches (e.g. reset usage counters on cleaning tapes), and optionally writes the patched dump back to the cartridge with read-back verification.

**Requirements:** Python 3, `nfc-ltocm` in your PATH (or in the same directory as the script), and an NFC reader plus LTO cartridge when using `--read` or `--apply`.

**Options:**

  - **Input:** either a dump file (`patch_ltocm.py <file.bin>`) or `--read` to read from the device.
  - **Actions:** `--reset-clean-usage` — zero Usage Information counters (only for cleaning tapes; ECMA-319 Annex D).
  - **Output:** `-o <file>` — patched dump file (default: derived from input, e.g. `*_patched.bin`).
  - **Apply:** `--apply` — write the patched dump to the device (only writable blocks), then re-read and compare to verify.

**When using `--read`:**

  - A backup of the original dump is always saved (e.g. `<prefix>_backup.bin`).
  - All written files use a filename prefix: cartridge barcode/serial if present, otherwise LTO-CM serial in hex.

**Examples:**

  - Read from device, apply reset clean usage, save patched file and backup:
    ```bash
    python3 patch_ltocm.py --read --reset-clean-usage -o patched.bin
    ```
  - Patch an existing dump file:
    ```bash
    python3 patch_ltocm.py CLNU05CU.bin --reset-clean-usage
    ```
  - Read, patch, write to device, and verify:
    ```bash
    python3 patch_ltocm.py --read --reset-clean-usage --apply
    ```

**Output:** For each modified page the script prints a hex diff (before/after). For the reset-clean-usage patch it also prints clear-text before/after values of the usage fields (e.g. Thread Count, Total Data Sets Written/Read). After `--apply`, it reports "Verify OK" or lists differing blocks.

**Precautions:** Use reset clean usage only on cleaning cartridges. Writing to the LTO-CM can invalidate metadata used by tape drives; the verify step after `--apply` helps ensure the write succeeded.


## Report and diff (report_ltocm.py, diff_ltocm.py)

**report_ltocm.py** — One dump: full page-by-page report (clear-text fields + hex). Two dumps (or one file and `--read`): side-by-side diff.

  ```bash
  python3 report_ltocm.py dump.bin
  python3 report_ltocm.py -o report.txt dump.bin
  python3 report_ltocm.py file1.bin file2.bin
  python3 report_ltocm.py --read file.bin   # diff file vs device
  ```

  Options: `-o FILE`, `--no-hex`, `--check-crc` / `--no-check-crc`.

**diff_ltocm.py** — Byte-level diff of two dump files with colored hex and region labels.

  ```bash
  python3 diff_ltocm.py original.bin patched.bin
  python3 diff_ltocm.py -c 8 a.bin b.bin --no-color
  ```


## Hints on antenna/LTO placement

The ACR122U (Touchatag) reader can read LTO-CM chips quite reliably, if slowly. Place the LTO-CM chip over the centre of the Touchatag (or NFC) logo.

The SCL3711 also works, but antenna placement is more critical. Place the tape flat down, with the rear-right corner over the NFC reader's antenna. Support the front-left corner to stop the tape from slipping.

The LTO-CM chip is located at the back of the cartridge, behind the right side of the label. This is on the opposite side of the label from the write protect tab.


## Write support and precautions

  Writing to the LTO-CM can change or invalidate cartridge metadata used by tape drives. Use write features only for repair or controlled testing. Write-inhibit (ECMA-319 Annex D.2.2) is enforced: blocks at or below the "Last Write-Inhibited Block Number" and block 1 when protected cannot be written.

## Limitations

LTO-CM memories of type 3 are not supported, due to a lack of tapes to test with.

LTO-CM memories of type 4 or later are not supported, as these are not specified in ECMA-319. If you have a datasheet or specification for a later revision of LTO-CM memory chip, please contact me on the email address above. If you've successfully added Type 3 or later memory device support, please open a PR.


## Credits

This code is based on the `libnfc-mfsetuid` example included with [libnfc](https://github.com/nfc-tools/libnfc/).

LTO-CM is specified in Annexes D and F of [ECMA-319](https://www.ecma-international.org/publications/files/ECMA-ST/ECMA-319.pdf)


## Licence

This is the same licence as applies to the `libnfc` examples.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

 1) Redistributions of source code must retain the above copyright notice,
 this list of conditions and the following disclaimer.

 2) Redistributions in binary form must reproduce the above copyright
 notice, this list of conditions and the following disclaimer in the
 documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.

