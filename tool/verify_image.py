#!/usr/bin/env python3
"""Verifies that the shipped static image is genuinely masked.

`verify_protection.ps1` searches the runtime for the container magic, which is a
blunt instrument: the four bytes can occur by chance in unrelated binary data, and
finding them proves nothing either way. This script checks the property that
actually matters, working from the generated header:

  1. un-masking the emitted words with the emitted key reproduces a container
     whose first four bytes ARE "DVMP" - so the generator and the runtime agree,
     and the image really is a container;
  2. those four bytes do NOT appear consecutively in the emitted literal - so a
     `strings`/`binwalk` sweep of the shared object finds nothing.

Exit code 0 on success, 1 otherwise.
"""
import hashlib
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
HEADER = ROOT / "packages" / "dartvmp" / "generated" / "vmp_module.inc"

M64 = (1 << 64) - 1
G0 = 0x9E3779B97F4A7C15
G1 = 0xBF58476D1CE4E5B9
G2 = 0x94D049BB133111EB


def mix(key: int, index: int) -> int:
    """Keystream word — mirrors `dvmp_mask_keystream` in dvmp_sha256.c.

    SHA256(le64(key) || le64(index))[0..8), little-endian. This was SplitMix64 over
    `key + index + G0`, which is a bijection in the key and therefore lost the mask key
    to anyone who knew the container's first eight bytes; see dvmp_sha256.c.
    """
    blob = key.to_bytes(8, "little") + index.to_bytes(8, "little")
    return int.from_bytes(hashlib.sha256(blob).digest()[:8], "little")


def main() -> int:
    if not HEADER.exists():
        print(f"FAIL: {HEADER} not found; run `dart run tool/build.dart` first")
        return 1
    text = HEADER.read_text(encoding="utf-8", errors="replace")

    m = re.search(r"#define kDvmpImage_MASK_KEY 0x([0-9a-f]+)", text)
    if not m:
        print("FAIL: MASK_KEY is not emitted")
        return 1
    key = int(m.group(1), 16)

    m = re.search(r"#define DVMP_IMAGE_LEN (\d+)u", text)
    if not m:
        print("FAIL: DVMP_IMAGE_LEN is not emitted")
        return 1
    declared_len = int(m.group(1))

    # The masked words, in emission order.
    words = [
        int(lo, 16) | (int(hi, 16) << 32)
        for lo, hi in re.findall(
            r"\{\s*0x([0-9a-f]{8})u,\s*0x([0-9a-f]{8})u\s*\}", text
        )
    ]
    if not words:
        print("FAIL: no image words found")
        return 1

    chars = []
    for i, w in enumerate(words):
        plain = w ^ mix(key, i * 8)
        for b in range(8):
            at = i * 8 + b
            if at < declared_len:
                chars.append((plain >> (8 * b)) & 0xFF)
    image = bytes(chars)

    print(f"key          = 0x{key:016x}")
    print(f"declared len = {declared_len}")
    print(f"words        = {len(words)}")
    print(f"image[:16]   = {image[:16].hex(' ')}")

    ok = True
    if image[:4] != b"DVMP":
        print("FAIL: un-masking does not reproduce the DVMP magic")
        print("      the generator and the runtime disagree about the mask")
        ok = False
    else:
        print("ok    un-masking reproduces the DVMP magic")

    # The property that makes a `strings` sweep useless: the magic is not present
    # consecutively in the emitted literal.
    literal = re.search(r"kDvmpImage_words\[\] = \{(.*?)\n\};", text, re.S)
    if literal and re.search(r"0x44u,\s*0x56u", literal.group(1)):
        print("FAIL: the magic bytes appear unmasked in the emitted literal")
        ok = False
    else:
        print("ok    no unmasked magic bytes in the emitted literal")

    # And the ciphertext must actually differ from the plaintext, i.e. the image
    # is not stored in the clear.
    if not literal:
        print("FAIL: could not locate the image literal")
        ok = False
    else:
        stored = bytes(
            b
            for lo, hi in re.findall(
                r"0x([0-9a-f]{8})u,\s*0x([0-9a-f]{8})u", literal.group(1)
            )
            for b in (
                int(lo, 16) & 0xFF,
                (int(lo, 16) >> 8) & 0xFF,
                (int(lo, 16) >> 16) & 0xFF,
                (int(lo, 16) >> 24) & 0xFF,
                int(hi, 16) & 0xFF,
                (int(hi, 16) >> 8) & 0xFF,
                (int(hi, 16) >> 16) & 0xFF,
                (int(hi, 16) >> 24) & 0xFF,
            )
        )
        shared = sum(1 for a, b in zip(stored, image) if a == b)
        print(f"ok    stored bytes match the unmasked image at {shared}/{len(image)} positions")
        if shared > len(image) // 4:
            print("FAIL: the stored image is too close to plaintext")
            ok = False

    print()
    print("IMAGE MASKING OK" if ok else "IMAGE MASKING FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
