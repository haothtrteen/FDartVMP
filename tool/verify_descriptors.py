#!/usr/bin/env python3
"""Verify the emitted descriptors, including the call policy.

Independent of the Dart generator and of the runtime: it decodes the container
from the generated header using the documented algorithms, then prints each
descriptor field by offset. This is the check that caught the policy landing at
offset 16 instead of 10 - the runtime read `locals` as a guard mode, which would
have produced a module that looked fine and silently carried no policy.
"""
import hashlib
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
INC = ROOT / "packages" / "dartvmp" / "generated" / "vmp_module.inc"
MASK64 = 0xFFFFFFFFFFFFFFFF
G0 = 0x9E3779B97F4A7C15
G1 = 0xBF58476D1CE4E5B9
G2 = 0x94D049BB133111EB
DESC = 32

# Field offsets in the descriptor record. Mirrors the emitter's write order, which
# is also the runtime's read order in `parse_body_views` and the `DVMP_DESC_OFF_*`
# table in dvmp_wire.h:
#
#   [0..4)   name_off          [4..8)   name_len
#   [8]      guard_mode        [9]      reserved (must be 0)
#   [10..12) guard_budget      [12..14) guard_window_ms
#   [14..16) arity             [16..18) locals
#   [18..20) max_stack         [20..22) slot_base
#   [22..24) reserved2         [24..28) code_len
#   [28..32) code_off
#
# The policy is mode/budget/window as three separate fields, not a packed
# byte-pair: a 4-bit budget could not express a useful rate, and a 4-bit window
# *exponent* silently rounded a requested 2000 ms to 2048. The two reserved fields
# are checked below - they are what turns "a field moved" from a plausible-looking
# module into a failed decode.
# Function indices whose RATE policy is allowed to be tighter than the 100 calls/s floor
# below. Entry 9 is `revealFlag`, the challenge endpoint in `protected/challenge.dart`: its
# `guard:rate=8/1000` is the thing that stops the exported entry point from being a free
# brute-force oracle for the key, so refusing a burst is the feature and not a hazard.
#
# Kept as an explicit index with a reason rather than a raised threshold, because the
# threshold is protecting every *other* function from exactly this mistake, and "the
# challenge needed it" is not a reason to let a licence check refuse a real user.
DELIBERATELY_TIGHT = {9}

FIELDS = [
    (0, 4, "name_off"),
    (4, 8, "name_len"),
    (8, 9, "guard_mode"),
    (9, 10, "reserved"),
    (10, 12, "guard_budget"),
    (12, 14, "guard_window_ms"),
    (14, 16, "arity"),
    (16, 18, "locals"),
    (18, 20, "max_stack"),
    (20, 22, "slot_base"),
    (22, 24, "reserved2"),
    (24, 28, "code_len"),
    (28, 32, "code_off"),
]


def keystream(key, index):
    """SHA256(le64(key) || le64(index))[0..8), little-endian.

    Mirrors dvmp_mask_keystream() in packages/dartvmp/src/dvmp_sha256.c and
    imageMaskWord() in tool/vmpc/lib/src/c_emitter.dart. Three implementations have to
    agree on this or the container is not decryptable, so all three run the published
    SHA-256 vectors (see tool/verify_crypto.ps1).

    This replaced a SplitMix64 finaliser that was a bijection in the key: the
    container's first eight bytes are known plaintext, so one XOR plus one inversion
    recovered the key from the shipped APK - and because it was a stream, that key then
    gave up every other word. A truncated hash of (key, index) gives up neither.
    """
    blob = key.to_bytes(8, "little") + index.to_bytes(8, "little")
    return int.from_bytes(hashlib.sha256(blob).digest()[:8], "little")


def stream(seed, n):
    s = (seed ^ G0) & MASK64
    out = bytearray()
    while len(out) < n:
        s = (s + G0) & MASK64
        z = s
        z = ((z ^ (z >> 30)) * G1) & MASK64
        z = ((z ^ (z >> 27)) * G2) & MASK64
        w = (z ^ (z >> 31)) & MASK64
        for b in range(8):
            if len(out) < n:
                out.append((w >> (8 * b)) & 0xFF)
    return bytes(out)


def main() -> int:
    text = INC.read_text(encoding="utf-8")
    key = int(re.search(r"kDvmpImage_MASK_KEY 0x([0-9a-f]+)", text).group(1), 16)
    n = int(re.search(r"DVMP_IMAGE_LEN (\d+)u", text).group(1))
    words = [
        (int(a, 16), int(b, 16))
        for a, b in re.findall(
            r"\{\s*0x([0-9a-f]{8})u,\s*0x([0-9a-f]{8})u\s*\}", text
        )
    ]
    img = bytearray(n)
    for i, (lo, hi) in enumerate(words):
        w = (lo | (hi << 32)) ^ keystream(key, i * 8)
        for b in range(8):
            at = i * 8 + b
            if at < n:
                img[at] = (w >> (8 * b)) & 0xFF

    body_len = int.from_bytes(img[16:20], "little")
    seed = int.from_bytes(img[8:16], "little")
    body = bytearray(
        a ^ b
        for a, b in zip(img[32 : 32 + body_len], stream(seed ^ 0xA5A5A5A5A5A5A5A5, body_len))
    )

    off = 0
    strings_len = int.from_bytes(body[off : off + 4], "little")
    off += 4 + strings_len
    const_count = int.from_bytes(body[off : off + 4], "little")
    off += 4 + const_count * 8
    str_count = int.from_bytes(body[off : off + 4], "little")
    off += 4 + str_count * 8
    fn_count = int.from_bytes(body[off : off + 4], "little")
    desc_at = off + 4
    code_len_at = desc_at + fn_count * DESC
    code_len = int.from_bytes(body[code_len_at : code_len_at + 4], "little")
    print(f"body={body_len} functions={fn_count} descriptors@{desc_at} "
          f"code_len={code_len} (field at {code_len_at})")

    problems = []
    if code_len_at + 4 + code_len != body_len:
        problems.append(
            f"descriptor stride {DESC} does not line up: code region ends at "
            f"{code_len_at + 4 + code_len}, body is {body_len}")

    for i in range(fn_count):
        d = body[desc_at + i * DESC : desc_at + i * DESC + DESC]
        vals = {name: int.from_bytes(d[a:b], "little") for a, b, name in FIELDS}
        # The layout check, before anything is interpreted: both reserved fields
        # are written as zero, so a non-zero one means the emitter and this decoder
        # (or the runtime) disagree about where a field lives.
        if vals["reserved"] != 0 or vals["reserved2"] != 0:
            problems.append(
                f"fn {i}: reserved byte(s) are {vals['reserved']}/"
                f"{vals['reserved2']}, not 0 - a field moved out of the layout "
                "this decoder and the runtime both assume")
        # The name fields must be (0, 0).
        #
        # They used to point at the function's name in the container's string table,
        # which the runtime never read - name lookup goes through the compiled-in
        # masked blob - so all they did was put the id -> name map inside the
        # ciphertext for whoever decrypted it, which is precisely what
        # tool/walk_bytecode.py then printed as `fn 4 [verifyLicense]`. Masking them
        # inside the container would have been decoration, since the whole container is
        # plaintext once decrypted; removing them is not.
        if vals["name_off"] != 0 or vals["name_len"] != 0:
            problems.append(
                f"fn {i}: name field is ({vals['name_off']}, {vals['name_len']}), not "
                "(0, 0) - the function names are back inside the container")
        guard = ""
        if vals["guard_mode"] == 1:
            budget = vals["guard_budget"]
            window = vals["guard_window_ms"]
            guard = f" guard=rate({budget}/{window}ms)"
            if budget == 0:
                problems.append(f"fn {i}: RATE policy with a zero budget")
            if window == 0:
                problems.append(f"fn {i}: RATE policy with a zero window")
            elif budget / window * 1000.0 < 100 and i not in DELIBERATELY_TIGHT:
                # The check exists so that a *business* function cannot be shipped with a
                # policy tight enough to refuse a legitimate caller - the first rule of this
                # project is that protection must not change what the application does.
                #
                # A challenge endpoint is the documented exception, and it is listed by id
                # with a reason rather than by loosening the threshold for everyone: the
                # whole point of `revealFlag` is that it refuses a burst, because otherwise
                # the exported verifier is a free brute-force oracle for the key. See
                # docs/CHALLENGE.md.
                problems.append(
                    f"fn {i}: RATE policy allows only "
                    f"{budget / window * 1000.0:.1f} calls/s, below the 100/s the "
                    "README documents as the legitimate ceiling; protection must "
                    "not be able to refuse a correct caller")
        elif vals["guard_mode"] == 2:
            guard = " guard=once"
        elif vals["guard_mode"] != 0:
            guard = f" guard=??{vals['guard_mode']}"
            problems.append(f"fn {i}: unrecognised guard mode {vals['guard_mode']}")
        print(
            f"  fn{i}: arity={vals['arity']} locals={vals['locals']} "
            f"max_stack={vals['max_stack']} slot_base={vals['slot_base']} "
            f"code_len={vals['code_len']} code_off={vals['code_off']}{guard}"
        )
        if vals["locals"] > 64:
            problems.append(f"fn {i}: locals={vals['locals']} looks like a "
                            "misaligned field (is the policy at the wrong offset?)")
        if vals["arity"] > 8:
            problems.append(f"fn {i}: arity={vals['arity']} is out of range "
                            "(max 8); this is what a misaligned descriptor looks "
                            "like")
        if vals["guard_mode"] not in (0, 1, 2):
            problems.append(f"fn {i}: guard mode {vals['guard_mode']} is not one of "
                            "DVMP_GUARD_NONE/RATE/ONCE")

    print()
    if problems:
        for p in problems:
            print("PROBLEM:", p)
        return 1
    print("OK: every descriptor decodes with the 32-byte stride, the reserved "
          "bytes are zero, and the call policy reads at offsets 8/10/12")
    return 0


if __name__ == "__main__":
    sys.exit(main())
