#!/usr/bin/env python3
"""Reverse test for item 1: the private instruction set must not be brute-forceable.

The threat this file exists to refute is concrete and was real until item 1 landed:

    The container's stream cipher is keyed by the seed in its own header, so an
    attacker can strip it offline. What is left is the opcode permutation - the
    "private instruction set". With the old affine mapping
    `wire = (op * 167 + (seed & 0xFF)) & 0xFF` the salt was public (header) and the
    multiplier had to be odd, so there were 128 candidates. Walking the stream under
    each candidate and keeping the one whose instruction boundaries land exactly on
    `code_len` with every opcode in range recovers the mapping. The stored CRC over
    the canonical body confirms the winner.

That is a few minutes of work, and it is why virtualizing `unpermute_code` used to
buy nothing: the answer fell out of the container anyway.

So this script does exactly that attack, against whatever container it is pointed at:

    python tool/recover_opcodes.py              # must FAIL on current output
    python tool/recover_opcodes.py --selftest   # must SUCCEED on a legacy container

`--selftest` re-packs the *current* decoded body with the old affine mapping, which
proves the attack and the detector both work. Without it, "the attack failed" would
be an untested claim - it would pass just as well against a script that never tried.
This mirrors tool/recover_from_shipped.py, whose default mode must also fail and whose
--selftest must also succeed.

Exit code: 0 when the attack fails (good), 1 when it succeeds (the mapping was
recovered, i.e. the container is weak).
"""
import pathlib
import sys
import zlib

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from walk_bytecode import (  # noqa: E402
    MASK64,
    OP_MAX,
    WIDTH,
    load_container,
    opcode_inverse,
    opcode_permutation,
    stream,
)

CRC_OFF = 20
SEED_OFF = 8
BODY_LEN_OFF = 16
HEADER = 32
TAG_SIZE = 8
LEGACY_MUL = 167


def split_container(img):
    body_len = int.from_bytes(img[BODY_LEN_OFF : BODY_LEN_OFF + 4], "little")
    seed = int.from_bytes(img[SEED_OFF : SEED_OFF + 8], "little")
    crc = int.from_bytes(img[CRC_OFF : CRC_OFF + 4], "little")
    stored = bytes(img[HEADER : HEADER + body_len])
    tag = int.from_bytes(img[HEADER + body_len : HEADER + body_len + TAG_SIZE], "little")
    return body_len, seed, crc, stored, tag


def decrypt(stored, seed):
    """Strip the container cipher.

    Public by construction: the key is `seed ^ 0xA5A5...` and the seed is in the
    header. This is the step an attacker does *not* have to defeat, and pretending
    otherwise would overstate what the container protects.
    """
    blob = stream(seed ^ 0xA5A5A5A5A5A5A5A5, len(stored))
    return bytearray(a ^ b for a, b in zip(stored, blob))


def fnv1a64(data):
    h = 0xCBF29CE484222325
    for byte in data:
        h = ((h ^ byte) * 0x100000001B3) & MASK64
    return h


def body_tag(permuted, seed):
    tail = (seed ^ 0x5DEECE66D).to_bytes(8, "little")
    return fnv1a64(bytes(permuted) + tail) ^ ((seed * 0x100000001B3) & MASK64)


def code_region(permuted):
    """Locate the instruction stream in a still-permuted body.

    Every field before it (string table, const pool, index lists, descriptors) is
    left alone by the permutation - only opcode *bytes* are rewritten, and only
    inside the code region - so the walk to the region is unaffected. That is the
    property that makes a boundary-walk attack worth trying at all.
    """
    body = permuted
    off = 0
    sl = int.from_bytes(body[off : off + 4], "little")
    off += 4 + sl
    cc = int.from_bytes(body[off : off + 4], "little")
    off += 4 + cc * 8
    sc = int.from_bytes(body[off : off + 4], "little")
    off += 4 + sc * 8
    fc = int.from_bytes(body[off : off + 4], "little")
    off += 4 + fc * 32
    cl = int.from_bytes(body[off : off + 4], "little")
    off += 4
    return off, cl


def walk(code, cl, inv):
    """Decode under a candidate inverse table; None when the walk desynchronises.

    Two independent tests have to pass, which is what makes a wrong candidate
    overwhelmingly unlikely to survive: every opcode must be in range (the inverse
    table returns 0xFF for a byte that is not one of the permutation's images) and
    the walk must consume the stream exactly, landing on `cl` and not past it.

    Operand bytes are copied through untouched, because the permutation rewrites
    opcode bytes only. Getting that wrong is not a subtle bug: this function
    originally returned `out = bytearray(cl)` with nothing but the opcodes written
    into it, which zeroed every operand. The walk still "succeeded" - the widths
    come from the decoded opcode, so the boundaries were right - but the resulting
    body no longer matched the stored CRC, and the CRC is the oracle the whole
    attack is confirmed with. Every candidate then failed, so the script reported
    "the mapping is not affine" for *any* input, including the legacy container it
    is supposed to recover. `--selftest` is what catches this class of mistake: a
    detector that can only ever say "nothing found" is a print statement.
    """
    out = bytearray(code)
    pc = 0
    while pc < cl:
        op = inv[code[pc]]
        if op >= OP_MAX:
            return None
        out[pc] = op
        pc += 1 + WIDTH[op]
    return out if pc == cl else None


def legacy_inverse(seed):
    """The inverse table the *old* runtime built: `(wire - salt) * 23 & 0xFF`.

    Kept because it is the honest description of what an attacker only needs to
    know one number of (the odd multiplier, 128 candidates) rather than the whole
    table - see `brute_force`, which does not even use this and sweeps both
    parameters instead.
    """
    salt = seed & 0xFF
    inv = [0xFF] * 256
    for op in range(OP_MAX):
        inv[(op * LEGACY_MUL + salt) & 0xFF] = op
    return inv


def brute_force(permuted, seed, crc):
    """Try every affine candidate, then confirm the winner against the stored CRC.

    The salt is known from the header, so the honest version of this attack is 128
    candidates; the full salt x multiplier sweep is used anyway so the result does
    not depend on the attacker having read the header field correctly, and so the
    count reported is the un-optimised work.
    """
    off, cl = code_region(permuted)
    code = bytes(permuted[off : off + cl])
    tried = 0
    for salt in range(256):
        for mul in range(1, 256, 2):
            tried += 1
            inv = [0xFF] * 256
            for op in range(OP_MAX):
                inv[(op * mul + salt) & 0xFF] = op
            dec = walk(code, cl, inv)
            if dec is None:
                continue
            canon = bytearray(permuted)
            canon[off : off + cl] = dec
            if zlib.crc32(bytes(canon)) & 0xFFFFFFFF == crc:
                return (salt, mul, dec, tried)
    return None


def decode_true(permuted, seed, crc):
    """Decode with the shipped constructor and verify the stored CRC.

    Needed for `--selftest` (to get the canonical body) and used as a control: if
    this fails, the container is not one this repository produced and the run means
    nothing. The CRC is checked here rather than assumed, so "the control passed"
    means the canonical body was actually reproduced - it is the same gate the
    runtime uses.
    """
    off, cl = code_region(permuted)
    dec = walk(bytes(permuted[off : off + cl]), cl, opcode_inverse(opcode_permutation(seed)))
    if dec is None:
        return None
    canon = bytearray(permuted)
    canon[off : off + cl] = dec
    if zlib.crc32(bytes(canon)) & 0xFFFFFFFF != crc:
        return None
    return canon, off, cl


def repack_legacy(canon, off, cl, seed, crc, entry_count):
    """Re-pack `canon` the way the *old* packer would have.

    Used only by --selftest. Re-packing the body we just decoded means the legacy
    container is byte-for-byte the shape the project shipped before item 1, rather
    than a synthetic blob the attack might fail on for unrelated reasons.
    """
    body = bytearray(canon)
    pc = 0
    while pc < cl:
        op = body[off + pc]
        body[off + pc] = (op * LEGACY_MUL + (seed & 0xFF)) & 0xFF
        pc += 1 + WIDTH[op]
    tag = body_tag(body, seed)
    cipher = stream(seed ^ 0xA5A5A5A5A5A5A5A5, len(body))
    out = bytearray(HEADER + len(body) + TAG_SIZE)
    out[0:4] = b"DVMP"
    out[4:6] = (1).to_bytes(2, "little")
    out[6:8] = (0).to_bytes(2, "little")
    out[SEED_OFF : SEED_OFF + 8] = seed.to_bytes(8, "little")
    out[BODY_LEN_OFF : BODY_LEN_OFF + 4] = len(body).to_bytes(4, "little")
    out[CRC_OFF : CRC_OFF + 4] = crc.to_bytes(4, "little")
    out[24:28] = entry_count.to_bytes(4, "little")
    out[HEADER : HEADER + len(body)] = bytes(a ^ b for a, b in zip(body, cipher))
    out[HEADER + len(body) :] = tag.to_bytes(8, "little")
    return out


def main() -> int:
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, OSError):
        pass

    image_arg = None
    args = sys.argv[1:]
    for i, a in enumerate(args):
        if a == "--image":
            image_arg = args[i + 1]
        elif a.startswith("--image="):
            image_arg = a.split("=", 1)[1]
    selftest = "--selftest" in args

    img, src = load_container(image_arg)
    body_len, seed, crc, stored, tag = split_container(img)
    print(f"container: {src} ({len(img)} bytes, body {body_len}, seed {seed:#018x})")

    permuted = decrypt(stored, seed)
    if body_tag(permuted, seed) != tag:
        print("auth tag does not verify: this is not a container this project produced")
        print("(or it was tampered with) - the run would prove nothing")
        return 2

    control = decode_true(permuted, seed, crc)
    if control is None:
        print("the shipped constructor cannot reproduce this container's canonical "
              "body; refusing to report a result either way")
        return 2
    canon, off, cl = control
    # From the *container header*, not the body: the same field name appears in both
    # places and reading the wrong one silently fed garbage into the re-packed header.
    entry_count = int.from_bytes(img[24:28], "little")
    print(f"code region: +{off} len {cl}, canonical CRC {crc:#010x}")

    if selftest:
        legacy = repack_legacy(canon, off, cl, seed, crc, entry_count)
        _, seed, crc, stored, ltag = split_container(legacy)
        permuted = decrypt(stored, seed)
        if body_tag(permuted, seed) != ltag:
            print("--selftest: the re-packed legacy container does not verify; "
                  "the test itself is broken")
            return 2
        print("--selftest: container re-packed with the legacy affine mapping "
              f"(mul={LEGACY_MUL}, salt={seed & 0xFF:#04x})")

    hit = brute_force(permuted, seed, crc)
    if hit is None:
        print("RESULT: attack FAILED after trying every affine candidate")
        if selftest:
            print("  ...but --selftest REQUIRES it to succeed: the detector is broken, "
                  "not the container")
            return 1
        print("  the private instruction set is not an affine map of the seed")
        return 0

    salt, mul, dec, tried = hit
    print(f"RESULT: mapping RECOVERED after {tried} affine candidates "
          f"(mul={mul}, salt={salt:#04x})")
    if not selftest:
        print("  item 1 has regressed: the shipped container is brute-forceable")
        return 1
    # Positive control: the recovered stream has to be the *right* stream, not just
    # a self-consistent one. A walk under a wrong-but-plausible candidate could in
    # principle satisfy the CRC by accident, and then this script would report a
    # recovery it did not actually make.
    if bytes(dec) != bytes(canon[off : off + cl]):
        print("  but the recovered stream != the canonical code: the CRC gate admits "
              "a wrong candidate, so this is not a positive control")
        return 1
    if (mul, salt) != (LEGACY_MUL, seed & 0xFF):
        print(f"  recovered mul/salt {mul}/{salt:#04x} != the injected "
              f"{LEGACY_MUL}/{seed & 0xFF:#04x}")
        return 1
    print("  recovered stream matches the canonical code byte for byte, and the "
          "multiplier and salt are the injected ones")
    print("  --selftest: as expected on a legacy container; the detector fires")
    return 0


if __name__ == "__main__":
    sys.exit(main())
