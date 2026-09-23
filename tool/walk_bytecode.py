#!/usr/bin/env python3
"""Walk the shipped bytecode exactly as the runtime walks it.

This decodes the container the way `module_open_locked` does - un-mask the static
image, strip the body cipher, un-permute the instruction stream - and then
disassembles every function using the runtime's own operand-width table. It is the
independent second implementation that the interesting bugs are found with: the
"load slot 2850 outside window" failure came from the runtime indexing the code
pointer one way and its operands another, and this script shows what the bytes
actually are, which is the part that is hard to see from inside the interpreter.

Run from the repository root:  python tool/walk_bytecode.py
"""
import hashlib
import pathlib
import re
import sys
import zlib

ROOT = pathlib.Path(__file__).resolve().parent.parent
MASK64 = 0xFFFFFFFFFFFFFFFF
G0 = 0x9E3779B97F4A7C15
G1 = 0xBF58476D1CE4E5B9
G2 = 0x94D049BB133111EB

# dvmp_wire.h: kWidth[] - operand bytes per opcode, in the *decoded* numbering.
WIDTH = [0, 4, 2, 2, 0, 0, 0, 0, 0, 0,
         2, 2, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         4, 4, 4, 2, 0, 0, 4, 0]
OP_MAX = 0x26
NAMES = {
    0x00: "nop", 0x01: "push_i", 0x02: "push_k", 0x03: "push_s", 0x04: "push_nil",
    0x05: "push_true", 0x06: "push_false", 0x07: "pop", 0x08: "dup", 0x09: "swap",
    0x0A: "load", 0x0B: "store", 0x0C: "add", 0x0D: "sub", 0x0E: "mul",
    0x0F: "div", 0x10: "mod", 0x11: "neg", 0x12: "and", 0x13: "or", 0x14: "xor",
    0x15: "shl", 0x16: "shr", 0x17: "not", 0x18: "cmplt", 0x19: "cmple",
    0x1A: "cmpgt", 0x1B: "cmpge", 0x1C: "cmpeq", 0x1D: "cmpne", 0x1E: "jmp",
    0x1F: "jmp_if_false", 0x20: "jmp_if_true", 0x21: "call", 0x22: "ret",
    0x23: "ret_void", 0x24: "host", 0x25: "abort",
}


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


def opcode_permutation(seed):
    """The keyed Fisher-Yates shuffle: perm[op] is the byte on the wire.

    Mirrors op_tables() in packages/dartvmp/src/dvmp_module.c and
    Packer.opcodePermutation() in tool/vmpc/lib/src/packer.dart. Third independent
    implementation on purpose - if any two of the three disagree, no container decodes.

    Draws one *byte* of keystream per step. Dart's `%` is Euclidean on a negative
    operand and C's unsigned `%` is not the same operation, so consuming a byte is what
    makes all three languages provably identical rather than identical by argument.

    This replaced `(op * 167 + (seed & 0xFF)) & 0xFF`. The seed is public (container
    header) and the multiplier odd, so 128 candidates recovered the old mapping; the CRC
    below was the oracle. See recover_opcodes.py, which must now fail.
    """
    pool = list(range(256))
    ks = stream(seed ^ 0x4F50434F44455031, 64)  # "OPCODEP1"; 39 draws needed
    perm = []
    for i in range(OP_MAX):
        j = i + ks[i] % (256 - i)
        pool[i], pool[j] = pool[j], pool[i]
        perm.append(pool[i])
    return perm


def opcode_inverse(perm):
    inv = [0xFF] * 256
    for op, wire in enumerate(perm):
        inv[wire] = op
    return inv


def load_container(image_path=None):
    """The raw container (`header || ciphertext || tag`) as it ships.

    Two sources, and the point is that they are interchangeable:
      * no argument - the masked `.rodata` image in the generated C header, which
        is what the runtime embeds;
      * `--image <file>` - a bare image file, which is what
        recover_from_shipped.py pulls out of the *shipped* `libdartvmp.so` with no
        repository artifacts at all.

    Factored out of `main` so recover_opcodes.py decodes the container exactly the
    way this walker does. Two copies of "un-mask the image" would eventually
    disagree, and the failure would look like a corrupt container.
    """
    if image_path:
        return bytearray(pathlib.Path(image_path).read_bytes()), image_path

    inc = (ROOT / "packages" / "dartvmp" / "generated" / "vmp_module.inc").read_text(
        encoding="utf-8"
    )
    key = int(re.search(r"kDvmpImage_MASK_KEY 0x([0-9a-f]+)", inc).group(1), 16)
    n = int(re.search(r"DVMP_IMAGE_LEN (\d+)u", inc).group(1))
    words = [
        (int(a, 16), int(b, 16))
        for a, b in re.findall(
            r"\{\s*0x([0-9a-f]{8})u,\s*0x([0-9a-f]{8})u\s*\}", inc
        )
    ]
    img = bytearray(n)
    for i, (lo, hi) in enumerate(words):
        w = (lo | (hi << 32)) ^ keystream(key, i * 8)
        for b in range(8):
            at = i * 8 + b
            if at < n:
                img[at] = (w >> (8 * b)) & 0xFF
    return img, "packages/dartvmp/generated/vmp_module.inc"


def main() -> int:
    # Names can contain any UTF-8; a GBK console would otherwise abort the walk
    # with a UnicodeEncodeError partway through, which reads like a corrupt
    # container rather than a terminal that cannot print the name.
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, OSError):
        pass
    image_arg = None
    for i, a in enumerate(sys.argv[1:]):
        if a == "--image":
            image_arg = sys.argv[i + 2]
        elif a.startswith("--image="):
            image_arg = a.split("=", 1)[1]

    img, src = load_container(image_arg)
    if image_arg:
        print(f"image: {src} ({len(img)} bytes, from the shipped artifact)")

    bl = int.from_bytes(img[16:20], "little")
    seed = int.from_bytes(img[8:16], "little")
    crc = int.from_bytes(img[20:24], "little")
    # `--tamper` flips one ciphertext byte before anything is decoded. It exists so
    # the CRC and tag checks below can be *shown* to fail: a check that has never
    # been seen to reject anything is a print statement, not a gate. Run
    # `python tool/walk_bytecode.py --tamper` and it must exit non-zero.
    tampered = "--tamper" in sys.argv[1:]
    if tampered:
        at = 32 + bl // 2
        img[at] ^= 0x40
        print(f"TAMPER: flipped bit 6 of image byte {at}")
    body = bytearray(
        a ^ b for a, b in zip(img[32 : 32 + bl], stream(seed ^ 0xA5A5A5A5A5A5A5A5, bl))
    )
    print(f"body={bl} seed={seed:#018x} stored_crc={crc:#010x}")

    off = 0
    sl = int.from_bytes(body[off : off + 4], "little")
    # `name_off` in a descriptor is relative to the *string blob*, not to the body
    # and not to the code region. Reading it out of the code region is what made
    # this walker print mojibake names for months: the offsets are small, so the
    # slice always landed inside the stream and looked like data.
    strblob_at = off + 4
    off += 4 + sl
    cc = int.from_bytes(body[off : off + 4], "little")
    off += 4 + cc * 8
    sc = int.from_bytes(body[off : off + 4], "little")
    off += 4 + sc * 8
    fc = int.from_bytes(body[off : off + 4], "little")
    desc = off + 4
    # The stride has to match DVMP_DESC_SIZE, and the region offset has to be
    # computed from the *stride*, not the old 24: getting this wrong made the
    # walker report `code_len=0` and every function's code offset out of range,
    # which looks like a corrupt container rather than a stale tool.
    DESC = 32
    off += 4 + fc * DESC
    cl = int.from_bytes(body[off : off + 4], "little")
    off += 4
    code = body[off : off + cl]
    print(f"funcs={fc} code_off={off} code_len={cl}")

    descs = []
    for i in range(fc):
        d = body[desc + i * DESC : desc + i * DESC + DESC]
        descs.append(
            (
                int.from_bytes(d[0:4], "little"),   # [0]  name_off
                int.from_bytes(d[4:8], "little"),   # [4]  name_len
                int.from_bytes(d[14:16], "little"), # [14] arity
                int.from_bytes(d[16:18], "little"), # [16] locals
                int.from_bytes(d[18:20], "little"), # [18] max_stack
                int.from_bytes(d[20:22], "little"), # [20] slot_base
                int.from_bytes(d[24:28], "little"), # [24] code_len
                int.from_bytes(d[28:32], "little"), # [28] code_off
                d[8],                               # [8]  guard_mode
                int.from_bytes(d[10:12], "little"), # [10] guard_budget
                int.from_bytes(d[12:14], "little"), # [12] guard_window_ms
                d[9],                               # [9]  reserved
                int.from_bytes(d[22:24], "little"), # [22] reserved2
            )
        )

    # Un-permute, exactly as unpermute_code does. The mapping is the keyed
    # Fisher-Yates shuffle in Packer.opcodePermutation / op_tables; this is the
    # third independent implementation, which is the point - if the Dart packer,
    # the C runtime and this file ever disagree, no container decodes.
    inv = opcode_inverse(opcode_permutation(seed))
    dec = bytearray(code)
    pc = 0
    while pc < cl:
        wire = dec[pc]
        op = inv[wire]
        if op >= OP_MAX:
            print(f"UNPERMUTE FAILED at +{pc}: wire={wire:#04x} -> op={op:#04x}")
            return 1
        dec[pc] = op
        pc += 1 + WIDTH[op]
    if pc != cl:
        print(f"UNPERMUTE overran: walked {pc} of {cl}")
        return 1
    print("unpermute: ok")

    ok = True
    for i, (
        no,
        nl,
        ar,
        loc,
        ms,
        base,
        clen,
        coff,
        gmode,
        gbud,
        gwin,
        rsv,
        rsv2,
    ) in enumerate(descs):
        start = coff - off
        if start < 0 or start + clen > cl:
            print(f"fn {i}: code offset {coff} out of range")
            ok = False
            continue
        # Both reserved fields are written as zero by the emitter and asserted zero
        # by the runtime. Checking them here is what makes a moved field a loud
        # failure instead of a plausible-looking walk.
        if rsv != 0 or rsv2 != 0:
            print(
                f"fn {i}: reserved fields are {rsv}/{rsv2}, not 0 - the descriptor "
                "layout this walker assumes is not the one that was emitted"
            )
            ok = False
        names = body[strblob_at + no : strblob_at + no + nl].decode("utf-8", "replace")
        # Call policy, if any: mode 1 = rate (budget u16 at [10..12), window u16 at
        # [12..14)), mode 2 = once. See DVMP_GUARD_* in dvmp_wire.h.
        guard = ""
        if gmode == 1:
            guard = f" guard=rate {gbud}/{gwin}ms"
            if gbud == 0 or gwin == 0:
                guard += " ** zero budget/window **"
                ok = False
        elif gmode == 2:
            guard = " guard=once"
        elif gmode != 0:
            guard = f" guard=?{gmode}"
        p = 0
        listing = []
        while p < clen:
            op = dec[start + p]
            w = WIDTH[op] if op < len(WIDTH) else 0
            operand = ""
            if w == 2:
                operand = str(dec[start + p + 1] | (dec[start + p + 2] << 8))
            elif w == 4:
                operand = str(
                    int.from_bytes(dec[start + p + 1 : start + p + 5], "little")
                )
            listing.append(f"{p}:{NAMES.get(op, hex(op))}" + (f"({operand})" if operand else ""))
            if op >= OP_MAX:
                print(f"fn {i}: bad opcode {op:#04x} at +{p}")
                ok = False
                break
            p += 1 + w
        print(
            f"fn {i} [{names}] arity={ar} locals={loc} slot_base={base} "
            f"len={clen} @+{start}{guard}"
        )
        # The policy is the reason a call can be refused, so a walker that silently
        # ignored it would report a module as callable that is not.
        if gmode not in (0, 1, 2):
            print(f"   ** unrecognised guard mode {gmode} **")
            ok = False

    # Two checks the runtime also performs, reproduced here so a disagreement
    # between the two implementations is a failure and not a printed number.
    #
    # 1. The header CRC covers the CANONICAL body - after the cipher is stripped
    #    *and* after the instruction stream is un-permuted. Computing it over the
    #    still-permuted body produced a number that never matched, which read as
    #    "the container is corrupt" when the label was the only thing wrong.
    canon = bytearray(body)
    canon[off : off + cl] = dec
    got_crc = zlib.crc32(bytes(canon)) & 0xFFFFFFFF
    if got_crc == crc:
        print(f"canonical CRC: ok ({got_crc:#010x})")
    else:
        print(f"canonical CRC: MISMATCH stored={crc:#010x} computed={got_crc:#010x}")
        ok = False

    # 2. The authenticity tag is `fnv1a64(permuted || seed')` keyed by the seed; it
    #    is the part an attacker who flips bytes in the image has to forge.
    h = 0xCBF29CE484222325
    for byte in bytes(body) + (seed ^ 0x5DEECE66D).to_bytes(8, "little"):
        h = ((h ^ byte) * 0x100000001B3) & MASK64
    got_tag = h ^ ((seed * 0x100000001B3) & MASK64)
    stored_tag = int.from_bytes(img[32 + bl : 32 + bl + 8], "little")
    if got_tag == stored_tag:
        print(f"auth tag: ok ({got_tag:#018x})")
    else:
        print(f"auth tag: MISMATCH stored={stored_tag:#018x} computed={got_tag:#018x}")
        ok = False

    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
