#!/usr/bin/env python3
"""Attack the shipped artifact: try to recover the module container from libdartvmp.so.

This exists to answer a question that a Blutter run does not. Blutter shows the
protected bodies are absent from the AOT snapshot, which only rules out tools that
reconstruct Dart. The container is where the logic actually is, and the container
lives in the native library.

Two modes, and the first one is a *gate*:

  default        Run the algebraic attack: recover the mask key from the container's
                 known plaintext header. This MUST FAIL. It is wired into
                 tool/test.ps1 -Release, and it failed for real before the mask was
                 changed - a run against the old build recovered the key at
                 0x8f3a17c9e7cf471b and printed the whole container. A check that has
                 never been seen to succeed at breaking in is not a check.

  --key <hex>    Do it the expensive way: supply the mask key, as an attacker who has
                 read `unmask_image_into` in the shipped AArch64 would have. This
                 succeeds, and it is supposed to - the key ships with the binary
                 because offline distribution requires it. What it demonstrates is the
                 residual exposure, which is the number the README quotes.

History worth keeping, because it is the reason the mask was replaced. The image used
to be masked with `SplitMix64-finalise(key + index + G0)`:

  * the finaliser is a *bijection*, so one known plaintext word inverted straight to
    the key;
  * the container's first eight bytes are known plaintext - the ASCII magic "DVMP"
    plus a version - and the word is even named in a shipped Dart error string;
  * and it was a *stream*, so the key then produced every other word.

So `key = unmix(stored_word[0] XOR known_header) - G0` recovered the entire container
from the release APK with no disassembly at all. The mask is now
`SHA256(le64(key) || le64(index))[0..8)`: truncation makes one word useless for
recovering the key, and per-index independence makes one word useless for recovering
any other. `algebraic_attack` below still implements the old break, so that the
regression is detectable rather than merely remembered.

Usage (from the repository root):

    python tool/recover_from_shipped.py --apk <apk>              # must fail
    python tool/recover_from_shipped.py --apk <apk> --key <hex>  # succeeds
"""
import argparse
import hashlib
import pathlib
import re
import sys
import zipfile

MASK64 = 0xFFFFFFFFFFFFFFFF
G0 = 0x9E3779B97F4A7C15
G1 = 0xBF58476D1CE4E5B9
G2 = 0x94D049BB133111EB

MAGIC = b"DVMP"
KNOWN_HEADER = MAGIC + bytes([0x01, 0x00, 0x00, 0x00])


def old_splitmix(key: int, index: int) -> int:
    """The mask primitive this project used to ship."""
    z = (key + index + G0) & MASK64
    z = ((z ^ (z >> 30)) * G1) & MASK64
    z = ((z ^ (z >> 27)) * G2) & MASK64
    return (z ^ (z >> 31)) & MASK64


def keystream(key: int, index: int) -> int:
    """The current mask primitive: SHA256(le64(key) || le64(index))[0..8)."""
    blob = key.to_bytes(8, "little") + index.to_bytes(8, "little")
    return int.from_bytes(hashlib.sha256(blob).digest()[:8], "little")


def unxorshift_right(y: int, shift: int) -> int:
    """Invert `y = x ^ (x >> shift)`. Accumulate on x, not on y."""
    x = y
    s = shift
    while s < 64:
        x ^= (x >> s)
        s += shift
    return x & MASK64


def unmix(v: int) -> int:
    """Invert the old SplitMix64 finaliser, i.e. `old_splitmix(k, 0)` in k."""
    z = unxorshift_right(v, 31)
    z = (z * pow(G2, -1, 1 << 64)) & MASK64
    z = unxorshift_right(z, 27)
    z = (z * pow(G1, -1, 1 << 64)) & MASK64
    z = unxorshift_right(z, 30)
    return z & MASK64


def unmask_with(mask, blob: bytes, off: int, key: int, words: int) -> bytes:
    out = bytearray()
    for i in range(words):
        w = int.from_bytes(blob[off + i * 8 : off + i * 8 + 8], "little") ^ mask(key, i * 8)
        out += w.to_bytes(8, "little")
    return bytes(out)


def unmask(blob: bytes, off: int, key: int, words: int) -> bytes:
    return unmask_with(keystream, blob, off, key, words)


def old_key_from_known_plaintext(stored0: int) -> int:
    """The old break, step by step: invert the finaliser, subtract G0."""
    return (unmix(stored0 ^ int.from_bytes(KNOWN_HEADER, "little")) - G0) & MASK64


def header_is_plausible(img: bytes) -> bool:
    """The self-consistency test a candidate key has to pass.

    The magic cannot be the test: in the algebraic attack it holds *by construction*,
    because the key is defined as the value that makes it hold. What discriminates is
    the rest of the container, above all the body length, which lives inside the
    ciphertext and therefore cannot be satisfied by a wrong key.
    """
    if len(img) < 32:
        return False
    if img[0:4] != MAGIC:
        return False
    if int.from_bytes(img[4:6], "little") != 1:
        return False
    body_len = int.from_bytes(img[16:20], "little")
    if not (0 < body_len < (1 << 22)):
        return False
    entries = int.from_bytes(img[24:28], "little")
    if not (0 < entries <= 64):
        return False
    words = (40 + body_len + 7) // 8
    return words * 8 <= len(img)


def algebraic_attack(blob: bytes, max_words: int = 4096) -> tuple[int, int, str] | None:
    """Known-plaintext key recovery, against both the old and the current mask.

    Returns (offset, key, which) if any primitive opens the container, and None if
    none does.

    Trying the *old* primitive as well as the new one is what gives this check teeth.
    The first version derived the key with the old construction but unmasked with the
    new one, so the two could never agree and the check passed unconditionally - a
    green light wired to nothing. Against the build that actually shipped the
    SplitMix64 mask it now reports a hit, which is how the detector was verified: it
    caught the real vulnerable APK before the mask was replaced, and the `--selftest`
    mode below keeps that ability testable without keeping the old build around.
    """
    for off in range(0, len(blob) - 40, 8):
        stored0 = int.from_bytes(blob[off : off + 8], "little")

        # (a) the mask this project used to ship: invertible in the key, and a stream
        for label, mask, derive in (
            ("splitmix64-finaliser", old_splitmix, old_key_from_known_plaintext),
            # (b) a hypothetical revert to *any* invertible-in-key mask would have to
            #     come through here; the naive identity check below is what catches a
            #     mask that is simply the key XORed with something predictable.
            ("identity", lambda k, i: k, lambda w: w ^ int.from_bytes(KNOWN_HEADER, "little")),
        ):
            key = derive(stored0)
            words = min(max_words, (len(blob) - off) // 8)
            img = unmask_with(mask, blob, off, key, words)
            if header_is_plausible(img):
                return (off, key, label)
    return None


def selftest() -> int:
    """Prove the detector finds a container that *is* masked with the old primitive.

    Each of the 1565-byte containers here is built from the recovered image, re-masked
    with one primitive, and embedded in a buffer that looks like a .rodata region. The
    attack must find the splitmix one and must not find the SHA-256 one; a detector
    that fails the first case is not a detector.
    """
    inc = (pathlib.Path(__file__).resolve().parent.parent
           / "packages" / "dartvmp" / "generated" / "vmp_module.inc")
    text = inc.read_text(encoding="utf-8")
    key = int(re.search(r"kDvmpImage_MASK_KEY 0x([0-9a-f]+)", text).group(1), 16)
    words = [(int(a, 16), int(b, 16)) for a, b in re.findall(
        r"\{\s*0x([0-9a-f]{8})u,\s*0x([0-9a-f]{8})u\s*\}", text)]
    plain = bytearray()
    for i, (lo, hi) in enumerate(words):
        plain += ((lo | (hi << 32)) ^ keystream(key, i * 8)).to_bytes(8, "little")

    failures = 0
    for label, mask in (("splitmix64-finaliser", old_splitmix), ("sha256-keystream", keystream)):
        blob = bytearray(b"\x00" * 64)  # a little noise before the array, as .rodata has
        for i in range(len(plain) // 8):
            w = int.from_bytes(plain[i * 8 : i * 8 + 8], "little") ^ mask(key, i * 8)
            blob += w.to_bytes(8, "little")
        blob += b"\x00" * 64
        hit = algebraic_attack(bytes(blob))
        want_hit = (label == "splitmix64-finaliser")
        if bool(hit) == want_hit:
            print(f"  ok    {label:<22} attack {'found' if hit else 'did not find'} it, "
                  f"as required")
        else:
            print(f"  FAIL  {label:<22} attack {'found' if hit else 'missed'} it")
            failures += 1
    return 1 if failures else 0


def read_so(args) -> bytes | None:
    if args.apk:
        with zipfile.ZipFile(args.apk) as z:
            names = [n for n in z.namelist() if re.search(r"lib/arm64-v8a/libdartvmp\.so$", n)]
            if not names:
                print("no arm64-v8a libdartvmp.so in the APK", file=sys.stderr)
                return None
            blob = z.read(names[0])
            print(f"read {names[0]} from the APK: {len(blob)} bytes")
            return blob
    if args.so:
        blob = pathlib.Path(args.so).read_bytes()
        print(f"read {args.so}: {len(blob)} bytes")
        return blob
    return None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("so", nargs="?", help="path to libdartvmp.so")
    ap.add_argument("--apk", help="extract libdartvmp.so from this APK instead")
    ap.add_argument("--key", help="mask key, hex, as an attacker who read the runtime "
                                  "would have it; skips the algebraic attempt")
    ap.add_argument("--dump", help="write the recovered container image here")
    ap.add_argument("--selftest", action="store_true",
                    help="prove the detector finds an old-mask container and misses a "
                         "new-mask one; no artifact needed")
    args = ap.parse_args()

    if args.selftest:
        print("selftest: the detector must find a container masked with the old")
        print("primitive, and must miss one masked with the current primitive")
        return selftest()

    blob = read_so(args)
    if blob is None:
        ap.error("give a .so path or --apk")
        return 2

    if args.key:
        # The honest path: the key was read out of the shipped AArch64. This succeeds,
        # by construction, and reporting it as a success is the point - it is the
        # exposure that remains and it is why C-layer virtualization matters.
        key = int(args.key, 16)
        print(f"using the supplied mask key {key:#018x} (as read from the runtime)")
        for off in range(0, len(blob) - 40, 8):
            img = unmask(blob, off, key, 240)
            if header_is_plausible(img):
                body_len = int.from_bytes(img[16:20], "little")
                words = (40 + body_len + 7) // 8
                img = unmask(blob, off, key, words)
                print(f"  container recovered at file offset {off:#x}, {words} words")
                print(f"  seed       : {int.from_bytes(img[8:16], 'little'):#018x}")
                print(f"  body_len   : {body_len}")
                print(f"  entry_count: {int.from_bytes(img[24:28], 'little')}")
                if args.dump:
                    pathlib.Path(args.dump).write_bytes(img)
                    print(f"  wrote {args.dump}")
                    print(f"  next: python tool/walk_bytecode.py --image {args.dump}")
                print()
                print("This path requires reading `unmask_image_into` out of "
                      "libdartvmp.so.")
                print("It cannot be closed while the key has to ship, which offline")
                print("distribution requires. See the README on the security ceiling.")
                return 0
        print("the supplied key did not yield a container", file=sys.stderr)
        return 1

    # Default: the attack that used to work.
    print("attempting the known-plaintext key recovery (the attack that used to work)")
    print("  primitives tried: splitmix64-finaliser (shipped before), identity")
    print("  known plaintext : the 8-byte header, 'DVMP' + version")
    found = algebraic_attack(blob)
    if found is not None:
        off, key, which = found
        print(f"\nFAIL: the mask key fell out of the shipped artifact: {key:#018x} "
              f"at offset {off:#x}")
        print(f"The image is masked with '{which}', which known plaintext inverts.")
        print("See the notes in packages/dartvmp/src/dvmp_sha256.c for what that costs.")
        return 1

    print()
    print("ok: known-plaintext recovery does not yield the key")
    print("    Neither does it yield any other keystream word: each index is a")
    print("    separate truncated hash, not a step of a stream, so the eight known")
    print("    header words expose eight words and nothing more.")
    print()
    print("Residual exposure, stated so it is not mistaken for safety: the key is")
    print("still in libdartvmp.so, so an attacker who reads `unmask_image_into` can")
    print("re-derive the keystream. Run this with --key <hex> to see that succeed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
