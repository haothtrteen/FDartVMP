#!/usr/bin/env python3
"""verify_wire_widths.py - the decoder's operand widths against the assembler's.

WHY THIS EXISTS
---------------
The bytecode is walked sequentially from both ends of the pipeline and neither walk
carries any redundancy: the Dart assembler writes each instruction's operand bytes
(``kOperandBytes`` in tool/vmpc/lib/src/opcodes.dart) and the runtime steps over them
(``op_width()`` in packages/dartvmp/src/dvmp_module.c). If the two tables disagree the
decode does not fail - it lands in the middle of an operand and keeps going, and the
container only refuses much later, or not at all, because a random byte is a valid wire
opcode about one time in seven.

The two tables were hand-copied from each other. They are compared here through the
runtime's own function (``dartvmp_wire_probe``) rather than by extracting the C source,
so what is checked is the *behaviour that ships*, not a second reading of it. The probe
answers ``DVMP_OP_MAX`` (0x26) for a byte that is not an opcode, so this also checks the
size of the opcode set in both directions:

    op <  len(kOperandBytes)   ->  probe(op) == kOperandBytes[op]
    op >= len(kOperandBytes)   ->  probe(op) == 0x26   (and not an opcode on either side)

An opcode added to the wire format without being added to the assembler (or the other
way round) therefore fails here instead of desynchronising a shipping decode.

WHY A NEGATIVE VALUE IS REJECTED
--------------------------------
The Dart table documents "a negative value marks an opcode whose operand width depends
on a second field (none today)". The runtime has no such case - ``op_width()`` is a
comparison chain that cannot express one - so a negative entry would be a width the
decoder does not implement. It is rejected explicitly rather than compared as an
unsigned byte and quietly passing.

Runs against the deployed desktop runtime (the same DLL the differential tests load):

    python tool/verify_wire_widths.py                       # app/build/native/dartvmp.dll
    python tool/verify_wire_widths.py --lib <path>          # explicit
    python tool/verify_wire_widths.py --negative-test       # prove the check can fail
"""

from __future__ import annotations

import argparse
import ctypes
import os
import platform
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
OPCODES_DART = REPO / "tool" / "vmpc" / "lib" / "src" / "opcodes.dart"
DVMP_OP_MAX = 0x26


def default_library() -> Path:
    if platform.system() == "Windows":
        return REPO / "app" / "build" / "native" / "dartvmp.dll"
    if platform.system() == "Darwin":
        return REPO / "app" / "build" / "native" / "libdartvmp.dylib"
    return REPO / "app" / "build" / "native" / "libdartvmp.so"


def parse_dart_widths(path: Path) -> list[int]:
    """The value list of `const List<int> kOperandBytes` in the assembler's table.

    Parsed rather than imported because this is a Python check and the Dart file is the
    one that defines the bytecode format; a regex over the literal is exact enough as
    long as the declaration is checked for existence, and any structural change to it
    fails loudly (see the length assertion) instead of silently parsing to nothing.
    """
    text = path.read_text(encoding="utf-8")
    m = re.search(r"kOperandBytes\s*=\s*<int>\[(.*?)\];", text, re.S)
    if not m:
        raise SystemExit(f"FAIL: could not find `kOperandBytes = <int>[...]` in {path}")
    body = re.sub(r"//[^\n]*", "", m.group(1))  # strip the per-entry comments
    values = [int(tok) for tok in re.findall(r"-?\d+", body)]
    if not values:
        raise SystemExit(f"FAIL: parsed zero entries out of {path}")
    return values


def load_probe(lib: Path):
    if not lib.exists():
        raise SystemExit(
            f"FAIL: {lib} not found - run `tool/build_native.ps1 -Configuration Release` "
            f"(or `tool/test.ps1`, which does it) first."
        )
    dll = ctypes.CDLL(str(lib))
    try:
        fn = dll.dartvmp_wire_probe
    except AttributeError:
        raise SystemExit(
            f"FAIL: {lib} does not export dartvmp_wire_probe - it was built with "
            f"DVMP_DIAGNOSTICS=OFF, or it predates the probe."
        )
    fn.argtypes = [ctypes.c_uint32]
    fn.restype = ctypes.c_uint32
    return fn


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--lib", type=Path, default=None)
    ap.add_argument(
        "--negative-test",
        action="store_true",
        help="pretend one assembler entry is wrong and require the check to catch it",
    )
    args = ap.parse_args()

    lib = args.lib or default_library()
    widths = parse_dart_widths(OPCODES_DART)
    probe = load_probe(lib)

    print(f"library          : {lib}")
    print(f"assembler table  : {OPCODES_DART.relative_to(REPO)} ({len(widths)} entries)")

    problems: list[str] = []

    negatives = [i for i, w in enumerate(widths) if w < 0]
    if negatives:
        problems.append(
            "the assembler declares negative ('depends on a second field') widths at "
            + ", ".join(f"0x{i:02x}" for i in negatives)
            + ", which op_width() cannot express - the runtime has no such case"
        )

    for op in range(256):
        got = probe(op)
        if op < len(widths):
            want = widths[op]
            if want < 0:
                continue  # already reported; there is no runtime value to compare to
            if got != want:
                problems.append(
                    f"opcode 0x{op:02x}: assembler says {want} operand byte(s), "
                    f"decoder says {got}"
                )
        elif got != DVMP_OP_MAX:
            problems.append(
                f"byte 0x{op:02x} is outside the assembler's table "
                f"({len(widths)} entries) but the decoder treats it as opcode "
                f"width {got}"
            )

    if len(widths) >= 256:
        problems.append(
            f"the assembler's table has {len(widths)} entries; the wire opcode is one "
            f"byte, so it cannot have more than 256"
        )

    if args.negative_test:
        # Reverse verification: the check is only worth its run time if it has been seen
        # to reject something. Flip the width of the first opcode that has one and
        # require the comparison to notice.
        victim = next((i for i, w in enumerate(widths) if w > 0), None)
        if victim is None:
            raise SystemExit("FAIL: negative test found no opcode with operands")
        want = widths[victim]
        widths[victim] = want + 2
        got = probe(victim)
        caught = got != widths[victim]
        print(
            f"negative test    : assembler 0x{victim:02x} forced from {want} to "
            f"{widths[victim]}, decoder still says {got} -> "
            f"{'caught' if caught else 'NOT CAUGHT'}"
        )
        if not caught:
            problems.append("the negative test was not caught: this check cannot fail")
        widths[victim] = want
        # And the reverse direction: a byte the assembler does not know.
        if probe(len(widths)) != DVMP_OP_MAX:
            problems.append(
                "the negative test found the decoder answering a width for a byte the "
                "assembler has no entry for"
            )

    if problems:
        print()
        for p in problems:
            print(f"FAIL: {p}")
        print(
            "\nThe two tables drive the same walk from opposite ends. Fix whichever side "
            "is wrong (`dvmp_wire.h` + `op_width()` in dvmp_module.c, or kOperandBytes in "
            "tool/vmpc/lib/src/opcodes.dart), then re-run `dart run tool/build.dart`."
        )
        return 1

    print(
        f"decoder and assembler agree on all 256 byte values "
        f"({len(widths)} opcodes, the rest rejected)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
