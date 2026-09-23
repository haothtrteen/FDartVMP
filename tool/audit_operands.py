#!/usr/bin/env python3
"""Audit every operand read in the interpreter for a preceding bounds check.

The bytecode container is attacker-controlled in the threat model, so each
instruction that reads `width` operand bytes must first establish that those bytes
are inside `cf->code_len`. A missing guard reads past the function's code into the
next function's bytes (or past the region), which is exactly the class of bug that
is invisible until someone crafts a container.

Prints one line per `case DVMP_OP_*` and whether a `next + N > cf->code_len` guard
appears inside it.
"""
import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parent.parent
VM = ROOT / "packages" / "dartvmp" / "src" / "dvmp_vm.c"
text = VM.read_text(encoding="utf-8")

# Widths from dvmp_wire.h's kWidth[], indexed by the public opcode numbering.
WIDTH = [0, 4, 2, 2, 0, 0, 0, 0, 0, 0,
         2, 2, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         4, 4, 4, 2, 0, 0, 4, 0]
NAMES = ["nop", "push_i", "push_k", "push_s", "push_nil", "push_true",
         "push_false", "pop", "dup", "swap", "load", "store", "add", "sub",
         "mul", "div", "mod", "neg", "and", "or", "xor", "shl", "shr", "not",
         "cmplt", "cmple", "cmpgt", "cmpge", "cmpeq", "cmpne", "jmp",
         "jmp_if_false", "jmp_if_true", "call", "ret", "ret_void", "host",
         "abort"]

# Split on `case DVMP_OP_X:` and keep the body up to the next case (or default).
parts = re.split(r"\n\s*case (DVMP_OP_\w+):", text)
bodies = {}
for i in range(1, len(parts), 2):
    name = parts[i]
    body = parts[i + 1]
    # Cut at the next case/default/`}` at the same indent level.
    cut = re.search(r"\n\s*(?:case DVMP_OP_|default:)", body)
    bodies.setdefault(name, []).append(body[: cut.start()] if cut else body)

# The wire enum values for the names we care about.
wire = (ROOT / "packages" / "dartvmp" / "src" / "dvmp_wire.h").read_text(encoding="utf-8")
enum_val = {}
for m in re.finditer(r"DVMP_OP_(\w+)\s*=\s*(0x[0-9a-fA-F]+)", wire):
    enum_val["DVMP_OP_" + m.group(1)] = int(m.group(2), 16)

problems = []
print(f"{'opcode':<22} {'wire':>5} {'width':>5}  guard")
for name in sorted(bodies, key=lambda n: enum_val.get(n, 999)):
    val = enum_val.get(name)
    if val is None or val >= len(WIDTH):
        continue
    w = WIDTH[val]
    for body in bodies[name]:
        has_guard = re.search(r"next\s*\+\s*%d\s*>\s*cf->code_len" % w, body) is not None
        reads = re.search(r"code\s*\[\s*next|rd_u32\(code\s*\+\s*next", body) is not None
        if w > 0 and not has_guard:
            problems.append((name, val, w, reads))
        if w > 0:
            print(f"{name:<22} {val:#5x} {w:>5}  {'guarded' if has_guard else 'MISSING'}"
                  f"{'' if reads else '  (no read found - check manually)'}")

print()
if problems:
    print("UNGUARDED OPERAND READS:")
    for name, val, w, reads in problems:
        print(f"  {name} (wire {val:#04x}, width {w})"
              f"{'' if reads else ' - no read matched, verify by hand'}")
else:
    print("every operand read in the switch has a matching `next + N > cf->code_len` guard")

# Also check the two reads outside the switch.
outside = [
    (m.start(), text[max(0, m.start() - 200): m.start() + 80])
    for m in re.finditer(r"code\[next\]|rd_u32\(code \+ next\)", text)
]
for _, ctx in outside:
    line = text[: text.find(ctx)].count("\n") + 1
print(f"\nreads inside the switch bodies: {sum(1 for b in bodies.values() for x in b if 'code[next]' in x or 'code + next' in x)}")
print(f"total `code[next]`/`code + next` occurrences in the file: {len(outside)}")
