# FDartVMP

**A source-level virtual machine protection system for Flutter.** Sensitive Dart functions
are compiled into a private instruction set, encrypted, embedded in a native library, and
executed by a private interpreter — so the original logic never exists in `libapp.so`.

[![License: AGPL v3](https://img.shields.io/badge/license-AGPL--3.0--or--later-blue.svg)](LICENSE)
[![Commercial license available](https://img.shields.io/badge/license-commercial%20available-green.svg)](LICENSING.md)
[![Platforms: Android, Windows](https://img.shields.io/badge/platforms-Android%20%7C%20Windows-lightgrey.svg)](#)

**Author:** haothtrteen · **Contact:** 2557976190@qq.com · **Dual-licensed:**
AGPL-3.0-or-later for open source, commercial license for closed-source products — see
[LICENSING.md](LICENSING.md).

**Try to break it:** the repository ships a CTF-style target built with the strongest
configuration this project has. See [docs/CHALLENGE.md](docs/CHALLENGE.md) for the target,
the rules, and the intended difficulty.

This is a working implementation with a real closed loop: compile → protect → run → verify. The compiler suite, the app suite (differential against a Dart reference
implementation), the shipped-APK protection checks and a real-device run are all part of
`tool/test.ps1 -Release`, and the results — including the parts that do *not* work — are
written down rather than glossed.

> 中文文档: [README.zh-CN.md](README.zh-CN.md)

---

## Naming

The project is **FDartVMP** (F for Flutter). The Dart packages, the CMake target and the
shipped library keep their original names — `dartvmp`, `vmpc`, `libdartvmp.so` — because
those names are part of the built artifact: the library name appears in every APK, the
`.so` name is in the protection gate's allowlist, and renaming them would be a wide change
with no benefit to anyone reading this. One name for the project, stable names for the
code.

---

## The problem this solves

Flutter's AOT artifact `libapp.so` is an ELF file containing a **Dart VM
snapshot**, not standard NDK machine code. It has no `JNI_OnLoad` entry point, so
generic SO VMP and DEX VMP tools cannot be applied to it — they would corrupt the
snapshot structure and the app would fail to initialise.

The way out is not to attack the snapshot's machine code, but to **move the
sensitive logic out of Dart entirely**:

```
core algorithm  ──► private bytecode  ──► encrypted  ──► embedded in C
      │                                                            │
      └──► stub in Dart  ←──  FFI return  ←──  private VM executes  ←─┘
```

An attacker reverse-engineering `libapp.so` finds a one-line stub. The real logic
exists only as bytecode inside the native library, and only in plaintext for the
duration of a call.

### Why not dart_eval?

The roadmap suggested `dart_eval` as the compiler and runtime. It is a good
project, but it does not solve the layer that matters here:

| | Custom VM (this repo) | dart_eval |
|---|---|---|
| Compiler | ~1 200 lines of Dart | provided |
| **Native interpreter** | ~700 lines of C | **still required** |
| Bytecode is hidden from Dart tooling | yes — never a Dart object | no — it is a Dart `Program` |
| Private instruction set | native | needs a fork to change |
| Result | logic genuinely absent from `libapp.so` | logic moved, not hidden |

`dart_eval`'s runtime is **pure Dart**. To execute its bytecode "in the C layer"
you would have to embed a Dart runtime in C — dragging in the very Dart VM
snapshot the design exists to avoid. So dart_eval saves the compiler and leaves
the hard half unsolved.

Building the interpreter is unavoidable either way, and once you are writing it,
co-designing a small instruction set with a small compiler is *less* work than
retrofitting a fork of someone else's opcode encoding. That is why this repository
ships its own VM.

The architecture keeps the boundary clean so a dart_eval front end can be added
later: anything that emits the instruction set in
`packages/dartvmp/src/dvmp_wire.h` works with the existing runtime.

---

## Architecture

```
protected/*.dart              the real implementations (NOT in the app)
        │
        ├── tool/vmpc:  lexer → parser → AST → bytecode → opcode permutation
        │             → stream cipher → container
        ├── packages/dartvmp/generated/vmp_module.inc   masked uint64 image (C header)
        ├── CMake (Windows: static link; Android: libdartvmp.so)
        ├── app/lib/generated/protected_stubs.dart      one-line stubs the app calls
        └── Dart FFI  ──► C interpreter (dvmp_vm.c)  ──► 23 audited builtins
                       └── guarded memory: decrypt → execute → wipe → re-encrypt
```

### The three protection layers

1. **Private instruction set.** Every opcode byte is permuted before it is written,
   by a keyed Fisher-Yates shuffle of the whole 0..255 byte range derived from the
   build seed (`Packer.opcodePermutation`, `op_tables` in `dvmp_module.c`), so the
   compiler's opcode numbering never appears on the wire. Recovering the instruction
   stream requires reversing this *and* the stream cipher. This replaced
   `perm(op) = (op * 167 + seed_byte) mod 256`, which the container gave up in 128
   attempts; see item 7 in
   [What was strengthened](#what-was-strengthened-and-what-was-deliberately-not)
   and its reverse test, `tool/recover_opcodes.py`.
2. **Stream cipher.** A SplitMix64 keystream XORed over the whole body. The seed
   **rotates on every call** and the working image is re-encrypted afterwards, so
   a dump of the *working buffer* taken between calls does not match the shipped
   binary, and two dumps do not share a keystream. The seed itself is in the
   container header and is therefore **obfuscation, not secrecy** — see
   [Where the plaintext actually is](#where-the-plaintext-actually-is).
3. **Static image masking.** The container is stored as 187 words, each XORed
   with a position- and build-dependent mask derived from the build id, so the
   `DVMP` magic is not findable with `strings` or `binwalk`.

### What is verified, and how

| Claim | Check |
|---|---|
| No protected logic in the AOT snapshot | `tool/verify_protection.ps1` scans `libapp.so` |
| No algorithm data in the native library | same script scans `libdartvmp.so` |
| No protected name reaches the shipped strings | the same script's name probes, which now require **zero** protected names in `libapp.so` - achievable only because the release APK is obfuscated |
| No dev-only oracle in the release snapshot | the same script checks the benchmark baseline is gone |
| The image really is masked | `tool/verify_image.py` un-masks and compares |
| Only the execution ABI is exported | `tool/list_symbols.py`, via the same script |
| The bytecode matches its generator | `tool/walk_bytecode.py` decodes it independently, checks the canonical CRC and the auth tag, and can be made to fail with `--tamper` |
| The descriptor layout has not drifted | the same script and `tool/verify_descriptors.py` both assert the two reserved fields are zero |
| The instruction store is not offline-decryptable | `app/test/vmp_e2e_test.dart` asserts its key is neither the shipped seed nor the previous call's |
| The plaintext window really closes between calls | the same file asserts the body buffer, the decoded slots and the store are all zero after a call |
| A call cannot make the whole program resident | the same file asserts `peak slots x largest function < total instruction bytes`, measured over a warm cache |
| A call does not leak native memory | the same file runs 256 calls and requires the guarded byte count to be unchanged |
| The desktop runner actually contains the runtime | `tool/capture_desktop_run.ps1 -CheckOnly`, run by `tool/test.ps1 -Release` |
| The desktop app really runs | `tool/capture_desktop_run.ps1` launches the release executable and captures the window |
| The C-layer hand-off actually finds its targets | `tool/apply_vmpacker.ps1` — refuses to run if a declared target is missing from the symbol table, if the library is not AArch64, if a helper of a target survived out of line, or if the tool translated only part of it |
| A virtualized target contains nothing VMPacker's VM cannot execute | the same script disassembles each target and refuses `bl`/`blr`/`adrp`/`adr`/`[pc,…]`, naming the instruction and offset |
| The protected library **runs** | `tool/verify_device_run.ps1` installs the repacked APK on a device and fails on a crash record — the only check here that executes the artifact |
| An ABI entry point has not been patched | `dvmp_integrity.c` scans the nine entry points for a branch at offset zero, and its decoder is self-tested against known encodings *and* against the real entry points; `app/test/vmp_e2e_test.dart` writes a real hook over one and requires the verdict to name it |
| The runtime enforces the policy the container declares | `dartvmp_guard_probe` exposes the runtime's own view (mode/budget/window/used); `app/test/vmp_challenge_test.dart` compares it against the manifest for every function |
| A declared policy is actually enforced, not merely encoded | the same file drives the *stub* path past its budget and requires a `TOO_MANY_CALLS` refusal |
| Overlapping calls from several threads agree | `tool/verify_concurrency.ps1` (C harness, 8 threads) |
| The artifacts under test are all from one build | the same file compares the runtime's build id against the manifest's |
| A release build has no anti-debug escape hatch | `tool/verify_antidebug_gate.ps1` builds both configurations and diffs them |
| The protection surface has no silent gaps | `vmpc check` asserts `// @vmp` count == compiled count |
| Every operand read in the interpreter is bounded | `tool/audit_operands.py` cross-checks each instruction against `kWidth[]` |
| The VM computes the same answers as Dart | `app/test/vmp_differential_test.dart` |
| Generator and runtime agree byte-for-byte | `tool/vmpc/test/image_contract_test.dart` |
| A declared call policy cannot refuse a legitimate caller | `app/test/vmp_e2e_test.dart` bursts past a documented legitimate ceiling and requires every call to succeed |

The differential suite is the important one: it runs every protected function
through the interpreter and diffs the result against the original Dart
implementation, for sweeps of inputs including 64-bit wraparound cases.

One asymmetry in the table above is worth stating rather than glossing: the
**tamper-detection** claim is proven by `tool/vmpc/test/image_contract_test.dart`,
which runs the packer and the tag/CRC maths in Dart. The runtime's own
verification path (`module_open_locked` in `dvmp_module.c`) is exercised only
indirectly — every call goes through it, so a *broken* check would fail the whole
suite, but a check that silently stopped firing would not be noticed, because
nothing feeds the shipped runtime a corrupted container. Closing that properly
needs a diagnostic entry point that accepts an arbitrary container and reports the
rejection reason; until then, treat "byte editing is rejected" as verified on the
generator side.

### What an independent tool sees

Everything above is this project checking itself. The stronger test is someone
else's tool, and the right tool for a Flutter app is
[Blutter](https://github.com/worawit/blutter): it reconstructs an AOT snapshot into
readable Dart with per-function disassembly — classes, method names, the object
pool, and the ARM64 for every function. Run against this app's **release**
`libapp.so`, that is the harshest static view available short of a full decompiler.

**Verdict: the protected bodies are not there.** Blutter reconstructed seven of the
nine stubs (the other two, `base32Index` and `checkSum`, are only called from inside
the protected module, so they were never reachable from the app and the tree-shaker
dropped them). Every one of the seven is the same three things: build an argument
list, call the native entry point with a constant id, type-check the result. All of
`selfTest`, as recovered:

```
static bool selfTest() {
  // ** addr: 0x28f398, size: 0x80
  r1 = <Object?>; r2 = 0
  r0 = _GrowableList()          ; the empty argument list
  r1 = 8
  r0 = call()
      bl  #0x28f418  ; [package:dartvmp/dartvmp.dart] Vmp::call
  ... IsType_bool_Stub ...
  ret
}
```

That is 128 bytes of marshalling. The id is an immediate (`add`=0, `normalizeKey`=2,
`verifyLicense`=4, `deviceToken`=5, `commandChecksum`=6, `makeLicenseKey`=7,
`selfTest`=8), so what an attacker gets is a dispatch table, not an implementation.
The IDs are not secret and never were — the stub declarations have to be named for
business code to call them.

The rest of the checks, from the same run:

| Checked | Result |
|---|---|
| `protected/licensing.dart`, `protected/keys.dart`, `licensing`, `keys.dart` | absent |
| `kAlphabet` (the canary), `kLicenseSeed` | absent |
| `2654435761`, `1048576`, `1099511628211` (algorithm constants) | absent |
| The dev-only benchmark baseline and its mixing expression | absent — the release snapshot really is the tree-shaken one |
| Protected function bodies | only FFI stubs, 0x80— xe4 bytes each |

The negative results are worth only as much as the positive control, so: Blutter's
dump of this same snapshot contains `demo-seed`, `pixel-7`, `1700000000`, `DartVMP
demo`, and real algorithm code — the `wire.dart` byte reader comes back with its
bounds check against the list length, the index increment and the `ldrb` array load.
The tool reconstructs this app's Dart faithfully. It just has nothing to reconstruct
for the functions that matter.

**One thing it did find, and it was our fault — and the second Blutter run found more.**
Sitting in the object pool beside those stubs was a plain-text description of the whole
mechanism, from two sources:

- the demo's own "How this works" card, which named `protected/*.dart`,
  `tool/vmpc`, the opcode permutation, the masked `uint64` image, the packed
  argument buffer and the per-call re-seed;
- the diagnostics binders in `packages/dartvmp`, whose `lookupFunction` string
  literals (`dartvmp_plaintext_probe`, `dartvmp_body_residue`,
  `dartvmp_session_probe`, …) name what each probe reveals, even though the probes
  themselves are compiled out of a release runtime.

Both were put behind `kReleaseMode`, and `verify_protection.ps1` grew a probe list for
exactly this — twelve mechanism *phrases*, checked against `libapp.so`. That fix worked
for the twelve phrases. **A fresh Blutter run then walked straight past all of them**,
because a phrase list only catches the leak you already knew about. What it found:

| Leaked to the snapshot | Why it matters |
|---|---|
| `"the shipped module image is not a DVMP container"` | names the container **magic** — which `tool/verify_image.py` exists to keep out of the binary and asserts is absent from the emitted literal. The Dart error table handed it back |
| `"invalid opcode in the module image"` | names the private instruction set |
| `"bad argument across the VMP boundary"`, `"internal VMP error"`, `"unknown VMP status"`, `"the VMP arena ran out of memory"` | four more entries of the same error table, naming the mechanism outright |
| `" does not fit in the VM's signed 64-bit slot"` | names the VM |
| `"dartvmp_instrumented_probe"`, `"dartvmp_antidebug_force"` | the two **newest** probe binders, which were added after the guard was written and without it |
| `"Every row below executed inside the native private VM. No Dart implementation of these functions exists in this application."` plus the benchmark card's `"deviceToken() runs 512 mixing rounds"` | the demo describing its own design, including a round count |

All of it is now fixed at the source, and each fix has a reason rather than a wording
change: the error table describes what failed for the caller and never how the protection
is built; the two unguarded binders got the guard; the demo's copy is release-neutral while
the detailed text stays in the source for non-release builds; the `wire.dart` exception
names the allowed types instead of the boundary's initials.

**And the check is now a category, not a list.** `verify_protection.ps1` searches
`libapp.so` for seventeen *mechanism words* (`DVMP`, `VMP`, `opcode`, `bytecode`,
`permut`, `SplitMix`, `mask key`, `private VM`, `native interpreter`, `masked uint64`,
`packed argument`, `protected/*.dart`, `tool/vmpc`, `mixing rounds`, `instrumented_probe`,
`antidebug_force`) plus the eight original phrases, with thirteen names allowlisted
*with their reason*: `libdartvmp.so` and the nine `dartvmp_*` ABI names are visible in the
APK's zip listing and in `.dynsym` regardless, so treating them as leaks would be
theatre, and `DartVMP` is the product name in the app's title (which contains `VMP` as a
substring, which is why the allowlisted strings are blanked out before the scan).
Reverse-verified the same way as before: run against the APK Blutter analysed it reports
nine leaks with surrounding context, and against the rebuilt one it reports none.

The two failures that were *not* wording, both now regression checks:

- **The unguarded binders.** The comment above them said "every diagnostics binder below
  returns early in a release build" and two did not. A comment cannot enforce that, so
  `app/test/vmp_e2e_test.dart` now walks `bindings.dart`: every `static` method whose name
  starts with `_bind` must reach its `lookupFunction` only after an `if (kReleaseMode)`
  return. Reverse-verified by deleting one guard and watching it name that binder.
- **The check's own reach.** The first version of *that* test scanned 400 characters past
  each signature, which is shorter than the comment on one of the binders — so a
  correctly gated binder was reported as a leak. It now brace-matches the whole method
  body. Same failure mode as the bug it exists for, one level up.

**Dart-side obfuscation, and what "zero names" means.** The release APK is built with
`--obfuscate --split-debug-info=<dir>`, and that turned out to matter more than expected.
Blutter reads whatever the snapshot keeps, and a plain release snapshot keeps the
generated stub declarations under their real names — business code calls `verifyLicense(…)`,
so the declaration had to be spelled that way. Obfuscation renames the declarations and the
call sites together, and the stubs dispatch by numeric id (`Vmp.call(4, …)`), so nothing
depends on the real name. With the flag on, the protected names went to **zero
occurrences** in `libapp.so`, and `verify_protection.ps1` now *requires* zero — the previous
standard ("the names present are stub declarations, therefore acceptable") is gone, because
it was the loophole that let the last copy of the map ship.

Getting there took two rounds, and the second one is the instructive part: after enabling
obfuscation, seven names were **still** in the snapshot — because this demo printed them as
its own row labels (`'verifyLicense(key)'`). The UI text was handing over the id → purpose
map that item 3 removed from the container. Release builds now label rows by id (`fn[4]`),
dev builds keep the names, and the screen above is the obfuscated build: `fn[0] 42`,
`fn[4] true`, `fn[7] ZVEXKFVVCDH93W6R`, with every value still matching the reference.

Both directions are verified rather than asserted: the same sources built **without**
`--obfuscate` fail the gate naming six of the eight probes, and the obfuscated build passes
with all eight absent. The cost is real and worth stating: the symbols directory must be
archived with each release, or crash stacks come back as `a`, `b`, `c`.

**What this does not hide, so the win is not overstated.** `Vmp.nameOf(id)` still resolves
the names *at runtime* from the masked table inside `libdartvmp.so` — the demo's own
dispatch rows print them (`dispatch [4] verifyLicense / 1 args`, visible in that same
screenshot). Removing them from the UI would be theatre: the lookup is public API and the
table is in the shipped library. **This work is about the static axis — what Blutter can
read out of `libapp.so` without running anything — and on that axis the app now carries no
map at all.**

### What was strengthened, and what was deliberately not

Eight items were on the list. Six are implemented and verified; one turned out to be
impossible with the available tool and was measured rather than assumed; one was rejected
after checking what it would actually buy. The rejections are the more useful half of this
section, because each of them looks like security and is not.

**1. Virtualize the C layer — applied, device-tested, and it does not hold.**
Recovering the container is mechanical (item 2 removed the cheapest route, and
`tool/recover_from_shipped.py` still does the honest version). What an attacker does next
is *read the bytecode*, and that used to be cheap because `dvmp_vm.c` compiles to a
readable switch that states each opcode's semantics. This item was supposed to close that
step. It closes part of it, and the honest summary is uncomfortable:

**The first device run made it work for the two functions that are worth the least. The
second one brought back three of the five that matter.** Seven functions were virtualized,
applied cleanly, and passed every structural check. Then the protected APK was installed on
a rooted Xiaomi 12 (Android 13, arm64-v8a) and five of the seven killed it. Tested one
target at a time — and then fixed, in our C layer, one limitation at a time:

| Target | On device | Why / what changed |
|---|---|---|
| `keystream_seed` | **runs correctly** | no calls, no globals — 4 instructions |
| `apply_keystream` | **runs correctly** | 79 instructions: immediates, register moves, byte loads/stores, branches |
| `permute_code` | **runs correctly** | died at `0x0` on the `kWidth[]` table's `adrp`; the table is now `op_width()`, a comparison chain over immediates (and its `CSEL` had to go too) |
| `unpermute_code` | **runs correctly** | died at `0x6dcc`, the address of `bl dvmp_vm_set_error`; the message is formatted by the caller now |
| `dvmp_body_tag` | **runs correctly** | died at `0x6d60`, the address of `bl dvmp_fnv1a64`; the hash is inlined (one definition, two views) |
| `dvmp_mask_keystream` | SIGSEGV | calls `dvmp_sha256`; also has a local array |
| `code_store_build` | SIGSEGV | calls five functions |

"Runs correctly" means the values, not the absence of a crash: the APK was launched,
screenshotted, and every figure on the demo card checked against the Dart oracle —
`add(20,22)=42`, `makeLicenseKey("demo-seed",7)=ZVEXKFVVCDH93W6R`, `verifyLicense` true for
the good key and false for the altered one, `deviceToken("pixel-7",1700000000)=
-5031510683369134119`, `selfTest()=true`. Those calls are dispatched through the
trampolines, and the module cannot open at all unless `dvmp_body_tag`, `permute_code` and
`unpermute_code` compute exactly what the Dart assembler computed. The suite's device step
only proves "no crash record", which is why this was checked by eye as well.

The fault addresses were the diagnosis for the first three. VMPacker 1.3's VM remaps
branches *inside* the function it translated and nothing else, so an external `bl` keeps
its link-time address and the VM jumps there without adding the library's load bias — which
is why the fault address **equals the call target**: `llvm-objdump -d` puts `dvmp_fnv1a64`
at `0x6d60` and `dvmp_vm_set_error` at `0x6dcc`, and those are exactly the two addresses
the process died on. `adrp`/`adr`/pc-relative loads are the same story for globals, which
is why `permute_code` — which calls nothing at all — died at `0x0`.

The fourth one had no fault address at all, and it is the interesting one. With calls,
`adrp` and SIMD gone, all five targets translated in full, the APK installed, the process
stayed up — and every protected call failed with `opcode 0x20 out of range at +0`: the
decode walk rejecting the first byte of the instruction stream. A device bisect
(`tool/bisect_vmpacker.ps1`, one target added at a time) put it on `unpermute_code`, and
comparing its disassembly against the three targets that worked pointed at `CSEL`: present
twice there (the shuffle's `r % (256 - i)`, and the `i < DVMP_OP_MAX ? i : DVMP_OP_MAX`
select in the inverse-table scatter) and absent from all three working targets. VMPacker's
VM has a `CSEL` handler, so the instruction is "supported" — it answers wrongly. The fix is
in our source rather than in the tool, because the pipeline has to stay reproducible with
the unmodified release: the shuffle uses an exact identity instead of a remainder
(`r - ((r + i) >> 8) * (256 - i)`, valid because `i < 38` and `r <= 255` make the quotient
exactly that shift) and the inverse table is built by two unconditional scatters instead of
one conditional one. This is the one failure in this project that no byte-level check could
have caught: it translates 100% and runs without crashing, and the only signal is a number
that is wrong.

So `tool/vmpacker_targets.txt` now lists five targets; the two that would still need a call
sit in a `#+pcrel` section that the **instruction-coverage check** in
`tool/apply_vmpacker.ps1` refuses by name and offset. That check is the durable artifact of
the first round: it catches in a second what took a device, a tombstone and a bisect to
find. It is reverse-verified — it fires on the real library, with `+0x4428 bl 0x9624
<vmp_secure_alloc>` and `+0x4590 adrp x0, ...` for `code_store_build`.

**What the five surviving targets are worth: more than the two were, and still not the
interpreter.** `apply_keystream` is SplitMix64 keyed by the seed in the container header,
and `keystream_seed` is `seed ^ 0xA5A5…`; both are documented above, in this file, in
enough detail to reimplement, so virtualizing them costs an attacker the ten minutes it
takes to write those two functions. The three that came back are a different kind of
target: `permute_code` and `unpermute_code` are the private opcode mapping itself, and
`dvmp_body_tag` is the container's authentication tag. Recovering any of them now means
either reimplementing the construction or inverting VMPacker's bytecode — the disassembly
route that used to answer "how is the mapping derived" in an afternoon is gone. What has
*not* changed is the layer underneath: `dvmp_vm.c` is still readable AArch64, so "read the
interpreter and you know what each opcode does" is exactly as cheap as it was. Item 7 is
still what protects the mapping's secrecy; this item raises the cost of the other route.

The rest of this item is the record of how the three checks around the invocation were
built, because they are what makes the target list trustworthy, and each was written after
watching the failure it catches:

- **Instruction coverage.** `bl`/`blr` and `adrp`/`adr`/`[pc, …]` are refused, with the
  offset named. This is the check that would have stopped all five crashes before the APK
  was built, and it is the only one here that could have been written without a device.
- **Full translation, per target.** `-v` reports `Translated: N/M`, and the script refuses
  a partial one. The byte-level post-flight cannot see this: VMPacker emits a trampoline
  for the instructions it did understand, so "the bytes changed and there is a branch"
  passes while the rest of the function sits in plain AArch64 next to it.
- **Helpers must not survive out of line.** A `static` helper called from two virtualized
  targets gets its own body at `-O2`, and that body is exactly what the trampoline hides:
  the attacker calls it and never enters the VM. Not hypothetical — the first
  keyed-permutation build shipped `t op_tables` at `0x4134`, and VMPacker's own verbose
  output showed `0x0040: BL raw=0x97FFFF0C` going into it. `DVMP_ALWAYS_INLINE` fixes it
  and `!op_tables` keeps it fixed.
- **The targets must exist at all**, and the library must be AArch64. A name-based tool
  that finds nothing exits 0 and ships an unvirtualized library that everyone believes is
  protected; a `.so` built for the *other* ABI has the same symbols and passes every name
  check.

**Two more failures this cost, both now fixed at the source.** Neither is a VMPacker
limitation; both were ours:

- **The stack canary.** The NDK compiles with `-fstack-protector-strong`, so every target
  with a local array begins `mrs x19, TPIDR_EL0` / `ldr x8, [x19, #0x28]`. VMPacker
  translates both and its VM does not reproduce the TLS read, so `x19` arrives as zero and
  the process dies with `fault addr 0x28` — the `#0x28` from that instruction, literally.
  `DVMP_VMPACKER_TARGET` now carries `no_stack_protector`, on the targets rather than as a
  file-wide flag, so the canary is dropped exactly where a VM executes the code.
- **SIMD from clang's *inline builtins*, not from the vectoriser.**
  `dvmp_mask_keystream` and `code_store_build` refused to translate (64/70, 202/210) on
  `movi` + `stp q0,q0` and `ldr q`/`str q`. `-fno-vectorize -fno-slp-vectorize` changed
  nothing, which was the surprise: the SIMD was a `memset` expansion (a 256-byte constant
  fill), a 32-byte constant copy of the SHA-256 initial state, and an inlined `memcpy`.
  `no_builtin("memset","memcpy")`, eight scalar assignments instead of
  `uint32_t h[8] = {…}`, and building the inverse opcode table as a data-dependent scatter
  instead of a constant fill took both to 100% — at which point the device showed the
  *next* problem, which was the call.

**The interpreter itself: measured, and out of reach.** `dvmp_vm_run` is where the ISA
semantics live, so it is the one target that would close the last readable step.
It does not work with this tool: with `dvmp.vmpacker.hot=true` (which de-vectorises
`dvmp_vm.c` as well) it translates **1029 of 1053** instructions and VMPacker aborts. The
24 refusals are 16-byte struct copies in SIMD registers — the interpreter's own value
moves, not a vectorised loop — and neither de-vectorise flag touches them. It would also
be the wrong thing to want: a VMPacker-protected function runs on a second interpreter, so
virtualizing the inner loop nests one VM inside another on every bytecode instruction of
every protected call. The switch exists (`-PcRel` does not include it; see the note in
`tool/vmpacker_targets.txt`) and is documented rather than deleted, so the decision can be
revisited if VMPacker grows SIMD coverage and call resolution.

**What a device run found that nothing else could.** The suite was ALL GREEN while the
protected APK crashed before its first frame: `apply_vmpacker.ps1` reported "all 5/5
targets replaced by VM trampolines" and read the bytes back to prove it, the exports were
intact, the container CRC and tag verified, and the APK installed. Byte-level checks answer
"did the tool do something"; they cannot answer "is the result executable". That is now a
step of its own — `tool/verify_device_run.ps1`, wired into `tool/test.ps1 -Release` — and
it is the check that turns this item from a claim into a measurement. It proves the process
survives startup and writes no crash record; the *values* are checked by reading the demo
screen, which prints the result of every protected function and all nine dispatch entries.
Both were done: with the two usable targets the protected APK runs and every value matches
the reference implementation, including `makeLicenseKey("demo-seed", 7) =
ZVEXKFVVCDH93W6R` and `deviceToken("pixel-7", 1700000000) = -5031510683369134119`.

**2. The mask no longer gives up its key to known plaintext — done.**
`tool/recover_from_shipped.py` used to recover the mask key from the release APK with no
disassembly at all. Three things combined: the mask was `SplitMix64-finalise(key +
index + G0)`, which is a **bijection in the key**; the container starts with eight bytes
of **known plaintext** (the magic plus a version); and it was a **stream**, so one word
implied the next 195. So `unmix(word[0] XOR known_header) - G0` was the key, and the key
was the container.

It is now `SHA256(le64(key) || le64(index))[0..8)`, which changes the *shape* rather than
merely the constants:

| | before | now |
|---|---|---|
| one known word reveals the key | yes, by inversion | no — 64 bits are discarded, so inverting costs ~2^64 |
| one known word reveals other words | yes, it is a stream | no — each index is an independent keyed function |
| what the eight header words expose | all 196 words | eight words |

SHA-256 rather than something cheaper because it has published vectors, which makes the
hand-written implementation *checkable*; a subtly wrong hash would otherwise be changed
into the Dart generator to match, the container would still round-trip, and every test
would still pass. `tool/verify_crypto.ps1` runs the vectors across every padding path
and then runs the attack. Both directions were verified: the detector finds a container
masked with the old primitive (`--selftest`), and it caught the **real** APK still on
disk, reporting `0x8f3a17c9e7cf471b at offset 0x1c50` — the same key recovered by hand
earlier. Against the rebuilt APK it reports nothing.

Residual exposure, stated so the win is not overstated: the key still ships inside
`libdartvmp.so`, because offline distribution requires it, so an attacker who reads
`unmask_image_into` can re-derive the keystream. What changed is that this now requires
**reading the runtime** instead of doing algebra on data the binary hands over. That is
a real step, and it is not the same thing as confidentiality.

**3. The function names are out of the container — done, by removing them.**
`walk_bytecode.py` used to print `fn 4 [verifyLicense]` from a decrypted container,
handing over the whole id → purpose map. Two things were true: nothing in the runtime
ever *read* `DvmpFuncDesc.name` (name lookup goes through the compiled-in masked
`kDvmpNameBlob`), and the emitter asserted the names had to be in the string table on the
stated grounds that `dartvmp_call_named` resolved against it — which was simply wrong.
So the names were dead weight whose only effect was to put the map inside the ciphertext.

Masking them *inside* the container was considered and rejected: everything in the
container is plaintext to whoever decrypts it, so masking there is decoration. Removing
them is the version that changes what an attacker has. String table 12 entries → 3,
container 1565 → 1398 bytes, and the walker now prints `fn 4 []`.
`tool/verify_descriptors.py` asserts the name fields are zero, reverse-verified by
restoring both halves of the old behaviour and watching it fire.

**4. Per-function keys — rejected, because it would have been theatre.**
The container's body is encrypted under a keystream derived from the seed *in its own
header*. Any per-function key derived from that seed is therefore available to anyone
who has the seed, which is anyone who has decrypted the container — which is the step
per-function keys were supposed to make harder. Deriving 9 keys instead of 1 from a
value the attacker already holds changes nothing.

The place per-function keying actually pays is the **runtime** store, and it is already
there: `code_store_build` draws fresh entropy per open and keys each function separately
(`keystream_seed(code_key ^ i)`) precisely so that materialising one function does not
reveal another's keystream. That is the version of this idea that has an attacker in
front of it.

**5. Anti-debug — wired up, but the reaction was changed first.**
The layer existed and was wired (`dartvmp_init_locked` refused to initialise when
instrumentation was detected), and it was off everywhere. Both halves of that were
wrong. Off everywhere meant the shipped APK had no runtime countermeasure at all; and
"refuse to initialise" meant the first false positive — a misconfigured `TracerPid`, an
emulator, a vendor's monitoring agent, a Frida-looking port — ships an application that
will not start. A protection layer that can break the application is the one outcome the
first rule in this README forbids.

The reaction is now to narrow the decoded-function cache from four slots to **one**:
under a debugger the plaintext window is one function wide instead of four, and the
interpreter returns bit-identical answers. Emptying the cache is not an option — a
function's stream has to stay valid for the instruction being executed — so one slot is
the narrowest correct setting, and `dvmp_code_ensure` revalidating the slot's identity is
what makes a one-slot cache correct rather than merely slow. Refusing outright is still
available via `-DDVMP_ANTIDEBUG_REFUSE`, opt-in, so the trade is made deliberately.

It is now **on in the shipped APK**, verified on a real device (no false positive, all
nine functions green), and `app/test/vmp_e2e_test.dart` forces the verdict through a
diagnostics-only hook to assert both halves: the cache really is one slot, and every
protected function still matches the reference implementation while it is.

**6. The ceiling, and the only structural answer.**
The exposure chain is now: `libdartvmp.so` contains the mask key → the key opens the
container → the container contains the bytecode → `libdartvmp.so` also contains the
interpreter that says what the bytecode means. Every arrow is "read something that
ships". Nothing in items 2, 3 or 5 removes an arrow; they raise the cost of the first one
from a script to a reversing session. **Item 1 was supposed to raise the cost of the last
one and does not**: the interpreter is still ordinary AArch64, because the VM that would
have hidden it cannot execute the instructions that function is made of. What item 7
raises is the cost of the *mapping*, not of the ISA — an attacker who reads `dvmp_vm.c`
still knows what every opcode does, and now has to reconstruct which byte means which.

So the honest statement of the ceiling is: **for a component that must work offline,
static recovery is a matter of effort, not of possibility.** Engineering can choose how
much effort; it cannot choose "none". If particular logic must be genuinely
unrecoverable, the only answer is architecture rather than obfuscation — keep that logic
on a server and let the shipped binary call it. The VMP then protects the parts that have
to work offline (the policy, the derivation, the checks a network dependency would make
unavailable), and the split should be made by asking which parts are worth a round trip,
not by asking which parts the obfuscator can hide best.

**7. The private instruction set was an affine map of a public byte — replaced.**
This one is worth its own item because it was the last step of the recovery chain that
could be brute-forced rather than reimplemented, and it was found by asking what an
attacker does *after* items 1 and 2 rather than by auditing the code.

The container's stream cipher is keyed by the seed in its own header, so it is public by
construction and an attacker strips it offline. What is left between them and the bytecode
is the opcode permutation. It was

```
wire = (op * 167 + (seed & 0xFF)) & 0xFF
```

and the seed is in the header, which leaves the multiplier — which must be odd, because
167 and 256 are coprime and the map has to be invertible. That is **128 candidates**.
`tool/recover_opcodes.py` runs the attack: try each candidate, walk the instruction stream
under it, and keep the one that consumes the stream exactly with every opcode in range.
The container's own CRC is the oracle, so the result is not a guess. Virtualizing
`unpermute_code` bought nothing while that was true, because the mapping fell out of the
container anyway.

It is now a keyed Fisher-Yates shuffle of the whole 0..255 byte range, driven by the same
SplitMix64 stream under a distinct domain constant, with the first `DVMP_OP_MAX` entries as
the wire values. There is no parameter to search: recovering it means finding an assignment
consistent with the entire instruction stream, and the search space is a permutation of 256
values rather than 128 odd numbers. The permutation is rebuilt from the seed on each call
rather than cached, on purpose: a cached table would be a second copy of the mapping in
memory for an attacker to find, which is the thing being hidden. That costs one 256-byte
shuffle per function materialised, against an interpreter that then runs thousands of
instructions.

`tool/recover_opcodes.py` now fails on shipped output — and, because a detector that can
only ever say "nothing found" is a print statement, its `--selftest` re-packs the same body
with the old affine mapping and must still recover *that*, byte for byte. Both directions
run in `tool/test.ps1 -Release`. The selftest earned its place immediately: the first
version of the script zeroed its own operand bytes while decoding, which broke the CRC
oracle, so it reported "not affine" for *every* input including the legacy container it was
supposed to crack. The attack that "failed" had never run.

**The ceiling does not move, and this item does not pretend otherwise — and the honest
version got *worse* when item 1 was measured.** The permutation's construction lives in
`op_tables`, inlined into `unpermute_code` and `permute_code`. Those two were supposed to be
VMPacker targets; the device run showed they crash, so they are **not** virtualized and the
construction ships as ordinary, readable AArch64. So the accurate statement is:

- before: the mapping could be recovered **mechanically** — 128 candidates, the container's
  CRC as the oracle, no reading of code required;
- now: it cannot be recovered mechanically, and the search space is a permutation of 256
  values rather than 128 odd numbers — but an attacker who reads ~100 instructions of
  `unpermute_code` (or recognises SplitMix64 plus a Fisher-Yates loop) reconstructs it
  directly.

What item 7 removed is the *script*. What it did not do is make the mapping secret, and
item 1 did not put it behind a trampoline. That is the difference this project can actually
buy, and it is why the honest framing throughout is "how much effort", not "whether".

**8. The cheapest attack was not defended at all — entry-point integrity, added.**
Everything above is about an attacker who wants to *understand* the protected logic. The
attack that actually happens to a licensing demo is cheaper than that: **patch the answer.**
Return `true`, intercept the entry point that produces it, hook the FFI call. None of it
requires reading the container, the bytecode or the interpreter, and none of the seven items
above touches it — which made this the largest unaddressed gap in the project, and it was
found by asking what an attacker wants rather than what the design protects.

`packages/dartvmp/src/dvmp_integrity.c` scans the nine ABI entry points for a branch at
offset zero, which is what both common tools (Frida's Interceptor, Dobby) and a hand-made
patch leave behind. The reaction follows the rule the rest of the runtime follows: record it,
fold it into the same verdict instrumentation gets (a one-slot decoded-function cache), and
**never change an answer**. Refusing to start stays opt-in under `-DDVMP_ANTIDEBUG_REFUSE`.

**The honest ceiling, stated as plainly as the rest of this file:** this finds a hook that
*begins* with a branch. A hook that saves the prologue first, or that patches the caller
instead, is not found — and the check is itself patchable by anyone who knows it is there. It
removes the *free* version of the attack; it does not remove the attack. If a bypass must be
genuinely prevented, no local check does it, because the attacker owns the process.

Two things about building it are worth keeping, because both are the pattern this project
keeps running into:

- **The first version had a false positive, and the fix made the check real.** It flagged any
  entry point starting with an unconditional branch — and on the Windows build three clean
  functions came back "hooked": `dartvmp_last_error`, `dartvmp_secure_bytes_live` and
  `dartvmp_build_id`. They are one-line wrappers, and MSVC ends such a function with `jmp`
  rather than a call/return pair: `E9 <rel32>` then `CC` padding, byte-for-byte what a hook
  looks like in the first four bytes. What separates them is where the branch *goes* — a tail
  call targets another function in the same module, a hook targets a trampoline in a different
  allocation — so the check now asks that (a module-range query on each platform, and "inside"
  when the platform cannot answer, so an unknown case is never reported as a hook).
- **The self-test is a measurement of this binary, not of invented constants.** It checks the
  decoder against known encodings *and* requires every real entry point to classify as clean,
  which is exactly the assertion that catches the tail-call case above. `app/test/vmp_e2e_test.dart`
  then does the attack for real: it makes the code page writable, writes a branch over
  `dartvmp_status_name`'s first instruction, and requires the verdict to report count 1 with
  the bit for *that* function set — then restores the bytes and requires a clean verdict again.
  A check that had only ever been seen to say "clean" would be a print statement.

**What was not done, and why it is not listed as a gap:**
deeper nesting of keys that all ship in the same binary; a second cryptographic layer over
a first one whose key is also in the binary; opacity tricks aimed at the *container*
format. Each costs maintenance and review effort, buys an attacker a few hours, and — the
part that matters — makes the code harder to reason about, which is how the real bugs in
this project were found.

### What only a real run could find

The suite above is green, and it was green while **the shipped Windows desktop
application could not start**. The runner builds the runtime as a static library
and links it in, so there is no `dartvmp.dll` anywhere in the bundle — but
`openRuntimeLibrary()` opened `dartvmp.dll` by name on every platform, and the
app's first screen read:

```
The protected runtime is unavailable
VmpUnavailable: could not open dartvmp.dll: ... (error code: 126)
```

Two separate faults had to line up for that, and each hid the other:

- **The plugin never linked the runtime.** Flutter's generated CMake runs
  `target_link_libraries(${BINARY_NAME} PRIVATE ${plugin}_plugin)` only for
  plugins in `FLUTTER_PLUGIN_LIST`; an FFI plugin lands in
  `FLUTTER_FFI_PLUGIN_LIST`, whose loop only *copies* files. So
  `packages/dartvmp/windows/CMakeLists.txt` built the static core and dropped it.
  Adding the link was still not enough: the MSVC linker discards a static library
  that nothing references by name, and nothing does — Dart resolves `dartvmp_*`
  through `GetProcAddress` at runtime. The executable has to be linked with
  `/WHOLEARCHIVE`. The first fix produced a 90 KB exe with an empty export table
  and *the same error message*.
- **Dart looked for the wrong thing.** With the runtime inside the executable,
  the symbols have to come from `DynamicLibrary.executable()`, not from
  `DynamicLibrary.open('dartvmp.dll')`. Android is the mirror image: the Gradle
  plugin packages `libdartvmp.so` into the APK, so `open()` is right there and
  `executable()` would find nothing.

Neither fault was reachable from `flutter test`, and that is structural rather
than an oversight in the tests: the test host is `flutter_tester.exe`, which does
not contain the runtime, so the suite *must* load a separately built DLL through
`DARTVMP_LIBRARY_PATH` — which is precisely the path a shipped desktop app does
not take. **A test host cannot exercise the way the product loads its own code.**
`tool/capture_desktop_run.ps1` closes that gap: it scans the built executable for
the ABI symbols (a link check that needs no display, and which `tool/test.ps1
-Release` now runs), then launches the real release executable and captures its
window. The current run shows `runtime loaded, 9 protected functions` and nine
green `dispatch [0..8]` rows.

The same review found that `pubspec.yaml` declared `ios`, `linux` and `macos` as
plugin platforms with no plugin directory behind any of them, so the package
advertised support it did not have. Those entries are gone; `openRuntimeLibrary`
keeps the branches so adding a platform is a matter of adding the directory.

Measured on the current build:

```
compiler tests        33 passed
app tests             31 passed   (16 differential + 15 protection)
libdartvmp.so         9 exported symbols, 0 interpreter internals
libapp.so             4.2 MB, no protected constants or algorithm data
                      (0 names: obfuscation renames the stub declarations too, and nothing else spells them)
dartvmp_demo.exe      126 KB, runtime linked in, 9/9 protected functions green
static image          1565 bytes across 196 masked words
bytecode              1525 bytes for 9 protected functions
code residency        4 slots, largest function 215 bytes, 958 bytes total
```

### What an adversarial review found

The claims above were checked by an independent audit that rebuilt the container
format from scratch, crafted arbitrary images, took a cross-process memory dump
of the live runtime, and ran a multi-thread probe. It found real problems, and
they are worth listing because the pattern is more useful than the individual
bugs:

| Finding | What it means |
|---|---|
| The body was never wiped | the documented plaintext window was the process lifetime, not the call — **fixed** |
| No lock existed despite the docs claiming one | concurrent calls returned wrong answers and crashed — **fixed** |
| `need_builder` accepted any object | a crafted image reached a wild-pointer dereference — **fixed** (builders have their own slot tag) |
| `entry_name_eq` read past the query's NUL | bounded over-read, reachable from `callNamed` — **fixed** |
| `strParseInt` returned a truncated prefix on overflow | silently wrong number, unlike the oracle — **fixed** |
| The generated image was not a build dependency | regenerating it did not recompile the library, so a stale image shipped — **fixed** |
| The diagnostics build was deployed into the runner directory | a desktop release could bind a runtime exporting `code_probe` — **fixed** |
| `verify_protection.ps1` reported the app's stub names as `info` | the masked table only helps if the names are not in `libapp.so` too — see below |

The common thread: **every one of those was a case where the documentation
described the intended design and the code did not implement it.** The prose was
not wrong about the plan; it was wrong about the state. That is why the fixes came
with checks that fail when the behaviour regresses, rather than with corrected
comments — a corrected comment would have been equally true and equally
unverified.

Findings that were gaps and are now closed, kept here because closing them took a
second look:

- **The stub names in `libapp.so` — closed, and the closing was two-sided.** The runtime's
  name table was masked and no name survived there, but the generated Dart stubs declared
  functions under their real names, because business code calls them by name — the one
  thing this design must not change. So `libapp.so` carried seven identifiers
  (`verifyLicense`, `checkSum`, …), and `verify_protection.ps1` reported them as a `note`
  rather than pretending they were clean.
  
  That reasoning was correct and is now obsolete, because `flutter build apk --release
  --obfuscate` renames the declarations *and* the call sites together, and the stubs
  dispatch by numeric id (`Vmp.call(4, …)`), so nothing depends on being called by the
  real name. With the flag on, the seven names went to **zero occurrences** — except they
  did not, and the second half is the interesting one: seven names were still there,
  because this demo printed them as its own row labels (`'verifyLicense(key)'`). The
  snapshot was handing over the id → purpose map through the UI text, which is the map
  item 3 worked to remove from the container. `main.dart` now labels rows by id in release
  (`fn[4]`) and by name in a dev build, and the gate's standard was raised from "the names
  present are stub declarations, therefore acceptable" to **zero protected names**.
  Reverse-verified both ways: the same source built *without* `--obfuscate` fails the gate
  naming six of the eight, and the obfuscated build passes.
  
  What this does not change: `Vmp.nameOf(id)` still resolves names at *runtime* from the
  masked table inside `libdartvmp.so`. This is a static-analysis win, which is the axis
  Blutter works on.
- **Malformed-image handling has no differential coverage.** The suite exercises
  the nine protected functions; `strParseInt`, the builder builtins, `abort` and
  the error paths are never called by any of them, which is why two of the bugs
  above were invisible. They were found by a harness that builds arbitrary
  containers, and reproducing that harness as a test is the next thing worth doing.

A footnote on the scanner itself, because it is a small lesson in gate design:
adding `add` to the probe list made the check fail on a library that contains no
such name — `add` is a substring of the runtime's own diagnostic
`strPush append failed: len=%u cap=%u add=%u`. The fix was not a more clever
matcher (an isolated identifier run is exactly what `add=%u` looks like) but to stop
the diagnostic colliding with a plausible function name. **A gate that cries wolf
is a gate people learn to ignore**, and the temptation when it fires wrongly is to
weaken the gate rather than remove the collision.

### What protects what

Each layer exists to block one specific way of getting at the logic, and it is
worth saying which, because a layer that cannot answer that question is not doing
anything:

| Attack | What stops it | Strength |
|---|---|---|
| **Static analysis** of the shipped binary | logic compiled to a private instruction set, container encrypted, entry names masked | strong |
| **Byte editing** the container | CRC over the body plus a body auth tag, both checked before an opcode runs | strong |
| **Dumping the instruction store** | it is encrypted under a key drawn from runtime entropy, never written into any header, and redrawn on every call | medium |
| **Dumping between calls** | the metadata body is wiped and the store is wiped when the call ends, so there is no plaintext and no ciphertext to find while the module is closed | strong |
| **Dumping during a call** | bounded — at most `DVMP_CODE_SLOTS` (4) decoded functions are resident, plus the metadata; the whole instruction stream never is | medium |
| **Reaching the logic through Dart** | the protected bodies are not in the AOT snapshot at all | strong |
| **Calling a protected function as an oracle** | a per-function call policy declared in the protected source, enforced by the runtime, refuses past its budget with a distinct status | weak, and only against the cheap version of the attack |
| **Overlapping calls from two threads** | a process-wide lock; the module and interpreter are single instances | strong |

Every row is now non-empty, which is a change from the first revision of this
table: two of them used to read "nothing", and those two were the honest boundary
of the design. Neither boundary has moved — see the two paragraphs after the
residency note — but both are now bounded rather than open.

**A dump between calls finds nothing, and that is a recent fix.** "Decrypt → execute → wipe → re-encrypt" was documented from the start and was **false**:
re-sealing rebuilt the container from a *copy* and wiped only the copy, so
`m->body` kept the canonical body — string table, constant pool, descriptors and
the decoded instruction stream — for the lifetime of the process. An adversarial
audit found the protected alphabet string and `add`'s decoded opcodes resting in a
single page after every test in this suite had passed, with `Vmp.secureBytesLive()`
reporting the same value before and after calls. The body is now wiped on seal and
the parsed views are rebuilt on open; `dvmp_module_body_residue()` reports a
content-free count of non-zero bytes in that buffer, and the suite asserts it is
zero once a call returns. That check is what the previous one could not do: it read
the `unsealed` flag, which was correctly 0 while the buffer was still full of
plaintext.

**A dump during a call no longer returns the whole program.** The decoded
instruction stream is not resident in bulk. `open` authenticates the shipped
container, decodes the metadata (string table, constant pool, descriptors) into the
body, then re-encrypts the instruction stream under `code_key` — fresh entropy on
every open, written into no header — into a store laid out exactly like the region
it came from, and **wipes the body's copy**. The interpreter materialises one
function at a time out of that store into four slots, and `dvmp_code_ensure`
revalidates the slot's identity on every instruction fetch, so a slot collision is
a reload and never a wrong answer.

Measured on this module: 9 functions and 958 bytes of instruction stream, of which
at most 4 × 215 = 860 bytes were ever simultaneously resident. The absolute numbers
are unimpressive because the module is tiny — the ratio is what scales, and it
improves with the number of functions, because the slot count is a constant. This
is stated plainly because the claim is easy to oversell: **it does not defeat a
debugger.** An attacker who can pause the process can pause it once per function
and reassemble, and the reassembly is mechanical because the descriptors in the
resident metadata carry every function's offset and length. What it changes is that
a *single* incidental capture — a crash dump, a swapped-out page, a paused
debugger, a screenshot of a hex editor — is worth one function instead of the
program. A static attacker is unaffected either way, because the shipped container
is decryptable offline by construction.

The property is checked by measurement rather than by prose, in
`app/test/vmp_e2e_test.dart`, through three content-free counts:

- `Vmp.codeResidency()` — slots, live slots, peak live slots, the largest function,
  and the module's total instruction bytes. The test asserts `peak * largest <
  total`, that `peak <= slots`, and that `slots < functionCount` (without which the
  bound would be vacuous). The main app calls every protected function first, so the
  bound is measured over a warm cache rather than an empty one.
- `Vmp.codeResidue()` — non-zero bytes in the decoded slots, in the body's code
  region **at the moment of sealing**, and in the store. The middle one is the
  sharp check: sealing is the only instant at which "the stream was still sitting in
  the body" is observable from outside a call, and the previous design would have
  reported the module's entire instruction length there. All three must be 0.
- `Vmp.decodedCodeProbe(id)` — still refuses while sealed, as before.

Each of the three was reverse-verified. With the body wipe disabled the suite fails
with `the body still held 559 bytes of instruction stream when the module sealed`;
with the slot count raised to 16 the suite fails with `the runtime has 16 slots for
9 functions, so "not everything at once" is not actually a constraint`. A check that
has never been seen to reject anything is a print statement, not a gate.

**The instruction store is not decryptable from the shipped header.** The shipped
container has to carry its own seed — offline distribution means the binary holds
its own key material, so that seed is public. The store does not use it: the key is
drawn from runtime entropy on every open and written into no header.
`Vmp.sessionProbe()` reports the shipped seed alongside the key and salt actually
used, and the suite asserts they differ and that the key rotates across calls,
because the failure mode here is silent: if the store were ever sealed under the
shipped seed, every call would still return the right answer.

This is worth stating precisely, because the earlier wording ("a dump of the
working copy cannot be attacked offline") overstated it. What the runtime-keyed
store buys is that a **partial** capture — one buffer, one page, a swap file, a
crash dump of a single allocation — is not openable with anything on disk. It does
not survive a **full-process** capture: `code_key` and `code_salt` live in the same
address space as the store, so whoever reads one can read the other. That was
equally true of the working container this store replaced, whose session key and
nonce were also resident. Removing that container is itself part of this change:
once `open` began wiping the body's code region, a re-sealed container could only
have been built from a body with its instruction stream zeroed, so its CRC and tag
would have described something that no longer existed. Nothing ever decrypted it and
no test noticed, which is exactly the shape of false invariant this repository has
been bitten by before — a documented lock that was never implemented, a documented
wipe that covered only a copy. The decoy is gone rather than left lying.

**Calls are serialised process-wide.** The module and the interpreter are single
instances, and `open`/`seal` rewrite the body in place, so two threads inside a
call corrupt each other. Dart isolates are separate threads sharing this library,
so `Isolate.run` and `compute` reach that state from ordinary application code.
The headers claimed a native lock from the beginning and **none existed**; the
observed result was wrong answers, a "module corrupt", and an access violation.
`dartvmp_call` and `dartvmp_init` now take a process-wide lock, verified by
`tool/verify_concurrency.ps1` — a C harness that drives the public ABI from eight
OS threads and compares every result against a single-threaded reference. With the
lock removed that harness reports thousands of errors, so the check has teeth.

**Every call used to leak a descriptor array.** `parse_body_views` ran on every
open — it has to, because sealing wipes the body it parses — and it allocated the
descriptor array with a bare `calloc` without freeing the previous one. So each
protected call leaked `funcCount x sizeof(DvmpFuncDesc)`. It survived three rounds
of audit for a specific reason worth recording: the array was **not** on the guarded
allocator, so `Vmp.secureBytesLive()` never counted it, and that was the only
leak-shaped check in the suite. The concurrency harness (3200 calls) would have
grown by about a megabyte and nobody was looking. The array is now allocated once
and reused, it lives on the guarded allocator, and `app/test/vmp_e2e_test.dart` has
a check that runs 256 calls and requires the guarded byte count to be *identical*
before and after. Reverse-verified by restoring the per-call allocation: the check
fails with `the guarded allocator grew by 1048576 bytes over 256 calls, so the open
path leaks 4096 bytes per call`.

**The oracle has a budget now, and the budget is the whole policy.** A protected
function whose job is to answer a yes/no question about a guess is a validator, and
calling it in a loop is the cheapest attack there is: measured on this machine, an
unguarded protected call runs at roughly 200 000 calls/second. `protected/` can now
declare a call policy next to the function:
```dart
// @vmp guard:rate=4096/1000      // at most 4096 calls per 1000 ms
// @vmp guard:once                // at most one call, ever
```

— which the compiler encodes into the function's descriptor and the runtime
enforces before doing any work, refusing with `DARTVMP_ERR_TOO_MANY_CALLS = -20`.
It refuses; it never returns a wrong answer, and `Vmp.resetCallPolicies()` (a
diagnostics-only export) lets a test assert both that the policy bites and that the
function still computes correctly afterwards. The default is no policy at all: a
guard is a deliberate statement about how often an application may call a function,
and only the author knows that.

The budget is calibrated from the **legitimate** rate, not from the attack rate, and
that took three attempts. `8/1024` and then `64/2048` were both chosen against the
oracle and both turned out to be below the rate this repository's own differential
suite reaches, so both made a *correct* caller fail — the one outcome the first rule
in this README forbids. The shipped policy is now `4096/1000`: 2% of the measured
ceiling, about 1000× a human entering a key, and comfortably above a batch
activation screen. Two tests pin it — one sizes its overrun loop from the budget
declared in the manifest rather than restating it, and one fails if the declared
budget drops below a documented legitimate burst of 512 calls.

What it does not do is stop anyone who patches the guard out; they own the process.
It stops the attack that needs no reversing at all, which is using the shipped
library as a fast validator.


### Where the plaintext actually is

The design's whole claim is "the logic is absent from `libapp.so`", which the APK
check verifies. That is a claim about **static** exposure. It is worth being
equally precise about the **runtime** one, because it decides which functions are
worth protecting at all.

An in-process interpreter cannot avoid materialising plaintext while it runs — and
in this architecture there is no `eval`/`exec` hand-off, so the only plaintext that
*normally* escapes the VM is what the protected function returns across the FFI
boundary. That gives a usable rule:

> **Values kept inside the VM are protected. Values returned across FFI are not.**

Applying it to the nine functions in `protected/`:

| Function | Returns | What crosses FFI | Worth protecting? |
|---|---|---|---|
| `verifyLicense` | `bool` | one bit; `key`, `groups`, `expected`, `sum` never leave the VM | **yes** |
| `checkSum` | `int` | a finalised `% 1048576` mix over an already-derived input | **yes** |
| `selfTest` | `bool` | one bit | **yes** |
| `commandChecksum` | `int` | a 64-bit FNV hash | partly |
| `add`, `base32Index` | `int` | the answer, which is not secret | little |
| `deviceToken`, `normalizeKey`, `makeLicenseKey` | `int`/`String` | **the derived product itself** | little |

The last row is the structural point, not a defect: a function whose job is to
*produce* a token must hand that token over, so moving its body into the VM costs an
attacker one ordinary call and nothing else. VMP pays off on functions where the
**inputs and the outputs are both uninteresting and only the process is secret** — which is exactly the license-verification shape.

Two consequences, both applied in this repository:

- The shipped app no longer contains a plain-Dart copy of a protected function.
  A differential oracle would be worth more to an attacker than the algorithm
  itself, because it turns recovery into a yes/no search. The AOT benchmark
  baseline in `app/lib/main.dart` is now unreachable under `kReleaseMode`, so the
  tree-shaker drops it, and `tool/verify_protection.ps1` fails the build if it
  reappears in the APK.
- `Vmp.verifyImage()` — which copies the entire container into the Dart heap to
  look for leaked probes — is a diagnostic, so the demo calls it only in non-release
  builds.

A cross-check of this review against a broader interpreter-VMP methodology
(attack-path assignment, structure/lexical binding, plaintext-window screening) is
in [docs/skill-review-lang-vmp-guide.md](docs/skill-review-lang-vmp-guide.md),
including the mechanisms there that deliberately *do not* apply here.

### The C layer: what is protected, and what is only wired up
Everything above protects the *bytecode*. The interpreter that executes it is
ordinary AArch64, and `docs/skill-review-lang-vmp-guide.md` has always listed that
as the one open gap (L5, "executor protection"): an attacker who reads
`dvmp_module.c` as machine code can reimplement the private instruction set and
write a disassembler for the bytecode — the asset the whole design exists to
protect.

The tool for that is [VMPacker](https://github.com/bivex/VMPacker), an ARM64 ELF
virtualizer. It is built from source locally — `tool/build_vmpacker.ps1` compiles the VM
interpreter stub with the NDK's clang/ld.lld/objcopy (the `aarch64-linux-gnu-` toolchain
its Makefile expects turned out not to be needed) and then the Go packer — and applied by
`tool/apply_vmpacker.ps1`. **Five functions are virtualized and verified on a device — by
value, not by absence of a crash; two are refused by a check, because the tool translates
them and they then crash.** The per-target evidence, the fault addresses, the `CSEL` that
answered wrongly and the reasoning are in item 1 of
[What was strengthened](#what-was-strengthened-and-what-was-deliberately-not); this
section is about the hand-off itself.

The hand-off is mostly checks, because a name-based tool fails *quietly*: if it finds no
matching symbol it has nothing to do, and "nothing to do" is indistinguishable from
success. Every branch below is reverse-verified — each was written after watching the
failure it catches:

| Branch | Result |
|---|---|
| Tool absent | `-AllowMissing` prints `RESULT: NOT APPLIED`, exit 0; otherwise it throws |
| Input is a **stripped** `.so` | refused: `has no symbol table, so VMPacker cannot find any function in it` |
| Input is the **x86_64** library | refused: `is a Advanced Micro Devices X86-64 library, and VMPacker rewrites AArch64 only` |
| A target no longer exists (inlined away) | refused, pointing at `-DDVMP_VMPACKER=ON` |
| A target **calls** something, or reads a global | refused, naming the instruction and offset: `+0x4428 bl 0x9624 <vmp_secure_alloc>` |
| A helper of a target survived out of line | refused: `these helpers exist as separate functions in …: op_tables` |
| Translation is **partial** | refused: `translated these targets only partially: — 64/70` |
| Tool exits 0 but changed nothing | refused: bytes at each entry point compared before/after |
| Tool really did the work | `RESULT: APPLIED`, 12-byte trampolines, ABI unchanged at 9 exports |
| The library does not **run** | refused: `tool/verify_device_run.ps1` installs it and fails on a crash record |

Four measurements decided the design, and each is a trap that would have produced a green
build around an unprotected library:

1. **The build has to keep an unstripped copy, and name it per ABI.** Gradle's release
   packaging strips the CMake output *in place* — `llvm-nm` on
   `intermediates/cxx/— obj/arm64-v8a/libdartvmp.so` says "no symbols" after some builds
   and not others, depending on which task ran last, so reading that file is a race. The
   first version of the file that solved this used one filename for every ABI, and the
   x86_64 build won: the path that said "arm64" held x86_64 and the tool refused it. Now
   each ABI's copy is `build/unstripped/libdartvmp.unstripped.<abi>.so`, and the machine
   check above is what caught the mistake.
2. **`noinline` is load-bearing, and so is `always_inline` in the other direction.** At
   `-O2` the small helpers have no separate existence — they are inlined into their
   callers — so `DVMP_VMPACKER_TARGET` adds `noinline, used` to make each target findable.
   The mirror case is worse: a `static` helper called from two targets keeps a body of its
   own, and that body is exactly what the trampolines are hiding. `op_tables` did, and
   `!op_tables` in `tool/vmpacker_targets.txt` is the check that keeps it from coming back.
3. **"Findable at build time but not callable at runtime" is not expressible on this
   toolchain.** Measured three ways: a non-`static` hidden-visibility function
   (`dvmp_module`, `dvmp_vm_run`) still comes out local (`t`); adding
   `visibility("default")` makes it global (`T`) *and* puts it in `.dynsym`, i.e. callable
   through `dlsym`; and the version script that pins the export surface localises it back
   to `t`, because `local: *` rewrites the whole symbol table and not just the dynamic one.
   It is a binary choice, and this project takes **unexported**: an exported
   `unpermute_code` is a working primitive for an attacker, while a local one still sits in
   `.symtab` under its own name, which is what a name-based tool reads.
4. **A target with a stack canary is not a target.** The NDK compiles with
   `-fstack-protector-strong`, and VMPacker's VM does not reproduce the TLS read that loads
   the canary, so `DVMP_VMPACKER_TARGET` carries `no_stack_protector`. See item 1.

The target list is the other half of the design, and it is now five entries rather than
eight:

```
virtualized, verified on device   apply_keystream, keystream_seed, dvmp_body_tag,
                                  permute_code, unpermute_code
refused: needs a call             dvmp_mask_keystream, code_store_build
not a target, by design           dvmp_vm_run (the instruction loop)
                                  dvmp_code_ensure (called once per instruction)
```

The three in the middle of that first line are the second round's work: each was moved out
of the refused list by removing the construct VMPacker cannot handle from *our* source - a
call, an `adrp`, SIMD register traffic, and finally a `CSEL` that was not a crash but a
wrong answer. `tool/vmpacker_targets.txt` is where that record lives, and the table in
item 1 above is the part of it that a reader should not have to reconstruct.

A VMPacker-protected function runs on a *second* interpreter, so the cost is per call, and
the interpreter loop is the one function that must not go in: it would nest one VM inside
another on every bytecode instruction of every protected call. The residency work above is
what makes the split clean — after it, the per-instruction set really is just those two
functions, so everything else is cold enough that virtualization would be free. It is the
*correctness* that stops it, not the cost.

Also worth stating plainly: **VMPacker rewrites ELF, so it does not apply to Windows at
all.** The desktop runtime is a PE image linked into `dartvmp_demo.exe`, and the C layer
there stays unvirtualized. This is an Android-only hardening step, and the Windows build
therefore keeps every one of these functions as ordinary x86_64 code, exactly the state
item 1 measures as readable. That is the honest state of the C layer: on Android, two
functions — neither of them the one that matters; on desktop, none.

### Release hardening

The diagnostic probes the test suite uses (`dartvmp_code_probe` and friends) are
compiled out of a release build. The Android plugin passes
`-DDVMP_DIAGNOSTICS=OFF`, which drops the shipped library from 20 exported symbols
to the 9 documented ABI functions; `verify_protection.ps1` fails the build if a
probe symbol survives. The desktop test library keeps them on
(`tool/build_native.ps1`), because that is the only way `flutter test` can reach
the interpreter's internals.

The export surface is now a link-time fact rather than a consequence of a CMake
preset: `packages/dartvmp/src/vmp_exports.map.in` is configured per build and passed
to the linker as a version script, so anything not listed is local to the DSO. It
fails loudly, too — the Android toolchain passes `-Wl,--no-undefined-version`, and
the first version of that file named the diagnostic probes unconditionally, which is
a link *error* in a release build where they are compiled out. That is how the
generated-per-configuration version was found to be necessary.

That flag is also the switch for **feature gates that must not survive into a
release**. The anti-debug layer's escape hatch is the one that matters:

```
DARTVMP_NO_ANTIDEBUG=1 ./app        # used to disable instrumentation detection
```

It was a runtime-only `getenv` check, so the layer was optional from the shell and
the variable name was greppable in the shipped `.so`. It is now compiled out of any
build without the diagnostic probes, and `tool/verify_antidebug_gate.ps1` builds
both configurations and asserts the name is present in the first and absent in the
second — because a gate that passes for the wrong reason is worse than no gate. The
build is also checked for the string directly, alongside the plaintext probes.

The general rule, and the reason this is written down: **a protection that can be
switched off by an environment variable is not a protection, and a switch that
exists only in the test build should not be compiled into the shipped one.**

---

## Quick start

Requires Flutter 3.41+, the Android SDK with NDK, and (for Windows desktop)
Visual Studio with the C++ workload.

```bash
# Compile, test, deploy the runtime and verify — one command
powershell -ExecutionPolicy Bypass -File tool/test.ps1
powershell -ExecutionPolicy Bypass -File tool/test.ps1 -Release   # + APK + protection check
```

Or step by step:

```bash
# 1. Compile the protected sources and generate every artifact
dart run tool/build.dart                    # random seed, as a release build should
dart run tool/build.dart --seed 0x1234      # reproducible

# 2. Inspect what was compiled
dart run tool/vmpc/bin/vmpc.dart disasm --seed 0x1234

# 3. Check the artifacts for leaks
dart run tool/vmpc/bin/vmpc.dart check

# 4. Compiler tests
cd tool/vmpc && dart test                   # 33 tests

# 5. Native runtime + app tests
cd ../..
powershell -ExecutionPolicy Bypass -File tool/build_native.ps1
cd app
$env:DARTVMP_LIBRARY_PATH = "$PWD/build/native/dartvmp.dll"
flutter test                                # 22 tests
Remove-Item Env:\DARTVMP_LIBRARY_PATH

# 6. Run the demo
flutter run -d windows

# 7. Ship and verify
flutter build apk --release --target-platform android-arm64
cd ..
powershell -ExecutionPolicy Bypass -File tool/verify_protection.ps1
```

### Why the native tests need an environment variable

`flutter test` builds its own host executable, so the desktop runtime — which
Flutter links *into the runner* — is not present, and the library has to be loaded
from disk. Dropping it next to the tests does not work reliably: the Flutter tool
truncates files it considers build output in the package root, which produced a
0-byte `app/dartvmp.dll` and made every native test report **skipped** rather than
failing. Deploying to `app/build/native` and pointing `DARTVMP_LIBRARY_PATH` at it
is deterministic. Without the variable the native groups skip loudly rather than
passing vacuously, so a CI run cannot mistake "the runtime was missing" for "the
runtime agreed".

---

## Writing protected code

Mark a function with `// @vmp` and it is compiled into the module. The file lives
under `protected/` and is **never imported by the app**.

**That comment is the whole selection mechanism.** There is no list of function names to
type in anywhere: the compiler reads the protected sources, and every `// @vmp` marker
becomes a compiled function while every unmarked declaration stays in the application
(and `vmpc check` reports it, so a function that looks protected but is not cannot be
silent). So the answer to "do I have to read the Dart source and enter the function
names" is: yes to the marker, no to entering names — you mark the function where it is
written, and the tool is told which *files* to read:

```powershell
dart run tool/build.dart                                  # protected/licensing.dart, protected/keys.dart
dart run tool/build.dart --source protected/a.dart,protected/b.dart
```

A marker can also carry a call policy, which is the only local answer to "an exported
verifier is a validator for anyone who can call it":

```dart
// @vmp guard:rate=4096/1000     at most 4096 calls per second, then refuse
// @vmp guard:once               one call per process
```

A refused call returns `DartVmpException` with `DARTVMP_ERR_TOO_MANY_CALLS`. It never
returns a wrong answer, and `tool/vmpc/lib/src/dart_source.dart` is where the syntax is
parsed and validated — a malformed guard is a build error, not a silent default.

```dart
// @vmp
bool verifyLicense(String rawKey) {
  String key = normalizeKey(rawKey);
  if (strLen(key) != 16) {
    return false;
  }
  String groups = strSub(key, 0, 15);
  int expected = base32Index(strAt(key, 15));
  return expected >= 0 && checkSum(groups) % 32 == expected;
}
```

### Supported subset

Because the interpreter is deliberately small, the compiler accepts a *subset* of
Dart and reports anything it cannot lower with a line number — it never silently
drops a body.

**Supported** — `int`, `String`, `bool`, `List`, `Map`; `if`/`else`, `while`,
C-style `for`, `for-in`, `break`, `continue`, `return`; `+ - * / % ~ & | ^ << >>`,
comparisons, `?:`, `&&`, `||`; `x++`/`x--`; `+=` and friends; calls to other
protected functions; `const` declarations; `import` of another protected file.

**Builtins** — `strLen`, `strAt`, `strCode`, `strSub`, `strIndexOf`,
`strContains`, `strToUpper`, `strToLower`, `strParseInt`, `intToStr`, `hash`,
`listLen`, `listAt`, `mapGet`, `abort`.

**Not supported** — closures, classes, generics (`List<int>` → use `List`),
`async`/`await`, generators, string interpolation, assignment into a `List`,
globals, package imports.

Two of these are worth calling out because they cost real debugging time to get
right, and are documented at the point of implementation:

- **Dart's `%` is Euclidean** — the result takes the *divisor's* sign, so
  `-11 % 32 == 21`, whereas C gives `-11`. The interpreter corrects for this;
  without it a key-derivation loop silently produced the wrong characters.
- **Dart's `>>` is arithmetic** and C's `>>` on `uint64_t` is logical. Every
  place the two languages hash the same bytes uses `>>>` in Dart and `>>` in C,
  and `image_contract_test.dart` pins the agreement.

### Performance

Interpretation is far slower than AOT code. The demo's benchmark card reports the
ratio for a 512-round key-derivation function. Protected functions belong in
**low-frequency, high-value** paths — activation checks, key derivation,
signature verification. Never in a render loop or a per-frame callback.

### A local UI for deciding what to protect

`tool/ui/` is a single-page web UI over the same CLI entry points, for the part that is
otherwise hand-editing:

```powershell
python tool\ui\serve.py            # http://127.0.0.1:8777, opens a browser
```

It lists every top-level function in `protected/`, marks which already carry `// @vmp`,
lets you tick and untick them and pick a guard, then **shows the diff and writes only
after a second confirmation**. The write path can only touch `// @vmp` marker lines, and
that is a checked property rather than a promise: the file with all marker lines removed
must be byte-identical before and after, the rewritten text is re-parsed and every
requested state re-checked, a stale `sha256` from the page is rejected with 409, the
first write to a file in a session is backed up to `<file>.bak`, and the write itself is
`os.replace`d atomically. It also has buttons for `vmpc check`,
`verify_descriptors.py`, `walk_bytecode.py` and (optionally) `verify_crypto.ps1`.

It is stdlib-only Python on `127.0.0.1`, with no authentication — anything that can reach
the port can edit marker lines in this repository, so do not bind it to a public
interface or put it behind a proxy. It deliberately does not run `tool/test.ps1`; see
`tool/ui/README.md` for the API and the limits.

---

## The challenge: find the flag

`examples` of this build ship as a CTF target: an app that reveals a flag only when you
supply the key its protected code expects. It exists to turn "how hard is this?" from an
adjective into a number, and the full brief — rules, levels, submission format — is in
[docs/CHALLENGE.md](docs/CHALLENGE.md).

Three things about it are worth stating here rather than there, because they are claims
about this project and not about the challenge:

- **The flag is not a string constant in the container.** `module_seal_locked` wipes the
  whole body between calls, so a plain constant would be readable by any memory dump taken
  while the app does *anything* — a five-minute solve. Instead the flag is stored rotated by
  a per-character offset derived from the key, so its plaintext exists only after a valid
  key has been accepted.
- **The intended solve is the static one**, and it is the same chain the README documents
  under "Honest limitations": read the runtime, un-mask the image, strip the container
  cipher, recover the permutation from `unpermute_code`, read the ISA in `dvmp_vm.c`, then
  rebuild the key derivation. Roughly a day or two of reversing, by the project's own
  estimate.
- **Patching the check works, and is scored as its own level.** The cheapest attack on any
  in-process protection is to bypass it rather than understand it. `dvmp_integrity.c`
  detects the common shapes of that attack but deliberately does not prevent it; the
  challenge says so up front instead of pretending the bypass does not exist.

The repository contains the reference flag so the app can be built and tested. The
*released* target is built with a different one — see the checklist in
[docs/CHALLENGE.md](docs/CHALLENGE.md).

## Repository layout

```
protected/                     protected sources — never imported by the app
docs/                          protection-boundary analysis and methodology review
tool/vmpc/                     the compiler
  lib/src/lexer.dart           restricted-Dart lexer
  lib/src/parser.dart          recursive-descent parser
  lib/src/emitter.dart         AST → private bytecode
  lib/src/packer.dart          opcode permutation + stream cipher + auth tag
  lib/src/c_emitter.dart       generated C header (masked image)
  lib/src/evict.dart           removes protected bodies from app sources
  bin/vmpc.dart                CLI: build / disasm / check
tool/build.dart                build entry point
tool/test.ps1                  one-command build + full test suite
tool/build_native.ps1          builds the runtime as a loadable library (desktop tests)
tool/verify_protection.ps1     scans shipped artifacts for leaks
tool/verify_image.py           proves the static image is masked
tool/verify_antidebug_gate.ps1 proves a release build has no escape hatch
tool/verify_concurrency.ps1    drives the ABI from 8 threads (builds its harness)
tool/concurrency_harness.c     the C harness that script compiles and runs
tool/capture_desktop_run.ps1   checks the runner links the runtime, then launches it
                               and captures the window (-CheckOnly for CI)
tool/apply_vmpacker.ps1        hands the C layer to VMPacker and proves it happened
tool/vmpacker_targets.txt      the virtualization targets, the device result for each,
                               and the section the coverage check refuses
tool/verify_device_run.ps1     installs a built APK on a device and fails if it crashes
tool/build_vmpacker.ps1        builds VMPacker from source (NDK clang + Go)
tool/repack_apk.ps1            replaces a library inside an APK, aligns and re-signs it
tool/repack_apk.py             the zip rebuild (--check-only verifies native lib storage)
tool/recover_from_shipped.py   the mask-key attack, with --selftest as its positive control
tool/recover_opcodes.py        the opcode-map attack, with the same two directions
tool/ui/serve.py               local UI for choosing what to protect (stdlib only)
tool/walk_bytecode.py          decodes the container, verifies CRC + tag, disassembles
                               (--tamper reverse-tests both checks)
tool/verify_descriptors.py     decodes every descriptor field by offset, independently
tool/audit_operands.py         checks every operand read for a bounds guard
tool/list_symbols.py           lists a shared object's exported ABI
build/unstripped/              per-ABI unstripped copies the CMake build keeps, because
                               Gradle strips the CMake output in place
packages/dartvmp/              the runtime
  lib/dartvmp.dart             public Dart API
  lib/src/wire.dart            FFI wire format codec
  src/dvmp_vm.c                the interpreter
  src/dvmp_module.c            container load / decrypt / code store / seal / unseal
  src/dvmp_sha256.c            SHA-256 and the mask keystream built on it
  src/dvmp_host.c              the 23-builtin host table
  src/dvmp_value.c             arena, heap objects, wire codec
  src/dvmp_secure.c            guarded memory (wipe after use)
  src/dvmp_antidebug.c         instrumentation detection (opt-in)
  src/dvmp_vmpacker.h          the hand-off surface, and why each attribute is there
app/                           the Flutter demo
  lib/main.dart                UI: calls, benchmark, protection evidence
  lib/generated/               generated stubs (do not edit)
  test/                        differential and protection tests
```

### The container format

Defined jointly by `tool/vmpc/lib/src/packer.dart` and
`packages/dartvmp/src/dvmp_module.c`, and pinned by `image_contract_test.dart`:

```
crc       = crc32(canonical body)        integrity of what the compiler emitted
permuted  = permute(body, seed)          private instruction set
tag       = fnv1a(permuted ‖ seed')      authenticity of the stored bytes
stored    = cipher(permuted, seed)       confidentiality
container = header(seed, crc, …) ‖ stored ‖ tag
```

The CRC covers the **canonical** body, so the runtime can only satisfy it after
decrypting *and* un-permuting — making it an end-to-end check of all three layers.
The tag covers the **permuted, pre-cipher** body, i.e. the bytes actually written
to disk, so a patched image is rejected before a single opcode runs.

Both are reproduced independently in `tool/walk_bytecode.py`, which recomputes the
canonical CRC and the tag from the shipped image and fails the run if either
disagrees. Run it with `--tamper` and it flips one ciphertext byte first, so the two
checks can be *seen* to reject: a check that has never been observed to fail is a
print statement, not a gate.

The descriptor record is 32 bytes and is written and read by name, never by a
literal, because the record has been 24, 26, 28 and 32 bytes across revisions and
every change shipped at least one place that kept an old number. The symptom was
never "descriptor misaligned" — it was an empty code region, or a body CRC
mismatch, three layers away. Two reserved fields, both asserted zero by the runtime
and by both analysis tools, now turn that whole class of mistake into a hard
failure at the first open:

```
[0..4)   name_off          [4..8)   name_len
[8]      guard_mode        [9]      reserved (0)
[10..12) guard_budget      [12..14) guard_window_ms
[14..16) arity             [16..18) locals
[18..20) max_stack         [20..22) slot_base
[22..24) reserved2 (0)     [24..28) code_len
[28..32) code_off
```

---

## Honest limitations

This is a working protection system, not a security guarantee. In particular:

- **The interpreter can be attacked directly.** Everything the VM relies on is
  readable by an attacker who is willing to reverse the C code. The private
  instruction set raises the cost of reading the *logic*; it does not make the
  implementation tamper-proof. The container's CRC and auth tag stop byte edits,
  not a patched interpreter.
- **A Dart-side debugger sees plaintext, and cannot be stopped from C.** The
  DevTools / VM Service debugger observes the Dart heap, and the return value of a
  protected function necessarily lands on that heap. Three cases are worth
  separating: a *device-level* debugger (`gdb`/`lldb` on the `.so`) sees the
  interpreter's arrays, which are now bounded to at most four decoded functions but
  which a debugger can still walk one function at a time; the *Dart* debugger sees
  the call's result, which cannot be hidden at all; and a debugger attached *during*
  the call window sees whichever functions are executing plus the metadata.
  `dvmp_antidebug.c` targets the cheap attacks (`ptrace`, Frida, the `frida-server`
  port) and is **off by default** — it is a speed bump, and every signature in it
  goes stale.
- **The seed is in the container header.** It has to be, for offline distribution:
  the binary carries its own runtime material by design. The SplitMix64 mixing, the
  mask derivation and the opcode permutation's construction all ship in
  `libdartvmp.so` as well, so a patient attacker can write a standalone decryptor —  `tool/verify_image.py` is a working demonstration of exactly that. What item 7
  changed is that the permutation is no longer a *parameter* they can search; what it
  did not change is that the construction is present. What the layers buy is that
  there is no single short secret to extract; what they do not buy is protection from
  someone willing to reimplement the scheme.
- **A single dump catches a whole call.** This one is **fixed**, and is kept here to
  record what it used to say: lazy per-chunk decryption is now implemented and
  verified — `open` re-encrypts the instruction stream into a runtime-keyed store and
  the interpreter materialises one function at a time. See "A dump during a call no
  longer returns the whole program" above, including its honest boundary: it does not
  stop a debugger, it reduces what one incidental capture is worth from a program to
  a function.
- **The entry-name table is masked, but the derivation ships.** `kDvmpEntries[]`
  used to carry each function's name as a string literal, which put a greppable
  list of the protection surface in `.rodata` — a map pointing at exactly which
  functions are worth attacking, plus a hint at the algorithm family
  (`verifyLicense` implies a comparison, `checkSum` a hash). Names are now stored
  masked and un-masked one byte at a time during lookup, so the shipped library
  contains no such list and no full plaintext name is ever resident. The
  derivation is in the binary, so an attacker who reverses the runtime can still
  recover them — this raises the cost, it does not make the names secret. The
  **stub declaration names** do remain in `libapp.so`: business code calls
  `verifyLicense(...)`, so the AOT snapshot has to keep that name to link. That is
  the direct cost of the "do not change call sites" rule, and
  `tool/verify_protection.ps1` now enumerates which names are present and why —  stub declarations pass, anything else is a `LEAK`.
- **The oracle is rate-limited, and the rate limit can be patched out.** The call
  policy is enforced in the runtime's C code, so removing it is a few bytes of
  patching. It stops the attack that needs no reversing at all — using the shipped
  library as a fast validator — and not someone willing to read the disassembly.
- **The resident plaintext is bounded, and the bound is not zero.** During a call at
  most four decoded functions plus the metadata (string table, constant pool,
  descriptors) are in memory. The metadata *has* to be resident — `push_k` / `push_s`
  can read it on any instruction — so string literals and the integer constant pool
  are what one dump still yields. The instruction stream is the larger part, and it
  is the part that was narrowed.
- **A full-process dump still gets everything.** The runtime keys (`code_key`,
  `code_salt`) live in the same address space as the instruction store. What runtime
  encryption buys is "a partial capture cannot be opened", not "a capture cannot be
  taken". See the residency section above.
- **A single dump catches the whole decrypted body.** This one is **also fixed**, and
  is kept as a record. It read: "The architecture decrypts the body into one guarded
  buffer when a call starts and wipes it when the call returns, so the plaintext
  window is the call, not an instruction. Bounding it further means decrypting the
  instruction stream per chunk and re-encrypting each chunk as execution leaves it,
  which was attempted in this session and **reverted rather than shipped**: three
  successive implementations each traded one silent state bug for another — a shared
  encode/decode helper two callers used with opposite intent, a module-wide "is
  plaintext" flag that skipped every chunk after the first, and a region offset
  translated twice — and all three presented as the same misleading 'chunk failed
  its tag'." The shared defence against all three is now in the code rather than in
  a comment: `dvmp_code_ensure` records *which function* a slot holds and
  revalidates it on every fetch, so a collision is a reload and never a wrong
  answer — **correctness does not depend on the cache hitting.** The original root
  cause, a `code` pointer that meant "function base" to the fetch and "current
  instruction" to the operand reads (function 0's first `load` reported slot 2850
  instead of 0), is still guarded by `tool/walk_bytecode.py`, which decodes the
  container independently and disassembles it — the means by which the discrepancy
  was finally located after the interpreter's own diagnostics had pointed at three
  innocent layers.
- **The arena is per-call and freed at the end, not incrementally.** Protected
  code cannot leak memory, but a pathological allocation loop hits the budget and
  faults rather than thrashing. `dvmp_arena_free` is a documented no-op.
- **Android and Windows only.** Those are the platforms with a real plugin
  directory. `ios`, `linux` and `macos` were declared in `pubspec.yaml` with no
  directory behind them — advertising support the package did not have — and those
  entries are now gone. `openRuntimeLibrary` keeps the branches, so adding a
  platform means adding a directory.
- **Windows takes the odd loading path, and so does Android.** The desktop runner
  links the runtime statically into the executable, so Dart has to use
  `DynamicLibrary.executable()`; Android packages `libdartvmp.so` into the APK, so
  it has to use `open()`. Neither path is reachable from `flutter test`, whose host
  executable contains no runtime and can only load an external DLL through
  `DARTVMP_LIBRARY_PATH` — see "What only a real run could find".
- **32-bit ARM is not shipped.** `abiFilters` is limited to `arm64-v8a` and
  `x86_64`; shipping an untested ABI for a security component is worse than not
  shipping it.
- **Anti-debug, APK signature checks, and OLLVM hardening of the C layer are out
  of scope here** — they are orthogonal to the Dart-side VMP and are better
  supplied by a dedicated native protector.
- **Function names are recoverable by reversing the runtime.** The generated
  `kDvmpEntries[]` no longer holds them as literals — they ship masked and are
  un-masked on demand (see the note above) — so the shipped binary contains no
  readable map of the protection surface. The mask derivation is in the binary, so
  this raises the cost of finding that map rather than hiding it.
- **An exported `verifyLicense` is an oracle, with a declared budget.** Anyone who
  can call the library can call it in a loop. The check digit makes a single guess
  unlikely to pass, and the call policy declared in `protected/licensing.dart` now
  caps how many guesses per second the *shipped, unmodified* library will answer.
  An attacker who patches the policy out is back to the measured 200 000
  calls/second ceiling, so this is a speed bump sized to be invisible to correct
  callers rather than a wall.

## A note on what went wrong along the way

The system now passes every test, but getting there surfaced a class of bug worth
knowing about if you extend this: **Dart and C disagree about integer semantics in
ways that are invisible until they corrupt your data.**

Every one of these was found by comparing against a reference implementation, not
by reading the code:

| Difference | Symptom |
|---|---|
| `>>` is arithmetic in Dart, logical in C on `uint64_t` | keystream diverged → body CRC mismatch |
| `%` is Euclidean in Dart, truncating in C | key characters wrong from round 2 onward |
| 64-bit hex formatting of a *negative* Dart int | mask key with the wrong sign bit → wrong magic |
| `x++` has no store unless lowered to `x = x + 1` | infinite loops, arena exhaustion |
| a bytecode descriptor caching a raw pointer | stale code after the body was rewritten |
| pointer stored in a `uint32_t` field | access violation on every concatenation |

The lesson is not "be careful" — it is that **a cross-language data contract needs
a test that pins it from both sides**. `image_contract_test.dart` un-masks the
generated header using the runtime's own algorithm and compares against the
packer's container; that single test would have caught four of the six.

### A documentation edit that corrupted this file

Worth recording because it is the same lesson one level out — *editing prose has no test* —
and because it happened to this README, in this session.

A shell idiom used to replace a few strings in this file was
`Get-Content -Raw` followed by `Set-Content -Encoding utf8`. On a CP936 console that decodes
the file's UTF-8 bytes as CP936 and writes the result back, so every non-ASCII character
became a `?`-terminated remnant (`e2 80 3f` where an em dash had been) and *the byte after it
was consumed with it*. It ran twice, and the damage compounded: 217 sites, the ASCII-art
diagrams reduced to placeholders, and the file no longer valid UTF-8.

Three things made it worse than a typo:

- **It is lossy.** The trailing byte is gone, so the transformation cannot be inverted. The
  em dashes, arrows and box characters were recovered by simulating the round-trip on known
  strings, grouping the damage by the byte that followed each marker (a marker followed by a
  word character meant "the space after the dash was eaten"), and then fixing the ~24 sites
  where that rule did not apply by hand — plus one real bug it introduced, where `‖` in the
  container format shares the damaged marker with the em dash and was silently replaced by
  one. The recovery scripts were kept in this workspace's `build/` directory while the repair
  was in progress (that directory is generated, so they are not part of the repository); what
  *is* durable is the method, recorded in `tool/check_encoding.py`'s docstring, and the check
  itself.
- **Nothing failed.** The build was green, every test passed, and the first symptom was a
  tool refusing to open the file.
- **It happened where there is no coverage.** Every other artefact in this repository has a
  check; prose does not.

So the fix is a check, in the pattern the rest of this file describes: `tool/check_encoding.py`
walks the repository's text files and requires each to decode as UTF-8, reporting the byte
offset when one does not, and `tool/test.ps1` runs it. Its first run found a second file
(`app/build_log.txt`, a stale compiler log in GBK) — which is what a check is for. The rule
for future edits is in the script's docstring: use a tool that writes UTF-8, never a
`Get-Content`/`Set-Content` round-trip on a file that has non-ASCII in it.
