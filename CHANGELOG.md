# Changelog

All notable changes to FDartVMP are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

The Dart package names inside the repository remain `dartvmp` (the runtime) and
`vmpc` (the compiler); the project name used for these documents is FDartVMP.

## [0.2.0] - 2026-09-23

The C-layer virtualization round. Same day as 0.1.0 and a separate entry on purpose: the
artifact 0.1.0 describes really did ship with two virtualized functions, and rewriting
that paragraph would erase the measurement it records.

### Changed

- **The VMPacker target set went from two functions to five.** `dvmp_body_tag`,
  `permute_code` and `unpermute_code` are now virtualized and verified on the device — by
  value, not by absence of a crash. Each was moved out of the refused list by removing,
  from our own source, the construct the tool cannot handle:
  - `kWidth[]` became `op_width()`, an immediate comparison chain. The table was the only
    `.rodata` operand in `permute_code` and `adrp` is what VMPacker cannot translate.
  - `unpermute_code` no longer formats its own error messages: `dvmp_vm_set_error` and its
    two format strings moved to the caller, which is not a target.
  - `dvmp_fnv1a64_core` is defined in `dvmp_internal.h` and inlined into `dvmp_body_tag`,
    with `dvmp_fnv1a64` kept as the out-of-line view of the same loop. VMPacker cannot
    execute a `bl`.
  - `DVMP_VMPACKER_NO_VECTORIZE` now compiles the cold translation units with
    `-mgeneral-regs-only`, which is what actually removes the compiler's SIMD (the
    SplitMix64 constants came out of a constant pool as `ldr q`). `-fno-vectorize` alone
    never did: the SIMD came from the loop-idiom, inline-memset and constant-pool paths.
- **The opcode shuffle no longer uses a remainder.** `r % (256 - i)` compiled to a `CSEL`,
  and VMPacker 1.3's VM answers that `CSEL` wrongly: a full translation, no crash, and
  every protected call failing with `opcode 0x20 out of range at +0`. The exact identity
  `r - ((r + i) >> 8) * (256 - i)` replaces it, and the inverse table is built by two
  unconditional scatters instead of one conditional one. The Dart side still uses the
  remainder; both produce the same integer. This is the only failure in the project that
  no byte-level check could have caught, and it was found by a device bisect
  (`tool/bisect_vmpacker.ps1`).

### Added

- `tool/verify_wire_widths.py` and the `dartvmp_wire_probe` entry point: the decoder's
  `op_width()` and the assembler's `kOperandBytes` are compared for all 256 byte values
  through the runtime's own code, so an opcode added on one side only fails a check
  instead of silently desynchronising the decode. Runs in `tool/test.ps1`.
- A **clone check** in `tool/apply_vmpacker.ps1`: any `<target>.something` symbol
  (`unpermute_code.specialized.1`, `.constprop.0`, `.isra.0`, `.part.0`, `.cold`) is
  refused, because a clone is the same code left in plain AArch64 beside a trampoline that
  claims to have replaced it. Reverse-verified against the artifact that had one.
- `tool/bisect_vmpacker.ps1`: applies VMPacker to a subset of targets, repacks, installs
  and screenshots, one variant at a time. It is how the `CSEL` was isolated.

### Fixed

- `unpermute_code`'s failure diagnostics are unchanged in content but now come from the
  caller, and a materialisation failure reports the function and the offending byte.

## [0.1.0] - 2026-09-23

First public release. This is a working implementation with a closed loop —
compile, protect, run, verify — and it is published with its limitations stated
rather than deferred. Version numbers in this file track the project as a whole;
they are not a claim about the maturity of the protection, which the sections
below and `README.md` describe as precisely as possible.

### Added

**Bytecode container.** A compact container defined jointly by
`tool/vmpc/lib/src/packer.dart` and `packages/dartvmp/src/dvmp_module.c`, and pinned
by `tool/vmpc/test/image_contract_test.dart`, which un-masks the generated header
using the runtime's own algorithm and compares it against the packer's container.
On the measured build: a 1 565-byte static image stored as 196 masked words, and
1 525 bytes of bytecode for 9 protected functions. Container layout:

- a **keyed opcode permutation** — a keyed Fisher-Yates shuffle of the whole 0..255
  byte range derived from the build seed, so the compiler's opcode numbering never
  appears on the wire. This replaced an affine map (`(op * 167 + seed_byte) mod 256`)
  that the container gave up in 128 attempts;
- a **SplitMix64 stream cipher** over the body, re-seeded on every call and
  re-encrypted afterwards, so two dumps of the working buffer do not share a
  keystream and neither matches the shipped binary;
- a **SHA-256-masked static image** — each word is XORed with a position- and
  build-dependent mask, so the container magic is not findable with `strings` or
  `binwalk`. The mask is derived as `SHA256(le64(key) || le64(index))[0..8)`, which
  replaced a stream construction that one known word inverted into the key;
- **CRC over the canonical body** plus an **auth tag over the permuted bytes**, so
  the runtime can only satisfy the CRC after decrypting *and* un-permuting, and a
  patched image is rejected before a single opcode runs;
- **32-byte descriptor records** written and read by name rather than by literal,
  with two reserved fields asserted zero by the runtime and by both analysis tools.

**Dart bytecode compiler (`tool/vmpc`).** A lexer, a recursive-descent parser, an
AST-to-bytecode emitter, the packer (opcode permutation, stream cipher, auth tag)
and a C header emitter for the masked image. The CLI
(`dart run tool/vmpc/bin/vmpc.dart`) provides `build`, `disasm` and `check`. The
selection mechanism is a `// @vmp` marker in the protected source — there is no list
of function names to maintain, and `vmpc check` asserts that the marker count equals
the compiled count so a function that looks protected but is not cannot be silent.
A marker may carry a call policy (`guard:rate=…`, `guard:once`). The compiler accepts
a documented subset of Dart and reports anything it cannot lower with a line number;
it never silently drops a body.

**Native interpreter and runtime (`packages/dartvmp`).** A private VM in C
(`src/dvmp_vm.c`) reached over FFI, with a 23-builtin host table
(`src/dvmp_host.c`), an arena and wire codec (`src/dvmp_value.c`), and guarded
memory that wipes after use (`src/dvmp_secure.c`). Specifically:

- a **runtime-keyed instruction store**: `open` authenticates the container, decodes
  the metadata into the body, re-encrypts the instruction stream under a key drawn
  from runtime entropy (written into no header), and wipes the body's copy. The
  interpreter materialises one function at a time;
- **per-call wipe**: the body is wiped on seal and the parsed views are rebuilt on
  open, so a dump taken between calls finds neither plaintext nor ciphertext. On the
  measured module, at most 4 × 215 = 860 bytes of the 958-byte instruction stream
  were ever simultaneously resident;
- **a process-wide lock** over `dartvmp_call` and `dartvmp_init`, because the module
  and interpreter are single instances and Dart isolates are separate threads
  sharing the library;
- **guards for call policy**, declared in the protected source, encoded into the
  function descriptor and enforced by the runtime before any work is done. A refused
  call returns `DARTVMP_ERR_TOO_MANY_CALLS`; it is never a wrong answer;
- **entry-point integrity checking** (`src/dvmp_integrity.c`): the nine ABI entry
  points are scanned for a branch at offset zero, which is what Frida's Interceptor,
  Dobby and a hand-made patch all leave behind. The reaction follows the rule the
  rest of the runtime follows — record it, fold it into the same verdict
  instrumentation gets, never change an answer;
- **anti-debug with a narrow-cache reaction** (`src/dvmp_antidebug.c`): detection
  narrows the decoded-function cache from four slots to one instead of refusing to
  initialise, so a false positive degrades performance rather than shipping an
  application that will not start. Refusing outright remains available as the opt-in
  `-DDVMP_ANTIDEBUG_REFUSE`;
- a **generated-version-script export surface**
  (`src/vmp_exports.map.in`), so only the nine documented ABI functions are
  exported; diagnostics and interpreter internals are local to the DSO.

**Differential tests against a Dart oracle.** `app/test/vmp_differential_test.dart`
runs every protected function through the interpreter and diffs the result against
the original Dart implementation over sweeps of inputs, including 64-bit wraparound
cases. `app/test/vmp_e2e_test.dart` adds the protection-property tests, including
the residency bound, the post-call residue counts, the runtime-keyed store, the call
policies, the entry-point hook, the anti-debug cache, and a 256-call check that the
guarded byte count does not grow. On the measured build: 33 compiler tests and 31
app tests pass.

**Verification tooling (`tool/`).** `tool/test.ps1` runs the whole suite in one
command and reports the failed steps rather than the first one; `-Release` adds the
release APK, the release desktop runner, the leak and protection scans, the
cryptographic vectors, the opcode-map reverse test, the C-layer hand-off, the device
run and the anti-debug gate. The individual tools include `verify_protection.ps1`
(scans `libapp.so` and `libdartvmp.so` for names, mechanism words and phrases),
`verify_image.py`, `list_symbols.py`, `walk_bytecode.py` (decodes the container
independently and verifies CRC and tag, with `--tamper` as its reverse test),
`verify_descriptors.py`, `audit_operands.py`, `verify_concurrency.ps1` (a C harness
driving the public ABI from eight OS threads), `capture_desktop_run.ps1`,
`verify_antidebug_gate.ps1`, and `recover_opcodes.py` / `recover_from_shipped.py`
(both attacks, each with a `--selftest` positive control).

**Release hardening.** The release APK is built with
`--obfuscate --split-debug-info=<dir>`, which renames the generated stub
declarations and their call sites together; the stubs dispatch by numeric id, so
nothing depends on a real name. `verify_protection.ps1` now requires **zero**
protected names in `libapp.so`, and the demo labels its dispatch rows by id in
release builds. Without the obfuscation flag the same sources fail that gate naming
six of eight probes, so the check is verified in both directions. The cost is real
and stated: the symbols directory must be archived with each release, or crash
stacks cannot be symbolised. The diagnostic probes and the `DARTVMP_NO_ANTIDEBUG`
escape hatch are compiled out of the shipped library.

**Supporting material.** `README.md` (and `README.zh-CN.md`), the container-format
and repository-layout references, `docs/` protection-boundary analysis and
methodology review, `tool/ui/` (a local stdlib-only Python UI for choosing what to
protect, bound to `127.0.0.1` and explicitly unauthenticated), `LICENSE`,
`LICENSING.md`, `CONTRIBUTING.md` and `SECURITY.md`.

### Documented limitations

These are recorded here because they are part of the release as much as the features
are. Each is described in full in `README.md`, under
[Honest limitations](README.md#honest-limitations) and
[What was strengthened, and what was deliberately not](README.md#what-was-strengthened-and-what-was-deliberately-not).

- **Nothing here makes logic unrecoverable.** The container's stream cipher is keyed
  by a seed stored in the container's own header, and the mask derivation, the
  opcode permutation's construction and the interpreter's instruction semantics all
  ship inside `libdartvmp.so`, because the component must work offline. A determined
  attacker who reads the runtime can recover the logic. What the layers buy is
  effort, not impossibility.
- **C-layer virtualization works for only two functions.** Seven functions were
  handed to VMPacker 1.3; it replaced all seven with VM trampolines and passed every
  structural check, and then **five of the seven killed the application on a real
  device** (a rooted Xiaomi 12, Android 13, arm64-v8a) with `SIGSEGV` before the
  first frame. The fault addresses equal the call targets, because VMPacker's VM
  remaps only branches inside the function it translated, so an external `bl` or an
  `adrp` keeps its link-time address. `tool/vmpacker_targets.txt` therefore lists two
  targets — `apply_keystream` and `keystream_seed` — and the five that need a call or
  an `adrp` sit in a section that the instruction-coverage check refuses by name. The
  two that remain are the ones the README documents in enough detail to reimplement;
  the function that would have been worth hiding, `unpermute_code`, is one of the
  five that crash and cannot be virtualized with this tool.
- **The interpreter itself is not virtualized.** `dvmp_vm_run` is where the ISA
  semantics live, and it is out of reach of this tool: with the hot-translation
  option enabled it translates 1 029 of 1 053 instructions and VMPacker aborts, on
  16-byte struct copies rather than a vectorised loop. It is also the wrong thing to
  want, since a protected function runs on a second interpreter and the cost would be
  per bytecode instruction of every call.
- **VMPacker rewrites ELF, so the Windows runtime is not virtualized at all.** The
  desktop runtime is a PE image linked into `dartvmp_demo.exe`. The C layer there
  stays ordinary x86_64 code.
- **The resident plaintext is bounded, not zero.** At most four decoded functions
  plus the metadata are resident during a call, and the metadata has to be resident.
  A debugger can still walk one function at a time and reassemble. The property
  changes what a single incidental capture is worth, not what a debugger can do.
- **A full-process dump still gets everything**, because the store's keys live in the
  same address space as the store.
- **The entry-point integrity check finds a hook that begins with a branch.** A hook
  that saves the prologue first, or that patches the caller instead, is not found, and
  the check is itself patchable by anyone who knows it is there.
- **The call policy can be patched out.** It stops the attack that needs no
  reversing — using the shipped library as a fast validator — and not someone willing
  to read the disassembly.
- **Dart-side debuggers see plaintext and cannot be stopped from C.** The return
  value of a protected function necessarily lands on the Dart heap.
- **Android and Windows only.** `ios`, `linux` and `macos` are not plugin platforms
  in this release; `openRuntimeLibrary` keeps the branches so adding one means adding
  a directory. `abiFilters` is limited to `arm64-v8a` and `x86_64`; 32-bit ARM is not
  shipped.
- **Interpretation is much slower than AOT code.** Protected functions belong in
  low-frequency, high-value paths: activation checks, key derivation, signature
  verification. Never in a render loop.

### Known gaps

- **Malformed-image handling has no differential coverage.** The suite exercises the
  nine protected functions; `strParseInt`, the builder builtins, `abort` and the error
  paths are never reached by them, which is how two memory-safety bugs survived three
  rounds of auditing. They were found by a harness that builds arbitrary containers,
  and reproducing that harness as a test is the next thing worth doing.
- **The runtime's own container-verification path is exercised only indirectly.**
  Every call goes through it, so a broken check would fail the suite — but a check
  that silently stopped firing would not be noticed, because nothing feeds the shipped
  runtime a corrupted container. Closing that needs a diagnostic entry point that
  accepts an arbitrary container and reports the rejection reason. Until then, "byte
  editing is rejected" is verified on the generator side.

### Notes on this release

- The device run is the only check in the suite that executes the protected artifact.
  It exists because every structural check was green while the shipped APK crashed
  before its first frame, and it says "no device attached" out loud rather than
  skipping silently.
- Several checks in this release are the *reverse* of a claim: `walk_bytecode.py
  --tamper`, `recover_opcodes.py --selftest` and `recover_from_shipped.py --selftest`
  must reject a known-bad artifact, so that a detector which can only ever report
  "nothing found" cannot pass as a gate. This is the discipline the project holds
  itself to and `CONTRIBUTING.md` requires of contributors.
