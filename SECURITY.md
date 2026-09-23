# Security Policy

## Reporting a vulnerability

Send reports privately to:

**haothtrteen — 2557976190@qq.com**

**Do not open a public issue for an exploitable finding.** A public issue that
describes how to defeat a protection layer, before there is a fix, is a working
recipe for anyone who reads it. If you are unsure whether something counts as
exploitable, mail it and ask; over-reporting privately costs nothing.

Please include, as far as you can:

- **which layer you defeated**, using the layer names in the README's
  [What was strengthened](README.md#what-was-strengthened-and-what-was-deliberately-not)
  section (see [Which layer?](#which-layer-did-you-defeat) below);
- the exact revision or commit you tested;
- the **platform and build** — Android (with ABI and device/OS version) or Windows
  desktop; release or debug; and whether the release APK was built with
  `--obfuscate --split-debug-info`;
- whether the C-layer virtualization step had been applied (`tool/apply_vmpacker.ps1`
  reports `APPLIED` or `NOT APPLIED`; the two look identical once built, so please
  say which it was);
- a minimal reproducer, or precise steps, and any artifacts (a script, a dump, a
  tombstone, a trace). A runnable script is worth far more than a description,
  because it can be turned directly into a check that fails on regression;
- what you expected versus what happened.

There is no bounty program and no guaranteed response time. Reports are read by the
maintainer, and a confirmed finding is credited in the release notes unless you ask
to remain anonymous.

## What this project claims

FDartVMP is an obfuscation and virtual-machine-protection component for Flutter. Its
purpose is to move sensitive logic out of the AOT snapshot so that it is not
readable there.

**It raises the cost of recovering protected logic from a shipped binary. It does
not make that logic unrecoverable, and it is not a security boundary in the
cryptographic sense.**

That is the claim the README makes and the only claim that should be held against
this project. Specifically:

- **The layers buy effort, not impossibility.** The design is sound about that:
  as the README puts it, for a component that must work offline, static recovery is
  a matter of effort rather than possibility, because engineering can choose how
  much effort but not "none".
- **Keys and derivations ship inside the library, by necessity.** The component has
  to work offline, so the binary carries its own key material. The container's
  stream cipher is keyed by a seed stored in the container's own header, and the
  SplitMix64 mixing, the mask derivation, the opcode-permutation construction and
  the interpreter's instruction semantics all ship in `libdartvmp.so`. That is not
  an oversight to be reported as one; it is the structural consequence of offline
  operation, and the README states it under
  [Honest limitations](README.md#honest-limitations).
- **A determined attacker who reads the runtime can recover the logic.** Reading
  `dvmp_vm.c` gives the meaning of every opcode; the README records that an
  attacker who reads roughly 100 instructions of `unpermute_code`, or who
  recognises SplitMix64 plus a Fisher-Yates shuffle, reconstructs the opcode
  mapping directly. Recovering the bytecode is mechanical for someone willing to
  reimplement the scheme.
- **Dart-side debuggers cannot be stopped from C.** The return value of a protected
  function necessarily lands on the Dart heap, where the VM Service / DevTools
  debugger can see it. The anti-debug layer targets the cheap attacks and is a
  speed bump whose signatures go stale.
- **A full-process capture gets everything.** The runtime-keyed instruction store
  means a *partial* capture (one buffer, one page, a crash dump of a single
  allocation) cannot be opened with anything on disk. It does not survive a
  full-process capture, because the keys live in the same address space as the
  store. This is documented rather than presented as a boundary.
- **The C-layer hardening is partial.** VMPacker virtualization is applied to two
  functions on Android, both of which the README argues are worth little; five
  further targets were virtualized and crash on a real device, so they are refused
  by a check instead. VMPacker rewrites ELF, so the Windows runtime is not
  virtualized at all: its functions are ordinary x86_64 code.
- **Nothing here makes logic unrecoverable.** If particular logic must be genuinely
  unrecoverable, no local obfuscation achieves it — the answer is architectural:
  keep that logic on a server and let the shipped binary call it.

In scope for a report: any way to defeat a protection layer *within* what the README
claims for it, any way to make a protected function return a wrong answer, any way
to make a legitimate caller fail, any crash or memory-safety defect in the runtime,
and any case where a shipped artifact contains something the README says it does
not.

Out of scope, because the README already documents them: that a debugger can see
the plaintext during a call; that the shipped binary contains its own key material;
that a full-process dump is recoverable; that a patched interpreter or a patched
call policy defeats its own layer; that the C layer is not fully virtualized or not
virtualized on Windows.

## Which layer did you defeat?

Naming the layer matters more than it might seem. Each layer in this project is
guarded by a check, and a finding that names the layer usually becomes a regression
check that fails when the flaw comes back. A finding that says only "the protection
can be bypassed" generally cannot be turned into one, so it tends to be fixed
once rather than permanently.

The layers, and what each is supposed to stop:

| Layer | Defeats | Documented strength |
|---|---|---|
| Private instruction set — keyed Fisher-Yates permutation of every opcode byte before it is written | reading the bytecode from the container | strong |
| Stream cipher — SplitMix64 keystream over the body, re-seeded on every call | offline decryption of the working buffer | obfuscation, since the seed is in the container header |
| Static image masking — SHA-256-derived per-word mask over the stored container | finding the container with `strings` or `binwalk`, and known-plaintext key recovery | medium |
| Container CRC plus body auth tag | editing the stored bytes | strong |
| Bytecode compiler (`tool/vmpc`) | recovering the original Dart from the AOT snapshot | strong |
| Native interpreter with a runtime-keyed instruction store and per-call wipe | dumping the decoded instruction stream, and dumps taken between calls | medium; the resident plaintext is bounded, not zero |
| Differential tests against a Dart oracle | the interpreter disagreeing with Dart semantics | not a protection layer; it is what makes the other layers trustworthy |
| Call policy guards (`// @vmp guard:rate=…`, `guard:once`) | using a shipped verifier as a fast yes/no oracle | weak, and only against the version that needs no reversing |
| Entry-point integrity checking (`dvmp_integrity.c`) | patching or hooking an ABI entry point | finds a hook that *begins* with a branch; a hook that saves the prologue first, or patches the caller, is not found |
| Anti-debug, with a narrow-cache reaction | attaching a debugger cheaply | a speed bump; signatures go stale |
| Process-wide lock | overlapping calls from several threads | strong |
| C-layer virtualization (VMPacker, Android arm64 only) | reading the C layer's machine code | applies to two functions; five targets crash on device and are refused; no Windows coverage |

Full detail, including the per-target device results and the reasoning behind
each rejection, is in the README sections
[What was strengthened, and what was deliberately not](README.md#what-was-strengthened-and-what-was-deliberately-not),
[What protects what](README.md#what-protects-what),
[Where the plaintext actually is](README.md#where-the-plaintext-actually-is) and
[Honest limitations](README.md#honest-limitations). Please read at least
[Honest limitations](README.md#honest-limitations) before reporting — a good part
of it is a list of things that are already known and already stated.

## What to expect

1. Acknowledgement of the report.
2. An assessment against the claims above: whether the layer behaved as documented,
   or the documentation and the claim were wrong.
3. A fix with a check that fails when the flaw comes back, wherever the finding
   admits one. Where it does not — a design limit rather than a defect — the README
   is corrected instead, so that the claim matches the state. This project treats
   "the prose described the intent and the code did not implement it" as the bug it
   actually is.
4. Credit in the release notes, unless you ask otherwise.

Fixes for confirmed findings, and the reverse-verified checks that come with them,
are recorded in [`CHANGELOG.md`](CHANGELOG.md).
