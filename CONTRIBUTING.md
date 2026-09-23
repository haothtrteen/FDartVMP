# Contributing to FDartVMP

Contributions are welcome, with two conditions that are unusual enough to state
first:

1. **Every contribution requires a contributor agreement.** The project is
   dual-licensed (AGPL-3.0-or-later plus a commercial license), so the maintainer
   must hold enough rights to license your code commercially as well. See
   [Contributor agreement](#contributor-agreement).
2. **Every fix ships with a check that fails when the bug comes back**, and every
   new check has to be shown rejecting something. See
   [Engineering discipline](#engineering-discipline).

If either of those does not work for you, please say so in an issue before writing
code — it is a much better conversation to have first.

---

## Before you start

Read [`README.md`](README.md). It is long, and it is the specification: it states
what each protection layer is for, which claims are verified and by which check,
what was deliberately *not* done, and where the honest limits of the design are.
A change that contradicts the README needs the README changed with it, and a change
that claims more than the README does will not be merged.

Two project rules that come up in review constantly:

- **Do not break correct callers.** A protection layer that can stop a legitimate
  application from working is worse than no layer. The README records three
  separate occasions where a guard or a rate budget was calibrated against the
  attack instead of against the legitimate rate, and a correct caller failed.
- **A claim in prose is not a check.** If the documentation says a buffer is wiped,
  a lock is taken, or a gate is enforced, there must be something in the suite that
  fails when that stops being true. The most expensive bugs in this project's
  history were exactly the cases where the documentation described the intended
  design and the code did not implement it.

## Requirements

- Flutter 3.41 or later, and the Dart SDK that ships with it.
- The Android SDK with the NDK, for the Android build and for the Rust-free C-layer
  toolchain steps. `ANDROID_HOME` (or the default SDK location) must be set.
- Visual Studio with the C++ workload, for the Windows desktop build and the native
  test runtime.
- Python 3 on `PATH`. Several checks are Python (`tool/check_encoding.py`,
  `tool/verify_image.py`, `tool/walk_bytecode.py`, `tool/recover_opcodes.py`,
  `tool/audit_operands.py`, `tool/recover_from_shipped.py`).
- Go, only if you intend to build VMPacker itself (see
  [`tool/build_vmpacker.ps1`](tool/build_vmpacker.ps1)). It is optional: the
  VMPacker step reports `NOT APPLIED` when the tool is absent.
- An attached Android device, only for the device-run check. Without one, that
  check says so out loud rather than skipping silently, because "no device" and
  "the protected runtime works" must not look the same in a log.

## Build and test

Everything below is run from the repository root, and the commands are the ones the
repository actually uses.

### One command

```powershell
powershell -ExecutionPolicy Bypass -File tool/test.ps1
powershell -ExecutionPolicy Bypass -File tool/test.ps1 -Release   # + APK, protection and crypto gates
powershell -ExecutionPolicy Bypass -File tool/test.ps1 -SkipBuild # reuse existing artifacts
```

This compiles the protected sources, runs the compiler tests, the artifact
self-check, the UTF-8 encoding check, the descriptor dump, the native runtime
build, the concurrency harness and the Flutter app tests. `-Release` adds the
release APK, the release desktop runner, the desktop link check, the leak and
protection scans, the cryptographic vectors, the opcode-map reverse test, the
C-layer hand-off, the device run, and the anti-debug gate. It prints `ALL GREEN`
and exits 0 only if every step passed, and it lists the failed steps otherwise.

Note that `-Release` expects an attached device for one step; when none is
attached that step reports the gap explicitly and does not fail the run.

### Step by step

```bash
# 1. Compile the protected sources and generate every artifact
dart run tool/build.dart                    # random seed, as a release build should
dart run tool/build.dart --seed 0x1234      # reproducible

# 2. Inspect what was compiled
dart run tool/vmpc/bin/vmpc.dart disasm --seed 0x1234
dart run tool/vmpc/bin/vmpc.dart check

# 3. Compiler tests
cd tool/vmpc && dart test

# 4. Native runtime, as a loadable library
cd ../..
powershell -ExecutionPolicy Bypass -File tool/build_native.ps1

# 5. App tests, including the native differential suite
cd app
$env:DARTVMP_LIBRARY_PATH = "$PWD/build/native/dartvmp.dll"
flutter test
Remove-Item Env:\DARTVMP_LIBRARY_PATH
```

On Linux or macOS the deployed library is `libdartvmp.so` rather than
`dartvmp.dll`; point `DARTVMP_LIBRARY_PATH` at it accordingly.

### Why `DARTVMP_LIBRARY_PATH` is required

`flutter test` builds its own host executable (`flutter_tester`), which does not
contain the runtime — the desktop application links the runtime *into the runner*,
and the test host cannot reproduce that. So the native groups load a separately
built library from disk, and the environment variable is how they find it.

Without the variable the native tests **skip loudly** rather than passing
vacuously, so a CI run cannot mistake "the runtime was missing" for "the runtime
agreed". Do not silence that: if those groups skip in your run, your change has not
been tested against the interpreter.

The deployed copy lives in `app/build/native/` deliberately. Dropping
`dartvmp.dll` next to the tests does not work — the Flutter tool truncates files it
considers build output in the package root, which produced a zero-byte DLL and made
every native test report *skipped*.

### Checks worth running on their own

```bash
# Every text file must be valid UTF-8 (see below — this one is not optional)
python tool/check_encoding.py

# Reverse tests: these must FAIL to find anything on shipped output,
# and must SUCCEED on the legacy artifact they are calibrated against
python tool/recover_opcodes.py
python tool/recover_opcodes.py --selftest

# The container's CRC and auth tag, reproduced independently of the runtime
python tool/walk_bytecode.py
python tool/walk_bytecode.py --tamper     # flip a byte, watch the checks reject

# The image really is masked, and only the ABI is exported
python tool/verify_image.py
python tool/list_symbols.py

# Every operand read in the interpreter is bounded
python tool/audit_operands.py
```

## Engineering discipline

This is the part of the process that gets enforced, because it is the part that
historically caught the real bugs.

### Every fix ships with a check that fails on regression

A bug fix is not complete when the behaviour is corrected. It is complete when
something in `tool/` or `app/test/` fails if the behaviour comes back. The
repository is full of examples, and the pattern is deliberate:

- the body wipe has a test asserting the post-call residue count is zero, and
  disabling the wipe makes it fail with the byte count;
- the process-wide lock has `tool/verify_concurrency.ps1`, a C harness that drives
  the public ABI from eight OS threads; with the lock removed it reports thousands
  of errors;
- the leak fix has a check that runs 256 calls and requires the guarded byte count
  to be identical before and after;
- the call policy has tests that size their overrun loop from the budget declared
  in the manifest instead of restating it, so the test cannot drift away from the
  policy.

If your fix cannot be observed failing before it is applied, say so in the pull
request and explain what you did instead. That is a legitimate answer; asserting
that it was verified when it was not is not.

### Every new check must be reverse-verified

**A check that has never been observed to reject anything is a print statement,
not a gate.** This is stated in several places in this repository, and it is
enforced on both sides of every new gate:

1. **It must be shown rejecting a real failure.** For a detector, that usually
   means a `--selftest` or `--tamper` mode that feeds it the bad artifact it is
   supposed to catch:

   ```powershell
   python tool/walk_bytecode.py --tamper       # flips one ciphertext byte first
   python tool/recover_opcodes.py --selftest   # re-packs the body with the old affine mapping
   ```

   `tool/recover_opcodes.py` is the cautionary tale and is why this is a hard rule.
   Its first version zeroed its own operand bytes while decoding, which broke the
   CRC oracle, so it reported "not affine" for *every* input — including the legacy
   container it existed to crack. The attack that "failed" had never run.

2. **It must be shown not rejecting a correct artifact.** A gate that cries wolf is
   a gate people learn to ignore, and the temptation when it fires wrongly is to
   weaken the gate rather than remove the collision. The entry-point integrity
   check shipped with a false positive that flagged three clean one-line MSVC
   wrappers as hooked; the fix was to make the check ask what the branch *targets*,
   not merely whether one exists. The `add` probe is the same lesson one level down:
   it collided with the runtime's own diagnostic text, and the fix was to change the
   diagnostic rather than to teach the matcher an exception.

3. **The gate's own reach has to be checked too.** The first version of the
   release-mode binder guard scanned 400 characters past each signature, which was
   shorter than the comment on one of the binders, so it reported a correctly gated
   binder as a leak. Same failure mode as the bug it existed for, one level up.

So a pull request that adds or changes a check should state, in the description,
what you ran to see it fail and what you ran to see it pass. If the check has a
`--selftest`-style mode, wire it into `tool/test.ps1 -Release` so it runs on every
release build.

### Do not weaken a gate to make your change pass

If a gate fails on your change, the question to answer is which side is wrong. If
the gate is genuinely too strict, tighten or replace it and add the case that
proved it wrong; do not extend an allowlist, and do not delete a check that has
become inconvenient. Every allowlist entry in this repository is expected to carry
its reason inline.

### Text encoding is checked, and the reason is concrete

```bash
python tool/check_encoding.py
```

Every text file in the repository must be valid UTF-8, and this runs as a step of
`tool/test.ps1`.

The reason is an actual incident, not a preference. `README.md` spent part of a
session as an invalid-UTF-8 file because of a shell idiom used to edit it:
`Get-Content -Raw` followed by `Set-Content -Encoding utf8` **on a CP936 console**
decodes the file's UTF-8 bytes as CP936 and writes the result back, so every
non-ASCII character becomes a `?`-terminated remnant (`e2 80 3f` where an em dash
had been) and **the byte after it is consumed too**. It ran twice, so the damage
compounded across 217 sites, and the ASCII diagrams were reduced to placeholders.

Three things made it expensive:

- it is **lossy**: the trailing byte is gone, so the transformation cannot be
  inverted, and the original characters had to be re-derived from context;
- **nothing failed.** The build stayed green and the tests passed; the first
  symptom was an unrelated tool refusing to open the file;
- it happened while *editing documentation*, which is the one place with no test.

**So: use a UTF-8-safe editor.** Do not round-trip text files through
`Get-Content`/`Set-Content`, and do not use `>` redirection against a file whose
content you care about. If `check_encoding.py` fails on a file you touched, repair
the bytes (the check reports the first bad offset) rather than re-saving the file.

## Contributor agreement

FDartVMP is dual-licensed: AGPL-3.0-or-later for open source use, plus a separate
paid commercial license for closed-source use. See
[`LICENSING.md`](LICENSING.md) for the full explanation.

For that to be possible, the maintainer has to hold enough rights in the whole
codebase to license it under both. A single outside contribution accepted without
those rights would make it legally impossible to sell commercial licenses for any
version containing it, because the contributor would still hold copyright in their
part.

Therefore every contribution must be accompanied by either:

- **a signed contributor license agreement**, supplied by the maintainer on
  request; or
- **an explicit statement in the pull request** that the contributor assigns, or
  grants the maintainer, the rights needed to license the contribution under both
  the AGPL-3.0-or-later and the commercial license, including the right to
  sublicense and to relicense under other terms.

**Pull requests without one of those cannot be merged.** This is not a judgement
about the contribution; it is a hard requirement of the dual-license model. If you
want to contribute and the paperwork is a problem, open an issue and ask — it is
better to resolve it before you write the code than after.

Also worth knowing before you contribute: this repository's build downloads and
runs VMPacker (AGPL-3.0) as an external tool and does not vendor it. Do not commit
third-party source, third-party binaries, or generated artifacts into the tree, and
do not add a dependency without saying so in the pull request — the license of every
new dependency has to be checked against the model above.

## Reporting security issues

**Do not open a public issue for an exploitable finding.** Send it privately to
haothtrteen at **2557976190@qq.com**, with enough detail to reproduce it. See
[`SECURITY.md`](SECURITY.md) for what the project does and does not claim, and for
what to include in a report.

A report is most useful when it names the layer that was defeated, because that
determines whether it becomes a regression check. A defeated layer with a reproducer
usually becomes one; a general statement that the protection "can be bypassed"
usually cannot.

## Pull request checklist

- [ ] The change is described, including *why* and what it affects.
- [ ] `tool/test.ps1` passes (or `tool/test.ps1 -Release` for anything touching the
      shipped artifact).
- [ ] Any new or changed check has been observed **failing** on the bad input and
      **passing** on the good one, and that is stated in the description.
- [ ] `python tool/check_encoding.py` passes, and no file was re-saved through a
      `Get-Content`/`Set-Content` round-trip.
- [ ] `README.md` (and `README.zh-CN.md`, if the change is user-visible) reflects
      the new state, and no claim is made that the suite does not verify.
- [ ] The same change was applied to both READMEs if both documents changed.
- [ ] The contributor agreement requirement above is satisfied.
- [ ] No third-party source, binary, or generated artifact was added to the tree.
