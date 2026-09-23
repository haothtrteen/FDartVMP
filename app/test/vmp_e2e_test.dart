import 'dart:ffi';
import 'dart:io';

import 'package:ffi/ffi.dart' show calloc;

import 'package:flutter_test/flutter_test.dart';
import 'package:dartvmp/dartvmp.dart';

import 'generated/protected_oracle.dart' as oracle;

/// End-to-end smoke test: every protected stub must run through the native VM
/// and agree with the Dart oracle, and the shipped container must be opaque.
void main() {
  setUpAll(() {
    Vmp.initialize();
  });

  test('a patched entry point is detected, and the detector is self-tested', () {
    // G2: the cheapest attack on this system is not to read the protected logic but to
    // patch the *answer* - an inline hook (Frida's Interceptor, Dobby, or a hand-made
    // branch) at the entry point that produces it. Every one of those puts an
    // unconditional branch where the target's first instruction was, and
    // `dvmp_integrity.c` scans for exactly that.
    //
    // This test does the attack for real rather than simulating it: it makes the code
    // page writable, writes a `B` over the first instruction of `dartvmp_status_name`,
    // asks the runtime to re-scan, and restores the bytes. It uses the least
    // load-bearing entry point in the ABI - nothing in this process calls it outside an
    // error path - and restores in a `finally`, because a test that left an entry point
    // patched would break every test after it.
    final integrity = Vmp.integrity();
    if (integrity == null) {
      // The release runtime compiles the probes out; the host test library does not.
      return;
    }
    expect(integrity.scanned, 9, reason: 'all nine ABI entry points are scanned');

    // The decoder's own known-encoding vectors. Without this, a decoder that always
    // answered "clean" would be indistinguishable from a clean process - which is the
    // failure this whole check exists to avoid, one level up.
    expect(integrity.selftestOk, isTrue,
        reason: 'the hook decoder must distinguish a branch from a prologue on '
            'known encodings before its "clean" verdict means anything');
    expect(integrity.hooked, 0, reason: 'nothing is hooked in a normal test run');

    final libPath = Platform.environment['DARTVMP_LIBRARY_PATH'];
    if (libPath == null || !File(libPath).existsSync()) {
      fail('DARTVMP_LIBRARY_PATH must point at the runtime; see tool/test.ps1');
    }
    final lib = DynamicLibrary.open(libPath);
    final entry =
        lib.lookup<NativeFunction<Void Function()>>('dartvmp_status_name');
    final addr = entry.address;
    final bytes = Pointer<Uint8>.fromAddress(addr);
    final original = List<int>.generate(4, (i) => bytes[i]);

    if (!_makeWritable(addr, 64)) {
      // Older Android/iOS forbid this outright; the check is still exercised by the
      // self-test above, so this is a skip with a reason rather than a silent pass.
      return;
    }
    try {
      // AArch64 `B #0`, the first instruction of a classic inline hook. (The decoder
      // also knows the x86-64 forms; the host test runs whichever the library is.)
      if (Abi.current() == Abi.androidArm64 ||
          Abi.current() == Abi.iosArm64 ||
          Abi.current() == Abi.macosArm64) {
        bytes[0] = 0x00;
        bytes[1] = 0x00;
        bytes[2] = 0x00;
        bytes[3] = 0x14;
      } else {
        bytes[0] = 0xE9; // jmp rel32
        bytes[1] = 0x00;
        bytes[2] = 0x00;
        bytes[3] = 0x00;
      }
      final patched = Vmp.integrity()!;
      expect(patched.hooked, 1,
          reason: 'a branch written over the first instruction of an ABI entry '
              'point must be reported (the earlier clean verdict is what makes this '
              'a measurement rather than an assumption)');
      // Bit 6 is `dartvmp_status_name`, the entry this test patched. Asserting the bit
      // rather than the count is what proves the scan attributed it to the right
      // function instead of flagging something at random.
      expect(patched.mask, 1 << 6,
          reason: 'the verdict must name the entry point that was patched');
    } finally {
      for (var i = 0; i < 4; i++) {
        bytes[i] = original[i];
      }
    }
    expect(Vmp.integrity()!.hooked, 0,
        reason: 'restoring the original instruction must clear the verdict');
  });

  test('the loaded runtime is the build the artifacts describe', () {
    // Every other release check scans the *APK*, which can be stale relative to
    // what `flutter test` loads: the native tests load `libdartvmp.so` from
    // `app/build/native`, compiled by `tool/build_native.ps1` from
    // `packages/dartvmp/generated/vmp_module.inc`. If that library were older
    // than the header, every leak probe would still pass while the tests
    // exercised different bytecode from the app - and the protection claim would
    // be about a build nobody ships.
    //
    // The manifest records the build id the compiler wrote into that header, and
    // the runtime reports the id compiled into its image, so the two can be
    // compared. Both come from one `vmpc build` run, so any mismatch means the
    // artifacts under test are from different runs.
    final buildId = _manifestBuildId();
    expect(Vmp.buildId(), buildId,
        reason: 'the loaded runtime was built from a different module image than '
            'the generated artifacts (manifest 0x${buildId.toRadixString(16)}, '
            'runtime 0x${Vmp.buildId().toRadixString(16)}). Run '
            '`dart run tool/build.dart` then `tool/build_native.ps1`.');
  });

  test('a declared call policy actually refuses excess calls', () {
    // `verifyLicense` declares a `guard:rate=...` policy in protected/licensing.dart,
    // and the policy ships inside the module rather than depending on the host
    // configuring it. This is the test that the declaration reached the runtime:
    // a policy that silently failed to encode would look identical from the
    // source, and "protection that reads like it is on but is not" is the failure
    // mode this whole audit kept finding.
    //
    // It is also the answer to the oracle problem - `verifyLicense` answers a
    // yes/no question, so calling it in a loop is the cheapest attack there is.
    // Refusing past a budget does not stop an attacker who patches the guard out,
    // but it does stop the shipped library from being a fast validator.
    //
    // The budget is read from the manifest, never restated here. An earlier
    // revision hardcoded a 40-iteration loop against a budget of 64 and so spent
    // its life asserting that a guard which never fired had not fired - the exact
    // shape of green-but-empty check this repository keeps trying to stamp out.
    const key = 'PKHDPV6CEE4QZKMX';
    final id = Vmp.functions().firstWhere((f) => f.name == 'verifyLicense').id;
    final declared = _declaredRate('verifyLicense');
    expect(declared, isNotNull,
        reason: 'verifyLicense is the oracle-shaped function in this module; a '
            'build that ships it with no declared policy has lost the only '
            'runtime control over how often it can be asked');

    final (budget, windowMs) = declared!;

    // Start from a clean counter: the correctness tests earlier in the file have
    // already spent part of the budget, and a policy test that depends on how many
    // calls other tests made would be a flake rather than a check.
    expect(Vmp.resetCallPolicies(), isTrue,
        reason: 'the diagnostics build must export the policy reset, otherwise '
            'this test cannot distinguish "the guard works" from "the budget was '
            'already spent"');

    // The first call inside a fresh window must succeed and answer correctly.
    expect(Vmp.callNamed('verifyLicense', const <Object?>[key]), isTrue);

    // Overrun the declared budget by a margin and count the refusals. The loop is
    // sized from the declaration, so retuning the policy cannot silently turn this
    // into a no-op again.
    const overshoot = 32;
    var refused = 0;
    for (var i = 0; i < budget + overshoot; i++) {
      try {
        Vmp.call(id, const <Object?>[key]);
      } on VmpFault catch (e) {
        if (e.status == VmpStatus.tooManyCalls) {
          refused++;
        } else {
          fail('unexpected fault from a guarded call: $e');
        }
      }
    }
    expect(refused, greaterThan(0),
        reason: 'the declared rate guard never refused a call after '
            '${budget + overshoot} calls against a declared budget of $budget, so '
            'the policy did not reach the runtime');
    expect(refused, greaterThanOrEqualTo(overshoot - 1),
        reason: 'only $refused of the $overshoot calls past the budget were '
            'refused, so the runtime is not enforcing the declared budget '
            '($budget per ${windowMs}ms)');

    // A refusal inside the window must not have poisoned the module: after a reset
    // the function answers correctly again. This is the property that keeps a
    // guard from being a protection-induced behaviour change.
    expect(Vmp.resetCallPolicies(), isTrue);
    expect(Vmp.callNamed('verifyLicense', const <Object?>[key]), isTrue);
    expect(Vmp.callNamed('verifyLicense', const <Object?>['WRONG']), isFalse);
  });

  test('the declared call policy cannot refuse a legitimate burst', () {
    // The hard rule for this project is that protection must not change what
    // business code does. A rate guard is the one mechanism here that can violate
    // it directly, by refusing a call the application had every right to make, so
    // the shipped budget has to be checked against legitimate usage and not only
    // against the attack it is meant to slow down.
    //
    // 512 calls in one burst is the documented legitimate ceiling: it covers an
    // activation screen checking a pasted list of keys, a self-test sweep over the
    // whole API, and a user hammering "verify" while a key is being typed, with
    // room to spare. The budget has already been raised twice because it was set
    // below this - 8/1024 and then 64/2048 both refused correct callers - so the
    // number is now pinned by a test rather than by a comment.
    const legitimateBurst = 512;
    const key = 'PKHDPV6CEE4QZKMX';

    final declared = _declaredRate('verifyLicense');
    expect(declared, isNotNull);
    final (budget, windowMs) = declared!;
    expect(budget, greaterThanOrEqualTo(legitimateBurst),
        reason: 'the declared budget is $budget per ${windowMs}ms, below the '
            '$legitimateBurst-call burst this project treats as legitimate '
            'application behaviour. Protection is not allowed to make a correct '
            'caller fail, so either raise the budget or lower the documented '
            'ceiling in the README - do not leave the two disagreeing.');

    expect(Vmp.resetCallPolicies(), isTrue);
    // Reset and burst with nothing in between, so the count is this test's alone.
    // The window is at least a second, and 512 calls take single-digit
    // milliseconds at the measured call rate, so the burst cannot straddle two
    // windows.
    for (var i = 0; i < legitimateBurst; i++) {
      Vmp.callNamed('verifyLicense', const <Object?>[key]);
    }
    expect(Vmp.resetCallPolicies(), isTrue);
  });

  test('a call cannot make the whole program resident', () {
    // The property this test exists for is the difference between "the plaintext
    // exists during a call" and "the plaintext exists during a call *and it is
    // everything*". The earlier design kept the entire decoded instruction stream
    // in the body for the whole of every call, so one snapshot taken at any moment
    // returned every protected function at once - the whole algorithm, in one
    // read, with nothing to reassemble.
    //
    // Now `open` re-encrypts the stream under a process-only key and the
    // interpreter materialises one function at a time into a fixed number of
    // slots, so the observable is `peak * largest < total`.
    //
    // Stated honestly, including what it does not buy, because this is exactly the
    // kind of claim that is easy to oversell: it does not defeat a debugger. An
    // attacker who can pause the process can pause it once per function and
    // reassemble, and the reassembly is mechanical because the descriptors carry
    // every function's offset and length. What it changes is that a *single*
    // incidental dump - a crash report, a swapped-out page, a paused debugger -
    // is worth one function instead of the program. A static attacker is
    // unaffected either way, because the shipped container is decryptable offline
    // by construction.
    final before = Vmp.codeResidency();
    expect(before, isNotNull,
        reason: 'the release runtime must not export this probe, but a '
            'diagnostics build must: without it, "the stream is not resident in '
            'bulk" is unfalsifiable from Dart');

    // Drive every protected function, so every slot that *can* be filled by this
    // module has been asked for at least once. If residency were unbounded this is
    // the loop that would make it show.
    expect(Vmp.callNamed('selfTest', const <Object?>[]), isTrue);
    for (final f in Vmp.functions()) {
      Vmp.resetCallPolicies();
      try {
        Vmp.call(f.id, _sampleArgsFor(f.name));
      } on VmpFault {
        // A wrong-arity or wrong-type sample is fine here: the fetch happens
        // before the function body runs, so the residency accounting is exercised
        // either way. A guard refusal is equally fine, for the same reason.
      }
    }

    final r = Vmp.codeResidency()!;
    expect(r.slots, greaterThan(0));
    expect(r.totalBytes, greaterThan(0));
    expect(r.largestFunctionBytes, greaterThan(0));

    // Non-vacuity, and this is the check that makes the rest mean something: if
    // the runtime had at least as many slots as the module has functions, the
    // bound below would hold for every possible module and would be measuring
    // nothing. The claim only has content while the cache cannot hold the program.
    expect(r.slots, lessThan(Vmp.functions().length),
        reason: 'the runtime has ${r.slots} slots for '
            '${Vmp.functions().length} functions, so "not everything at once" is '
            'not actually a constraint on this module');
    expect(r.peak, greaterThanOrEqualTo(2),
        reason: 'no call loaded more than one function, so this test measured an '
            'empty cache rather than a bounded one');

    // The contract: never more slots live than exist.
    expect(r.peak, lessThanOrEqualTo(r.slots),
        reason: 'the runtime reported more decoded functions resident at once '
            'than it has slots for');

    // The bound, stated as the bound: residency is capped by the slot count times
    // the largest function, not by the module.
    expect(r.peakResidentBytes, lessThanOrEqualTo(r.slots * r.largestFunctionBytes),
        reason: 'resident decoded bytes exceeded slots x largest function');

    // And the claim: what was ever simultaneously resident is a fraction of the
    // module. The margin here is thin - this module is small enough that four
    // slots times its largest function is only just under the whole stream - and
    // the ratio is what scales, not the absolute numbers: it improves with the
    // number of functions, because slots are a constant.
    expect(r.peakResidentBytes, lessThan(r.totalBytes),
        reason: 'at some instant the runtime held ${r.peakResidentBytes} decoded '
            'bytes across ${r.peak} slots, against ${r.totalBytes} bytes of '
            'instruction stream in the module - so a single memory dump could '
            'still have returned the whole program (${r.slots} slots, largest '
            'function ${r.largestFunctionBytes} bytes)');

    // And once the call has returned, nothing decoded is left anywhere.
    expect(r.live, 0,
        reason: 'decoded functions are still resident after the call returned');
    final residue = Vmp.codeResidue();
    expect(residue, isNotNull);
    expect(residue!.slotResidue, 0,
        reason: 'the decoded code slots still hold non-zero bytes while the '
            'module is sealed, so the instruction stream outlived the call');
    // The sharp one: at the instant the module sealed, the body still contained
    // this many bytes of instruction stream. `open` wipes that region after moving
    // it into the runtime-keyed store, so it must be 0 - and the design this
    // replaced kept the whole stream there for the entire call, which is exactly
    // what one memory dump would have collected.
    expect(residue.bodyRegionResidue, 0,
        reason: 'the body still held ${residue.bodyRegionResidue} bytes of '
            'instruction stream when the module sealed, so the decoded program '
            'was resident for the whole call');
    expect(residue.bodyRegionResiduePeak, 0,
        reason: 'at some earlier seal the body held '
            '${residue.bodyRegionResiduePeak} bytes of instruction stream');
    // The store is ciphertext while open and must be wiped at seal: a store that
    // outlived the call would be a captured container sitting in memory, which is
    // most of what the store exists to avoid.
    expect(residue.storeResidue, 0,
        reason: 'the runtime-keyed instruction store still holds '
            '${residue.storeResidue} bytes while the module is sealed, so it '
            'outlived the call');
    expect(Vmp.decodedCodeProbe(0), isNull,
        reason: 'decoded bytecode is readable while the module is sealed');
  });

  test('a call does not leak native memory', () {
    // The module is reopened on every call, so anything the open path allocates
    // is allocated once per call. That is a shape where a missing `free` is
    // invisible: the descriptor array used to be a bare `calloc` per open, and
    // nothing noticed because it is not on the guarded allocator, so
    // `secureBytesLive()` never counted it and no test looked. In an application
    // that calls a protected function in a loop this would grow without bound.
    //
    // The fix was to allocate the array once and reuse it, and this test is the
    // gate for it. It measures the *guarded* allocator, which now does cover the
    // array - the descriptors carry function names and code offsets, so they
    // belong on the wipe-on-release allocator anyway - and it runs enough calls
    // that a per-call allocation of any size would show.
    Vmp.callNamed('add', const <Object?>[1, 2]);
    final baseline = Vmp.secureBytesLive();

    const calls = 256;
    for (var i = 0; i < calls; i++) {
      final n = i;
      expect(Vmp.callNamed('add', [n, 1]), n + 1);
    }

    final after = Vmp.secureBytesLive();
    final grew = after - baseline;
    expect(after, baseline,
        reason: 'the guarded allocator grew by $grew bytes over $calls calls, so '
            'the open path leaks ${calls == 0 ? 0 : grew ~/ calls} bytes per call');
  });

  test('instrumentation detection narrows the window and changes no answer', () {
    // The shipping reaction to a detected debugger is a cache size, not a refusal and
    // not a different result. That shape is deliberate: the project's first rule is
    // that protection must not change what business code does, and a check that
    // refuses to run - or worse, computes something else - breaks real users the moment
    // it false-positives on a device nobody tested (a misconfigured TracerPid, an
    // emulator, a vendor's monitoring agent, a Frida-looking port).
    //
    // It is also otherwise untestable, because a test host has nothing attached to it,
    // so the verdict is forced through a diagnostics-only hook.
    if (!Vmp.forceInstrumented(true)) {
      markTestSkipped('this runtime does not export the diagnostics force hook');
      return;
    }
    try {
      expect(Vmp.instrumented(), isTrue);
      expect(Vmp.instrumentationReason(), isNotEmpty);

      // 1. The window narrows: one slot instead of four. `code_store_build` sizes the
      //    cache from this flag on every open, so the very next call picks it up.
      final add = Vmp.functions().firstWhere((f) => f.name == 'add');
      expect(Vmp.call(add.id, const <Object?>[20, 22]), 42);
      final r = Vmp.codeResidency();
      expect(r, isNotNull);
      expect(r!.slots, 1,
          reason: 'instrumentation was detected and the decoded-function cache was '
              'still ${r.slots} slots wide, so detection has no effect at all');

      // 2. And nothing else: every protected function still answers exactly as the
      //    reference implementation does, including the ones that call each other -
      //    which is where a narrower cache would show up as a wrong answer rather than
      //    as a cache miss, if `dvmp_code_ensure` did not revalidate the slot.
      expect(Vmp.callNamed('add', const <Object?>[20, 22]), oracle.add(20, 22));
      final key = Vmp.callNamed('makeLicenseKey', const <Object?>['demo-seed', 7]) as String;
      expect(key, oracle.makeLicenseKey('demo-seed', 7));
      expect(Vmp.callNamed('verifyLicense', [key]), oracle.verifyLicense(key));
      expect(Vmp.callNamed('verifyLicense', [key.substring(1)]),
          oracle.verifyLicense(key.substring(1)));
      expect(Vmp.callNamed('selfTest', const <Object?>[]), oracle.selfTest());
      expect(Vmp.callNamed('deviceToken', const <Object?>['pixel-7', 1700000000]),
          oracle.deviceToken('pixel-7', 1700000000));
      expect(Vmp.callNamed('commandChecksum', const <Object?>[
        <Object?>[0x41, 0x50, 0x4B, 0x00, 0xFF, 0x10]
      ]), oracle.commandChecksum(const <int>[0x41, 0x50, 0x4B, 0x00, 0xFF, 0x10]));

      // 3. A module reopened while narrowed is still intact.
      expect(Vmp.callNamed('selfTest', const <Object?>[]), isTrue);
    } finally {
      expect(Vmp.forceInstrumented(false), isTrue);
    }
    expect(Vmp.instrumented(), isFalse);

    // And the window goes back to four once the verdict is cleared. A call first: the
    // cache is sized inside `code_store_build`, which runs on open, so the residency
    // probe reports the value from the last open until another one happens.
    expect(Vmp.callNamed('add', const <Object?>[1, 2]), 3);
    final r2 = Vmp.codeResidency();
    expect(r2!.slots, greaterThan(1),
        reason: 'clearing the verdict did not restore the cache size');
  });

  test('the plaintext window is closed between calls, not just re-encrypted', () {
    // This is the property the whole design rests on and the one an earlier
    // revision only *claimed*: re-sealing rebuilt the container from a copy and
    // wiped the copy, so `m->body` kept the decoded body - string table,
    // constants, descriptors and instruction stream - for the life of the
    // process. A single read of the process found the protected alphabet string
    // and `add`'s decoded opcodes in one page with the module nominally sealed.
    //
    // The runtime now wipes the body when it seals and refuses to serve decoded
    // code while sealed, so the probe returning null after a call is evidence
    // that the window is actually shut. Before the fix this returned the 14
    // opcode bytes of `add`.
    final addId = Vmp.functions().firstWhere((f) => f.name == 'add').id;
    expect(Vmp.callNamed('add', const <Object?>[20, 22]), 42);

    // Three observables, because they fail independently:
    //   * the flag can be right while the buffer is full of plaintext (the bug
    //     the audit found - `unsealed` was 0 and the body was fully decoded);
    //   * the buffer can be wiped while the probe still serves it;
    //   * and the probe's refusal is what a caller would actually notice.
    expect(Vmp.plaintextResident(), isFalse,
        reason: 'the runtime reports the decrypted body as resident after the '
            'call returned');
    expect(Vmp.bodyResidue(), 0,
        reason: 'the body buffer still has non-zero bytes while the module is '
            'sealed, so the decoded module is resident between calls');
    expect(Vmp.decodedCodeProbe(addId), isNull,
        reason: 'decoded bytecode is readable while the module is sealed, so the '
            'plaintext window is the process lifetime rather than the call');
  });

  test('every protected function runs and matches the oracle', () {
    expect(Vmp.callNamed('add', [20, 22]), oracle.add(20, 22));
    expect(Vmp.callNamed('base32Index', ['A']), oracle.base32Index('A'));
    expect(Vmp.callNamed('normalizeKey', ['ab-2345']),
        oracle.normalizeKey('ab-2345'));

    for (var i = 0; i < 20; i++) {
      final key = Vmp.callNamed('makeLicenseKey', ['k$i', i]) as String;
      expect(key, oracle.makeLicenseKey('k$i', i));
      expect(Vmp.callNamed('verifyLicense', [key]), isTrue);
    }
    expect(Vmp.callNamed('checkSum', ['ABC']), oracle.checkSum('ABC'));
    expect(Vmp.callNamed('deviceToken', ['pixel-7', 1700000000]),
        oracle.deviceToken('pixel-7', 1700000000));
    expect(Vmp.callNamed('commandChecksum', [<int>[1, 2, 3]]),
        oracle.commandChecksum(<int>[1, 2, 3]));
    expect(Vmp.callNamed('selfTest', []), isTrue);
  });

  test('the shipped container is encrypted and leak-free', () {
    final ev = Vmp.verifyImage();
    expect(ev.hasMagic, isTrue,
        reason: 'the runtime must hold a DVMP container');
    expect(ev.imageBytes, greaterThan(0));
    expect(ev.leakedProbes, isEmpty,
        reason: 'no protected string may appear in the shipped image');
    expect(ev.clean, isTrue);
  });

  test('the runtime holds guarded native memory and releases it', () {
    // The decrypted working image is a real allocation the runtime tracks; it
    // must be non-zero while loaded, which is the observable half of the
    // "wipe after use" design.
    expect(Vmp.secureBytesLive(), greaterThan(0));
  });

  test('module layout is stable across calls (re-sealing is lossless)', () {
    // Each call re-seals the image under a fresh seed; a round-trip error would
    // show up as a differing result on the second identical call.
    final first = Vmp.callNamed('deviceToken', ['pixel-7', 42]);
    final second = Vmp.callNamed('deviceToken', ['pixel-7', 42]);
    expect(second, first);
    expect(Vmp.callNamed('selfTest', []), isTrue);
  });

  test('the protected sources are not compiled into the app', () {
    // The benchmark card in `main.dart` keeps an AOT copy of `deviceToken` as a
    // comparison baseline, but only in non-release builds: the benchmark path
    // returns early under kReleaseMode before any call site, so the function is
    // tree-shaken out of a shipped snapshot (tool/verify_protection.ps1 checks
    // the real APK for it). Everything else must be free of the algorithm at all
    // times: a protected implementation leaking into another app source would
    // defeat the design outright.
    final lib = Directory('lib');
    final offenders = <String>[];
    for (final f in lib.listSync(recursive: true).whereType<File>()) {
      final path = f.path.replaceAll('\\', '/');
      if (!path.endsWith('.dart')) continue;
      if (path.endsWith('lib/main.dart')) continue;
      final text = f.readAsStringSync();
      if (text.contains('acc ^ (acc << 13)') ||
          text.contains('2654435761') ||
          text.contains('1048576')) {
        offenders.add(path);
      }
    }
    expect(offenders, isEmpty,
        reason: 'protected implementations must not exist under app/lib '
            '(except the documented dev-only benchmark baseline in main.dart)');
  });

  test('the benchmark baseline is dev-only and gated', () {
    // Guards the exception above: the baseline must stay unreachable in release
    // builds, or the app ships a working oracle for a protected function.
    final main = File('lib/main.dart').readAsStringSync();
    expect(main.contains('benchmarkBaselineDeviceToken'), isTrue);
    expect(main.contains('throwaway copy'), isTrue,
        reason: 'the AOT baseline in main.dart must stay clearly documented as '
            'not being the shipped implementation');
    expect(main.contains('if (kReleaseMode)'), isTrue,
        reason: 'the benchmark must bail out before any baseline call site so '
            'the AOT compiler drops the baseline from release builds');
    // No baseline call may appear before the kReleaseMode early return: the
    // gate has to be the first thing the method does.
    final gate = main.indexOf('if (kReleaseMode)');
    final firstCall = main.indexOf('benchmarkBaselineDeviceToken(');
    expect(gate, greaterThan(0));
    expect(firstCall, greaterThan(gate),
        reason: 'every baseline call site must sit after the release gate');
  });

  test('every diagnostics binder is gated before its symbol lookup', () {
    // THE ROOT CAUSE OF A LEAK THAT ACTUALLY SHIPPED, made into a check.
    //
    // Each `_bind*` diagnostics helper returns early under kReleaseMode so the
    // tree-shaker drops the probe's *name* - the symbol string passed to
    // lookupFunction is otherwise dead data in the object pool, where a Blutter dump
    // reads it straight out. The comment above those helpers said "every diagnostics
    // binder below returns early in a release build", and two binders added later did
    // not: `dartvmp_instrumented_probe` and `dartvmp_antidebug_force` shipped in the
    // release snapshot of the demo APK, next to error text naming the mechanism.
    //
    // A comment cannot enforce that, so this walks the file: every static method whose
    // name starts with `_bind` must reach its lookup only after an
    // `if (kReleaseMode) return ...` statement.
    final src = File('../packages/dartvmp/lib/src/bindings.dart').readAsStringSync();
    final binders = RegExp(r'static\s+\w+\??\s+(_bind\w+)\(', multiLine: true)
        .allMatches(src)
        .map((m) => m.group(1)!)
        .toList();
    expect(binders.length, greaterThanOrEqualTo(9),
        reason: 'the diagnostics binders should all be found by this scan');
    final ungated = <String>[];
    for (final name in binders) {
      // The *definition*, not the call site in the constructor: every binder takes the
      // library as its only parameter, which is what distinguishes the two.
      final start = src.indexOf('$name(DynamicLibrary');
      if (start < 0) continue;
      // The whole method body, found by matching braces from the opening one. A fixed
      // window does not work: the first version of this check scanned 400 characters
      // past the signature, which is *shorter than the explanatory comment* on one of
      // the binders, so the gate fell outside the window and a correctly gated binder
      // was reported as a leak. (Which is the same failure mode as the bug this test
      // exists for, one level up: a check whose reach does not cover what it claims.)
      final open = src.indexOf('{', start);
      if (open < 0) continue;
      var depth = 0;
      var end = open;
      for (var i = open; i < src.length; i++) {
        final c = src[i];
        if (c == '{') depth++;
        if (c == '}') {
          depth--;
          if (depth == 0) {
            end = i;
            break;
          }
        }
      }
      final body = src.substring(start, end + 1);
      final gate = body.indexOf('if (kReleaseMode)');
      final lookup = body.indexOf('lookupFunction');
      if (gate < 0 || (lookup >= 0 && gate > lookup)) ungated.add(name);
    }
    expect(ungated, isEmpty,
        reason: 'these diagnostics binders look up their symbol before the '
            'kReleaseMode early return, so the probe name ships in the release '
            'snapshot: ${ungated.join(', ')}');
  });

  test('verifying the image is not part of the shipped app path', () {
    // Vmp.verifyImage copies the whole encrypted container into the Dart heap.
    // That is a diagnostic, not something a user-facing path should do.
    final main = File('lib/main.dart').readAsStringSync();
    final verify = main.indexOf('Vmp.verifyImage(');
    expect(verify, greaterThan(0));
    final gate = main.lastIndexOf('if (!kReleaseMode)', verify);
    expect(gate, greaterThan(0),
        reason: 'the only Vmp.verifyImage() call in the app must be guarded by '
            'a non-release check');
  });

  test('the instruction store is not decryptable from the shipped header', () {
    // The shipped container must carry its own seed (offline distribution), so
    // that seed is public. The runtime's instruction store must NOT be sealed
    // under it: it uses fresh entropy drawn on every open and written into no
    // header. If the two ever match, a memory dump plus the on-disk binary is
    // enough to recover every protected function offline - and no functional test
    // would notice, because every call would still return the right answer.
    //
    // This used to check `m->work`, a decoy second container. That buffer is gone:
    // once `open` began wiping the body's code region, a re-sealed container could
    // only be built from a body with its instruction stream zeroed, so its CRC and
    // tag described something that no longer existed. The check moved to the store,
    // which is the thing that actually holds the streams now.
    final before = Vmp.sessionProbe();
    expect(before.masterSeed, isNot(0));
    expect(before.storeKey, isNot(0),
        reason: 'the store has no key, so it cannot have been encrypted');
    expect(before.storeSalt, isNot(0),
        reason: 'a zero salt is the identity permutation, which would ship the '
            'public opcode numbering inside the store');
    expect(before.storeKey, isNot(before.masterSeed),
        reason: 'the instruction store is sealed under the shipped seed, so a '
            'dump of it can be decrypted with what is on disk');
    expect(before.storeIsNotOfflineDecryptable, isTrue);

    // And it rotates: every call reopens the module under new entropy.
    Vmp.callNamed('deviceToken', ['pixel-7', 1]);
    final after = Vmp.sessionProbe();
    expect(after.masterSeed, before.masterSeed,
        reason: 'the shipped container must never be rewritten');
    expect(after.storeKey, isNot(before.storeKey),
        reason: 'reopening must draw a fresh store key, or a store captured from '
            'one call opens the next call\'s');
  });

  test('protected names resolve through the masked table', () {
    // Entry names ship masked and are un-masked one byte at a time during
    // lookup, so name resolution is the end-to-end check that the mask
    // derivation, the offset table and the comparison all agree. A single wrong
    // mask byte would surface here and nowhere else, because dispatch by id
    // (which the generated stubs use) does not consult the name table at all.
    final names = Vmp.functions().map((f) => f.name).toList();
    expect(names.toSet(), oracle.kOracleFunctions.toSet(),
        reason: 'every protected name must decode out of the masked table');

    // A name that is not in the table must miss rather than match a prefix.
    expect(() => Vmp.callNamed('', const <Object?>[]),
        throwsA(isA<VmpFault>()));
    expect(() => Vmp.callNamed('noSuchFunction', const <Object?>[]),
        throwsA(isA<VmpFault>()));

    // And a name resolves to the *right* function, not merely to something:
    // calling by name has to give the same answer as calling by id.
    final info = Vmp.functions().firstWhere((f) => f.name == 'add');
    expect(info.arity, 2);
    expect(Vmp.callNamed('add', const <Object?>[20, 22]),
        Vmp.call(info.id, const <Object?>[20, 22]));
    // The name is derivable from the id, which is what lets a stub omit it.
    expect(Vmp.nameOf(info.id), 'add');
    expect(Vmp.nameOf(9999), contains('9999'));
  });
}

/// Sample arguments for a protected function, used by the residency test.
///
/// Deliberately allowed to be wrong: the point of that test is to reach the
/// instruction fetch, which happens before any argument is examined, so a bad
/// sample still exercises the loader. Returning a best-effort vector rather than
/// failing keeps the test about residency instead of about argument shapes.
List<Object?> _sampleArgsFor(String name) {
  switch (name) {
    case 'add':
      return const <Object?>[1, 2];
    case 'base32Index':
      return const <Object?>['A'];
    case 'normalizeKey':
    case 'checkSum':
    case 'verifyLicense':
      return const <Object?>['ABCDEFGHJKLMNPQR'];
    case 'deviceToken':
      return const <Object?>['pixel-7', 1700000000];
    case 'commandChecksum':
      return const <Object?>[
        <Object?>[1, 2, 3]
      ];
    case 'makeLicenseKey':
      return const <Object?>['seed', 7];
    default:
      return const <Object?>[];
  }
}

/// Build id the compiler recorded for the module image it generated.
///
/// Read from the manifest rather than from the generated stubs so this file keeps
/// importing only what the tests need. The manifest and the header are written by
/// the same `vmpc build` run, so its id is the header's id.
int _manifestBuildId() {
  final text = File('test/generated/vmp_manifest.json').readAsStringSync();
  final m = RegExp(r'"buildId":\s*"0x([0-9a-fA-F]+)"').firstMatch(text);
  if (m == null) {
    fail('vmp_manifest.json has no buildId; regenerate with '
        '`dart run tool/build.dart`');
  }
  return int.parse(m.group(1)!, radix: 16);
}

/// The call policy declared for [name] in `protected/`, as `(budget, windowMs)`,
/// or null when the function declares none.
///
/// Read out of the manifest instead of restated in the test on purpose. The
/// budget has been retuned twice, and both times a test that had the old number
/// baked in went on passing while asserting nothing about the shipped policy -
/// the guard test `for (var i = 0; i < 40; i++)` could not reach a budget of 64,
/// so "the guard fires" quietly became "the guard was never asked".
(int, int)? _declaredRate(String name) {
  final text = File('test/generated/vmp_manifest.json').readAsStringSync();
  if (!text.contains('"name": "$name"')) {
    fail('vmp_manifest.json has no function "$name"; regenerate with '
        '`dart run tool/build.dart`');
  }
  // Each entry is small and well-formed, so anchoring on the name and scanning
  // forward to the guard key is enough and keeps dart:convert out of this file.
  final at = text.indexOf('"name": "$name"');
  final guard = RegExp(r'"guard":\s*(null|"([^"]*)")')
      .firstMatch(text.substring(at));
  if (guard == null) {
    fail('vmp_manifest.json has no "guard" key for "$name": the manifest was '
        'generated by an older tool/vmpc, so this test cannot see the policy it '
        'is supposed to check. Regenerate with `dart run tool/build.dart`.');
  }
  final spec = guard.group(2);
  if (spec == null || spec.isEmpty) return null;
  final m = RegExp(r'^rate=(\d+)/(\d+)$').firstMatch(spec);
  if (m == null) {
    fail('the manifest declares guard "$spec" for "$name", which this test '
        'cannot interpret; it knows rate=BUDGET/WINDOW_MS');
  }
  return (int.parse(m.group(1)!), int.parse(m.group(2)!));
}

/// Makes `len` bytes at `addr` writable, returning false when the platform refuses.
///
/// The G2 test patches a real instruction, so it needs the code page writable. Windows
/// and POSIX spell that differently, and a platform that forbids it is not a failure of
/// the runtime under test - the test skips with a reason instead, which is why this
/// returns a bool rather than throwing.
bool _makeWritable(int addr, int len) {
  try {
    if (Platform.isWindows) {
      final k32 = DynamicLibrary.open('kernel32.dll');
      final vp = k32.lookupFunction<
          Int32 Function(Pointer<Void>, IntPtr, Uint32, Pointer<Uint32>),
          int Function(Pointer<Void>, int, int, Pointer<Uint32>)>('VirtualProtect');
      final old = calloc<Uint32>();
      try {
        return vp(Pointer<Void>.fromAddress(addr), len, 0x40, old) != 0;
      } finally {
        calloc.free(old);
      }
    }
    final libc = DynamicLibrary.process();
    final mp = libc.lookupFunction<
        Int32 Function(Pointer<Void>, IntPtr, Int32),
        int Function(Pointer<Void>, int, int)>('mprotect');
    final page = addr & ~0xFFF;
    return mp(Pointer<Void>.fromAddress(page), addr - page + len, 7) == 0;
  } catch (_) {
    return false;
  }
}