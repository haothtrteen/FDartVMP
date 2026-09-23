// Differential test: every protected function must produce byte-identical
// results to the original Dart implementation, for a range of inputs.
//
// The oracle (`generated/protected_oracle.dart`) is written by the compiler from
// the same source the bytecode came from, so a mismatch here means the compiler
// or the interpreter is wrong - not that the test data drifted.
//
// The native groups need the runtime as a loadable library, which desktop builds
// do not produce by default (Flutter links plugin code into the runner). Deploy
// it and point DARTVMP_LIBRARY_PATH at it:
//
//     powershell -File tool/build_native.ps1
//     cd app
//     $env:DARTVMP_LIBRARY_PATH = "$PWD/build/native/dartvmp.dll"
//     flutter test
//
// Without that the native groups report "skipped" rather than passing vacuously,
// so a CI run cannot mistake "the runtime was missing" for "the runtime agreed".
import 'package:dartvmp/dartvmp.dart' as vmp;
import 'package:flutter_test/flutter_test.dart';

import 'generated/protected_oracle.dart' as oracle;

/// True when the native runtime can actually be loaded in this process.
///
/// `flutter test` builds a standalone test host rather than the app runner, so on
/// desktop the statically linked runtime is simply not there and this returns
/// false. The native groups below then report themselves as *skipped* rather
/// than passing vacuously.
///
/// To run them, deploy the runtime and point [vmp.kLibraryPathEnvVar] at it:
///
///     powershell -File tool/build_native.ps1
///     cd app
///     $env:DARTVMP_LIBRARY_PATH = "$PWD/build/native/dartvmp.dll"
///     flutter test
bool nativeRuntimeIsAvailable() {
  try {
    vmp.openRuntimeLibrary();
    return true;
  } catch (_) {
    return false;
  }
}

void main() {
  final haveNative = nativeRuntimeIsAvailable();

  group('oracle self-consistency (pure Dart, no native runtime)', () {
    test('add', () {
      expect(oracle.add(20, 22), 42);
      expect(oracle.add(-5, 5), 0);
    });

    test('normalizeKey keeps only alphabet characters, upper-cased', () {
      expect(oracle.normalizeKey('abcd-2345 efgh'), 'ABCD2345EFGH');
      expect(oracle.normalizeKey('iii!'), ''); // I is not in the alphabet
    });

    test('makeLicenseKey produces a self-verifying 16-character key', () {
      for (var i = 0; i < 40; i++) {
        final key = oracle.makeLicenseKey('seed-$i', i);
        expect(key.length, 16, reason: 'key length for counter $i');
        expect(oracle.verifyLicense(key), isTrue,
            reason: 'freshly generated key $key must verify');
      }
    });

    test('a wrong key is rejected at the rate the check digit allows', () {
      final key = oracle.makeLicenseKey('demo', 1);
      expect(oracle.verifyLicense(key), isTrue);

      // The check digit is five bits, so it detects about 31/32 of errors - it
      // cannot reject every mutation, and pretending otherwise would be a
      // stronger claim than the scheme supports. What the test *can* pin down is
      // that the checksum is not affine: a linear hash would let a change in one
      // character be cancelled by a change in another, and the rejection rate
      // would collapse.
      const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
      var rejected = 0;
      var accepted = 0;
      for (var i = 0; i < 15; i++) {
        for (final c in alphabet.split('')) {
          if (c == key[i]) continue;
          final mutated = key.substring(0, i) + c + key.substring(i + 1);
          if (oracle.verifyLicense(mutated)) {
            accepted++;
          } else {
            rejected++;
          }
        }
      }
      final total = rejected + accepted;
      expect(total, 15 * 31);
      expect(rejected / total, greaterThan(0.90),
          reason: 'a 5-bit check digit should reject >90% of single-character '
              'edits; a much lower rate means the hash is degenerate');
    });

    test('the check digit is a pure function of the payload', () {
      final key = oracle.makeLicenseKey('demo', 1);
      final payload = key.substring(0, 15);
      // Swapping the check digit for a different alphabet character must
      // invalidate the key, since only one digit can satisfy the checksum.
      final digit = key[15];
      final alt = digit == 'A' ? 'B' : 'A';
      expect(oracle.verifyLicense('$payload$alt'), isFalse);
    });

    test('verifyLicense rejects malformed input', () {
      expect(oracle.verifyLicense(''), isFalse);
      expect(oracle.verifyLicense('AAAA'), isFalse);
      expect(oracle.verifyLicense('!!!!!!!!!!!!!!!!'), isFalse);
    });

    test('commandChecksum is FNV-1a over the list', () {
      expect(oracle.commandChecksum(<int>[]), 2166136261);
      final a = oracle.commandChecksum(<int>[1, 2, 3]);
      final b = oracle.commandChecksum(<int>[1, 2, 4]);
      expect(a, isNot(b));
    });

    test('selfTest exercises the whole module', () {
      expect(oracle.selfTest(), isTrue);
    });
  });

  group('private VM matches Dart AOT', () {
    // setUpAll cannot be conditional in package:test, so the native calls are
    // guarded inside each test.
    test('runtime loads and reports its function table', () {
      if (!haveNative) {
        markTestSkipped('native runtime not loadable in this test host');
        return;
      }
      vmp.Vmp.initialize();
      final fns = vmp.Vmp.functions();
      expect(fns.map((f) => f.name).toSet(), oracle.kOracleFunctions.toSet());
      for (final f in fns) {
        final decl = oracle.kOracleFunctions.contains(f.name);
        expect(decl, isTrue, reason: '${f.name} must be a declared oracle fn');
      }
    });

    test('add matches for a large input sweep', () {
      if (!haveNative) {
        markTestSkipped('no native runtime');
        return;
      }
      for (final (a, b) in const <(int, int)>[
        (0, 0),
        (1, 2),
        (-1, 1),
        (2147483647, 1),
        (-2147483648, -1),
        (1 << 40, 1 << 20),
        (-(1 << 52), 12345),
      ]) {
        expect(vmp.Vmp.callNamed('add', [a, b]), oracle.add(a, b),
            reason: 'add($a, $b)');
      }
    });

    test('makeLicenseKey and verifyLicense match', () {
      if (!haveNative) {
        markTestSkipped('no native runtime');
        return;
      }
      // This loop is a differential fuzz harness, not an application flow: it
      // deliberately drives `verifyLicense` as hard as it can, which is precisely
      // the pattern the shipped call policy exists to refuse. The policy is a
      // statement about how often the *application* may ask, so a harness that
      // asks faster than any application is expected to clear the counter first
      // rather than to weaken the policy.
      //
      // Clearing it here also keeps the two files independent: the module is a
      // process-wide singleton, so without this the e2e file's burst test and
      // this loop would share one budget across isolates and turn each other into
      // flakes.
      expect(vmp.Vmp.resetCallPolicies(), isTrue,
          reason: 'a harness that outruns the declared policy has to be able to '
              'say so; if the reset is missing, this test measures the guard '
              'instead of the interpreter');
      for (var i = 0; i < 60; i++) {
        final seed = 'seed-$i-\u00e9';
        final got = vmp.Vmp.callNamed('makeLicenseKey', [seed, i]) as String;
        final want = oracle.makeLicenseKey(seed, i);
        expect(got, want, reason: 'makeLicenseKey("$seed", $i)');
        expect(vmp.Vmp.callNamed('verifyLicense', [got]),
            oracle.verifyLicense(want));
      }
      expect(vmp.Vmp.resetCallPolicies(), isTrue);
    });

    test('verifyLicense matches on adversarial keys', () {
      if (!haveNative) {
        markTestSkipped('no native runtime');
        return;
      }
      expect(vmp.Vmp.resetCallPolicies(), isTrue);
      for (final k in const [
        '',
        'A',
        'AAAAAAAAAAAAAAAA',
        'ABCDEFGHJKLMNPQR',
        'abcd efgh jklm np',
        '!!!!!!!!!!!!!!!!',
        'ZZZZZZZZZZZZZZZZ',
        '0000000000000000',
      ]) {
        expect(vmp.Vmp.callNamed('verifyLicense', [k]),
            oracle.verifyLicense(k),
            reason: 'verifyLicense("$k")');
      }
      expect(vmp.Vmp.resetCallPolicies(), isTrue);
    });

    test('normalizeKey matches', () {
      if (!haveNative) {
        markTestSkipped('no native runtime');
        return;
      }
      for (final s in const [
        '',
        'abc',
        'ABC-2345',
        'iiii',
        'a b c 2 3 4',
        'lowercase-uppercase-2345',
      ]) {
        expect(vmp.Vmp.callNamed('normalizeKey', [s]), oracle.normalizeKey(s),
            reason: 'normalizeKey("$s")');
      }
    });

    test('deviceToken matches, including 64-bit wraparound', () {
      if (!haveNative) {
        markTestSkipped('no native runtime');
        return;
      }
      for (final id in <String>['', 'a', 'pixel-7', 'x' * 200]) {
        for (final ts in const [0, 1, -1, 1700000000, 1 << 40]) {
          expect(vmp.Vmp.callNamed('deviceToken', [id, ts]),
              oracle.deviceToken(id, ts),
              reason: 'deviceToken("$id", $ts)');
        }
      }
    });

    test('commandChecksum matches for lists of every size', () {
      if (!haveNative) {
        markTestSkipped('no native runtime');
        return;
      }
      for (var n = 0; n <= 40; n++) {
        final data = List<int>.generate(n, (i) => (i * 37) & 0xFF);
        expect(vmp.Vmp.callNamed('commandChecksum', [data]),
            oracle.commandChecksum(data),
            reason: 'commandChecksum of $n bytes');
      }
    });

    test('selfTest passes inside the VM', () {
      if (!haveNative) {
        markTestSkipped('no native runtime');
        return;
      }
      expect(vmp.Vmp.callNamed('selfTest', []), isTrue,
          reason: 'the module must not have been patched');
    });
  });
}
