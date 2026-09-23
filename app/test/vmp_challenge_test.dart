// The challenge's own tests: the intended solve, the anti-brute-force policy, and the
// runtime's view of that policy.
//
// WHY THESE GO THROUGH THE STUBS. The first version of this file called the *generated
// oracle* - the pure-Dart reference implementation - and so tested the algorithm while
// proving nothing about the protection: 4200 calls "with no refusal", and a flag returned
// for a key that was not the right one, were both symptoms of talking to Dart rather than
// to the VM. The stubs are what the application calls and what the container actually
// executes, so they are what the challenge's claims have to be asserted against.
// `protected_oracle.dart` stays as the reference to diff against, which is its job.
import 'dart:ffi';
import 'dart:io';

import 'package:ffi/ffi.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:dartvmp/dartvmp.dart';
import 'package:dartvmp_demo/generated/protected_stubs.dart' as p;

import 'generated/protected_oracle.dart' as oracle;

const String kExpectedFlag = 'FDartVMP{th3_l0g1c_w4s_n3v3r_1n_l1b4pp_s0}';

void main() {
  setUpAll(() {
    Vmp.initialize();
  });

  test('the intended solve works, through the runtime that ships', () {
    // The seed and counter are protected too, so a solver who has not recovered them has
    // not solved the challenge either.
    final seed = p.challengeSeed();
    final counter = p.challengeCounter();
    expect(seed, 'f-dartvmp');
    expect(counter, 7);

    final key = p.makeLicenseKey(seed, counter);
    expect(p.verifyLicense(key), isTrue,
        reason: 'the runtime must accept the key a solver derives, or the challenge has '
            'no intended solution');

    final flag = p.revealFlag(key);
    expect(flag, kExpectedFlag,
        reason: 'the intended solve must produce the flag on the shipped runtime');
    expect(flag, oracle.revealFlag(key),
        reason: 'the VM and the Dart reference must agree on the flag');
  });

  test('a wrong key yields nothing, through the runtime', () {
    final key = p.makeLicenseKey(p.challengeSeed(), p.challengeCounter());
    // Genuinely wrong keys. The distinction between "wrong" and "checksum-valid but
    // different" matters and is worth stating: `verifyLicense` is a 5-bit check digit, so
    // roughly one in 32 random keys is *accepted* - but the flag's rotation is derived from
    // the key itself, so an accepted wrong key produces nonsense, never the flag.
    final wrong = <String>[
      '',
      key.substring(0, key.length - 1) + (key.endsWith('G') ? 'H' : 'G'),
      'AAAAAAAAAAAAAAAA',
      'f-dartvmp',
    ];
    for (final w in wrong) {
      final got = p.revealFlag(w);
      expect(got, isNot(kExpectedFlag),
          reason: 'a wrong key must never produce the flag (tried "$w")');
      expect(got.contains('FDartVMP'), isFalse,
          reason: 'a wrong key must not produce the flag prefix (tried "$w")');
    }
  });

  test('the declared policy refuses a burst instead of answering it', () {
    // `revealFlag` is declared `guard:rate=8/1000`. Without it the exported entry point is
    // a free oracle for the key; with it, the ninth call inside a second is an error the
    // caller can see. A refusal must be an error and never a wrong answer, or the challenge
    // would be unfair rather than hard.
    final key = p.makeLicenseKey(p.challengeSeed(), p.challengeCounter());
    expect(Vmp.resetCallPolicies(), isTrue);
    for (var i = 0; i < 8; i++) {
      expect(p.revealFlag(key), kExpectedFlag,
          reason: 'call $i is inside the declared budget of 8');
    }
    var refusals = 0;
    for (var i = 0; i < 8 && refusals == 0; i++) {
      try {
        p.revealFlag(key);
      } on VmpFault catch (e) {
        expect(e.status, VmpStatus.tooManyCalls,
            reason: 'the ninth call must be refused by the policy, not by something else');
        refusals++;
      }
    }
    expect(refusals, greaterThan(0),
        reason: 'the declared rate policy must refuse past its budget, or the challenge '
            'can be brute-forced through the public API. This assertion is what would have '
            'caught the guard silently not firing - and the first version of this file, '
            'which called the Dart oracle instead of the runtime, could not catch it, '
            'because the oracle has no policy at all.');
    Vmp.resetCallPolicies();
  });

  test('the runtime holds the policy the container declares', () {
    // THE CHECK THAT FOUND A REAL BUG. Three views of a call policy exist - the source
    // declaration, the bytes in the shipped container, and what the running runtime holds -
    // and they can disagree while everything still *reads* correctly: a declared policy that
    // never fires is invisible from any of the artifacts. This compares the third view
    // against the other two, for every function in the module.
    final libPath = Platform.environment['DARTVMP_LIBRARY_PATH'];
    if (libPath == null || !File(libPath).existsSync()) {
      fail('DARTVMP_LIBRARY_PATH must point at the runtime; see tool/test.ps1');
    }
    final probe = DynamicLibrary.open(libPath).lookupFunction<
        Uint32 Function(Uint32, Pointer<Uint32>, Pointer<Uint32>, Pointer<Uint32>,
            Pointer<Uint32>, Pointer<Uint64>),
        int Function(int, Pointer<Uint32>, Pointer<Uint32>, Pointer<Uint32>,
            Pointer<Uint32>, Pointer<Uint64>)>('dartvmp_guard_probe');

    final mode = calloc<Uint32>();
    final budget = calloc<Uint32>();
    final window = calloc<Uint32>();
    final used = calloc<Uint32>();
    final start = calloc<Uint64>();
    try {
      final manifest = File('test/generated/vmp_manifest.json').readAsStringSync();
      var compared = 0;
      for (final f in Vmp.functions()) {
        expect(probe(f.id, mode, budget, window, used, start), 0,
            reason: 'the probe must answer for every function in the module');
        final declared = _guardOf(manifest, f.name);
        if (declared.startsWith('rate=')) {
          final (b, w) = _rateOf(manifest, f.name);
          expect(mode.value, 1,
              reason: 'the runtime must hold a RATE policy for ${f.name}: the declaration '
                  'reached the container but not the enforcement');
          expect(budget.value, b, reason: 'budget for ${f.name}');
          expect(window.value, w, reason: 'window for ${f.name}');
          compared++;
        } else {
          expect(mode.value, 0,
              reason: '${f.name} declares no policy; the runtime must not invent one');
        }
      }
      expect(compared, greaterThanOrEqualTo(2),
          reason: 'the module declares at least two rate policies; if this drops, the '
              'comparison stopped covering them');
    } finally {
      calloc.free(mode);
      calloc.free(budget);
      calloc.free(window);
      calloc.free(used);
      calloc.free(start);
    }
  });

  test('neither the flag nor its stored form is in the app', () {
    for (final path in <String>['lib/main.dart', 'lib/generated/protected_stubs.dart']) {
      final text = File(path).readAsStringSync();
      expect(text.contains('FDartVMP{'), isFalse, reason: '$path contains the flag');
      expect(text.contains('A4HRMueaBqXmoGO0Bi'), isFalse,
          reason: '$path contains the stored cipher');
    }
  });
}

String _guardOf(String manifest, String name) {
  final at = manifest.indexOf('"name": "$name"');
  if (at < 0) return '';
  final m = RegExp(r'"guard":\s*(null|"([^"]*)")').firstMatch(manifest.substring(at));
  return m?.group(2) ?? '';
}

(int, int) _rateOf(String manifest, String name) {
  final m = RegExp(r'^rate=(\d+)/(\d+)$').firstMatch(_guardOf(manifest, name));
  if (m == null) fail('guard for $name is not a rate policy this test understands');
  return (int.parse(m.group(1)!), int.parse(m.group(2)!));
}
