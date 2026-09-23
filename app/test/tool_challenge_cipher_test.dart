// Derives [kFlagCipher] for `protected/challenge.dart`.
//
// The rotation is defined by the *protected* code (`revealFlag`), so the cipher has to be
// computed with the same implementations the VM uses - `makeLicenseKey`, `normalizeKey`
// and `hash`. Rather than reimplement them here and hope, this imports the generated
// oracle and `vm_builtins` shim, which the differential suite pins against the runtime.
//
// Run from `app/` with the runtime available:
//
//     flutter test test/tool_challenge_cipher_test.dart
//
// It prints the cipher; paste it into `kFlagCipher` and re-run `dart run tool/build.dart`.
// It also asserts the round trip, so a wrong paste fails here rather than in the challenge.
import 'package:flutter_test/flutter_test.dart';

import 'generated/challenge.dart' as c;
import 'generated/keys.dart' as k;
import 'generated/licensing.dart' as l;
import 'generated/vm_builtins.dart' as b;

// The flag the challenge is about. Kept here rather than in the module: after the cipher
// is derived, this file's only purpose is the round-trip assertion.
const String kFlag = 'FDartVMP{th3_l0g1c_w4s_n3v3r_1n_l1b4pp_s0}';

String rotate(String flag, String key, {required bool toCipher}) {
  const codebook = c.kFlagCodebook;
  final acc = b.hash(l.normalizeKey(key)) % 2147483647;
  final mod = codebook.length;
  final out = StringBuffer();
  for (var i = 0; i < flag.length; i++) {
    final at = codebook.indexOf(flag[i]);
    expect(at, greaterThanOrEqualTo(0),
        reason: 'the flag may only use characters from kFlagCodebook');
    final off = (acc + i * 7) % mod;
    final idx = toCipher ? (at - off) % mod : (at + off) % mod;
    out.write(codebook[idx]);
  }
  return out.toString();
}

void main() {
  test('derive and verify kFlagCipher', () {
    final seed = c.challengeSeed();
    final counter = c.challengeCounter();
    final key = k.makeLicenseKey(seed, counter);
    // ignore: avoid_print
    print('seed=$seed counter=$counter');
    // ignore: avoid_print
    print('key=$key');
    // ignore: avoid_print
    print('verifyLicense(key)=${l.verifyLicense(key)}');
    // ignore: avoid_print
    print('hash(normalizeKey(key)) % 2147483647 = '
        '${b.hash(l.normalizeKey(key)) % 2147483647}');
    // ignore: avoid_print
    print('flag length=${kFlag.length}');

    final cipher = rotate(kFlag, key, toCipher: true);
    // ignore: avoid_print
    print('CIPHER=$cipher');

    expect(rotate(cipher, key, toCipher: false), kFlag,
        reason: 'the stored cipher must rotate back to the flag for the right key');
    expect(cipher.length, kFlag.length);
    expect(cipher.contains('FDartVMP'), isFalse,
        reason: 'the stored form must not contain the flag prefix');
    expect(cipher.contains('l0g1c'), isFalse,
        reason: 'the stored form must not contain a distinctive flag substring');
  });
}
