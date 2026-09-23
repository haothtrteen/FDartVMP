// The challenge: recover the flag.
//
// DESIGN, AND WHY THE FLAG IS NOT A PLAIN CONSTANT
// ------------------------------------------------
// `module_seal_locked` wipes the *whole* body buffer between calls, so nothing from the
// container is resident while the app is idle. But it is resident *during* a call - the
// interpreter reads the string table on every `push_s` - so a flag stored as an ordinary
// string constant would fall out of any memory dump taken while the app does anything at
// all. That is a five-minute solve and a bad challenge.
//
// So the flag is stored **rotated**: each character's index in [kFlagCodebook] is shifted
// by a per-position offset derived from the license key. The plaintext flag therefore
// exists in memory only after a *valid* key has been accepted, which makes the two
// intended solves the interesting ones:
//
//   * reconstruct the protected logic (the container, the keyed permutation, the key
//     derivation) and the `revealFlag` rotation - a static solve;
//   * or bypass the check entirely (patch/inline-hook the ABI entry point) - which the
//     project documents as the cheapest attack and which `dvmp_integrity.c` now detects
//     but deliberately does not prevent.
//
// What this is NOT: cryptography. The rotation is obfuscation of the *storage*, and an
// attacker who already has the decrypted container can brute-force the per-position
// offsets. The difficulty of this challenge lives upstream of here - in getting the
// container decrypted and the private instruction set decoded at all.
//
// `guard:rate=8/1000` is the reason the key cannot be brute-forced through this function:
// more than 8 attempts per second and it refuses with TOO_MANY_CALLS instead of answering.
// A refusal is an error, never a wrong answer, so the challenge stays fair.

// Characters the flag is drawn from. Kept separate from [kAlphabet] (the base32 key
// alphabet) so the flag can contain punctuation without shifting the key encoding.
import 'licensing.dart';

const String kFlagCodebook =
    'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789{}_';

// The flag, rotated: character `i` is the flag's character shifted *back* by the offset
// the correct key derives for position `i`. Computed by `tool/challenge_cipher.dart` and
// pinned by `app/test/vmp_challenge_test.dart`, which requires the reveal to return the
// flag for a valid key and an empty string for every other key.
const String kFlagCipher =
    'A4HRMueaBqXmoGO0Bi}opWjDM{}s6oTlDMsBsl1abf';

// @vmp guard:rate=8/1000
String revealFlag(String rawKey) {
  if (!verifyLicense(rawKey)) {
    return '';
  }
  int acc = hash(normalizeKey(rawKey)) % 2147483647;
  // The modulus is the codebook's own length rather than a literal, because a literal is
  // exactly the kind of thing that drifts: the first version of this file used 68 for a
  // 65-character codebook and the failure showed up as a RangeError in the challenge's
  // own derivation tool, not in the app.
  int mod = strLen(kFlagCodebook);
  String out = '';
  for (int i = 0; i < strLen(kFlagCipher); i++) {
    int at = strIndexOf(kFlagCodebook, strAt(kFlagCipher, i));
    if (at < 0) {
      return '';
    }
    int off = (acc + i * 7) % mod;
    out = out + strAt(kFlagCodebook, (at + off) % mod);
  }
  return out;
}

// The challenge's public statement: which key is expected. Kept in the module so the app
// does not have to name it, and so the *seed* has to be recovered too.
//
// @vmp
String challengeSeed() {
  return 'f-dartvmp';
}

// @vmp
int challengeCounter() {
  return 7;
}
