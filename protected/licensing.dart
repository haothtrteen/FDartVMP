// DartVMP protected source - NOT part of the application.
//
// Nothing under `protected/` is imported by `app/`. That is what keeps these
// bodies out of the AOT snapshot: the compiler turns each `// @vmp` function
// into bytecode for the private instruction set, and the application only ever
// links against the generated stubs.
//
// Language subset (enforced by tool/vmpc, see lib/src/lang_limits in the README)
//   * int, String, bool, List, Map, dynamic
//   * if / else, while, for (C-style and for-in), break, continue, return
//   * + - * / % ~ & | ^ << >> , comparisons, ?:, && ||
//   * calls to other @vmp functions in the same module
//   * builtins: strLen, strAt, strCode, strSub, strIndexOf, strContains,
//     strToUpper, strToLower, strParseInt, intToStr, hash, listLen, listAt,
//     mapGet, abort
//
// Not supported on purpose: closures, classes, generics, async/await,
// generators, string interpolation, `List[i] = v`, globals, imports.
// `dart run vmpc build` reports any construct it cannot lower, with a line
// number, instead of silently dropping the body.

// The string below is a canary: it must never appear in the shipped binary.
// Add it to Vmp.markedProbes in packages/dartvmp/lib/dartvmp.dart and the
// protection test will fail the build if it ever leaks.
const String kAlphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';

// @vmp
int add(int a, int b) {
  return a + b;
}

// @vmp
int base32Index(String ch) {
  return strIndexOf(kAlphabet, ch);
}

// @vmp
String normalizeKey(String raw) {
  String out = '';
  for (int i = 0; i < strLen(raw); i++) {
    String c = strAt(raw, i);
    if (strContains(kAlphabet, strToUpper(c))) {
      out = out + strToUpper(c);
    }
  }
  return out;
}

// @vmp
int checkSum(String normalized) {
  int acc = 0;
  for (int i = 0; i < strLen(normalized); i++) {
    int v = base32Index(strAt(normalized, i));
    // Position-weighted polynomial hash. `+ 1` keeps a missing character
    // (base32Index returns -1) from cancelling out.
    acc = (acc * 33 + v + 1) % 1048576;
  }
  // Finaliser. Without this the hash is affine over GF(2) - the multiply and
  // add are both linear, so a change in one character can be cancelled by a
  // change in another and a large fraction of single-character edits collide.
  // The shifts and xors break that structure, which is what makes the check
  // digit below actually detect corruption.
  int mixed = acc ^ 3735928559;
  mixed = (mixed ^ (mixed << 13)) % 1048576;
  mixed = (mixed ^ (mixed >> 7)) % 1048576;
  mixed = (mixed * 2654435761) % 1048576;
  mixed = mixed ^ (mixed << 17);
  if (mixed < 0) {
    mixed = -mixed;
  }
  return mixed % 1048576;
}

// @vmp guard:rate=4096/1000
// ^ Call policy, enforced by the runtime, not by the caller.
//
// `verifyLicense` answers a yes/no question about a guess, which makes it useful
// to an attacker purely as a validator: call it in a loop and watch. No amount of
// interpreter hardening changes that - answering is the function's job. What the
// runtime can do is refuse beyond a budget, and it refuses with a distinct status
// rather than a wrong answer, so the application never sees a protection-induced
// behaviour change.
//
// CALIBRATION - the numbers are the whole policy, so here is where they come from.
// A protected call re-seals the module, so the measured ceiling is around 200k
// calls/second on desktop: unguarded, the shipped library is a ~200k-guess/second
// validator that costs an attacker nothing to use. 4096 calls per second is 2% of
// that - a 49x throttle - while sitting far above anything the application itself
// does: a human entering a key tops out near 5 attempts/second, and an activation
// screen validating a batch of 1000 keys in one burst still fits inside a window.
//
// The budget has been raised twice for the same reason, and the reason is worth
// recording. The first policy was 8/1024 and the second 64/2048; both were chosen
// against the *oracle* and both turned out to be below the rate this repository's
// own differential suite reaches, so both made a legitimate caller fail. That is
// the one outcome a protection layer is not allowed to produce here (see the
// first rule in the README: a VMP must not change what business code does), and a
// policy that has to be switched off to run the tests is a policy that will be
// switched off in production. The throttle is worth having only while it is
// invisible to correct callers, so it is now sized from the highest legitimate
// rate rather than from the lowest attack rate, and
// `app/test/vmp_e2e_test.dart` fails if the declared budget drops back under a
// documented legitimate burst.
//
// This cannot stop someone who patches the guard out; they own the process. It
// stops the *cheap* attack - using the shipped library as a fast oracle needs no
// reversing, and this makes it need some. See README "What protects what".
bool verifyLicense(String rawKey) {
  String key = normalizeKey(rawKey);

  if (strLen(key) != 16) {
    return false;
  }

  String groups = strSub(key, 0, 15);
  String encoded = strAt(key, 15);
  int expected = base32Index(encoded);

  if (expected < 0) {
    return false;
  }

  // The check digit is derived from the other fifteen characters, so a key
  // cannot be guessed one character at a time.
  return checkSum(groups) % 32 == expected;
}

// @vmp
int deviceToken(String deviceId, int timestamp) {
  // A 64-bit FNV offset basis is deliberately out of range for Dart's signed
  // int, so the constant is written as its two's-complement equivalent. The
  // VM's arithmetic wraps on 64 bits, matching this expression exactly.
  int acc = hash(deviceId) ^ -3750763034362895579;
  int rounds = 512;
  for (int i = 0; i < rounds; i++) {
    acc = acc ^ (acc << 13);
    acc = acc ^ (acc >> 7);
    acc = acc ^ (acc << 17);
    acc = acc + timestamp;
  }
  return acc;
}

// @vmp
int commandChecksum(List command) {
  int acc = 2166136261;
  for (int i = 0; i < listLen(command); i++) {
    acc = acc ^ listAt(command, i);
    acc = acc * 16777619;
  }
  return acc;
}
