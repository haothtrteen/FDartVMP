// Second protected source file.
//
// Exists to prove two things the single-file demo cannot:
//   1. function ids are stable across files, in `sources` order;
//   2. a protected function may call another one, including across files,
//      because the whole module is compiled into one flat namespace.

import 'licensing.dart';

// @vmp
String makeLicenseKey(String seed, int counter) {
  String body = '';
  int acc = hash(seed) ^ counter;

  for (int i = 0; i < 15; i++) {
    acc = acc ^ (acc << 13);
    acc = acc ^ (acc >> 7);
    acc = acc ^ (acc << 17);
    int idx = (acc >> 3) % 32;
    if (idx < 0) {
      idx = -idx;
    }
    body = body + strAt(kAlphabet, idx);
  }

  int check = checkSum(body) % 32;
  return body + strAt(kAlphabet, check);
}

// @vmp
bool selfTest() {
  // Cheap invariant that must hold for the shipped module: if the bytecode
  // was patched so that add() no longer adds, this returns false.
  if (add(20, 22) != 42) {
    return false;
  }
  if (strLen(makeLicenseKey('seed', 1)) != 16) {
    return false;
  }
  return verifyLicense(makeLicenseKey('seed', 1));
}
