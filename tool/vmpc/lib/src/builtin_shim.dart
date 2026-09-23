/// Pure-Dart mirror of the private VM's host builtin table.
///
/// The [builtinShimSource] string below is emitted by the compiler next to the
/// test oracle so the original protected functions can be executed as ordinary
/// Dart - the ground truth the interpreter is diffed against.
///
/// It is a specification, not an implementation detail: if the native table in
/// `packages/dartvmp/src/dvmp_host.c` and this shim ever disagree, the
/// differential test fails, which is exactly what should happen.
library;

/// The shim, as source text.
const String builtinShimSource = r'''
/// Pure-Dart mirror of the private VM's host builtin table (GENERATED).
///
/// WHY THIS EXISTS
/// ---------------
/// The restricted subset that `vmpc` compiles is *almost* ordinary Dart: the
/// only thing missing is the builtin set (`strLen`, `strAt`, `hash`, ...),
/// which normally lives in the native runtime. Emitting this shim lets the test
/// suite run the original implementations as real Dart, and diff them against
/// the interpreter.
///
/// SEMANTIC CONTRACT
/// -----------------
///   * Strings are indexed by *byte*, not by UTF-16 code unit. Protected code is
///     expected to work on ASCII; multi-byte UTF-8 passes through strSub/strAt
///     unchanged rather than being decoded, and strLen/hash see UTF-8 bytes.
///   * `+` on two ints wraps at 64 bits (two's complement), matching both the
///     interpreter's slot arithmetic and Dart's own VM behaviour.
///   * `strParseInt` is `int.tryParse(s) ?? 0` and clamps on overflow instead of
///     wrapping.
///
/// NOTE: this file is only ever written under `test/`. Shipping it inside an
/// application would put the protected logic back into the AOT snapshot, which
/// is the one thing the whole design exists to prevent.
library;

import 'dart:convert';
import 'dart:typed_data';

/// Upper bound mirrored from DARTVMP_MAX_STRING.
const int kMaxStringBytes = 1 << 20;

String _bytesToString(Uint8List b) => utf8.decode(b, allowMalformed: true);

Uint8List _stringToBytes(String s) => Uint8List.fromList(utf8.encode(s));

/// Byte length, matching the native `strLen`.
int strLen(String s) => _stringToBytes(s).length;

/// Byte at [i] as a one-character string.
String strAt(String s, int i) {
  final b = _stringToBytes(s);
  if (i < 0 || i >= b.length) {
    throw RangeError.index(i, b, 'index', null, b.length);
  }
  return String.fromCharCode(b[i]);
}

/// Byte value at [i].
int strCode(String s, int i) {
  final b = _stringToBytes(s);
  if (i < 0 || i >= b.length) {
    throw RangeError.index(i, b, 'index', null, b.length);
  }
  return b[i];
}

/// Byte substring starting at [start] with byte length [len], clamped.
String strSub(String s, int start, int len) {
  final b = _stringToBytes(s);
  if (start < 0 || len < 0 || start > b.length) {
    throw RangeError('strSub($start, $len) out of range for ${b.length} bytes');
  }
  var n = len;
  if (start + n > b.length) n = b.length - start;
  return _bytesToString(Uint8List.sublistView(b, start, start + n));
}

/// Byte offset of [needle] in [s], or -1.
int strIndexOf(String s, String needle) {
  final h = _stringToBytes(s);
  final n = _stringToBytes(needle);
  if (n.isEmpty) return 0;
  outer:
  for (var i = 0; i + n.length <= h.length; i++) {
    for (var j = 0; j < n.length; j++) {
      if (h[i + j] != n[j]) continue outer;
    }
    return i;
  }
  return -1;
}

bool strContains(String s, String needle) => strIndexOf(s, needle) >= 0;

/// ASCII-only case conversion: bytes >= 0x80 are left untouched so a multi-byte
/// sequence is never corrupted into invalid UTF-8.
String strToUpper(String s) {
  final b = _stringToBytes(s);
  for (var i = 0; i < b.length; i++) {
    if (b[i] >= 0x61 && b[i] <= 0x7A) b[i] -= 32;
  }
  return _bytesToString(b);
}

String strToLower(String s) {
  final b = _stringToBytes(s);
  for (var i = 0; i < b.length; i++) {
    if (b[i] >= 0x41 && b[i] <= 0x5A) b[i] += 32;
  }
  return _bytesToString(b);
}

/// `int.tryParse(s) ?? 0`, clamping on overflow to match the native side.
int strParseInt(String s) {
  var i = 0;
  var neg = false;
  if (s.isNotEmpty && (s[0] == '-' || s[0] == '+')) {
    neg = s[0] == '-';
    i = 1;
  }
  if (i >= s.length) return 0;
  var acc = 0;
  for (; i < s.length; i++) {
    final c = s.codeUnitAt(i);
    if (c < 0x30 || c > 0x39) return 0;
    final d = c - 0x30;
    if (acc > (0x7FFFFFFFFFFFFFFF - d) ~/ 10) {
      return neg ? -0x8000000000000000 : 0x7FFFFFFFFFFFFFFF;
    }
    acc = acc * 10 + d;
  }
  return neg ? -acc : acc;
}

String intToStr(int v) => '$v';

/// FNV-1a 64 over the UTF-8 bytes, as a signed 64-bit value.
///
/// Dart's `int` is a signed 64-bit two's-complement value whose arithmetic
/// wraps, so the multiply needs no explicit masking - which is also true of the
/// interpreter's wrap_mul.
// ignore: non_constant_identifier_names
int hash(String s) {
  var h = 0xCBF29CE484222325;
  for (final b in _stringToBytes(s)) {
    h = h ^ b;
    h = h * 0x100000001B3;
  }
  return h;
}

int listLen(List l) => l.length;

/// Returns `dynamic` rather than `Object?`, matching the fact that the
/// interpreter's slots are dynamically typed: the protected source may apply an
/// int operator to the result without a cast, and the VM only checks the tag at
/// run time.
dynamic listAt(List l, int i) {
  if (i < 0 || i >= l.length) {
    throw RangeError.index(i, l, 'index', null, l.length);
  }
  return l[i];
}

dynamic mapGet(Map m, Object? k) {
  if (!m.containsKey(k)) {
    throw StateError('map key not present');
  }
  return m[k];
}

/// Raises a fault, like the VM's `abort` builtin.
Never abort(String message) => throw StateError('bytecode abort: $message');
''';
