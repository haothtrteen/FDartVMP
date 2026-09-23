/// Wire-format codec shared with the native runtime.
///
/// MUST stay byte compatible with `packages/dartvmp/src/dvmp_wire.h`. The
/// encoding is deliberately minimal - a one-byte tag plus a payload - so that a
/// captured FFI buffer reveals nothing beyond the shape of the call.
///
///     0x00 nil
///     0x01 bool     u8
///     0x02 int      i64 little-endian
///     0x03 string   u32 byte length, then UTF-8
///     0x04 list     u32 count, then `count` values
///     0x05 map      u32 count, then `count` (key, value) pairs
library;

import 'dart:convert';
import 'dart:typed_data';

/// Type tags, mirroring `DvmpTag` in dvmp_wire.h.
class WireTag {
  static const int nil = 0x00;
  static const int bool_ = 0x01;
  static const int int_ = 0x02;
  static const int string = 0x03;
  static const int list = 0x04;
  static const int map = 0x05;
}

/// The largest integer the private VM can represent: its slots are 64-bit
/// two's-complement, same as Dart's `int` on the VM but not on the web.
const int kMaxInt64 = 0x7FFFFFFFFFFFFFFF;
const int kMinInt64 = -0x8000000000000000;

/// Largest string the native side will accept, mirroring DARTVMP_MAX_STRING.
const int kMaxStringBytes = 1 << 20;

/// Nesting limit enforced by the reader/writer on both sides.
const int kMaxWireDepth = 16;

class VmpWireError implements Exception {
  final String message;
  VmpWireError(this.message);
  @override
  String toString() => 'VmpWireError: $message';
}

/// Incremental encoder. Reused across calls to avoid reallocating a builder for
/// every protected invocation.
class WireWriter {
  final BytesBuilder _b = BytesBuilder(copy: false);

  void reset() => _b.clear();

  Uint8List takeBytes() => _b.takeBytes();

  int get length => _b.length;

  void u8(int v) => _b.addByte(v & 0xFF);

  void u32(int v) {
    _b.add(<int>[v & 0xFF, (v >> 8) & 0xFF, (v >> 16) & 0xFF, (v >> 24) & 0xFF]);
  }

  void i64(int v) {
    final out = Uint8List(8);
    var x = v;
    for (var i = 0; i < 8; i++) {
      out[i] = x & 0xFF;
      // Arithmetic shift keeps the sign bit for negative values.
      x >>= 8;
    }
    _b.add(out);
  }

  /// Encodes a single Dart value. Throws [VmpWireError] for anything the VM
  /// cannot represent, rather than coercing it - a silent `toString()` here
  /// would turn a type bug into a security bug.
  void value(Object? v, [int depth = 0]) {
    if (depth > kMaxWireDepth) {
      throw VmpWireError('value nested deeper than $kMaxWireDepth levels');
    }
    if (v == null) {
      u8(WireTag.nil);
      return;
    }
    if (v is bool) {
      u8(WireTag.bool_);
      u8(v ? 1 : 0);
      return;
    }
    if (v is int) {
      if (v > kMaxInt64 || v < kMinInt64) {
        throw VmpWireError(
            'integer $v does not fit in the VM\'s signed 64-bit slot');
      }
      u8(WireTag.int_);
      i64(v);
      return;
    }
    if (v is String) {
      final bytes = utf8.encode(v);
      if (bytes.length > kMaxStringBytes) {
        throw VmpWireError(
            'string of ${bytes.length} bytes exceeds the $kMaxStringBytes '
            'byte limit');
      }
      u8(WireTag.string);
      u32(bytes.length);
      _b.add(bytes);
      return;
    }
    if (v is List) {
      u8(WireTag.list);
      u32(v.length);
      for (final e in v) {
        value(e, depth + 1);
      }
      return;
    }
    if (v is Map) {
      u8(WireTag.map);
      u32(v.length);
      for (final e in v.entries) {
        value(e.key, depth + 1);
        value(e.value, depth + 1);
      }
      return;
    }
    throw VmpWireError(
        // "across the VMP boundary" was one of the nine strings a Blutter dump read
        // out of the release snapshot: it names the mechanism, in an exception message
        // an attacker gets for free. The message still has to tell a caller what to
        // do, so it names the *allowed types*, not the boundary's initials.
        'cannot pass a ${v.runtimeType} to a protected function; use int, '
        'String, bool, List, Map or null');
  }
}

/// Incremental decoder over a byte buffer produced by the native side.
class WireReader {
  final Uint8List _d;
  int _p = 0;

  WireReader(this._d);

  bool get atEnd => _p >= _d.length;

  int _byte() {
    if (_p >= _d.length) throw VmpWireError('truncated value');
    return _d[_p++];
  }

  int _u32() {
    if (_p + 4 > _d.length) throw VmpWireError('truncated length prefix');
    final v = _d[_p] | (_d[_p + 1] << 8) | (_d[_p + 2] << 16) | (_d[_p + 3] << 24);
    _p += 4;
    return v;
  }

  int _i64() {
    if (_p + 8 > _d.length) throw VmpWireError('truncated integer');
    var v = 0;
    for (var i = 7; i >= 0; i--) {
      // `<<` then `|` on a signed 64-bit int performs the two's-complement
      // interpretation for free: once the high bit is set the accumulator is
      // already negative, which is exactly the value the native side encoded.
      v = (v << 8) | _d[_p + i];
    }
    _p += 8;
    return v;
  }

  Object? value([int depth = 0]) {
    if (depth > kMaxWireDepth) {
      throw VmpWireError('value nested deeper than $kMaxWireDepth levels');
    }
    final tag = _byte();
    switch (tag) {
      case WireTag.nil:
        return null;
      case WireTag.bool_:
        return _byte() != 0;
      case WireTag.int_:
        return _i64();
      case WireTag.string:
        final n = _u32();
        if (_p + n > _d.length) throw VmpWireError('truncated string payload');
        final s = utf8.decode(_d.sublist(_p, _p + n), allowMalformed: true);
        _p += n;
        return s;
      case WireTag.list:
        final n = _u32();
        final out = List<Object?>.generate(n, (_) => value(depth + 1));
        return out;
      case WireTag.map:
        final n = _u32();
        final out = <Object?, Object?>{};
        for (var i = 0; i < n; i++) {
          final k = value(depth + 1);
          final v = value(depth + 1);
          out[k] = v;
        }
        return out;
      default:
        throw VmpWireError('unknown value tag 0x${tag.toRadixString(16)}');
    }
  }
}
