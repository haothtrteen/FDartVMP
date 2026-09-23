/// Container packing: opcode permutation, stream cipher and auth tag.
///
/// This is the Dart half of the "private instruction set". It MUST stay byte
/// compatible with `packages/dartvmp/src/vmp_module.c`.
library;

import 'dart:math';
import 'dart:typed_data';

import 'opcodes.dart';

/// Stream cipher: SplitMix64 keyed by the module seed.
///
/// Deliberately not AES. The seed is public (it sits in the container header),
/// so no block cipher buys anything here - what matters is that an attacker who
/// dumps the shipped `.so` sees neither the instruction stream nor the string
/// table, and that the keystream is cheap enough to regenerate on every call.
class VmpCipher {
  static const int _g0 = 0x9E3779B97F4A7C15;
  static const int _g1 = 0xBF58476D1CE4E5B9;
  static const int _g2 = 0x94D049BB133111EB;

  int _state;
  VmpCipher(int seed) : _state = _mask64(seed ^ _g0);

  static int _mask64(int v) => v & 0xFFFFFFFFFFFFFFFF;

  /// SplitMix64 next().
  ///
  /// The shifts are `>>>` (logical) on purpose. Dart's `>>` is an *arithmetic*
  /// shift, so on the many iterations where the state is negative it would
  /// sign-extend, while the C runtime shifts a `uint64_t` and fills with zeros.
  /// The two then produce completely different keystreams, and the symptom is
  /// only "body CRC mismatch" three layers away. `>>>` shifts the 64-bit
  /// pattern without regard to sign, which is what SplitMix64 is defined in
  /// terms of.
  int next() {
    _state = _mask64(_state + _g0);
    var z = _state;
    z = _mask64((z ^ (z >>> 30)) * _g1);
    z = _mask64((z ^ (z >>> 27)) * _g2);
    return _mask64(z ^ (z >>> 31));
  }

  /// XORs [data] in place with the keystream starting at byte [offset].
  void apply(Uint8List data, {int offset = 0}) {
    var i = 0;
    while (i < data.length) {
      final word = next();
      for (var b = 0; b < 8 && i < data.length; b++, i++) {
        data[i] = (data[i] ^ ((word >> (8 * b)) & 0xFF)) & 0xFF;
      }
    }
  }
}

/// FNV-1a 64 over a byte range, used for the body CRC and - keyed - for the
/// integrity tag the VM checks before executing anything.
int fnv1a64(List<int> data, [int start = 0, int? end]) {
  var h = 0xCBF29CE484222325;
  final e = end ?? data.length;
  for (var i = start; i < e; i++) {
    h = (h ^ (data[i] & 0xFF)) & 0xFFFFFFFFFFFFFFFF;
    h = (h * 0x100000001B3) & 0xFFFFFFFFFFFFFFFF;
  }
  return h;
}

int crc32(List<int> data, [int start = 0, int? end]) {
  final e = end ?? data.length;
  var crc = 0xFFFFFFFF;
  for (var i = start; i < e; i++) {
    crc ^= data[i] & 0xFF;
    for (var k = 0; k < 8; k++) {
      crc = (crc & 1) != 0 ? (crc >> 1) ^ 0xEDB88320 : crc >> 1;
    }
  }
  return (~crc) & 0xFFFFFFFF;
}

/// Result of packing: the container bytes plus the numbers a reviewer needs to
/// verify the layer independently.
class PackedModule {
  final Uint8List container;
  final int seed;
  final int crc;
  final int authTag;
  final int plaintextBytes;

  const PackedModule(this.container, this.seed, this.crc, this.authTag,
      this.plaintextBytes);

  int get totalBytes => container.length;
}

class Packer {
  /// Applies the opcode permutation in place over a contiguous code region.
  ///
  /// Walks instructions sequentially from the region start: operand widths come
  /// from the *decoded* opcode, so decoding must begin at a valid boundary and any
  /// desynchronisation shows up as an out-of-range opcode rather than as silent
  /// nonsense. The runtime's `unpermute_code` mirrors this walk exactly.
  ///
  /// THE MAPPING IS A KEYED RANDOM PERMUTATION, derived from the container seed. It
  /// used to be `(op * 167 + salt) & 0xFF`, and the reason that was not good enough is
  /// worth recording because it is not obvious from the source: the salt is
  /// `seed & 0xFF`, and the seed is *in the container header*, so an attacker who has
  /// decrypted the container knows the salt. That leaves one unknown byte - the
  /// multiplier - and the multiplier is odd, so there are 128 candidates. Try each,
  /// walk the stream, keep the one whose instruction boundaries land exactly on
  /// `codeLen` with every opcode in range: that is a few minutes of work, which made
  /// virtualizing `unpermute_code` pointless, since the mapping fell out anyway.
  ///
  /// A random permutation of the opcode set has no such parameterisation. Recovering
  /// it means finding an assignment consistent with the whole stream, which is a
  /// constraint search rather than a loop over 128 values. It is not cryptographically
  /// hard - the ISA's operand widths are readable in `dvmp_vm.c`, and the container's
  /// CRC is an oracle the search can test against - so this raises the cost by orders
  /// of magnitude rather than making the mapping secret. See the README on why
  /// virtualizing the interpreter is the lever that actually bounds this.
  static void permuteOpcodes(Uint8List code, int codeOff, int codeLen, int seed) {
    final perm = opcodePermutation(seed);
    var pc = 0;
    while (pc < codeLen) {
      final abs = codeOff + pc;
      final op = code[abs];
      if (op >= kOperandBytes.length) {
        throw StateError('invalid opcode 0x${op.toRadixString(16)} at +$pc');
      }
      code[abs] = perm[op];
      pc += 1 + kOperandBytes[op];
    }
  }

  /// The opcode permutation for [seed]: `perm[op]` is the byte that stands for `op` on
  /// the wire.
  ///
  /// A Fisher-Yates shuffle of 0..255, keeping the first `kOperandBytes.length`
  /// entries. Distinct by construction, which is what makes the inverse a lookup table
  /// rather than a search.
  ///
  /// The shuffle draws one *byte* of SplitMix64 keystream per step rather than a whole
  /// 64-bit word reduced modulo the range. That is not a stylistic choice: Dart's `%`
  /// is Euclidean and returns a non-negative result even when the operand is a
  /// negative-looking 64-bit pattern, while C's `unsigned %` on the same bit pattern
  /// gives a different number. Consuming a byte makes the two implementations
  /// identical by construction instead of by argument. (The same trap as `>>>` vs
  /// `>>` in [VmpCipher.next], and it fails just as far from its cause.)
  ///
  /// Mirrored by `op_tables` in packages/dartvmp/src/dvmp_module.c and by
  /// `opcode_permutation` in tool/walk_bytecode.py. Three implementations have to
  /// agree or the container is not decodable, so `compiler_test.dart` checks this
  /// against the runtime's inverse and `walk_bytecode.py` un-permutes a real
  /// container on every release run.
  static Uint8List opcodePermutation(int seed) {
    final pool = Uint8List(256);
    for (var i = 0; i < 256; i++) {
      pool[i] = i;
    }
    // Domain separator, so the permutation stream is not the body cipher's stream.
    final rng = VmpCipher(seed ^ 0x4F50434F44455031); // "OPCODEP1"
    var word = 0;
    var have = 0;
    int nextByte() {
      if (have == 0) {
        word = rng.next();
        have = 8;
      }
      final b = word & 0xFF;
      word = (word >>> 8) & 0x00FFFFFFFFFFFFFF;
      have--;
      return b;
    }

    final perm = Uint8List(kOperandBytes.length);
    for (var i = 0; i < perm.length; i++) {
      final j = i + nextByte() % (256 - i);
      final t = pool[i];
      pool[i] = pool[j];
      pool[j] = t;
      perm[i] = pool[i];
    }
    return perm;
  }

  /// Inverse of [opcodePermutation]: `inv[wire]` is the opcode, or 0xFF when the byte
  /// is not an opcode in this build.
  static Uint8List opcodeInverse(int seed) {
    final perm = opcodePermutation(seed);
    final inv = Uint8List(256);
    for (var i = 0; i < 256; i++) {
      inv[i] = 0xFF;
    }
    for (var op = 0; op < perm.length; op++) {
      inv[perm[op]] = op;
    }
    return inv;
  }

  /// The affine mapping ① replaced, kept only so the reverse test can prove it is
  /// gone: `tool/recover_opcodes.py` brute-forces this and must fail.
  static int legacyAffineWire(int op, int seed) =>
      (op * 167 + (seed & 0xFF)) & 0xFF;

  /// Packs [body] (the output of `encodeBody`) into a shippable container.
  ///
  /// THE CONTAINER CONTRACT — the runtime's `module_unseal_locked` mirrors this
  /// pipeline step for step, and `tool/vmpc/test/image_contract_test.dart`
  /// pins it:
  ///
  ///     crc       = crc32(body)               integrity of the canonical body
  ///     permuted  = permute(body, seed)       private instruction set
  ///     tag       = fnv1a(permuted || seed')  authenticity of the stored bytes
  ///     stored    = cipher(permuted, seed)    stream cipher
  ///     container = header(seed, crc, ...) || stored || tag
  ///
  /// `crc` covers the CANONICAL body, so the runtime can only satisfy it after
  /// it has decrypted *and* un-permuted the instruction stream — which makes it
  /// an end-to-end check of all three layers.
  ///
  /// `tag` covers the PERMUTED, pre-cipher body, i.e. the bytes that are about
  /// to be written to disk. It is deliberately checked before anything is
  /// decoded, so a patched image is rejected without running a single opcode.
  ///
  /// Getting these two ranges the wrong way round is an easy and expensive
  /// mistake: both values look plausible in the header, and the only symptom is
  /// a mismatch three layers away. See the note in dvmp_wire.h.
  ///
  /// [seed] must be non-null for reproducible builds; pass null to draw a fresh
  /// one from [Random.secure].
  static PackedModule pack(
    Uint8List body, {
    required int codeOff,
    required int codeLen,
    required int entryCount,
    int? seed,
  }) {
    final s = seed ?? _randomSeed();
    final work = Uint8List.fromList(body);

    // Step 1: integrity of the canonical body - which is stored *permuted*, so
    // this CRC only passes at runtime after decrypting **and** un-permuting. That
    // is what makes it an end-to-end check of both layers.
    final crc = crc32(body);

    // Step 2: the private instruction set. Applied here, to the copy that becomes
    // the container, under the seed-derived salt. The body itself keeps the
    // decoded stream because the CRC describes it that way - that asymmetry is what
    // makes the CRC an end-to-end check: it can only pass after decrypting *and*
    // un-permuting.
    if (codeLen <= 0 || codeOff + codeLen > body.length) {
      throw StateError('refusing to pack a body with an empty or '
          'out-of-range instruction stream: codeOff=$codeOff codeLen=$codeLen '
          'bodyLen=${body.length}');
    }
    permuteOpcodes(work, codeOff, codeLen, s);

    // Step 3: authenticity of the stored bytes, over the permuted plaintext.
    final tagSource = Uint8List(work.length + 8);
    tagSource.setRange(0, work.length, work);
    _putU64(tagSource, work.length, s ^ 0x5DEECE66D);
    final tag = fnv1a64(tagSource) ^ (s * 0x100000001B3);

    // Step 4: the cipher.
    VmpCipher(s ^ 0xA5A5A5A5A5A5A5A5).apply(work);

    final out = Uint8List(32 + work.length + 8);
    out[0] = 0x44; // D
    out[1] = 0x56; // V
    out[2] = 0x4D; // M
    out[3] = 0x50; // P
    _putU16(out, 4, 1); // container version
    _putU16(out, 6, 0); // flags
    _putU64(out, 8, s);
    _putU32(out, 16, work.length);
    _putU32(out, 20, crc);
    _putU32(out, 24, entryCount);
    _putU32(out, 28, 0);
    out.setRange(32, 32 + work.length, work);
    _putU64(out, 32 + work.length, tag);
    return PackedModule(out, s, crc, tag, body.length);
  }

  static int _randomSeed() {
    final r = Random.secure();
    var v = 0;
    for (var i = 0; i < 8; i++) {
      v = (v << 8) | r.nextInt(256);
    }
    return v;
  }

  static void _putU16(Uint8List b, int off, int v) {
    b[off] = v & 0xFF;
    b[off + 1] = (v >> 8) & 0xFF;
  }

  static void _putU32(Uint8List b, int off, int v) {
    b[off] = v & 0xFF;
    b[off + 1] = (v >> 8) & 0xFF;
    b[off + 2] = (v >> 16) & 0xFF;
    b[off + 3] = (v >> 24) & 0xFF;
  }

  static void _putU64(Uint8List b, int off, int v) {
    for (var i = 0; i < 8; i++) {
      b[off + i] = (v >> (8 * i)) & 0xFF;
    }
  }
}
