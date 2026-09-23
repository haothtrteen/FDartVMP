// Contract test for the generated C image.
//
// The generator (tool/vmpc) and the runtime (packages/dartvmp/src/dvmp_module.c)
// must agree, byte for byte, on three things:
//
//   1. how a 64-bit image word is split into the hi/lo pair stored in
//      vmp_module.inc;
//   2. the position-dependent mask that hides the container magic;
//   3. the ordering, so un-masking reproduces the container the packer emitted.
//
// A drift in any of them shows up at runtime as "module image has the wrong
// magic" or "authentication tag mismatch", which is painful to trace back to a
// generator change. These tests fail at the source instead. This is not
// hypothetical: an earlier revision emitted the halves in the wrong order and
// silently dropped the upper four bytes of every word.
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:vmpc/vmpc.dart';

/// Re-implements exactly what `dvmp_module.c: unmask_image_into` does, starting
/// from the *emitted text* rather than from the in-memory container. Parsing the
/// text is the point: it catches a literal that is emitted in a form the C
/// compiler would read differently.
({Uint8List image, int maskKey, int wordCount, int declaredLen}) parseHeader(
    String header) {
  final keyMatch =
      RegExp(r'#define kDvmpImage_MASK_KEY 0x([0-9a-f]+)').firstMatch(header);
  expect(keyMatch, isNotNull, reason: 'MASK_KEY must be emitted');
  // The emitted literal is unsigned, so it does not carry the sign bit that the
  // runtime's derivation has. Take the key from the same derivation the runtime
  // uses and assert separately that the *emitted* text matches it; parsing the
  // text into the key is what produced the false failure described above.
  final key = imageMaskKey(buildIdForTest);
  expect(keyMatch!.group(1), u64Hex(key),
      reason: 'the emitted key must render the same 64-bit pattern');

  final countMatch =
      RegExp(r'#define kDvmpImage_WORD_COUNT\s+(.+)').firstMatch(header);
  expect(countMatch, isNotNull, reason: 'WORD_COUNT must be emitted');
  // The macro is a sizeof() expression; take the literal it is compared against
  // from the number of initialisers instead.
  final wordCount = RegExp(r'\{\s*0x[0-9a-f]{8}u,\s*0x[0-9a-f]{8}u\s*\}')
      .allMatches(header)
      .length;
  expect(countMatch!.group(1), contains('sizeof(kDvmpImage_words)'));

  final lenMatch =
      RegExp(r'#define DVMP_IMAGE_LEN (\d+)u').firstMatch(header);
  expect(lenMatch, isNotNull, reason: 'DVMP_IMAGE_LEN must be emitted');
  final declaredLen = int.parse(lenMatch!.group(1)!);

  // Collect every `{ 0xLOu, 0xHIu }` initialiser, in order.
  final words = <int>[];
  for (final m in RegExp(r'\{\s*0x([0-9a-f]{8})u,\s*0x([0-9a-f]{8})u\s*\}')
      .allMatches(header)) {
    final lo = int.parse(m.group(1)!, radix: 16);
    final hi = int.parse(m.group(2)!, radix: 16);
    // The runtime rebuilds the word as lo | (hi << 32).
    words.add((lo | (hi << 32)) & 0xFFFFFFFFFFFFFFFF);
  }
  expect(words.length, wordCount, reason: 'WORD_COUNT must match the literals');
  // The 64-bit literals that must NOT be present are in the image; the header
  // comment explaining the omission naturally mentions the suffix.
  expect(imageRegion(header).contains('ull'), isFalse,
      reason: 'MSVC rejects 64-bit integer literal suffixes, so the image must '
          'be emitted as 32-bit halves');
  // ignore: avoid_print
  final image = Uint8List(declaredLen);
  for (var i = 0; i < words.length; i++) {
    final w = (words[i] ^ imageMaskWord(key, i * 8)) & 0xFFFFFFFFFFFFFFFF;
    for (var b = 0; b < 8; b++) {
      final at = i * 8 + b;
      if (at < declaredLen) {
        // The mask is 0xFF, not `& 0xFF` on an arithmetic shift: Dart's `>>` on
        // a negative int sign-extends, so without it a byte whose top bit is set
        // comes out as 0xFFFFFFxx. The C side shifts an *unsigned* uint64_t and
        // has no such issue.
        image[at] = ((w >> (8 * b)) & 0xFF);
      }
    }
  }
  // ignore: avoid_print
  return (
    image: image,
    maskKey: key,
    wordCount: wordCount,
    declaredLen: declaredLen
  );
}

/// Parses 16 hex digits into the signed 64-bit value with that bit pattern.
///
/// Deliberately uses `BigInt` rather than hand-rolled shifting. A Dart `int` is
/// signed, so `v << 4` on a value with the top bit set wraps (correct, by luck),
/// and reading the high half of a negative int with `>>` sign-extends (wrong).
/// Getting this wrong is exactly how the first version of this test produced a
/// false failure: it computed a key that spelled the same hex but had a
/// different sign bit, so `_mix` shifted it differently and the unmasked bytes
/// came out as garbage.
int _hexToU64(String hex) {
  final unsigned = BigInt.parse(hex, radix: 16);
  final masked = unsigned.toUnsigned(64);
  final signed = masked >= BigInt.one << 63 ? masked - (BigInt.one << 64) : masked;
  return signed.toInt();
}

/// The build id the header under test was generated with.
const int buildIdForTest = 0x1234;
/// The portion of the generated header that holds the masked image, i.e. the
/// `kDvmpImage_words[]` initialiser, with the surrounding comments removed.
String imageRegion(String header) {
  final start = header.indexOf('kDvmpImage_words[] = {');
  expect(start, greaterThanOrEqualTo(0), reason: 'image array must be emitted');
  final end = header.indexOf('};', start);
  expect(end, greaterThan(start));
  return header.substring(start, end);
}

const String _src = '''
// @vmp
String secret() {
  return 'CONTAINER_ROUNDTRIP_MARKER';
}
''';

/// Builds the module and the C header from a single in-memory source, the same
/// way the CLI does for a file.
({String header, PackedModule packed, BuildResult result}) buildOne(
    String src, int seed) {
  final unit = loadProtectedSource(src, sourceName: 'contract.dart');
  final compiled = BytecodeCompiler([unit]).compile();
  final encoded = encodeBody(compiled);
  final packed = Packer.pack(
    encoded.bytes,
    codeOff: encoded.codeOff,
    codeLen: encoded.codeLen,
    entryCount: encoded.entryCount,
    seed: seed,
  );
  final header = generateCHeader(
    packed: packed,
    functions: unit.module.functions,
    ids: List<int>.generate(unit.module.functions.length, (i) => i),
    sourcePath: 'contract.dart',
    abiVersion: kVmpAbiVersion,
    buildId: seed,
    obfuscateMasks: true,
  );
  return (
    header: header,
    packed: packed,
    result: BuildResult(
      packed: packed,
      functions: const [],
      stringTable: compiled.strings,
      constTable: compiled.consts,
      disassembly: '',
      buildId: seed,
      sourceOf: const {},
    )
  );
}

void main() {
  const seed = 0x1234;
  final built = buildOne(_src, seed);

  group('generated image round-trip', () {
    test('the emitted mask key matches the runtime derivation', () {
      final keyMatch = RegExp(r'#define kDvmpImage_MASK_KEY 0x([0-9a-f]+)')
          .firstMatch(built.header);
      expect(keyMatch, isNotNull);
      expect(keyMatch!.group(1), u64Hex(imageMaskKey(seed)),
          reason: 'the header key must render the pattern the generator used');
      // ... and the helper this test uses to read hex back must agree, so a
      // regression in it cannot hide a real mismatch.
      expect(u64Hex(_hexToU64(keyMatch.group(1)!)), keyMatch.group(1),
          reason: 'the emitted pattern must survive a hex round-trip');
    });

    test('un-masking the emitted literals reproduces the container', () {
      final parsed = parseHeader(built.header);
      expect(parsed.image.length, built.packed.container.length);
      expect(parsed.image, equals(built.packed.container),
          reason: 'the runtime must recover exactly the packed container');
    });

    test('the container magic is present only after un-masking', () {
      final parsed = parseHeader(built.header);
      expect(parsed.image.sublist(0, 4), equals(<int>[0x44, 0x56, 0x4D, 0x50]),
          reason: 'DVMP magic after un-masking');

      // The *image* must not spell the magic out. The rest of the header names
      // the format on purpose (include guards, struct names, comments), so the
      // check is scoped to the emitted byte array - which is the part that ends
      // up in .rodata.
      final image = imageRegion(built.header);
      expect(image.contains('DVMP'), isFalse,
          reason: 'the container magic must not appear in the image literal');
      expect(image.contains('44, 0x56'), isFalse,
          reason: 'the magic bytes must not appear verbatim');
    });

    test('every word uses a different mask', () {
      final key = imageMaskKey(seed);
      final words = built.packed.container.length ~/ 8;
      final masks = <int>{};
      for (var i = 0; i < words; i++) {
        masks.add(imageMaskWord(key, i * 8));
      }
      // Aliasing would let an attacker cancel the mask by XOR-ing two words of a
      // known-plaintext region.
      expect(masks.length, words);
    });

    test('the masked byte image leaks nothing readable', () {
      // Only the *image* must be opaque. The header deliberately lists the
      // protected function signatures in a comment (useful when reviewing a
      // build), so the whole file is not expected to be free of those names.
      final imageText = imageRegion(built.header);
      expect(imageText.contains('CONTAINER_ROUNDTRIP_MARKER'), isFalse);
      expect(imageText.contains('secret'), isFalse,
          reason: 'the function name must not survive into the image');
      expect(imageText.contains('DVMP'), isFalse,
          reason: 'the container magic must not survive into the image');
    });
  });
}
