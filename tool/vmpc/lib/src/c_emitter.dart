/// C header emitter: turns the packed container into `vmp_module.inc`.
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' show sha256;

import 'ast.dart';
import 'packer.dart';

/// Writes the generated include file the native runtime compiles against.
///
/// The image sits in `.rodata`, so the *encrypted* form is what a static
/// analysis of `libdartvmp.so` finds. Decryption happens into a guarded heap
/// allocation at init time and the image is re-encrypted after every call.
String generateCHeader({
  required PackedModule packed,
  required List<FuncDecl> functions,
  required List<int> ids,
  required String sourcePath,
  required int abiVersion,
  required int buildId,
  required bool obfuscateMasks,
}) {
  final sb = StringBuffer();
  sb.writeln('/*');
  sb.writeln(' * vmp_module.inc - GENERATED FILE, DO NOT EDIT.');
  sb.writeln(' *');
  sb.writeln(' * Source     : $sourcePath');
  sb.writeln(' * Build id   : 0x${buildId.toRadixString(16).padLeft(8, '0')}');
  sb.writeln(' * ABI        : $abiVersion');
  sb.writeln(' * Plaintext  : ${packed.plaintextBytes} bytes (body)');
  sb.writeln(' * Container  : ${packed.totalBytes} bytes');
  sb.writeln(' * Seed       : 0x${u64Hex(packed.seed)}');
  sb.writeln(' * Body CRC32 : 0x${packed.crc.toRadixString(16).padLeft(8, '0')}');
  sb.writeln(' * Entries    : ${functions.length}');
  sb.writeln(' *');
  // The per-function listing that used to live here - name, parameter types and
  // return type for each protected function - has been removed. It was the same
  // protection-surface map that `kDvmpEntries[]` leaked, just written as a
  // comment: a reviewer reading the generated header learned exactly which
  // functions are protected and roughly what shape they have. Generated files
  // get copied around, attached to bug reports and committed by accident, so
  // "it is only a comment" is not a reason to keep it. `vmpc build` prints the
  // listing to the console and the manifest records it under app/test/, neither
  // of which is compiled into a shipped artifact.
  sb.writeln(' *');
  sb.writeln(' * The byte image below is opcode-permuted and stream-ciphered. It is');
  sb.writeln(' * NEVER executed in place; see vmp_module.c.');
  sb.writeln(' */');
  sb.writeln();
  sb.writeln('#ifndef DVMP_GENERATED_MODULE_INC_');
  sb.writeln('#define DVMP_GENERATED_MODULE_INC_');
  sb.writeln();
  sb.writeln('#define DVMP_BUILD_ID 0x${buildId.toRadixString(16).padLeft(8, '0')}u');
  sb.writeln('#define DVMP_GENERATED_ABI ${abiVersion}u');
  sb.writeln();
  sb.writeln('/*');
  sb.writeln(' * One masked 64-bit image word, kept as two 32-bit halves so the');
  sb.writeln(' * literal stays inside the C89/C99 32-bit integer constant range.');
  sb.writeln(' * MSVC rejects 0x...ull literals, and this file has to compile with');
  sb.writeln(' * cl.exe as well as clang.');
  sb.writeln(' */');
  sb.writeln('typedef struct DvmpImageWord {');
  sb.writeln('  uint32_t lo;');
  sb.writeln('  uint32_t hi;');
  sb.writeln('} DvmpImageWord;');
  sb.writeln();

  _array(sb, 'kDvmpImage', packed.container,
      masks: obfuscateMasks, buildId: buildId);
  sb.writeln();
  sb.writeln('#define DVMP_IMAGE_LEN ${packed.container.length}u');
  // `_Static_assert` (C11), not `static_assert`: the latter is only a keyword
  // from C23 onward, and clang - which the Android NDK uses - compiles this
  // header with `-std=gnu11`, where `static_assert` is not declared. MSVC
  // accepts `_Static_assert` in C mode too, so this spelling is portable.
  sb.writeln('_Static_assert(DVMP_IMAGE_LEN >= DVMP_HEADER_SIZE + DVMP_TAG_SIZE,');
  sb.writeln('               "generated module image is truncated");');
  sb.writeln();

  // Function metadata mirrors the module body so the runtime can resolve
  // `dartvmp_call_named` and expose a function table without parsing. Only the
  // id and arity live here; the *names* are a separate, masked table - see
  // _namesTable below.
  sb.writeln('static const DvmpEntryMeta kDvmpEntries[] = {');
  for (var i = 0; i < functions.length; i++) {
    sb.writeln('  { ${ids[i]}u, ${functions[i].arity}u },');
  }
  sb.writeln('};');
  sb.writeln('#define DVMP_ENTRY_COUNT '
      '((uint32_t)(sizeof(kDvmpEntries) / sizeof(kDvmpEntries[0])))');
  sb.writeln();

  // The names are NOT stored as string literals. Written that way they sat in
  // `.rodata` as a greppable list of what the protection covers - a map that
  // tells an attacker which of the ~2500 functions in libapp.so is worth
  // attacking, and hints at the algorithm family ("verifyLicense" implies a
  // comparison, "checkSum" a hash). Instead each name is masked under a
  // build-derived keystream and the runtime un-masks **one byte at a time
  // while comparing**, so a full name never exists as a contiguous plaintext
  // buffer that a dump could catch. That is the "ciphertext resident, decrypt
  // on demand" pattern applied to the metadata rather than the code.
  _namesTable(sb, functions, ids, buildId);
  sb.writeln();
  sb.writeln('#endif /* DVMP_GENERATED_MODULE_INC_ */');
  return sb.toString();
}

/// Per-build key for the entry-name table. Independent of the image mask key so
/// recovering one does not give up the other.
int entryNameMaskKey(int buildId) =>
    (buildId ^ 0x1D2E3F4A5B6C7D8E) & 0xFFFFFFFFFFFFFFFF;

/// Position-dependent mask byte for the entry-name table.
///
/// Reuses the SplitMix64 step from [imageMaskWord], so there is one mixing
/// primitive to keep in sync rather than two. `>>>` is deliberate: see the note
/// on [imageMaskWord].
int entryNameMaskByte(int key, int position) {
  final w = imageMaskWord(key, position & ~7);
  return (w >>> (8 * (position & 7))) & 0xFF;
}

void _namesTable(
    StringBuffer sb, List<FuncDecl> functions, List<int> ids, int buildId) {
  final key = entryNameMaskKey(buildId);
  final offsets = <int>[];
  final bytes = <int>[];
  var maxLen = 1;
  for (final f in functions) {
    offsets.add(bytes.length);
    bytes.add(f.name.length);
    for (final c in f.name.codeUnits) {
      bytes.add(c & 0xFF);
    }
    if (f.name.length + 1 > maxLen) maxLen = f.name.length + 1;
  }
  final masked = <int>[
    for (var i = 0; i < bytes.length; i++)
      ((bytes[i] ^ entryNameMaskByte(key, i)) & 0xFF)
  ];

  sb.writeln('/*');
  sb.writeln(' * Entry names, masked. Each entry is a u8 length followed by the');
  sb.writeln(' * name bytes, all XORed with a keystream derived from');
  sb.writeln(' * DVMP_NAMES_MASK_KEY. The runtime never materialises a whole name:');
  sb.writeln(' * dvmp_module_name_copy() un-masks straight into the caller\'s buffer');
  sb.writeln(' * (or compares byte by byte for lookups). Hard-coding the names here');
  sb.writeln(' * as literals would publish the protection surface in .rodata.');
  sb.writeln(' */');
  sb.writeln('#define DVMP_NAMES_MASK_KEY 0x${u64Hex(key)}');
  sb.writeln('static const uint8_t kDvmpNameOffsets[] = {');
  _hexRows(
      sb, Uint8List.fromList([for (final o in offsets) o & 0xFF]), 16, '  ');
  sb.writeln('};');
  sb.writeln('static const uint8_t kDvmpNameBlob[] = {');
  _hexRows(sb, Uint8List.fromList(masked), 16, '  ');
  sb.writeln('};');
  sb.writeln('#define DVMP_NAME_BLOB_LEN '
      '((uint32_t)(sizeof(kDvmpNameBlob) / sizeof(kDvmpNameBlob[0])))');
  sb.writeln('#define DVMP_OFFSET_TABLE_LEN '
      '((uint32_t)(sizeof(kDvmpNameOffsets) / '
      'sizeof(kDvmpNameOffsets[0])))');
  sb.writeln('/* Longest name plus its NUL, for fixed-size caller buffers. */');
  sb.writeln('#define DVMP_MAX_NAME_LEN ${maxLen}u');
  sb.writeln('_Static_assert(DVMP_OFFSET_TABLE_LEN == DVMP_ENTRY_COUNT,');
  sb.writeln('               "entry name table does not match the entry count");');
}

/// Emits the image as an array of masked 64-bit words, split into hi/lo 32-bit
/// halves.
///
/// When [masks] is true each word is XOR-obfuscated against a position- and
/// build-dependent mask, which defeats naive `strings`/`binwalk` sweeps for the
/// container magic and makes the on-disk representation differ from the
/// in-memory one. The runtime un-masks into the secure buffer, so the cost is a
/// few microseconds at init.
///
/// The literal is deliberately emitted as two `uint32_t` fields rather than one
/// `0x...ull` constant: 64-bit integer literals are a GCC/Clang extension and
/// MSVC rejects them outright, which would break the Windows desktop build.
void _array(StringBuffer sb, String name, Uint8List data,
    {required bool masks, required int buildId}) {
  final maskKey = imageMaskKey(buildId);
  if (!masks) {
    sb.writeln('static const uint8_t $name[] = {');
    _hexRows(sb, data, 12, '  ');
    sb.writeln('};');
    return;
  }
  // Pad to a multiple of 8 so the mask is well defined.
  final padded = Uint8List((data.length + 7) & ~7);
  padded.setRange(0, data.length, data);
  final words = <int>[];
  for (var i = 0; i < padded.length; i += 8) {
    var w = 0;
    for (var b = 0; b < 8; b++) {
      w |= padded[i + b] << (8 * b);
    }
    words.add((w ^ (imageMaskWord(maskKey, i) & 0xFFFFFFFFFFFFFFFF)) &
        0xFFFFFFFFFFFFFFFF);
  }
  sb.writeln('/* Image stored as ${words.length} masked words. The mask is');
  sb.writeln(' * derived from DVMP_IMAGE_MASK_KEY and the word position, so the');
  sb.writeln(' * container magic is not greppable in this file. */');
  sb.writeln('static const DvmpImageWord ${name}_words[] = {');
  for (var i = 0; i < words.length; i += 2) {
    final end = (i + 2 <= words.length) ? i + 2 : words.length;
    final row = <String>[];
    for (var j = i; j < end; j++) {
      // Little-endian halves: `lo` holds image bytes 0..3 and `hi` holds 4..7,
      // so the runtime can rebuild the word with `lo | (hi << 32)` without
      // caring about host endianness. Emitting them the other way round would
      // silently drop the upper half of every word.
      final lo = words[j] & 0xFFFFFFFF;
      final hi = (words[j] >> 32) & 0xFFFFFFFF;
      row.add('{ 0x${lo.toRadixString(16).padLeft(8, '0')}u, '
          '0x${hi.toRadixString(16).padLeft(8, '0')}u }');
    }
    sb.writeln('  ${row.join(', ')},');
  }
  sb.writeln('};');
  sb.writeln('#define ${name}_MASKED 1u');
  // No integer suffix: MSVC rejects the `ull`/`ui64` spellings that GCC and
  // Clang accept. A hexadecimal constant that needs more than 32 bits is
  // promoted to a 64-bit type by every compiler we target, and the value is
  // always consumed through a (uint64_t) cast, so the exact type is irrelevant.
  sb.writeln('#define ${name}_MASK_KEY 0x${u64Hex(maskKey)}');
  sb.writeln('#define ${name}_WORD_COUNT '
      '((uint32_t)(sizeof(${name}_words) / sizeof(${name}_words[0])))');
}

/// The position-dependent mask applied to image word [index] under [key].
///
/// Uses `>>>` (logical shift) rather than `>>` (arithmetic). This is not
/// cosmetic: `z` is a 64-bit pattern that is frequently negative, and Dart's
/// `>>` sign-extends, while the C runtime shifts a `uint64_t` and therefore
/// fills with zeros. The two agree on the first three steps - as the reference
/// tables in tool/hostlib/mask_probe.c and tool/vmpc/bin/mixref.dart show - and
/// diverge only at the last `z ^ (z >>> 31)`, which is precisely the kind of
/// mismatch that surfaces as "module image has the wrong magic" with no clue
/// where to look. `>>>` exists for exactly this: it shifts the 64-bit pattern
/// without regard to sign.
///
/// Keystream word for the static image and the entry-name table.
///
/// `SHA256(le64(key) || le64(index))[0..8)`, read back little-endian. Mirrors
/// `dvmp_mask_keystream` in packages/dartvmp/src/dvmp_sha256.c, and the two are
/// diffed by `image_contract_test.dart` through the runtime's mask probe.
///
/// This replaced `SplitMix64-finalise(key + index + G0)`, which was a *bijection in
/// the key*: the container's first eight bytes are known plaintext (the magic plus a
/// version), so `recover_from_shipped.py` recovered the key from the release APK by
/// XORing and inverting - and because the old construction was a stream, the key then
/// yielded every other word. A truncated hash fixes both halves: one known word
/// reveals neither the key nor any other word.
///
/// Public so the contract test can un-mask a generated header and diff it against the
/// container the packer produced, and so the Python tools can mirror it with
/// `hashlib.sha256`.
int imageMaskWord(int key, int index) {
  final input = Uint8List(16);
  for (var i = 0; i < 8; i++) {
    input[i] = (key >>> (8 * i)) & 0xFF;
    input[8 + i] = (index >>> (8 * i)) & 0xFF;
  }
  final digest = sha256.convert(input).bytes;
  var v = 0;
  for (var i = 7; i >= 0; i--) {
    v = ((v << 8) | digest[i]) & _m64;
  }
  return v;
}

const int _m64 = 0xFFFFFFFFFFFFFFFF;

/// The mask key derived from a build id.
int imageMaskKey(int buildId) =>
    (buildId ^ 0x8F3A17C95E2B4D61) & 0xFFFFFFFFFFFFFFFF;

/// Formats a 64-bit pattern as a 16-digit unsigned hex literal suitable for C.
///
/// This is far more delicate than it looks, because a Dart `int` is *signed*:
///
///   * `v.toRadixString(16)` on a negative value emits `-70c5e836...`, which is
///     not a valid C literal;
///   * `v & 0xFFFFFFFFFFFFFFFF` does not help, because bitwise AND preserves the
///     sign, so the result is still negative;
///   * `(v >> 32) & 0xFFFFFFFF` is wrong too - Dart's `>>` is an *arithmetic*
///     shift, so the sign bits fill in and the high half comes out as
///     `0xFFFFxxxx`, silently corrupting the top 16 bits of the literal.
///
/// `BigInt` has real arbitrary-precision semantics, so `toUnsigned(64)` gives
/// the bit pattern directly with no shift or sign subtleties to get wrong. This
/// value ends up in a `#define` that the C runtime XORs into every image word,
/// so a single wrong bit means the module fails to authenticate - worth being
/// unambiguous about.
String u64Hex(int v) =>
    BigInt.from(v).toUnsigned(64).toRadixString(16).padLeft(16, '0');

void _hexRows(StringBuffer sb, Uint8List data, int perRow, String indent) {
  for (var i = 0; i < data.length; i += perRow) {
    final end = (i + perRow < data.length) ? i + perRow : data.length;
    final row = <String>[];
    for (var j = i; j < end; j++) {
      row.add('0x${data[j].toRadixString(16).padLeft(2, '0')}');
    }
    sb.writeln('$indent${row.join(', ')},');
  }
}

/// Emits a human-readable manifest, useful for CI assertions such as
/// "the shipped app must not contain the literal `_kLicenseSeed`".
String generateManifest({
  required PackedModule packed,
  required List<FuncDecl> functions,
  required List<int> ids,
  required String sourcePath,
  required int buildId,
  required List<String> protectedStringTable,
  Map<String, String> guards = const <String, String>{},
}) {
  return const JsonEncoder.withIndent('  ').convert({
    'buildId': '0x${buildId.toRadixString(16).padLeft(8, '0')}',
    'source': sourcePath,
    'container': {
      'bytes': packed.totalBytes,
      'plaintextBodyBytes': packed.plaintextBytes,
      'seed': '0x${u64Hex(packed.seed)}',
      'bodyCrc32': '0x${packed.crc.toRadixString(16).padLeft(8, '0')}',
      'authTag': '0x${u64Hex(packed.authTag)}',
    },
    'functions': [
      for (var i = 0; i < functions.length; i++)
        {
          'id': ids[i],
          'name': functions[i].name,
          'arity': functions[i].arity,
          'returnType': functions[i].returnType.dartName,
          // The declared call policy, verbatim, or null when the function has
          // none. It is in the manifest so the tests can read the budget instead
          // of restating it: a hardcoded copy in a test silently stops testing
          // anything the moment the policy is retuned, which is exactly what
          // happened when the budget went from 8 to 64.
          'guard': guards[functions[i].name],
          'params': [
            for (final p in functions[i].params)
              {'name': p.name, 'type': p.type.dartName}
          ],
        }
    ],
    'stringTable': protectedStringTable,
  });
}
