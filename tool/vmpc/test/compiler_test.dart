import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:vmpc/vmpc.dart';

const String _addSrc = '''
// @vmp
int add(int a, int b) {
  return a + b;
}
''';

/// Compiles a single anonymous source string the way the CLI would: inject
/// markers, parse, fold consts, then build the module in one file unit.
CompiledModule compileSrc(String src) {
  final unit = loadProtectedSource(src, sourceName: 't.dart');
  return BytecodeCompiler([unit]).compile();
}

/// Packs a compiled module the way the CLI would.
PackedModule packSrc(String src, {int? seed}) {
  final compiled = compileSrc(src);
  final enc = encodeBody(compiled);
  return Packer.pack(enc.bytes,
      codeOff: enc.codeOff,
      codeLen: enc.codeLen,
      entryCount: enc.entryCount,
      seed: seed ?? 1);
}

void main() {
  group('lexer', () {
    test('tokenizes integers in all supported radices', () {
      final toks = Lexer('0x1F 0b101 42').tokenize();
      expect(toks[0].intValue, 31);
      expect(toks[1].intValue, 5);
      expect(toks[2].intValue, 42);
    });

    test('rejects string interpolation loudly', () {
      expect(() => Lexer(r"'a$x'").tokenize(), throwsA(isA<LexError>()));
      expect(() => Lexer(r"'a${x}'").tokenize(), throwsA(isA<LexError>()));
    });
  });

  group('marker injection', () {
    test('turns a // @vmp comment into an annotation, preserving line count',
        () {
      const src = '// header\n\n// @vmp\nint f() {\n  return 1;\n}\n';
      final out = injectMarkers(src, sourceName: 't.dart');
      expect(out.split('\n').length, src.split('\n').length);
      expect(out.split('\n')[2], '@vmp');
    });

    test('rejects a marker nested inside a body', () {
      const src = 'int f() {\n  // @vmp\n  return 1;\n}\n';
      expect(() => injectMarkers(src, sourceName: 't.dart'),
          throwsA(isA<StateError>()));
    });
  });

  group('parser', () {
    test('parses a protected function', () {
      final m = Parser.fromSource(
              injectMarkers(_addSrc, sourceName: 't.dart'),
              sourceName: 't.dart')
          .parseModule();
      expect(m.functions, hasLength(1));
      expect(m.functions.single.name, 'add');
      expect(m.functions.single.arity, 2);
    });

    test('reports unmarked functions instead of silently ignoring them', () {
      const src = '''
// @vmp
int a() {
  return 1;
}

int b() {
  return 2;
}
''';
      final m = Parser.fromSource(injectMarkers(src, sourceName: 't.dart'),
              sourceName: 't.dart')
          .parseModule();
      expect(m.functions.map((f) => f.name), ['a']);
      expect(m.unmarked.map((f) => f.name), ['b']);
    });

    test('parses const and import declarations', () {
      const src = '''
import 'other.dart' as other;

const String kAlphabet = 'AB';

// @vmp
int f() {
  return 1;
}
''';
      final m = Parser.fromSource(injectMarkers(src, sourceName: 't.dart'),
              sourceName: 't.dart')
          .parseModule();
      expect(m.imports.single.uri, 'other.dart');
      expect(m.imports.single.prefix, 'other');
      expect(m.consts.single.name, 'kAlphabet');
    });

    test('rejects generics with an actionable message', () {
      const src = '// @vmp\nList<int> f() {\n  return [];\n}\n';
      expect(
          () => Parser.fromSource(injectMarkers(src, sourceName: 't.dart'),
                  sourceName: 't.dart')
              .parseModule(),
          throwsA(isA<ParseError>()
              .having((e) => e.message, 'message', contains('generic'))));
    });

    test('rejects member access with a pointer to the builtins', () {
      const src = "// @vmp\nint f(String s) {\n  return s.length;\n}\n";
      expect(
          () => Parser.fromSource(injectMarkers(src, sourceName: 't.dart'),
                  sourceName: 't.dart')
              .parseModule(),
          throwsA(isA<ParseError>()), reason: 'member access must not parse');
    });

    test('rejects string interpolation', () {
      const src = "// @vmp\nString f(int a) {\n  return 'v=\$a';\n}\n";
      expect(
          () => Parser.fromSource(injectMarkers(src, sourceName: 't.dart'),
                  sourceName: 't.dart')
              .parseModule(),
          throwsA(isA<LexError>()));
    });
  });

  group('emitter', () {
    test('compiles add() to store/store/load/load/add/ret', () {
      final c = compileSrc(_addSrc);
      expect(c.functions, hasLength(1));
      final code = c.functions.single.code;
      final op = (int i) => code[i];
      final imm = (int i) => code[i] | (code[i + 1] << 8);
      // The prologue stores parameters in REVERSE order: each `store` pops the
      // eval stack and a call site leaves the last argument on top, so the last
      // `store` must fill parameter 0. Emitting them in declaration order
      // silently mirrored every parameter list.
      //   store slot=1 / store slot=0 / load a / load b / add / ret
      expect(op(0), Op.store);
      expect(imm(1), 1);
      expect(op(3), Op.store);
      expect(imm(4), 0);
      expect(op(6), Op.load);
      expect(imm(7), 0);
      expect(op(9), Op.load);
      expect(imm(10), 1);
      expect(op(12), Op.add);
      expect(op(13), Op.ret);
      expect(code.length, 14);
      expect(c.functions.single.locals, 2);
      // The window is `arity + locals` wide, and the interpreter adopts it
      // verbatim (it is not derived from the call depth).
      expect(c.functions.single.globalSlot, 0);
    });

    test('folds integer constants', () {
      const src = '// @vmp\nint f() {\n  return 2 * 21;\n}\n';
      final c = compileSrc(src);
      expect(c.functions.single.code[0], Op.pushI);
      final v = c.functions.single.code[1] |
          (c.functions.single.code[2] << 8) |
          (c.functions.single.code[3] << 16) |
          (c.functions.single.code[4] << 24);
      expect(v, 42);
    });

    test('inlines const declarations and keeps their names out of the module',
        () {
      const src = '''
const String kSecretAlphabet = 'XYZ';

// @vmp
int f() {
  return strIndexOf(kSecretAlphabet, 'Y');
}
''';
      final c = compileSrc(src);
      // The value must be present, the *name* must not.
      expect(c.strings, contains('XYZ'));
      expect(c.strings.any((s) => s.contains('kSecretAlphabet')), isFalse);
    });

    test('rejects falling off the end of a non-void function', () {
      const src = '// @vmp\nint f(int a) {\n  int b = a;\n}\n';
      expect(() => compileSrc(src), throwsA(isA<CompileError>()));
    });

    test('accepts a function whose every path returns', () {
      const src = '''
// @vmp
int f(int a) {
  if (a > 0) {
    return 1;
  } else {
    return 2;
  }
}
''';
      expect(() => compileSrc(src), returnsNormally);
    });

    test('emits a final call target for forward references', () {
      const src = '''
// @vmp
int useIt(int x) {
  return helper(x) * 2;
}

// @vmp
int helper(int x) {
  return x + 1;
}
''';
      final c = compileSrc(src);
      final code = c.functions[0].code;
      final i = code.indexOf(Op.call);
      expect(i, greaterThanOrEqualTo(0));
      // helper() is index 1 in declaration order.
      expect(code[i + 1] | (code[i + 2] << 8), 1);
    });

    test('lowers for-in over a list', () {
      const src = '''
// @vmp
int f(List xs) {
  int acc = 0;
  for (int x in xs) {
    acc = acc + x;
  }
  return acc;
}
''';
      final c = compileSrc(src);
      final code = c.functions.single.code;
      // The loop must contain a listLen and a listGet host call.
      var sawListLen = false;
      var sawListGet = false;
      for (var i = 0; i + 4 < code.length; i++) {
        if (code[i] == Op.host) {
          final id = code[i + 1] | (code[i + 2] << 8);
          if (id == HostFn.listLen) sawListLen = true;
          if (id == HostFn.listGet) sawListGet = true;
        }
      }
      expect(sawListLen, isTrue);
      expect(sawListGet, isTrue);
    });

    test('rejects assignment into a list', () {
      const src = '''
// @vmp
int f(List xs) {
  xs[0] = 1;
  return 1;
}
''';
      expect(
          () => compileSrc(src),
          throwsA(isA<CompileError>()
              .having((e) => e.message, 'message', contains('List'))));
    });
  });

  group('packer', () {
    test('produces a container with the DVMP magic', () {
      final compiled = compileSrc(_addSrc);
      final enc = encodeBody(compiled);
      final p = Packer.pack(enc.bytes,
          codeOff: enc.codeOff,
          codeLen: enc.codeLen,
          entryCount: 1,
          seed: 0x1234);
      expect(String.fromCharCodes(p.container.sublist(0, 4)), 'DVMP');
      expect(p.container.length, 32 + enc.bytes.length + 8);
      expect(p.plaintextBytes, enc.bytes.length);
    });

    test('cipher is an involution', () {
      final data = Uint8List.fromList(List.generate(64, (i) => i * 7 & 0xFF));
      final copy = Uint8List.fromList(data);
      VmpCipher(0xDEADBEEF).apply(copy);
      expect(copy, isNot(equals(data)));
      VmpCipher(0xDEADBEEF).apply(copy);
      expect(copy, equals(data));
    });

    test('opcode permutation is a bijection over the opcode range', () {
      for (final seed in <int>[0, 1, 0x5A, 0x1234567890ABCDEF, 0xFFFFFFFFFFFFFFFF]) {
        final perm = Packer.opcodePermutation(seed);
        final inv = Packer.opcodeInverse(seed);
        final seen = <int>{};
        for (var op = 0; op < Op.max; op++) {
          expect(inv[perm[op]], op, reason: 'op $op did not round-trip at seed $seed');
          seen.add(perm[op]);
        }
        expect(seen.length, Op.max, reason: 'permutation must be injective');
        // Every wire byte must also be outside the opcode range for the bytes the
        // stream does not use - otherwise a desynchronised walk lands on a legal opcode
        // by luck far more often than it should.
        final outside = perm.where((w) => w >= Op.max).length;
        expect(outside, greaterThan(0),
            reason: 'a permutation confined to 0..${Op.max} would be enumerable');
      }
    });

    test('the opcode permutation is not the affine map it replaced', () {
      // The reverse test for item 1. The old mapping was (op * 167 + salt) & 0xFF with
      // the salt in the container header, so 128 candidates for the multiplier - tested
      // against the container CRC - recovered the private instruction set in minutes.
      // This asserts the shipped permutation cannot be described that way at all, for
      // any salt and any odd multiplier. If someone reinstates an affine map (or a
      // close relative), this fails rather than silently weakening the container.
      for (final seed in <int>[0, 0x5A, 0x1234567890ABCDEF]) {
        final perm = Packer.opcodePermutation(seed);
        var affineHits = 0;
        for (var salt = 0; salt < 256; salt++) {
          for (var mul = 1; mul < 256; mul += 2) {
            var all = true;
            for (var op = 0; op < Op.max; op++) {
              if (((op * mul + salt) & 0xFF) != perm[op]) {
                all = false;
                break;
              }
            }
            if (all) affineHits++;
          }
        }
        expect(affineHits, 0,
            reason: 'seed $seed: permutation is affine, recoverable in 128 tries');
        expect(Packer.legacyAffineWire(0, seed), isNot(perm[0]),
            reason: 'the legacy mapping must not survive');
      }
    });

    test('encrypted image leaks no plaintext', () {
      const src = '''
// @vmp
String secret() {
  return 'TOP_SECRET_MARKER_1234';
}
''';
      final p = packSrc(src);
      final asLatin = String.fromCharCodes(p.container);
      expect(asLatin.contains('TOP_SECRET_MARKER_1234'), isFalse);
      expect(asLatin.contains('secret'), isFalse);
    });

    test('different seeds give completely different ciphertext', () {
      final compiled = compileSrc(_addSrc);
      final enc = encodeBody(compiled);
      final p1 = Packer.pack(enc.bytes,
          codeOff: enc.codeOff,
          codeLen: enc.codeLen,
          entryCount: 1,
          seed: 1);
      final p2 = Packer.pack(enc.bytes,
          codeOff: enc.codeOff,
          codeLen: enc.codeLen,
          entryCount: 1,
          seed: 2);
      expect(p1.container.sublist(32), isNot(equals(p2.container.sublist(32))));
      // ... and the header differs only in the seed field.
      expect(p1.container.sublist(0, 8), equals(p2.container.sublist(0, 8)));
      expect(p1.container.sublist(8, 16), isNot(equals(p2.container.sublist(8, 16))));
    });

    test('a tampered container fails the auth tag check', () {
      // Mirrors what the native side does: flip one ciphertext byte and verify
      // the recomputed tag no longer matches the stored one.
      const src = '''
// @vmp
int f(int a) {
  return a * 3;
}
''';
      final p = packSrc(src, seed: 0x1122334455667788);
      final img = Uint8List.fromList(p.container);
      img[40] ^= 0x01; // inside the body
      final bodyLen = img[16] | (img[17] << 8) | (img[18] << 16) | (img[19] << 24);
      final work = Uint8List.fromList(img.sublist(32, 32 + bodyLen));
      VmpCipher(p.seed ^ 0xA5A5A5A5A5A5A5A5).apply(work);
      final tag = fnv1a64(work) ^ (p.seed * 0x100000001B3);
      expect(tag, isNot(equals(p.authTag)),
          reason: 'one flipped byte must invalidate the tag');
    });
  });

  group('eviction', () {
    test('removes protected bodies and reports them', () {
      const src = '''
int keepMe(int x) {
  return x;
}

// @vmp
int protectMe(int x) {
  return x * 3;
}
''';
      final ev = evictProtectedFunctions(
          injectMarkers(src, sourceName: 't.dart'));
      expect(ev.removedNames, ['protectMe']);
      expect(ev.source.contains('x * 3'), isFalse);
      expect(ev.source.contains('keepMe'), isTrue);
    });

    test('keeps surrounding declarations intact', () {
      const src = '''
int a() {
  return 1;
}

// @vmp
int b() {
  return 2;
}

int c() {
  return 3;
}
''';
      final ev = evictProtectedFunctions(
          injectMarkers(src, sourceName: 't.dart'));
      expect(ev.removedNames, ['b']);
      expect(ev.source.contains('int a()'), isTrue);
      expect(ev.source.contains('int c()'), isTrue);
    });

    test('handles multiple protected functions in one file', () {
      const src = '''
// @vmp
int a() {
  return 1;
}

// @vmp
String b(String s) {
  return s + s;
}
''';
      final ev = evictProtectedFunctions(
          injectMarkers(src, sourceName: 't.dart'));
      expect(ev.removedNames, ['a', 'b']);
      expect(ev.source.contains('s + s'), isFalse);
    });
  });

  group('oracle generation', () {
    test('strips annotations and flattens imports', () {
      const src = '''
import '../protected/licensing.dart';

// @vmp
bool f(int a) {
  return a > 0;
}
''';
      // The oracle is generated from the marker-injected form, which is what
      // the build feeds it.
      final out =
          generateOracleFile(injectMarkers(src, sourceName: 't.dart'));
      expect(out.contains('@vmp'), isFalse);
      expect(out.contains("import 'licensing.dart';"), isTrue);
      expect(out.contains('a > 0'), isTrue);
    });
  });
}
