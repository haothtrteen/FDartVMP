/// Top-level build API for the DartVMP compiler.
///
/// Pipeline (the phase-3 toolchain):
///
///     protected/*.dart
///        |  injectMarkers()      `// @vmp` -> `@vmp` annotation
///        v
///     marker-injected source
///        |  Parser                restricted-Dart -> AST
///        v
///     AST
///        |  BytecodeCompiler      AST -> private instruction stream
///        v
///     CompiledModule
///        |  encodeBody()          container body layout
///        v
///     body bytes
///        |  Packer                opcode permutation + stream cipher + tag
///        v
///     container bytes
///        |  generateCHeader()     vmp_module.inc (masked uint64 image)
///        |  generateStubs()       generated/protected_stubs.dart
///        |  generateOracle()      test/protected_oracle.dart
///        v
///     build outputs
library;

import 'dart:convert';
import 'dart:io';
import 'dart:math';

import 'src/ast.dart';
import 'src/builtin_shim.dart';
import 'src/c_emitter.dart';
import 'src/dart_source.dart';
import 'src/emitter.dart';
import 'src/evict.dart';
import 'src/packer.dart';
import 'src/parser.dart';

export 'src/ast.dart';
export 'src/c_emitter.dart'
    show generateCHeader, generateManifest, u64Hex, imageMaskWord, imageMaskKey;
export 'src/dart_source.dart'
    show
        injectMarkers,
        generateStubs,
        generateOracle,
        generateOracleFile,
        describeSignature;
export 'src/emitter.dart';
export 'src/evict.dart';
export 'src/lexer.dart';
export 'src/opcodes.dart';
export 'src/packer.dart' show PackedModule, Packer, VmpCipher, crc32, fnv1a64;
export 'src/parser.dart';

const int kVmpAbiVersion = 1;


/// Builds a [FileUnit] from one source string: inject `@vmp` markers, parse,
/// and fold `const` declarations.
///
/// Single-file convenience used by tests and by callers that do not need
/// imports. A full build goes through [VmpCompiler], which resolves the import
/// graph with the same rules.
FileUnit loadProtectedSource(String source,
    {String sourceName = '<source>'}) {
  final injected = injectMarkers(source, sourceName: sourceName);
  final module =
      Parser.fromSource(injected, sourceName: sourceName).parseModule();
  final unit = FileUnit(module);
  for (final c in module.consts) {
    final v = evalConstExpr(c.value, unit.consts, unit.importedConsts);
    if (v == null) {
      throw StateError('$sourceName:${c.line}: constant "${c.name}" is not a '
          'compile-time expression (only int, String, bool literals and other '
          'constants are allowed)');
    }
    unit.consts[c.name] = v;
  }
  return unit;
}

/// A protected function as seen by the build.
class BuiltFunction {
  final int id;
  final FuncDecl decl;
  final String source;

  BuiltFunction(this.id, this.decl, this.source);

  String get name => decl.name;
}

class BuildResult {
  final PackedModule packed;
  final List<BuiltFunction> functions;
  final List<String> stringTable;
  final List<int> constTable;
  final String disassembly;
  final int buildId;
  final Map<String, String> sourceOf;

  /// Number of `// @vmp` markers seen in the protected sources.
  ///
  /// Must equal [functions].length. A marker that does not become a function is
  /// a hole in the protection surface, and the whole point of counting is that
  /// such a hole can never be silent - see `vmpc check`.
  final int markerCount;

  /// Top-level functions declared in protected sources *without* a marker.
  /// They stay in the application, so they are compiled into the AOT snapshot;
  /// `vmpc check` reports them rather than letting them look protected.
  final List<FuncDecl> unmarked;

  /// Declared call policies, keyed by function name. See `injectMarkers`.
  ///
  /// A guard makes a function a poor oracle: the runtime refuses calls beyond the
  /// budget instead of answering them. It is the only local answer to "an exported
  /// verifier is a validator for anyone who can call it".
  final Map<String, String> guards;

  BuildResult({
    required this.packed,
    required this.functions,
    required this.stringTable,
    required this.constTable,
    required this.disassembly,
    required this.buildId,
    required this.sourceOf,
    this.markerCount = 0,
    this.unmarked = const [],
    this.guards = const {},
  });

  int get bodyBytes => packed.plaintextBytes;
  int get imageBytes => packed.totalBytes;
}

class BuildConfig {
  /// Protected source files, in the order their exported functions receive ids.
  final List<String> sources;

  /// Deterministic seed. `null` draws a fresh cryptographically random seed on
  /// every build, which is what a release build should do.
  final int? seed;

  /// XOR-mask the static image so it never appears verbatim in `.rodata`.
  final bool obfuscateMasks;

  const BuildConfig({
    required this.sources,
    this.seed,
    this.obfuscateMasks = true,
  });
}

class VmpCompiler {
  final BuildConfig config;

  VmpCompiler(this.config);

  BuildResult build() {
    // Load the protected sources, following `import` edges depth-first. Each
    // file registers its functions in source order, which is what fixes the
    // global function ids: a file reachable from two roots is only registered
    // once, so ids stay stable no matter how the roots are ordered.
    final loader = _SourceLoader();
    for (final path in config.sources) {
      loader.load(File(path).absolute.path);
    }
    if (loader.units.isEmpty) {
      throw StateError('no protected functions found in '
          '${config.sources.join(', ')}');
    }

    final allDecls = loader.orderedFunctions;
    final buildId = _buildId();
    final compiled =
        BytecodeCompiler(loader.units,
                orderedFunctions: allDecls, guards: loader.guards)
            .compile();
    final encoded = encodeBody(compiled);
    final packed = Packer.pack(
      encoded.bytes,
      codeOff: encoded.codeOff,
      codeLen: encoded.codeLen,
      entryCount: encoded.entryCount,
      seed: config.seed,
    );

    return BuildResult(
      packed: packed,
      functions: [
        for (var i = 0; i < allDecls.length; i++)
          BuiltFunction(i, allDecls[i], loader.sourceOf[allDecls[i].name]!)
      ],
      stringTable: compiled.strings,
      constTable: compiled.consts,
      disassembly: disassemble(compiled),
      buildId: buildId,
      sourceOf: loader.sourceOf,
      markerCount: loader.markerCount,
      unmarked: loader.unmarked,
      guards: loader.guards,
    );
  }

  int _buildId() {
    if (config.seed != null) return config.seed! & 0xFFFFFFFF;
    return Random.secure().nextInt(0xFFFFFFFF);
  }
}

/// Depth-first loader for the protected source graph.
///
/// Depth-first order is what makes ids stable: dependencies are registered
/// before the files that import them, and each file is registered exactly once
/// even when it is reachable from several roots.
class _SourceLoader {
  final Map<String, FileUnit> _byPath = <String, FileUnit>{};
  final List<FileUnit> units = <FileUnit>[];
  final List<FuncDecl> orderedFunctions = <FuncDecl>[];
  final Map<String, String> sourceOf = <String, String>{};
  final Set<String> _visiting = <String>{};

  /// Total `// @vmp` markers seen across every loaded file. Compared against
  /// the compiled function count by `vmpc check`: a marker that produces no
  /// function is a hole in the protection surface and must not be silent.
  int markerCount = 0;

  /// Declarations found in protected sources without a marker.
  final List<FuncDecl> unmarked = <FuncDecl>[];

  /// Declared call policies, keyed by function name. See injectMarkers.
  final Map<String, String> guards = <String, String>{};

  /// Raw (annotation-stripped) source per file, for the oracle and eviction
  /// steps.
  final Map<String, String> rawSource = <String, String>{};

  void load(String path) {
    // Canonicalise first: `protected/keys.dart` and `protected\keys.dart`
    // resolve to the same file, and registering it twice would duplicate every
    // function it declares (which the flat function-id namespace rejects).
    final file = File(path);
    if (!file.existsSync()) {
      throw StateError('protected source not found: $path');
    }
    final absolutePath = _canonicalPath(file);

    if (_byPath.containsKey(absolutePath)) return;
    if (!_visiting.add(absolutePath)) {
      throw StateError(
          'circular import detected at $absolutePath; protected sources must '
          'form a DAG because functions are resolved by index');
    }
    final original = file.readAsStringSync();
    rawSource[absolutePath] = original;
    final counter = <int>[0];
    final injected = injectMarkers(original,
        sourceName: absolutePath, markersFound: counter, guards: guards);
    markerCount += counter[0];
    final module =
        Parser.fromSource(injected, sourceName: absolutePath).parseModule();
    final unit = FileUnit(module);
    unmarked.addAll(module.unmarked);

    // Dependencies first, so their functions get the lower ids.
    for (final imp in module.imports) {
      final resolved = _resolve(absolutePath, imp.uri);
      load(resolved);
      final dep = _byPath[resolved]!;
      for (final entry in dep.functions.entries) {
        final key = imp.prefix == null
            ? entry.key
            : '${imp.prefix}.${entry.key}';
        unit.importedFunctions[key] = entry.value;
      }
      for (final entry in dep.consts.entries) {
        final key = imp.prefix == null
            ? entry.key
            : '${imp.prefix}.${entry.key}';
        unit.importedConsts[key] = entry.value;
      }
      // Re-export one level of constants so `a -> b -> c` chains resolve.
      for (final entry in dep.importedConsts.entries) {
        unit.importedConsts.putIfAbsent(entry.key, () => entry.value);
      }
    }

    // Evaluate this file's own constants. Done after the imports so a const may
    // reference an imported one.
    final constEnv = <String, ConstValue>{};
    for (final c in module.consts) {
      final v = _evalConst(c, constEnv, unit);
      if (v == null) {
        throw StateError('$absolutePath:${c.line}: constant "${c.name}" is not '
            'a compile-time expression (only int, String, bool literals and '
            'other constants are allowed)');
      }
      if (unit.consts.containsKey(c.name)) {
        throw StateError(
            '$absolutePath:${c.line}: duplicate constant "${c.name}"');
      }
      constEnv[c.name] = v;
      unit.consts[c.name] = v;
    }

    for (final f in module.functions) {
      if (sourceOf.containsKey(f.name)) {
        throw StateError('duplicate protected function name "${f.name}": also '
            'declared in ${sourceOf[f.name]}. Protected functions share one '
            'flat namespace because they are called by index.');
      }
      final id = orderedFunctions.length;
      orderedFunctions.add(f);
      sourceOf[f.name] = absolutePath;
      unit.functions[f.name] = id;
    }

    _byPath[absolutePath] = unit;
    units.add(unit);
    _visiting.remove(absolutePath);
  }

  /// Folds a `const` declaration. Delegates to the shared evaluator so the
  /// loader and the emitter agree on exactly which expressions are constant.
  ConstValue? _evalConst(ConstDecl c, Map<String, ConstValue> env, FileUnit u) {
    return evalConstExpr(c.value, env, u.importedConsts);
  }

  /// Resolves an import URI relative to the importing file, then canonicalises
  /// it so the same target reached by different spellings is only registered
  /// once. Package imports are rejected: a protected file must not depend on
  /// arbitrary pub code, because the compiler can only lower what it can see.
  String _resolve(String fromFile, String uri) {
    if (uri.startsWith('package:') || uri.startsWith('dart:')) {
      throw StateError('$fromFile: cannot import "$uri": protected sources may '
          'only import other protected sources by relative path');
    }
    final dir = File(fromFile).parent.path;
    final joined = File('$dir${Platform.pathSeparator}$uri');
    if (!joined.existsSync()) {
      throw StateError('$fromFile: imported protected source not found: $uri');
    }
    return _canonicalPath(joined);
  }
}

// ---------------------------------------------------------------------------
// Filesystem-facing convenience wrapper used by the CLI
// ---------------------------------------------------------------------------

class VmpBuildOutputs {
  final BuildResult result;
  final File headerFile;
  final File stubFile;
  final File oracleFile;
  final File manifestFile;
  final File evictedFile;

  VmpBuildOutputs({
    required this.result,
    required this.headerFile,
    required this.stubFile,
    required this.oracleFile,
    required this.manifestFile,
    required this.evictedFile,
  });
}

/// Runs a full build and writes every artifact.
///
/// Emitted files:
///   * `<includeDir>/vmp_module.inc`       - image the native runtime embeds
///   * `<stubDir>/protected_stubs.dart`    - stubs the app imports
///   * `<testDir>/protected_oracle.dart`   - reference impls for diff testing
///   * `<testDir>/vmp_manifest.json`       - CI-assertable build manifest
///   * `<evictedDir>/<name>.evicted.dart`  - sources with bodies removed
VmpBuildOutputs buildAndWrite({
  required BuildConfig config,
  required String includeDir,
  required String stubDir,
  required String testDir,
  required String evictedDir,
  String headerName = 'vmp_module.inc',
  String runtimeImport = 'package:dartvmp/dartvmp.dart',
}) {
  final result = VmpCompiler(config).build();
  final decls = result.functions.map((f) => f.decl).toList();
  final ids = result.functions.map((f) => f.id).toList();
  final sourcePath = config.sources.join(', ');

  final hdr = File('$includeDir/$headerName');
  hdr.parent.createSync(recursive: true);
  hdr.writeAsStringSync(generateCHeader(
    packed: result.packed,
    functions: decls,
    ids: ids,
    sourcePath: sourcePath,
    abiVersion: kVmpAbiVersion,
    buildId: result.buildId,
    obfuscateMasks: config.obfuscateMasks,
  ));

  final stubs = File('$stubDir/protected_stubs.dart');
  stubs.parent.createSync(recursive: true);
  stubs.writeAsStringSync(generateStubs(
    functions: decls,
    moduleId: result.buildId,
    ids: ids,
    runtimeImport: runtimeImport,
  ));

  // The oracle is a *copy* of the protected sources with the annotations
  // stripped and imports flattened, so the test package can compile it as
  // ordinary Dart and diff the two implementations. It also needs a shim for
  // the builtin table, which normally only exists inside the native runtime.
  final oracle = File('$testDir/protected_oracle.dart');
  oracle.parent.createSync(recursive: true);
  File('$testDir/vm_builtins.dart').writeAsStringSync(builtinShimSource);
  final copied = <({String sourcePath, String source, String targetName})>[];
  final seenTargets = <String>{};
  for (final p in config.sources) {
    final file = File(p);
    var targetName = _baseName(p) + '.dart';
    // Two roots with the same file name would collide in the flattened test
    // layout; disambiguate rather than silently overwrite.
    var n = 2;
    while (!seenTargets.add(targetName)) {
      targetName = '${_baseName(p)}_$n.dart';
      n++;
    }
    final source = file.readAsStringSync();
    // Feed the marker-injected form so both `// @vmp` and `@vmp` are stripped.
    File('$testDir/$targetName').writeAsStringSync(generateOracleFile(
        injectMarkers(source, sourceName: p)));
    copied.add(
        (sourcePath: p, source: source, targetName: targetName));
  }
  oracle.writeAsStringSync(generateOracle(
    files: copied,
    functions: decls,
    entryFileName: copied.last.targetName,
  ));

  final manifest = File('$testDir/vmp_manifest.json');
  manifest.writeAsStringSync(generateManifest(
    packed: result.packed,
    functions: decls,
    ids: ids,
    sourcePath: sourcePath,
    buildId: result.buildId,
    protectedStringTable: result.stringTable,
    guards: result.guards,
  ));

  // Evict every protected body from a copy of the sources so the build can
  // prove the application never sees them.
  final evicted =
      File('$evictedDir/${_baseName(config.sources.first)}.evicted.dart');
  evicted.parent.createSync(recursive: true);
  final buf = StringBuffer();
  for (final p in config.sources) {
    final injected = injectMarkers(File(p).readAsStringSync(), sourceName: p);
    final ev = evictProtectedFunctions(injected);
    buf.writeln('// ---- evicted from $p (${ev.removedNames.join(', ')}) ----');
    buf.writeln(ev.source);
    buf.writeln();
  }
  evicted.writeAsStringSync(buf.toString());

  return VmpBuildOutputs(
    result: result,
    headerFile: hdr,
    stubFile: stubs,
    oracleFile: oracle,
    manifestFile: manifest,
    evictedFile: evicted,
  );
}

String _baseName(String path) {
  final i = path.replaceAll('\\', '/').lastIndexOf('/');
  final n = i < 0 ? path : path.substring(i + 1);
  return n.endsWith('.dart') ? n.substring(0, n.length - 5) : n;
}

/// Must be called with the file path *before* it is canonicalised, so the
/// compiler and the resolver agree on the key even when the caller passes a
/// forward-slash path on Windows.
String _canonicalPath(File f) => f.resolveSymbolicLinksSync();

/// Serialises a [BuildResult] summary for the CLI.
String formatBuildSummary(BuildResult r) {
  final sb = StringBuffer();
  sb.writeln(
      '  build id      : 0x${r.buildId.toRadixString(16).padLeft(8, '0')}');
  sb.writeln('  functions     : ${r.functions.length}');
  sb.writeln('  string table  : ${r.stringTable.length} entries');
  sb.writeln('  const pool    : ${r.constTable.length} entries');
  sb.writeln('  bytecode      : ${r.bodyBytes} bytes');
  sb.writeln('  image         : ${r.imageBytes} bytes '
      '(seed 0x${u64Hex(r.packed.seed)})');
  return sb.toString();
}

/// Encodes a Dart string list as JSON for embedding in the manifest.
String jsonStringList(List<String> items) => jsonEncode(items);
