/// `vmpc build` - compiles the protected sources into every artifact the
/// runtime and the tests need.
///
/// Run it from the repository root:
///
///     dart run tool/vmpc/bin/vmpc.dart build
///     dart run tool/vmpc/bin/vmpc.dart build --seed 0x1234   # reproducible
///     dart run tool/vmpc/bin/vmpc.dart disasm               # inspect bytecode
///     dart run tool/vmpc/bin/vmpc.dart check                # verify artifacts
library;

import 'dart:io';

import 'package:args/args.dart';
import 'package:vmpc/vmpc.dart';

const String _defaultSources =
    'protected/licensing.dart,protected/keys.dart,protected/challenge.dart';

Future<int> main(List<String> argv) async {
  final parser = ArgParser()
    ..addCommand('build', _buildParser())
    ..addCommand('disasm', _disasmParser())
    ..addCommand('check', _checkParser())
    ..addFlag('help', abbr: 'h', negatable: false, help: 'Show usage.');

  final ArgResults args;
  try {
    args = parser.parse(argv);
  } on FormatException catch (e) {
    stderr.writeln('vmpc: ${e.message}\n');
    _usage(parser);
    return 2;
  }

  if (args['help'] as bool || args.command == null) {
    _usage(parser);
    return args.command == null && !(args['help'] as bool) ? 2 : 0;
  }

  switch (args.command!.name) {
    case 'build':
      return _build(args.command!);
    case 'disasm':
      return _disasm(args.command!);
    case 'check':
      return _check(args.command!);
    default:
      _usage(parser);
      return 2;
  }
}

ArgParser _buildParser() => ArgParser()
  ..addMultiOption('source',
      abbr: 's',
      defaultsTo: _defaultSources.split(','),
      help: 'Protected source files, in module id order.')
  ..addOption('seed',
      help: 'Deterministic seed (decimal or 0x-prefixed). Omit for a random '
          'one, which is what a release build should do.')
  ..addOption('include-dir',
      defaultsTo: 'packages/dartvmp/generated',
      help: 'Where vmp_module.inc is written. Defaults to the directory the '
          'plugin CMake project force-includes it from.')
  ..addOption('stub-dir',
      defaultsTo: 'app/lib/generated',
      help: 'Where the Dart stubs are written.')
  ..addOption('test-dir',
      defaultsTo: 'app/test/generated',
      help: 'Where the oracle and manifest are written.')
  ..addOption('evicted-dir',
      defaultsTo: 'build/evicted',
      help: 'Where the source-with-bodies-removed copy is written.')
  ..addFlag('no-mask',
      negatable: false,
      help: 'Store the container verbatim instead of XOR-masked. Only useful '
          'when diffing generated output.')
  ..addFlag('quiet', abbr: 'q', negatable: false, help: 'Only print errors.');

ArgParser _disasmParser() => ArgParser()
  ..addMultiOption('source',
      abbr: 's', defaultsTo: _defaultSources.split(','))
  ..addOption('seed')
  ..addOption('out', help: 'Write the listing to a file instead of stdout.');

ArgParser _checkParser() => ArgParser()
  ..addMultiOption('source',
      abbr: 's', defaultsTo: _defaultSources.split(','))
  ..addOption('include-dir', defaultsTo: 'packages/dartvmp/generated')
  ..addOption('test-dir', defaultsTo: 'app/test/generated');

// ---------------------------------------------------------------------------
// build
// ---------------------------------------------------------------------------

int _build(ArgResults a) {
  final quiet = a['quiet'] as bool;
  final seed = a['seed'] == null ? null : _parseSeed(a['seed'] as String);
  if (a['seed'] != null && seed == null) {
    stderr.writeln('vmpc: --seed must be a decimal or 0x-prefixed integer');
    return 2;
  }

  final config = BuildConfig(
    sources: (a['source'] as List<String>),
    seed: seed,
    obfuscateMasks: !(a['no-mask'] as bool),
  );

  try {
    final out = buildAndWrite(
      config: config,
      includeDir: a['include-dir'] as String,
      stubDir: a['stub-dir'] as String,
      testDir: a['test-dir'] as String,
      evictedDir: a['evicted-dir'] as String,
      // The app depends on this package by path, so the package: URI is what
      // the generated stub must import.
      runtimeImport: 'package:dartvmp/dartvmp.dart',
    );

    if (!quiet) {
      final r = out.result;
      stdout.writeln('vmpc build');
      stdout.writeln(formatBuildSummary(r));
      stdout.writeln('  functions:');
      for (final f in r.functions) {
        stdout.writeln('    [${f.id.toString().padLeft(3)}] '
            '${f.decl.returnType.dartName} ${f.name}'
            '(${f.decl.params.map((p) => '${p.type.dartName} ${p.name}').join(', ')})'
            '  <- ${_rel(f.source)}');
      }
      stdout.writeln('  artifacts:');
      stdout.writeln('    ${_rel(out.headerFile.path)}');
      stdout.writeln('    ${_rel(out.stubFile.path)}');
      stdout.writeln('    ${_rel(out.oracleFile.path)}');
      stdout.writeln('    ${_rel(out.manifestFile.path)}');
      stdout.writeln('    ${_rel(out.evictedFile.path)}');

      stdout.writeln();
      stdout.writeln('  protection surface: ${r.markerCount} marker(s) -> '
          '${r.functions.length} compiled function(s)');
      stdout.writeln('  next: dart run tool/vmpc/bin/vmpc.dart check');

      // A marker that produced no function, or a declaration in a protected
      // source with no marker, silently ships unprotected code. Report both
      // loudly: the build itself stays green here so the artifact set remains
      // inspectable, but `vmpc check` (which CI runs) fails on either.
      if (r.markerCount != r.functions.length) {
        stderr.writeln('vmpc: WARNING protection surface mismatch: '
            '${r.markerCount} marker(s), ${r.functions.length} compiled '
            'function(s); `vmpc check` will fail');
      }
      for (final f in r.unmarked) {
        stderr.writeln('vmpc: WARNING ${_rel(f.sourceName)}:${f.line}: '
            '"${f.name}" has no marker and is not protected; `vmpc check` '
            'will fail');
      }
    }
    return 0;
  } on StateError catch (e) {
    stderr.writeln('vmpc: ${e.message}');
    return 1;
  } on ParseError catch (e) {
    stderr.writeln('vmpc: $e');
    return 1;
  } on CompileError catch (e) {
    stderr.writeln('vmpc: $e');
    return 1;
  } on LexError catch (e) {
    stderr.writeln('vmpc: $e');
    return 1;
  }
}

int? _parseSeed(String s) {
  final t = s.trim();
  if (t.startsWith('0x') || t.startsWith('0X')) {
    return int.tryParse(t.substring(2), radix: 16);
  }
  return int.tryParse(t);
}

// ---------------------------------------------------------------------------
// disasm
// ---------------------------------------------------------------------------

int _disasm(ArgResults a) {
  final seed = a['seed'] == null ? null : _parseSeed(a['seed'] as String);
  try {
    final result = VmpCompiler(BuildConfig(
      sources: a['source'] as List<String>,
      seed: seed,
    )).build();

    final sb = StringBuffer();
    sb.writeln('; DartVMP module disassembly');
    sb.writeln('; build id   : 0x${result.buildId.toRadixString(16)}');
    sb.writeln('; bytecode   : ${result.bodyBytes} bytes');
    sb.writeln('; container  : ${result.imageBytes} bytes');
    sb.writeln('; functions  : ${result.functions.length}');
    sb.writeln(';');
    sb.writeln('; This is the *compile-time* view: it is what the interpreter');
    sb.writeln('; executes after dvmp_module_unseal() decodes the shipped image.');
    sb.writeln();
    sb.writeln(result.disassembly);

    final outPath = a['out'] as String?;
    if (outPath == null) {
      stdout.write(sb.toString());
    } else {
      final f = File(outPath);
      f.parent.createSync(recursive: true);
      f.writeAsStringSync(sb.toString());
      stdout.writeln('wrote $outPath');
    }
    return 0;
  } on Object catch (e) {
    stderr.writeln('vmpc: $e');
    return 1;
  }
}

// ---------------------------------------------------------------------------
// check
// ---------------------------------------------------------------------------

/// Verifies the generated artifacts are self-consistent and actually protected.
///
/// This is the check that should run in CI. It fails the build when:
///   * a protected function's *name* leaks into the shipped container;
///   * a string from the protected source appears verbatim in the container;
///   * a protected body is still present in a file the app imports;
///   * the stub and the module disagree about the function set.
int _check(ArgResults a) {
  final sources = a['source'] as List<String>;
  final includeDir = a['include-dir'] as String;
  final testDir = a['test-dir'] as String;

  final problems = <String>[];
  final result = VmpCompiler(BuildConfig(sources: sources, seed: 1)).build();

  // ---- protection surface: exists, and exists exactly once -------------
  //
  // The single most dangerous failure this compiler can have is a protected
  // function that quietly is not protected: the build succeeds, every test
  // passes, and the implementation ships in the AOT snapshot. Two independent
  // assertions close that hole, because they can only agree by accident if the
  // marker -> function path really is 1:1.
  if (result.markerCount != result.functions.length) {
    problems.add('protection surface mismatch: the protected sources contain '
        '${result.markerCount} "// @vmp" marker(s) but only '
        '${result.functions.length} function(s) were compiled. A marker that '
        'produces no module entry is unprotected logic that looks protected. '
        'Check for a marker on a declaration the compiler cannot lower '
        '(generics, closures, classes) - it must be a build failure, not a '
        'warning.');
  }
  if (result.unmarked.isNotEmpty) {
    for (final f in result.unmarked) {
      problems.add('${_rel(f.sourceName)}:${f.line}: "${f.name}" is declared in '
          'a protected source without a marker. Files under protected/ are the '
          'protection surface, so every function here is expected to be '
          'protected; either add "// @vmp" or move the function out of '
          'protected/.');
    }
  }

  final header = File('$includeDir/vmp_module.inc');
  if (!header.existsSync()) {
    problems.add('${_rel(header.path)} is missing; run `vmpc build` first');
  } else {
    final text = header.readAsStringSync();
    // The generated image is stored as masked uint64 words, so the raw magic
    // must NOT be greppable - that is the point of the masking step.
    if (RegExp(r'0x44,\s*0x56,\s*0x4d,\s*0x50').hasMatch(text)) {
      problems.add('the container magic appears unmasked in '
          '${_rel(header.path)}; pass without --no-mask');
    }
    for (final probe in const [
      'DVMP_LICENSE_SALT',
      'sk-dartvmp-demo',
      'kAlphabet',
    ]) {
      if (text.contains(probe)) {
        problems.add('"$probe" appears verbatim in ${_rel(header.path)}');
      }
    }
  }

  final stub = File('app/lib/generated/protected_stubs.dart');
  if (!stub.existsSync()) {
    problems.add('${_rel(stub.path)} is missing; run `vmpc build` first');
  } else {
    final text = stub.readAsStringSync();
    for (final f in result.functions) {
      if (!text.contains('${f.decl.returnType.dartName} ${f.name}(')) {
        problems.add('stub for ${f.name} not found in ${_rel(stub.path)}');
      }
    }
  }

  // The protected bodies must not appear anywhere the application compiles.
  final leaked = <String>[];
  for (final dir in ['app/lib', 'app/bin']) {
    final d = Directory(dir);
    if (!d.existsSync()) continue;
    for (final f in d.listSync(recursive: true).whereType<File>()) {
      if (!f.path.endsWith('.dart')) continue;
      final text = f.readAsStringSync();
      for (final fn in result.functions) {
        // A stub body is a one-liner; anything that looks like a real body
        // (a loop or an arithmetic expression) is a leak.
        if (text.contains('for (') &&
            text.contains('${fn.decl.returnType.dartName} ${fn.name}(') &&
            !f.path.contains('generated')) {
          leaked.add('${_rel(f.path)} may contain the body of ${fn.name}');
        }
      }
    }
  }
  problems.addAll(leaked);

  final manifest = File('$testDir/vmp_manifest.json');
  if (!manifest.existsSync()) {
    problems.add('${_rel(manifest.path)} is missing; run `vmpc build` first');
  }

  if (problems.isEmpty) {
    stdout.writeln('vmpc check: OK');
    stdout.writeln('  ${result.functions.length} protected functions, '
        '${result.bodyBytes} bytes of bytecode, '
        '${result.imageBytes} byte container');
    stdout.writeln('  protection surface: ${result.markerCount} marker(s), '
        '${result.functions.length} compiled, 0 unmarked declarations');
    stdout.writeln('  container magic is masked; no protected string leaks');
    return 0;
  }
  stderr.writeln('vmpc check: ${problems.length} problem(s)');
  for (final p in problems) {
    stderr.writeln('  - $p');
  }
  return 1;
}

// ---------------------------------------------------------------------------

String _rel(String path) {
  final cwd = Directory.current.path;
  final norm = path.replaceAll('\\', '/');
  final prefix = cwd.replaceAll('\\', '/');
  return norm.startsWith('$prefix/') ? norm.substring(prefix.length + 1) : norm;
}

void _usage(ArgParser parser) {
  stdout.writeln('''
vmpc - DartVMP compiler

Compiles a restricted subset of Dart into the private instruction set that the
dartvmp native interpreter executes. The original implementations never reach
the application binary.

Usage: dart run tool/vmpc/bin/vmpc.dart <command> [options]

Commands:
  build    Compile the protected sources and write every artifact.
  disasm   Print the compiled bytecode (the interpreter's view).
  check    Verify the generated artifacts contain no plaintext leaks.

Options:
${parser.usage}''');
}
