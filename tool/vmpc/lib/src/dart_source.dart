/// Source-level instrumentation helpers.
///
/// The "instrumentation" step of the roadmap has two halves:
///
///  1. **Marker injection** - turn `// @vmp` line comments into real `@vmp`
///     annotations so the parser sees them. This is done as a pure text
///     transform that preserves line numbers, so every diagnostic the compiler
///     emits still points at the original file.
///
///  2. **Stub generation** - emit the replacement function bodies that stay in
///     the application. The real implementation is *never* referenced from the
///     app's import graph, which is what keeps it out of the AOT snapshot.
library;

import 'ast.dart';

/// Injects `@vmp` annotations for `// @vmp` markers, preserving line numbers.
///
/// Only comments that sit on their own line, and whose next non-blank,
/// non-comment line starts a declaration, are treated as markers. That avoids
/// the classic footgun of a stray marker inside a function body silently
/// exporting nothing (the parser would have rejected it anyway).
///
/// A marker may carry a **call policy**, which is how a function that is useful to
/// an attacker as an oracle declares a budget on itself:
///
///     // @vmp guard:rate=8/1000     at most 8 calls per 1000 ms
///     // @vmp guard:once            at most one call per process
///
/// The guard is recorded into [guards] under the function's name rather than
/// becoming new syntax in the parser. That keeps the marker file the single place
/// where protection is declared, and keeps the restricted-Dart grammar from
/// growing a construct that only exists for this tool.
///
/// [markersFound] is incremented once per marker seen. The counter exists so a
/// caller can assert that *every* marker became a compiled function: a marker
/// that injects cleanly but produces no function would otherwise be a silent
/// hole in the protection surface, which is the most dangerous failure this
/// compiler can have.
String injectMarkers(String source,
    {required String sourceName,
    List<int>? markersFound,
    Map<String, String>? guards}) {
  final lines = source.split('\n');
  final out = <String>[];
  final pending = <int>[]; // indices in `out` awaiting an annotation
  var markerDepth = 0;
  // Function names awaiting their declaration, so a policy can be attached to the
  // right one. Kept parallel to `pending` because several markers can stack.
  String? pendingGuard;

  for (final line in lines) {
    // Track brace depth so a marker inside a body can be reported.
    markerDepth += _countChar(line, '{');
    final inBody = markerDepth > 0;
    markerDepth -= _countChar(line, '}');
    if (markerDepth < 0) markerDepth = 0;

    final trimmed = line.trimLeft();
    if (trimmed.startsWith('//')) {
      final body = trimmed.substring(2).trim();
      if (body == '@vmp' || body == '@protect' ||
          body.startsWith('@vmp ') || body.startsWith('@protect ')) {
        if (inBody) {
          throw StateError('$sourceName: a "// @vmp" marker appears inside a '
              'function body; it must sit immediately before a top-level '
              'function declaration');
        }
        // `guard:...` on the marker line declares a call policy for the function
        // it protects. Anything else after `@vmp` is a typo, and a typo in a
        // protection directive is exactly the kind of thing that silently does
        // nothing, so it is a build error.
        final rest = body.replaceFirst(RegExp(r'^@(vmp|protect)\s*'), '').trim();
        if (rest.isNotEmpty) {
          if (!rest.startsWith('guard:')) {
            throw StateError('$sourceName: unrecognised marker option '
                '"$rest" - the only supported form is '
                '"// @vmp guard:rate=N/MS" or "// @vmp guard:once"');
          }
          final spec = rest.substring('guard:'.length).trim();
          if (!_guardSpecs.containsKey(spec.split('=').first.trim())) {
            throw StateError('$sourceName: unknown guard "$spec"; expected '
                '"once" or "rate=N/MS"');
          }
          if (!RegExp(r'^(once|rate=\d+/\d+)$').hasMatch(spec)) {
            throw StateError('$sourceName: malformed guard "$spec"; expected '
                '"once" or "rate=N/MS" with integers');
          }
          pendingGuard = spec;
        }
        pending.add(out.length);
        out.add(line);
        if (markersFound != null) markersFound[0] = markersFound[0] + 1;
        continue;
      }
      out.add(line);
      continue;
    }
    if (trimmed.isEmpty) {
      out.add(line);
      continue;
    }
    if (pending.isNotEmpty) {
      // Replace the marker lines with real annotations, keeping the same number
      // of lines so error positions stay valid.
      for (final at in pending) {
        out[at] = '@vmp';
      }
      pending.clear();
      if (pendingGuard != null && guards != null) {
        // The declaration is the next non-blank, non-comment line; pull its name
        // out so the policy can be attached to it by name.
        final m = RegExp(r'^[A-Za-z_][\w<>, ]*\s+([A-Za-z_]\w*)\s*\(')
            .firstMatch(trimmed);
        if (m == null) {
          throw StateError('$sourceName: a "// @vmp guard:" marker is not '
              'followed by a function declaration');
        }
        guards[m.group(1)!] = pendingGuard;
      }
      pendingGuard = null;
    }
    out.add(line);
  }
  if (pending.isNotEmpty) {
    throw StateError('$sourceName: a "// @vmp" marker is not followed by a '
        'function declaration');
  }
  return out.join('\n');
}

/// Recognised call-policy forms. See [injectMarkers].
const Map<String, String> _guardSpecs = {
  'once': 'at most one call per process',
  'rate': 'at most N calls per MS milliseconds',
};

int _countChar(String s, String ch) {
  var n = 0;
  var inStr = false;
  var inLineComment = false;
  var quote = '';
  for (var i = 0; i < s.length; i++) {
    final c = s[i];
    if (inLineComment) break;
    if (inStr) {
      if (c == r'\') {
        i++;
        continue;
      }
      if (c == quote) inStr = false;
      continue;
    }
    if (c == "'" || c == '"') {
      inStr = true;
      quote = c;
      continue;
    }
    if (c == '/' && i + 1 < s.length && s[i + 1] == '/') {
      inLineComment = true;
      continue;
    }
    if (c == ch) n++;
  }
  return n;
}

/// Names of parameters whose types need a `$Value`-style conversion on the way
/// in. Listed only for documentation in the generated stub header.
String describeSignature(FuncDecl f) {
  final args = f.params.map((p) => '${p.type.dartName} ${p.name}').join(', ');
  return '${f.returnType.dartName} ${f.name}($args)';
}

/// Generates the Dart stub file that lives in the application.
///
/// Every stub is a plain function with the original signature; its body is a
/// single FFI round-trip. The doc comment records the *index* of the target
/// function in the module, which is what the runtime dispatches on - so a
/// reverse engineer who greps the app for the function name learns nothing
/// about the implementation.
String generateStubs({
  required List<FuncDecl> functions,
  required int moduleId,
  required List<int> ids,
  String libraryName = 'protected_api',
  String runtimeImport = "package:dartvmp/dartvmp.dart",
}) {
  final sb = StringBuffer();
  sb.writeln('// GENERATED CODE - DO NOT MODIFY BY HAND');
  sb.writeln('//');
  sb.writeln('// Produced by `dart run vmpc build`.');
  sb.writeln('//');
  sb.writeln('// Each function below is a *stub*: the real implementation was compiled');
  sb.writeln('// to the private instruction set and is executed by the native interpreter');
  sb.writeln('// inside libdartvmp. Removing the original source from the application is');
  sb.writeln('// what keeps it out of the AOT snapshot.');
  sb.writeln('library $libraryName;');
  sb.writeln();
  sb.writeln("import '$runtimeImport';");
  sb.writeln();
  sb.writeln('/// Module identity - must match the module compiled into the runtime.');
  sb.writeln('const int kVmpModuleId = $moduleId;');
  sb.writeln();
  // The build id of the header these stubs were generated from. The runtime
  // reports the build id compiled into its own image, so comparing the two
  // detects the one failure mode the leak probes cannot see: a `libdartvmp`
  // left over from an earlier `vmpc build`, which would mean the suite is
  // testing different bytecode from the application.
  sb.writeln('/// Build id of the module image these stubs were generated from.');
  sb.writeln('///');
  sb.writeln('/// `Vmp.buildId()` reports the id compiled into the loaded runtime; a');
  sb.writeln('/// mismatch means the artifacts came from different compiler runs.');
  sb.writeln('const int kDvmpBuildId = $moduleId;');
  sb.writeln();
  for (var i = 0; i < functions.length; i++) {
    final f = functions[i];
    sb.writeln('/// Protected implementation of `${describeSignature(f)}`.');
    sb.writeln('///');
    sb.writeln('/// Executed inside the native private VM; no Dart implementation of');
    sb.writeln('/// this function exists in the shipped application.');
    sb.writeln('${f.returnType.dartName} ${f.name}('
        '${f.params.map((p) => '${p.type.dartName} ${p.name}').join(', ')}) {');
    final argList = f.params.map((p) => p.name).join(', ');
    /*
     * No function *name* is passed here, deliberately.
     *
     * This line used to read `Vmp.call(id, 'makeLicenseKey', [...])`, which put
     * every protected function's name into the shipped `libapp.so` as a string
     * literal - one per call site. The runtime's own name table is masked so that
     * reading it costs work, and this handed the same list back for free.
     *
     * The name is not needed to dispatch (the id is the identity) and not needed
     * for diagnostics either: `Vmp` resolves it from the id, in the native masked
     * table, only when it is building a fault message. So the name survives
     * exactly where a developer needs it and nowhere in the shipped strings.
     */
    sb.writeln("  return Vmp.call(${ids[i]}, "
        '[${argList.isEmpty ? '' : argList}]) as ${f.returnType.dartName};');
    sb.writeln('}');
    sb.writeln();
  }
  return sb.toString();
}

/// Produces a *compilable* reference library holding the original
/// implementations, for use in `test/` only.
///
/// The restricted subset the VMP compiler accepts is valid Dart, so the only
/// transformation needed is dropping the `@vmp` annotations and making the
/// relative imports point at the copied files. The result is the ground truth
/// the differential test diffs the VM against.
///
/// Shipping this library inside an app would defeat the whole design, which is
/// why [buildAndWrite] only ever writes it under `test/`.
String generateOracle({
  required List<({String sourcePath, String source, String targetName})> files,
  required List<FuncDecl> functions,
  required String entryFileName,
}) {
  final sb = StringBuffer();
  sb.writeln('// GENERATED CODE - DO NOT MODIFY BY HAND');
  sb.writeln('//');
  sb.writeln('// Reference implementations copied verbatim from:');
  for (final f in files) {
    sb.writeln('//   ${f.sourcePath}');
  }
  sb.writeln('//');
  sb.writeln('// NEVER import this from application code: doing so puts the protected');
  sb.writeln('// logic straight back into the AOT snapshot, which is the one thing the');
  sb.writeln('// whole design exists to prevent. The build asserts this file lives under');
  sb.writeln('// test/.');
  sb.writeln('library;');
  sb.writeln();
  // Export *every* copied file, not just the last one: a protected file that is
  // imported by another still declares its own exported functions, and the test
  // needs them all in one namespace. The flattened copies keep their relative
  // imports, so a re-export of the entry point would miss nothing - but being
  // explicit makes the oracle independent of the import graph.
  for (final f in files) {
    sb.writeln("export '${f.targetName}';");
  }
  sb.writeln();
  sb.writeln('/// Protected function names, in module id order.');
  sb.writeln('const List<String> kOracleFunctions = <String>[');
  for (final f in functions) {
    sb.writeln("  '${f.name}',");
  }
  sb.writeln('];');
  return sb.toString();
}

/// The oracle for one protected file: identical to the source except that the
/// `@vmp` / `@protect` annotations are removed (they mean nothing to the Dart
/// analyzer), the builtin shim is imported, and relative imports are rewritten
/// to the flattened test layout.
///
/// Expects the *marker-injected* source, i.e. the output of [injectMarkers], so
/// that both the `// @vmp` comment form and the `@vmp` annotation form are
/// handled by the same code path.
String generateOracleFile(String markerInjectedSource,
    {String builtinShim = 'vm_builtins.dart'}) {
  final lines = <String>[];
  var sawImport = false;
  for (final line in markerInjectedSource.split('\n')) {
    final t = line.trim();
    if (t == '@vmp' || t == '@protect') continue;
    if (t.startsWith('import ') &&
        (t.endsWith(".dart';") || t.endsWith('.dart";'))) {
      if (!sawImport) {
        lines.add("import '$builtinShim';");
        sawImport = true;
      }
      lines.add(_flattenImport(line));
      continue;
    }
    lines.add(line);
  }
  if (!sawImport) {
    // No imports of its own: still needs the builtins.
    lines.insert(0, "import '$builtinShim';");
  }
  return lines.join('\n');
}

/// `import '../protected/licensing.dart';` -> `import 'licensing.dart';`
String _flattenImport(String line) {
  final m = RegExp(r"""^(\s*import\s+['"])([^'"]+)(['"].*)$""").firstMatch(line);
  if (m == null) return line;
  final path = m.group(2)!.replaceAll('\\', '/');
  final slash = path.lastIndexOf('/');
  final base = slash < 0 ? path : path.substring(slash + 1);
  return '${m.group(1)}$base${m.group(3)}';
}
