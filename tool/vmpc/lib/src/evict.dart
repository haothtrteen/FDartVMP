/// Source rewriter used by the "剔除源码" (source eviction) step.
///
/// The real protection guarantee is not that the bytecode is encrypted - it is
/// that **the original Dart implementation never reaches the AOT snapshot**.
/// This module performs that eviction and, crucially, reports exactly what it
/// removed so the build can fail loudly if a protected body is still reachable
/// from the application's import graph.
library;

/// A whole-function replacement: `start`/`end` are 0-based line indices into
/// the *marker-injected* source, `end` being exclusive.
class FunctionSpan {
  final String name;
  final int start;
  final int end;
  const FunctionSpan(this.name, this.start, this.end);
}

/// Result of [evictProtectedFunctions].
class EvictedSource {
  /// The rewritten source, with every `@vmp`-marked function removed.
  final String source;

  /// The bodies that were removed, in source order.
  final List<String> removedBodies;

  /// Names of the functions that were removed.
  final List<String> removedNames;

  const EvictedSource(this.source, this.removedBodies, this.removedNames);
}

/// Locates every top-level declaration preceded by an `@vmp` annotation.
///
/// This is a *textual* scan, run before parsing, so a syntax error inside a
/// protected body still allows eviction to happen. Deliberately conservative:
/// any ambiguity is an error rather than a guess, because guessing wrong here
/// means either shipping the protected body or deleting the wrong code.
List<FunctionSpan> findProtectedSpans(String markerInjectedSource) {
  final lines = markerInjectedSource.split('\n');
  final spans = <FunctionSpan>[];
  var i = 0;
  var depth = 0;
  var pendingName = <String>[];

  while (i < lines.length) {
    final raw = lines[i];
    final t = raw.trim();
    if (t == '@vmp' || t == '@protect') {
      pendingName.add('@');
      i++;
      continue;
    }
    if (t.isEmpty || t.startsWith('//')) {
      i++;
      continue;
    }
    if (pendingName.isNotEmpty) {
      pendingName.clear();
      final start = i;
      // Scan to the end of the declaration: the matching closing brace.
      var declDepth = 0;
      var seenOpen = false;
      var j = i;
      for (; j < lines.length; j++) {
        final l = lines[j];
        final open = _countTopLevel(l, '{');
        final close = _countTopLevel(l, '}');
        declDepth += open;
        if (open > 0) seenOpen = true;
        declDepth -= close;
        if (!seenOpen && l.trimRight().endsWith(';')) {
          // Prototype-style declaration; nothing to evict.
          break;
        }
        if (seenOpen && declDepth <= 0) {
          j++;
          break;
        }
      }
      final end = j > start ? j : start + 1;
      final name = _functionName(lines.sublist(start, end));
      spans.add(FunctionSpan(name, start, end));
      i = end;
      continue;
    }
    // Track brace depth of non-protected code so an `@vmp` nested somewhere
    // illegal is still found (and rejected) rather than silently ignored.
    depth += _countTopLevel(lines[i], '{') - _countTopLevel(lines[i], '}');
    i++;
  }
  if (depth != 0) {
    throw StateError('source is not brace balanced (depth $depth after scan); '
        'refusing to rewrite it');
  }
  return spans;
}

/// Extracts the declared name of a function from its source lines.
String _functionName(List<String> decl) {
  final joined = decl.join(' ');
  final m = RegExp(r'([A-Za-z_$][A-Za-z0-9_$]*)\s*\(').firstMatch(joined);
  if (m == null) {
    throw StateError('cannot determine the function name in declaration:\n'
        '${decl.take(3).join('\n')}');
  }
  return m.group(1)!;
}

/// Counts braces on a line, ignoring string literals and line comments.
int _countTopLevel(String line, String ch) {
  var n = 0;
  var inStr = false;
  var quote = '';
  for (var i = 0; i < line.length; i++) {
    final c = line[i];
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
    if (c == '/' && i + 1 < line.length && line[i + 1] == '/') break;
    if (c == ch) n++;
  }
  return n;
}

/// Removes every protected function body, leaving a clearly marked gap.
EvictedSource evictProtectedFunctions(String markerInjectedSource) {
  final lines = markerInjectedSource.split('\n');
  final spans = findProtectedSpans(markerInjectedSource);
  final out = <String>[];
  final removed = <String>[];
  final names = <String>[];
  var cursor = 0;
  for (final sp in spans) {
    while (cursor < sp.start) {
      out.add(lines[cursor]);
      cursor++;
    }
    removed.add(lines.sublist(sp.start, sp.end).join('\n'));
    names.add(sp.name);
    out.add('// [dartvmp] implementation of `${sp.name}` was compiled to the private');
    out.add('// instruction set and evicted from the application source.');
    out.add('// The stub in generated/protected_stubs.dart is the only remaining');
    out.add('// reference; the body below would have been AOT-compiled otherwise.');
    cursor = sp.end;
  }
  while (cursor < lines.length) {
    out.add(lines[cursor]);
    cursor++;
  }
  return EvictedSource(out.join('\n'), removed, names);
}
