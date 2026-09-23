import 'dart:async';
import 'dart:ui' show FontFeature;

import 'package:dartvmp/dartvmp.dart';
import 'package:flutter/foundation.dart' show kReleaseMode;
import 'package:flutter/material.dart';

import 'generated/protected_stubs.dart' as protected;

void main() {
  runApp(const DartVmpDemoApp());
}

class DartVmpDemoApp extends StatelessWidget {
  const DartVmpDemoApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'DartVMP demo',
      debugShowCheckedModeBanner: false,
      theme: ThemeData(
        colorScheme: ColorScheme.fromSeed(
          seedColor: const Color(0xFF2F6FEB),
          brightness: Brightness.dark,
        ),
        useMaterial3: true,
      ),
      home: const DemoHome(),
    );
  }
}

/// One row in the results log.
class LogLine {
  final String label;
  final String value;
  final bool ok;
  const LogLine(this.label, this.value, {this.ok = true});
}

class DemoHome extends StatefulWidget {
  const DemoHome({super.key});

  @override
  State<DemoHome> createState() => _DemoHomeState();
}

class _DemoHomeState extends State<DemoHome> {
  final List<LogLine> _lines = <LogLine>[];
  String? _fatal;
  bool _benchmarking = false;
  // Challenge card state. `_reveal` drives the *stub*, i.e. the shipped path.
  final TextEditingController _keyInput = TextEditingController();
  String _challengeResult = '';
  String? _challengeError;
  int _challengeAttempts = 0;
  String _benchmark = '';

  @override
  void initState() {
    super.initState();
    // Deferred so a native failure shows up in the UI instead of killing the
    // first frame.
    WidgetsBinding.instance.addPostFrameCallback((_) => _run());
  }

  void _log(String label, Object? value, {bool ok = true}) {
    setState(() => _lines.add(LogLine(label, '$value', ok: ok)));
  }

  /// The row label for a protected function, named in a dev build and by id in a
  /// release build.
  ///
  /// WHY THIS EXISTS, measured rather than assumed: with `flutter build apk
  /// --obfuscate`, the release snapshot no longer contains the stub *declarations*
  /// under their real names (`protected_stubs` and `dartvmp_demo` both drop to zero
  /// occurrences in `libapp.so`) - but seven protected names were still there, because
  /// this file printed them as its own labels. A Blutter dump of that snapshot read the
  /// whole id → purpose map straight out of the object pool, which is the same map that
  /// item 3 of the README worked to remove from the container and that the masked
  /// native name table exists to avoid handing over.
  ///
  /// The stubs dispatch by numeric id (`Vmp.call(4, ...)`), so a label is free to be an
  /// id: nothing in the application depends on a protected function's *name*.
  ///
  /// What this does not do, stated so the win is not overstated: the id → name mapping
  /// is still available at *runtime* through `Vmp.nameOf(id)`, which resolves against
  /// the masked table inside `libdartvmp.so`. That is the documented C-layer boundary -
  /// this change is about what a *static* analysis of `libapp.so` can read.
  String _l(String dev, int id) => kReleaseMode ? 'fn[$id]' : dev;

  void _run() {
    setState(() {
      _lines.clear();
      _fatal = null;
    });
    try {
      Vmp.initialize();
      _log('runtime', 'loaded, ${Vmp.functionCount()} protected functions');
    } catch (e) {
      setState(() => _fatal = '$e');
      return;
    }

    // --- 1. the trivial closed loop -------------------------------------
    try {
      _log(_l('protected.add(20, 22)', 0), protected.add(20, 22));
    } catch (e) {
      _log(_l('protected.add', 0), e, ok: false);
    }

    // --- 2. a protected function calling other protected functions ------
    try {
      final key = protected.makeLicenseKey('demo-seed', 7);
      _log(_l('makeLicenseKey("demo-seed", 7)', 7), key);
      _log(_l('verifyLicense(key)', 4), protected.verifyLicense(key));
      _log(_l('verifyLicense(key with 1 char changed)', 4),
          protected.verifyLicense(_corrupt(key)));
      _log(_l('normalizeKey(key.toLowerCase())', 2),
          protected.normalizeKey(key.toLowerCase()));
    } catch (e) {
      _log('key demo', e, ok: false);
    }

    // --- 3. collections across the FFI boundary -------------------------
    try {
      const List<int> command = <int>[0x41, 0x50, 0x4B, 0x00, 0xFF, 0x10];
      _log(_l('commandChecksum([6 bytes])', 6), protected.commandChecksum(command));
    } catch (e) {
      _log(_l('commandChecksum', 6), e, ok: false);
    }

    try {
      _log(_l('deviceToken("pixel-7", 1700000000)', 5),
          protected.deviceToken('pixel-7', 1700000000));
    } catch (e) {
      _log(_l('deviceToken', 5), e, ok: false);
    }

    // --- 4. the module's own self-check ---------------------------------
    try {
      _log(_l('module selfTest()', 8), protected.selfTest());
    } catch (e) {
      _log(_l('selfTest', 8), e, ok: false);
    }

    // --- 5. evidence: is the shipped image really encrypted? ------------
    // Dev-only. `verifyImage` copies the whole container out of native memory
    // into the Dart heap so it can look for plaintext probes, i.e. it hands a
    // debugger the encrypted module wholesale. Useful while developing, wrong
    // in a shipped build, so release builds skip it entirely.
    if (!kReleaseMode) {
      try {
        final ev = Vmp.verifyImage();
        _log('container magic "DVMP" present', ev.hasMagic);
        _log('container size', '${ev.imageBytes} bytes');
        _log(
          'plaintext leaks',
          ev.leakedProbes.isEmpty ? 'none found' : '${ev.leakedProbes}',
          ok: ev.leakedProbes.isEmpty,
        );
        _log('guarded native memory', '${Vmp.secureBytesLive()} bytes');
      } catch (e) {
        _log('image verification', e, ok: false);
      }
    }

    // --- 6. how calls are dispatched ------------------------------------
    try {
      for (final f in Vmp.functions()) {
        _log('dispatch [${f.id}]', '${f.name} / ${f.arity} args');
      }
    } catch (e) {
      _log('function table', e, ok: false);
    }
  }

  static String _corrupt(String key) {
    if (key.isEmpty) return 'X';
    final c = key.codeUnitAt(0) == 0x41 ? 'B' : 'A';
    return '$c${key.substring(1)}';
  }

  /// Interpreter vs. AOT throughput. This is the number that decides where a
  /// protected function is allowed to be called from.
  ///
  /// Debug-only: it needs a plain-Dart copy of a protected implementation to
  /// compare against (see [benchmarkBaselineDeviceToken]), and that copy must
  /// not exist in a distributed build.
  Future<void> _runBenchmark() async {
    setState(() {
      _benchmarking = true;
      _benchmark = '';
    });
    if (kReleaseMode) {
      setState(() {
        _benchmarking = false;
        _benchmark = 'dev builds only - the AOT baseline is compiled out of '
            'release builds so no plain-Dart copy of a protected function '
            'ships with the app.';
      });
      return;
    }
    // Yield so the spinner paints before the synchronous FFI work starts.
    await Future<void>.delayed(const Duration(milliseconds: 16));

    const iterations = 2000;
    // Warm up both paths so neither pays for first-call page faults.
    for (var i = 0; i < 50; i++) {
      protected.deviceToken('pixel-7', i);
      benchmarkBaselineDeviceToken('pixel-7', i);
    }

    final sw = Stopwatch()..start();
    var sink = 0;
    for (var i = 0; i < iterations; i++) {
      sink ^= protected.deviceToken('pixel-7', i);
    }
    sw.stop();
    final vmpUs = sw.elapsedMicroseconds / iterations;

    final sw2 = Stopwatch()..start();
    var acc = 0;
    for (var i = 0; i < iterations; i++) {
      acc ^= benchmarkBaselineDeviceToken('pixel-7', i);
    }
    sw2.stop();
    final dartUs = sw2.elapsedMicroseconds / iterations;

    if (!mounted) return;
    setState(() {
      _benchmarking = false;
      _benchmark = 'deviceToken, 512 rounds per call\n'
          '  private VM    ${vmpUs.toStringAsFixed(2)} us/call\n'
          '  plain Dart    ${dartUs.toStringAsFixed(3)} us/call\n'
          '  ratio         ${(vmpUs / dartUs).toStringAsFixed(0)}x\n'
          '  cross-check   ${sink == acc ? 'results agree' : 'MISMATCH'}';
    });
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Scaffold(
      appBar: AppBar(
        title: const Text('DartVMP demo'),
        actions: [
          IconButton(
            tooltip: 'Run again',
            onPressed: _fatal == null ? _run : null,
            icon: const Icon(Icons.refresh),
          ),
        ],
      ),
      body: ListView(
        padding: const EdgeInsets.all(16),
        children: [
          if (_fatal != null) _fatalCard(theme) else _resultsCard(theme),
          const SizedBox(height: 16),
          _challengeCard(theme),
          const SizedBox(height: 16),
          _benchmarkCard(theme),
          const SizedBox(height: 16),
          _explainerCard(theme),
        ],
      ),
    );
  }

  Widget _fatalCard(ThemeData theme) {
    return Card(
      color: theme.colorScheme.errorContainer,
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              'The protected runtime is unavailable',
              style: theme.textTheme.titleMedium
                  ?.copyWith(color: theme.colorScheme.onErrorContainer),
            ),
            const SizedBox(height: 8),
            SelectableText(
              _fatal!,
              style: theme.textTheme.bodySmall
                  ?.copyWith(color: theme.colorScheme.onErrorContainer),
            ),
            const SizedBox(height: 8),
            // Deliberately does not name the generator command or the generated
            // header it emits. This string ships in the release snapshot, and naming
            // the build step tells a reader where the protected bodies come from -
            // which is the one thing the demo's own source tree is not supposed to
            // advertise in a shipped artifact. The actionable part survives: rebuild
            // with the protected artifacts present.
            Text(
              'This build has no protected artifacts. Rebuild the application '
              'from its protected sources.',
              style: theme.textTheme.bodySmall
                  ?.copyWith(color: theme.colorScheme.onErrorContainer),
            ),
          ],
        ),
      ),
    );
  }

  Widget _resultsCard(ThemeData theme) {
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text('Protected calls', style: theme.textTheme.titleMedium),
            const SizedBox(height: 4),
            Text(
              // Blutter dumps every string in the snapshot, so this caption is part
              // of the shipped attack surface. It used to read "executed inside the
              // native private VM. No Dart implementation of these functions exists
              // in this application" - a one-line summary of the design, handed over
              // for free. The release wording says what the *user* needs (these calls
              // do not run as ordinary Dart) without naming the mechanism; the
              // detailed version stays in this source file, for non-release builds.
              kReleaseMode
                  ? 'These calls are dispatched to native code. The Dart '
                      'implementations are not part of this application.'
                  : 'Every row below executed inside the native private VM. No Dart '
                      'implementation of these functions exists in this application.',
              style: theme.textTheme.bodySmall,
            ),
            const Divider(height: 24),
            for (final l in _lines)
              Padding(
                padding: const EdgeInsets.symmetric(vertical: 3),
                child: Row(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Icon(
                      l.ok ? Icons.check_circle_outline : Icons.error_outline,
                      size: 16,
                      color:
                          l.ok ? Colors.greenAccent : theme.colorScheme.error,
                    ),
                    const SizedBox(width: 8),
                    Expanded(
                      child: SelectableText.rich(
                        TextSpan(
                          children: [
                            TextSpan(
                              text: '${l.label}  ',
                              style: const TextStyle(
                                fontFeatures: [FontFeature.tabularFigures()],
                              ),
                            ),
                            TextSpan(
                              text: l.value,
                              style: TextStyle(
                                fontFamily: 'monospace',
                                color: theme.colorScheme.primary,
                              ),
                            ),
                          ],
                        ),
                      ),
                    ),
                  ],
                ),
              ),
          ],
        ),
      ),
    );
  }

  /// The challenge: enter the key, get the flag.
  ///
  /// Everything here goes through the generated stubs, which means every attempt is a real
  /// call into the interpreter - including the policy, so the ninth attempt inside a second
  /// produces a visible refusal rather than a wrong answer. That is deliberate: a challenge
  /// whose guard silently misbehaves would be unfair rather than hard.
  Widget _challengeCard(ThemeData theme) {
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text('Challenge', style: theme.textTheme.titleMedium),
            const SizedBox(height: 8),
            Text(
              // Release wording names no protected function: the protection gate requires
              // that no protected name appears in the shipped snapshot, and the full hint
              // spells `makeLicenseKey`. "KDF" is the same information without the name.
              kReleaseMode
                  ? 'Enter the key. Hint: it is what KDF("seed", n) produces for the seed '
                      'and counter below.'
                  : 'Enter the key. Hint: it is what makeLicenseKey(seed, counter) '
                      'produces below.',
              style: theme.textTheme.bodySmall,
            ),
            const SizedBox(height: 8),
            Text(
              'seed = ${_challengeSeed()}   counter = ${_challengeCounter()}',
              style: const TextStyle(fontFamily: 'monospace', fontSize: 12),
            ),
            const SizedBox(height: 8),
            Row(
              children: [
                Expanded(
                  child: TextField(
                    controller: _keyInput,
                    decoration: const InputDecoration(
                      labelText: 'key',
                      border: OutlineInputBorder(),
                      isDense: true,
                    ),
                  ),
                ),
                const SizedBox(width: 8),
                FilledButton.tonal(
                  onPressed: _reveal,
                  child: const Text('Reveal'),
                ),
              ],
            ),
            if (_challengeAttempts > 0) ...[
              const SizedBox(height: 8),
              Text('attempts: $_challengeAttempts',
                  style: theme.textTheme.bodySmall),
            ],
            if (_challengeError != null) ...[
              const SizedBox(height: 8),
              Text(_challengeError!,
                  style: TextStyle(color: theme.colorScheme.error)),
            ],
            if (_challengeResult.isNotEmpty) ...[
              const SizedBox(height: 8),
              SelectableText(
                _challengeResult,
                style: const TextStyle(fontFamily: 'monospace', fontSize: 14),
              ),
            ],
          ],
        ),
      ),
    );
  }

  /// The seed and counter are protected as well, so a solver who has not recovered them
  /// has not solved the challenge either - and the UI has to ask the VM for them.
  String _challengeSeed() {
    try {
      return protected.challengeSeed();
    } catch (_) {
      return '?';
    }
  }

  int _challengeCounter() {
    try {
      return protected.challengeCounter();
    } catch (_) {
      return -1;
    }
  }

  void _reveal() {
    setState(() {
      _challengeAttempts++;
      _challengeError = null;
      try {
        final got = protected.revealFlag(_keyInput.text.trim());
        _challengeResult = got.isEmpty ? '' : got;
        if (got.isEmpty) {
          _challengeError = 'wrong key';
        }
      } on VmpFault catch (e) {
        // A policy refusal is an error, never a wrong answer, and the UI has to show it
        // as such - otherwise a solver cannot tell "the guard fired" from "the key is
        // wrong", which would make the challenge unfair.
        _challengeResult = '';
        _challengeError = e.status == VmpStatus.tooManyCalls
            ? 'call policy refused this attempt (slow down)'
            : e.reason;
      } catch (e) {
        _challengeResult = '';
        _challengeError = '$e';
      }
    });
  }

  Widget _benchmarkCard(ThemeData theme) {
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                Text('Cost of protection', style: theme.textTheme.titleMedium),
                const Spacer(),
                if (_benchmarking)
                  const SizedBox(
                    width: 16,
                    height: 16,
                    child: CircularProgressIndicator(strokeWidth: 2),
                  )
                else
                  FilledButton.tonal(
                    onPressed: _fatal == null ? _runBenchmark : null,
                    child: const Text('Measure'),
                  ),
              ],
            ),
            const SizedBox(height: 8),
            Text(
              // The round count is part of the *algorithm*, and Blutter read this
              // sentence out of the release snapshot's object pool. The release build
              // keeps the part that tells a developer how to use the number, and drops
              // the part that describes the implementation.
              kReleaseMode
                  ? 'The ratio is what decides where a protected function may be '
                      'called from.'
                  : 'deviceToken() runs 512 mixing rounds, so it is a fair stand-in '
                      'for a real key-derivation step. The ratio is what decides where '
                      'a protected function may be called from.',
              style: theme.textTheme.bodySmall,
            ),
            if (_benchmark.isNotEmpty) ...[
              const Divider(height: 24),
              SelectableText(
                _benchmark,
                style: const TextStyle(fontFamily: 'monospace', fontSize: 12),
              ),
            ],
          ],
        ),
      ),
    );
  }

  Widget _explainerCard(ThemeData theme) {
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text('How this works', style: theme.textTheme.titleMedium),
            const SizedBox(height: 8),
            // The long form names protected/*.dart, tool/vmpc, the opcode
            // permutation, the masked uint64 image, the packed argument buffer and
            // the per-call re-seed. That is a complete map of the mechanism, and a
            // Blutter dump of the *release* snapshot showed it sitting in the object
            // pool in plain text - the same mistake the benchmark baseline made, and
            // it is fixed the same way: `kReleaseMode` is a compile-time constant, so
            // the release branch keeps no reference to the text and the tree-shaker
            // drops it. The release text still has to be true, so it says what is
            // actually true without describing how.
            SelectableText(
              kReleaseMode
                  ? 'The sensitive functions of this demo do not exist in this '
                      'application. Their implementation is compiled out of release '
                      'builds.'
                  : '1. protected/*.dart holds the real implementations. Nothing in '
                      'this app imports that directory.\n'
                      '2. tool/vmpc compiles them into a private instruction set, '
                      'permutes the opcodes, encrypts the image, and embeds it in the '
                      'native runtime as masked uint64 words.\n'
                      '3. This app calls one-line stubs that hand a function id and a '
                      'packed argument buffer to the native interpreter.\n'
                      '4. The interpreter decrypts the image into a guarded buffer, '
                      'executes, wipes it, and re-encrypts under a fresh seed so a '
                      'memory dump does not match the shipped binary.\n\n'
                      'Reproduce: dart run tool/build.dart, then rebuild.',
              style: const TextStyle(fontFamily: 'monospace', fontSize: 12),
            ),
          ],
        ),
      ),
    );
  }
}

/// Baseline used only by the benchmark card, and only in non-release builds.
///
/// This is deliberately NOT the protected function: it is a throwaway copy that
/// exists so the comparison has an AOT reference point. Keeping it in `main.dart`
/// rather than in `protected/` makes it obvious which one ships.
///
/// It is reachable *only* from the benchmark path in `_DemoHomeState._runBenchmark`,
/// which returns early under [kReleaseMode] before any call site, so the AOT
/// compiler drops this whole function from a release snapshot.
/// `tool/verify_protection.ps1` fails the build if it ever reappears there: a
/// shipped plain-Dart copy of a protected implementation is a complete oracle for
/// the protection, and a differential oracle is worth more to an attacker than
/// the algorithm itself.
int benchmarkBaselineDeviceToken(String deviceId, int timestamp) {
  var acc = _fnv1a(deviceId) ^ -3750763034362895579;
  const rounds = 512;
  for (var i = 0; i < rounds; i++) {
    acc = acc ^ (acc << 13);
    acc = acc ^ (acc >> 7);
    acc = acc ^ (acc << 17);
    acc = acc + timestamp;
  }
  return acc;
}

/// FNV-1a 64, matching the VM's `hash()` builtin including its signed-int
/// interpretation.
///
/// The constant `0x10000000000000000` (2^64) does not fit in a Dart int
/// literal - Dart's ints are signed 64-bit - so the sign conversion uses
/// `~0x7FFFFFFFFFFFFFFF` (== -2^63) instead, which is exactly the same number.
int _fnv1a(String s) {
  var h = 0xCBF29CE484222325;
  for (final b in s.codeUnits) {
    h = h ^ b;
    h = h * 0x100000001B3;
  }
  return h;
}
