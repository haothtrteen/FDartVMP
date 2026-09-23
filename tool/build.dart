/// Compiles the protected sources. Run from the repository root:
///
///     dart run tool/build.dart
///     dart run tool/build.dart --seed 0x1234     # reproducible
///
/// Thin wrapper so the build works without knowing the tool package's path.
library;

import 'dart:io';

Future<int> main(List<String> args) async {
  final script = File('tool/vmpc/bin/vmpc.dart');
  if (!script.existsSync()) {
    stderr.writeln('tool/build.dart: run me from the repository root '
        '(tool/vmpc/bin/vmpc.dart not found)');
    return 2;
  }
  final r = await Process.start(
    Platform.resolvedExecutable,
    ['run', script.path, 'build', ...args],
    mode: ProcessStartMode.inheritStdio,
  );
  return r.exitCode;
}
