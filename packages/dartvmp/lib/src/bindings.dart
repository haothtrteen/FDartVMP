/// Hand-written FFI bindings for the dartvmp native runtime.
///
/// Mirrors `packages/dartvmp/src/dartvmp.h`. The ABI is three functions, one
/// struct and a few helpers, so it is maintained by hand rather than with
/// ffigen (see ffigen.yaml if you prefer to regenerate).
library;

import 'dart:ffi';
import 'dart:io' show Platform;

import 'package:ffi/ffi.dart';
import 'package:flutter/foundation.dart' show kReleaseMode;

// ---------------------------------------------------------------------------
// Status codes (DartVmpStatus)
// ---------------------------------------------------------------------------

class VmpStatus {
  static const int ok = 0;
  static const int notInitialized = -1;
  static const int badArgument = -2;
  static const int moduleMagic = -3;
  static const int moduleVersion = -4;
  static const int moduleAuth = -5;
  static const int moduleCorrupt = -6;
  static const int functionNotFound = -7;
  static const int stepLimit = -8;
  static const int stackOverflow = -9;
  static const int stackUnderflow = -10;
  static const int type = -11;
  static const int divZero = -12;
  static const int indexRange = -13;
  static const int depthExceeded = -14;
  static const int outOfMemory = -15;
  static const int invalidOpcode = -16;
  static const int jumpRange = -17;
  static const int debugger = -18;
  static const int internal = -19;

  /// The function's declared call policy refused this call.
  ///
  /// Distinct from a normal negative answer on purpose. A protected verifier that
  /// silently answered "no" when its budget ran out would be a
  /// protection-induced behaviour change, and the rule for this system is that
  /// protection must be invisible to the business code - so a refusal is an
  /// error the caller can see, count and log, not a fake result.
  static const int tooManyCalls = -20;

  /// Human-readable descriptions, written so that **they do not describe the
  /// mechanism**.
  ///
  /// This table ships in the AOT snapshot, and Blutter dumps every string in it - so
  /// the previous wording was a real leak, not a stylistic one. It said "DVMP
  /// container" (the container magic, which `tool/verify_image.py` exists to keep out
  /// of the binary), "invalid opcode in the module image" (the private instruction
  /// set), and "VMP"/"VM" in four more entries. An attacker with Blutter learned the
  /// design from the error table in the first minute.
  ///
  /// The rule applied here: a message may name *what failed for the caller*, never
  /// *how the protection is built*. "the module image" stays - the app's own API has
  /// `Vmp.verifyImage()`, so the existence of a module image is public by design -
  /// while the format's name, the instruction set and the initials of the mechanism
  /// are gone. `tool/verify_protection.ps1` now checks these as a *category*, so a
  /// future message that reintroduces one fails the build.
  static const Map<int, String> _names = {
    ok: 'OK',
    notInitialized: 'the native runtime is not initialised',
    badArgument: 'bad argument passed to a protected function',
    moduleMagic: 'the shipped module image is missing or has the wrong format',
    moduleVersion: 'module image version mismatch',
    moduleAuth: 'module image authentication failed (tampered)',
    moduleCorrupt: 'module image is corrupt',
    functionNotFound: 'no such protected function',
    stepLimit: 'protected code exceeded its instruction budget',
    stackOverflow: 'protected code overflowed the operand stack',
    stackUnderflow: 'protected code underflowed the operand stack',
    type: 'type error inside protected code',
    divZero: 'division by zero inside protected code',
    indexRange: 'index out of range inside protected code',
    depthExceeded: 'protected code exceeded the call depth limit',
    outOfMemory: 'the protected runtime ran out of memory',
    invalidOpcode: 'the module image failed to decode',
    jumpRange: 'a branch in the module image left its code region',
    debugger: 'instrumentation detected; refusing to run protected code',
    internal: 'internal runtime error',
    tooManyCalls: 'the function\'s call policy refused this call',
  };

  /// Human-readable, non-empty description for any status code.
  static String describe(int s) => _names[s] ?? 'unknown runtime status $s';
}

// ---------------------------------------------------------------------------
// Struct (documentation / tests)
// ---------------------------------------------------------------------------

/// `DartVmpResult`. The Dart API goes through the byte-buffer entry points
/// instead, but the layout is part of the ABI and is asserted by a test.
final class DartVmpResult extends Struct {
  @Int32()
  external int type;

  @Int32()
  external int status;

  @Int64()
  external int i64;

  external Pointer<Uint8> str;

  @Uint32()
  external int len;

  @Uint64()
  external int steps;
}

// ---------------------------------------------------------------------------
// Function signatures
// ---------------------------------------------------------------------------

typedef _InitC = Int32 Function(Pointer<Uint8>, Uint32, Pointer<Uint64>);
typedef _InitD = int Function(Pointer<Uint8>, int, Pointer<Uint64>);

typedef _CallC = Int32 Function(
    Uint32, Pointer<Uint8>, Uint32, Pointer<Uint8>, Pointer<Uint32>);
typedef _CallD = int Function(
    int, Pointer<Uint8>, int, Pointer<Uint8>, Pointer<Uint32>);

typedef _CallNamedC = Int32 Function(
    Pointer<Utf8>, Pointer<Uint8>, Uint32, Pointer<Uint8>, Pointer<Uint32>);
typedef _CallNamedD = int Function(
    Pointer<Utf8>, Pointer<Uint8>, int, Pointer<Uint8>, Pointer<Uint32>);

typedef _CountC = Uint32 Function();
typedef _CountD = int Function();

typedef _BuildIdC = Uint32 Function();
typedef _BuildIdD = int Function();

typedef _InfoC = Int32 Function(
    Uint32, Pointer<Pointer<Utf8>>, Pointer<Uint32>, Pointer<Uint32>);
typedef _InfoD = int Function(
    int, Pointer<Pointer<Utf8>>, Pointer<Uint32>, Pointer<Uint32>);

typedef _StrC = Pointer<Utf8> Function();
typedef _StrD = Pointer<Utf8> Function();

typedef _SessionProbeC = Int32 Function(Pointer<Uint64>, Pointer<Uint64>,
    Pointer<Uint64>);
typedef _SessionProbeD = int Function(Pointer<Uint64>, Pointer<Uint64>,
    Pointer<Uint64>);

typedef _CodeProbeC = Int32 Function(
    Uint32, Pointer<Uint8>, Uint32, Pointer<Uint32>);
typedef _CodeProbeD = int Function(
    int, Pointer<Uint8>, int, Pointer<Uint32>);

typedef _PlaintextProbeC = Int32 Function(Pointer<Uint32>);
typedef _PlaintextProbeD = int Function(Pointer<Uint32>);

typedef _ResidueC = Int32 Function(Pointer<Uint32>, Pointer<Uint32>);
typedef _ResidueD = int Function(Pointer<Uint32>, Pointer<Uint32>);

typedef _VoidProbeC = Int32 Function();
typedef _VoidProbeD = int Function();

// Residency counters: five out-params, and a plain count for the residue so a
// missing value cannot be mistaken for zero.
typedef _ChunkProbeC = Void Function(Pointer<Uint32>, Pointer<Uint32>,
    Pointer<Uint32>, Pointer<Uint32>, Pointer<Uint32>);
typedef _ChunkProbeD = void Function(Pointer<Uint32>, Pointer<Uint32>,
    Pointer<Uint32>, Pointer<Uint32>, Pointer<Uint32>);
typedef _CodeResidueC = Void Function(Pointer<Uint32>, Pointer<Uint32>,
    Pointer<Uint32>, Pointer<Uint32>);
typedef _CodeResidueD = void Function(Pointer<Uint32>, Pointer<Uint32>,
    Pointer<Uint32>, Pointer<Uint32>);

// Instrumentation verdict: one out-flag and one out-string, plus a force hook with a
// C string argument.
typedef _InstrumentedProbeC = Int32 Function(Pointer<Uint32>, Pointer<Pointer<Utf8>>);
typedef _InstrumentedProbeD = int Function(Pointer<Uint32>, Pointer<Pointer<Utf8>>);
typedef _ForceC = Void Function(Int32, Pointer<Utf8>);
typedef _ForceD = void Function(int, Pointer<Utf8>);

// Entry-point integrity: three out-values, returns the hooked count.
typedef _IntegrityProbeC = Uint32 Function(
    Pointer<Uint32>, Pointer<Uint32>, Pointer<Uint32>);
typedef _IntegrityProbeD = int Function(
    Pointer<Uint32>, Pointer<Uint32>, Pointer<Uint32>);

typedef _StatusNameC = Pointer<Utf8> Function(Int32);
typedef _StatusNameD = Pointer<Utf8> Function(int);

typedef _LiveC = Uint32 Function();
typedef _LiveD = int Function();

/// The entry points, bound once per process.
class NativeVmp {
  final _InitD init;
  final _CallD call;
  final _CallNamedD callNamed;
  final _CountD functionCount;
  final _InfoD functionInfo;
  final _StrD lastError;
  final _StatusNameD statusName;
  final _LiveD secureBytesLive;

  /// Build id compiled into the loaded runtime's module image. Present in every
  /// build, unlike the diagnostic probes: a host uses it to check that the module
  /// it loaded is the one its generated stubs were built against.
  final _BuildIdD buildId;

  /// Diagnostic only, and absent from a release build of the runtime: the
  /// Android plugin compiles the probe entry points out via
  /// `-DDVMP_DIAGNOSTICS=OFF`, so callers must treat a missing symbol as
  /// "unavailable" rather than an error.
  final _SessionProbeD? sessionProbe;

  NativeVmp._(this.init, this.call, this.callNamed, this.functionCount,
      this.functionInfo, this.lastError, this.statusName, this.secureBytesLive,
      this.buildId, this.sessionProbe, this.codeProbe, this.plaintextProbe,
      this.bodyResidue, this.guardReset, this.chunkProbe, this.codeResidue, this.instrumentedProbe,
      this.antidebugForce, this.integrityProbe);

  static NativeVmp bind(DynamicLibrary lib) => NativeVmp._(
        lib.lookupFunction<_InitC, _InitD>('dartvmp_init'),
        lib.lookupFunction<_CallC, _CallD>('dartvmp_call'),
        lib.lookupFunction<_CallNamedC, _CallNamedD>('dartvmp_call_named'),
        lib.lookupFunction<_CountC, _CountD>('dartvmp_function_count'),
        lib.lookupFunction<_InfoC, _InfoD>('dartvmp_function_info'),
        lib.lookupFunction<_StrC, _StrD>('dartvmp_last_error'),
        lib.lookupFunction<_StatusNameC, _StatusNameD>('dartvmp_status_name'),
        lib.lookupFunction<_LiveC, _LiveD>('dartvmp_secure_bytes_live'),
        lib.lookupFunction<_BuildIdC, _BuildIdD>('dartvmp_build_id'),
        _bindSessionProbe(lib),
        _bindCodeProbe(lib),
        _bindPlaintextProbe(lib),
        _bindBodyResidue(lib),
        _bindGuardReset(lib),
        _bindChunkProbe(lib),
        _bindCodeResidue(lib),
        _bindInstrumentedProbe(lib),
        _bindAntidebugForce(lib),
        _bindIntegrityProbe(lib),
      );

  /// Every diagnostics binder below returns early in a release build.
  ///
  /// The probes themselves are compiled out of a release runtime
  /// (-DDVMP_DIAGNOSTICS=OFF), so there is nothing to bind - but that alone does not
  /// keep their *names* out of the app. `dartvmp_plaintext_probe`,
  /// `dartvmp_body_residue`, `dartvmp_session_probe` are string literals passed to
  /// lookupFunction, and a release AOT snapshot kept them as dead data in the object
  /// pool, where a Blutter dump reads them straight out: names that describe what
  /// each probe reveals, sitting next to a plain-text description of the mechanism.
  ///
  /// `kReleaseMode` is a compile-time constant, so `if (kReleaseMode) return null;`
  /// makes the lookup below unreachable and the tree-shaker drops the string with it.
  /// The guard has to be inside the binder rather than at the call sites for that to
  /// happen - the same shape the benchmark baseline in app/lib/main.dart uses.
  ///
  /// Binds `dartvmp_session_probe`, returning null when the runtime was built
  /// with `-DDVMP_DIAGNOSTICS=OFF` and the symbol does not exist.
  ///
  /// Written as a concrete helper rather than a generic one: Dart's type system
  /// cannot instantiate `lookupFunction<C, D>` through a generic type parameter,
  /// so a `_optional<C, D>()` helper does not compile.
  static _SessionProbeD? _bindSessionProbe(DynamicLibrary lib) {
    if (kReleaseMode) return null;
    try {
      return lib.lookupFunction<_SessionProbeC, _SessionProbeD>(
          'dartvmp_session_probe');
    } on ArgumentError {
      return null;
    }
  }

  /// Diagnostic only, and absent from a release runtime. Reads back the decoded
  /// instruction bytes of a function, which is how the suite proves that the
  /// plaintext window is actually closed between calls rather than merely
  /// re-encrypted.
  final _CodeProbeD? codeProbe;

  static _CodeProbeD? _bindCodeProbe(DynamicLibrary lib) {
    if (kReleaseMode) return null;
    try {
      return lib.lookupFunction<_CodeProbeC, _CodeProbeD>(
          'dartvmp_code_probe');
    } on ArgumentError {
      return null;
    }
  }

  /// Diagnostic only, and absent from a release runtime. Reports whether the
  /// decrypted body is resident, which is how the suite asserts the plaintext
  /// window closes when a call returns.
  final _PlaintextProbeD? plaintextProbe;

  static _PlaintextProbeD? _bindPlaintextProbe(DynamicLibrary lib) {
    if (kReleaseMode) return null;
    try {
      return lib.lookupFunction<_PlaintextProbeC, _PlaintextProbeD>(
          'dartvmp_plaintext_probe');
    } on ArgumentError {
      return null;
    }
  }

  /// Diagnostic only. Reports how many bytes of the decrypted-body buffer are
  /// non-zero; it must be all zero while the module is sealed. A content-free
  /// count, so it is not a route to the protected bytes.
  final _ResidueD? bodyResidue;

  /// Diagnostic only: clears every call-policy usage counter, so a test can
  /// assert a policy refuses *and* that the function still works.
  final _VoidProbeD? guardReset;

  static _VoidProbeD? _bindGuardReset(DynamicLibrary lib) {
    if (kReleaseMode) return null;
    try {
      return lib.lookupFunction<_VoidProbeC, _VoidProbeD>('dartvmp_guard_reset');
    } on ArgumentError {
      return null;
    }
  }

  static _ResidueD? _bindBodyResidue(DynamicLibrary lib) {
    if (kReleaseMode) return null;
    try {
      return lib.lookupFunction<_ResidueC, _ResidueD>('dartvmp_body_residue');
    } on ArgumentError {
      return null;
    }
  }

  /// Diagnostic only, and absent from a release runtime. Reports the
  /// instruction-stream residency counters: slot count, live slots, the peak since
  /// the last open, and the largest function's stream length.
  ///
  /// This is how the suite checks the claim that a call cannot make the whole
  /// program resident: `peak * largest` bounds the decoded code that was ever
  /// simultaneously present, and the test compares it against the module's total.
  final _ChunkProbeD? chunkProbe;

  static _ChunkProbeD? _bindChunkProbe(DynamicLibrary lib) {
    if (kReleaseMode) return null;
    try {
      return lib.lookupFunction<_ChunkProbeC, _ChunkProbeD>(
          'dartvmp_code_chunk_probe');
    } on ArgumentError {
      return null;
    }
  }

  /// Diagnostic only. Non-zero bytes across the decoded code slots; zero whenever
  /// the module is sealed. The instruction-stream counterpart of [bodyResidue].
  final _CodeResidueD? codeResidue;

  /// Diagnostic only. Reports whether instrumentation was detected, and forces the
  /// verdict so the *reaction* to detection can be tested - the reaction is a narrower
  /// decoded-function cache, which is otherwise only reachable with something actually
  /// attached.
  final _InstrumentedProbeD? instrumentedProbe;
  final _ForceD? antidebugForce;

  /// Diagnostic only. Re-scans the ABI entry points for an inline hook, which is how
  /// the suite can patch one and watch the verdict change - the value recorded at init
  /// necessarily cannot change after the fact.
  final _IntegrityProbeD? integrityProbe;

  static _InstrumentedProbeD? _bindInstrumentedProbe(DynamicLibrary lib) {
    // Blutter found this name in the release snapshot: these two binders were added
    // after the guard below was written, without it, and the doc comment above said
    // "every diagnostics binder returns early in a release build" while two of them
    // did not. A comment is not a check - `app/test/vmp_e2e_test.dart` now asserts
    // that every `_bind*` diagnostic in this file carries the guard.
    if (kReleaseMode) return null;
    try {
      return lib.lookupFunction<_InstrumentedProbeC, _InstrumentedProbeD>(
          'dartvmp_instrumented_probe');
    } on ArgumentError {
      return null;
    }
  }

  static _ForceD? _bindAntidebugForce(DynamicLibrary lib) {
    if (kReleaseMode) return null;
    try {
      return lib.lookupFunction<_ForceC, _ForceD>('dartvmp_antidebug_force');
    } on ArgumentError {
      return null;
    }
  }

  static _IntegrityProbeD? _bindIntegrityProbe(DynamicLibrary lib) {
    if (kReleaseMode) return null;
    try {
      return lib.lookupFunction<_IntegrityProbeC, _IntegrityProbeD>(
          'dartvmp_integrity_probe');
    } on ArgumentError {
      return null;
    }
  }

  static _CodeResidueD? _bindCodeResidue(DynamicLibrary lib) {
    if (kReleaseMode) return null;
    try {
      return lib.lookupFunction<_CodeResidueC, _CodeResidueD>(
          'dartvmp_code_residue');
    } on ArgumentError {
      return null;
    }
  }

  /// Opens the shared object for the current platform and binds the ABI.
  static NativeVmp open() => bind(openRuntimeLibrary());
}

/// File name (or framework path) of the runtime for the current platform.
///
/// Only meaningful where the runtime ships as its own loadable library. On
/// Windows it does not - see [openRuntimeLibrary].
String runtimeLibraryFileName() {
  if (Platform.isWindows) return 'dartvmp.dll';
  if (Platform.isMacOS || Platform.isIOS) return 'dartvmp.framework/dartvmp';
  return 'libdartvmp.so';
}

/// Environment variable that overrides where the runtime is loaded from.
///
/// Needed for `flutter test` on desktop: the test host is a fresh executable, so
/// the statically linked desktop runtime is not present and the library must be
/// loaded from disk. Dropping it next to the tests is unreliable - the Flutter
/// tool truncates files it treats as build output in the package root, which
/// produced a 0-byte `app/dartvmp.dll` and made every native test *skip* instead
/// of pass. `tool/build_native.ps1` therefore deploys to `app/build/native` and
/// the test suite points this variable at it.
const String kLibraryPathEnvVar = 'DARTVMP_LIBRARY_PATH';

/// Opens the runtime, honouring [kLibraryPathEnvVar] when it is set.
///
/// **On Windows the runtime is not a loadable library.** The plugin builds it
/// statically and links it into the runner executable, so the symbols live in
/// `dartvmp_demo.exe` itself and have to be resolved with
/// [DynamicLibrary.executable]. Opening `dartvmp.dll` by name - which is what
/// this function used to do on every platform - made the shipped desktop app fail
/// on its first screen with `VmpUnavailable: could not open dartvmp.dll ... error
/// code: 126`, while the whole test suite stayed green, because `flutter test`
/// points [kLibraryPathEnvVar] at a separately built DLL and never exercises the
/// runner. That is the one class of bug a test host structurally cannot catch, and
/// `tool/capture_desktop_run.ps1` exists to catch it instead.
///
/// Android is the mirror image: the Gradle plugin packages `libdartvmp.so` into
/// the APK, so the library is opened by name and `executable()` would find
/// nothing.
DynamicLibrary openRuntimeLibrary() {
  final override = Platform.environment[kLibraryPathEnvVar];
  if (override != null && override.isNotEmpty) {
    return DynamicLibrary.open(override);
  }
  if (Platform.isWindows) return DynamicLibrary.executable();
  if (Platform.isIOS) return DynamicLibrary.process();
  return DynamicLibrary.open(runtimeLibraryFileName());
}

/// Where the runtime will be loaded from, for diagnostics and error messages.
String runtimeLoadPath() {
  final override = Platform.environment[kLibraryPathEnvVar];
  if (override != null && override.isNotEmpty) return override;
  if (Platform.isWindows) {
    return 'the application executable (the runtime is linked into it)';
  }
  if (Platform.isIOS) return 'the application process';
  return runtimeLibraryFileName();
}

/// Allocates a native byte buffer.
Pointer<Uint8> allocBytes(int bytes) => malloc<Uint8>(bytes);

/// Frees a buffer from [allocBytes].
void freeBytes(Pointer<Uint8> p) => malloc.free(p);
