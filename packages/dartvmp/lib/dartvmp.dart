/// Public Dart API of the DartVMP runtime.
///
/// Usage from application code is normally indirect: the compiler generates
/// `protected_stubs.dart` whose function bodies are a single [Vmp.call]. See
/// `packages/dartvmp/README.md` for the end-to-end workflow.
library;

import 'dart:ffi';
import 'dart:io' show File, Platform;
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import 'src/bindings.dart';
import 'src/wire.dart';

export 'src/bindings.dart'
    show
        VmpStatus,
        DartVmpResult,
        runtimeLibraryFileName,
        runtimeLoadPath,
        openRuntimeLibrary,
        kLibraryPathEnvVar;

/// Thrown when the native runtime cannot be loaded at all. This is an
/// installation/build problem, not a protection event.
class VmpUnavailable implements Exception {
  final String message;
  VmpUnavailable(this.message);
  @override
  String toString() => 'VmpUnavailable: $message';
}

/// Thrown when the native runtime ran but reported a fault. [status] is one of
/// the [VmpStatus] constants; [detail] carries the interpreter's own diagnostic.
class VmpFault implements Exception {
  final int status;
  final String function;
  final String detail;

  VmpFault(this.status, this.function, this.detail);

  String get reason => VmpStatus.describe(status);

  @override
  String toString() =>
      'VmpFault($function): $reason${detail.isEmpty ? '' : ' [$detail]'}';
}

/// Metadata for one protected function, as shipped in the module.
class VmpFunctionInfo {
  final int id;
  final String name;
  final int arity;

  const VmpFunctionInfo(this.id, this.name, this.arity);

  @override
  String toString() => 'VmpFunctionInfo($id, $name, arity: $arity)';
}

/// Result of [Vmp.verifyImage], the evidence behind the protection claim.
class VmpImageEvidence {
  /// Size of the container embedded in the runtime.
  final int imageBytes;

  /// First bytes of the container actually embedded in the shipped binary.
  final Uint8List header;

  /// True when the embedded container carries the DVMP magic, i.e. the runtime
  /// really does hold a private bytecode image rather than nothing at all.
  final bool hasMagic;

  /// How many of [Vmp.markedProbes] were found verbatim in the image. Must be
  /// zero: the whole point is that the protected strings are not present.
  final List<String> leakedProbes;

  const VmpImageEvidence({
    required this.imageBytes,
    required this.header,
    required this.hasMagic,
    required this.leakedProbes,
  });

  bool get clean => hasMagic && leakedProbes.isEmpty;

  @override
  String toString() => 'VmpImageEvidence(bytes: $imageBytes, '
      'magic: $hasMagic, leaks: ${leakedProbes.length})';
}

/// Result of [Vmp.sessionProbe]: the difference between the key that opens the
/// shipped container and the key that protects the runtime's instruction store.
class VmpSessionEvidence {
  /// Seed stored in the shipped container. Public by design - the binary has to
  /// carry its own key material for offline distribution.
  final int masterSeed;

  /// The runtime-only key that encrypts the instruction store. Fresh entropy on
  /// every open, and written into no header and into nothing that ships.
  final int storeKey;

  /// The opcode-permutation salt used inside the store, derived from [storeKey].
  final int storeSalt;

  const VmpSessionEvidence({
    required this.masterSeed,
    required this.storeKey,
    required this.storeSalt,
  });

  /// True when the instruction store is not sealed under anything readable on
  /// disk, i.e. a dump of that buffer cannot be opened with what ships.
  ///
  /// Weaker than it sounds, and deliberately named for what it checks: this is
  /// about a *partial* capture. A full-process capture also gets `storeKey`, which
  /// lives in the same address space - see the note in the README on what the
  /// runtime-keyed store does and does not buy.
  bool get storeIsNotOfflineDecryptable =>
      storeKey != 0 && storeKey != masterSeed && storeSalt != 0;

  @override
  String toString() =>
      'VmpSessionEvidence(master: 0x${masterSeed.toRadixString(16)}, '
      'storeKey: 0x${storeKey.toRadixString(16)}, '
      'offlineDecryptable: ${!storeIsNotOfflineDecryptable})';
}

/// Result of [Vmp.codeResidency]: how much decoded code the runtime is holding.
/// See the doc comment on [Vmp.codeResidency] for what the numbers mean and why
/// they are the observable for "a call cannot make the whole program resident".
class VmpCodeResidency {
  /// How many function slots exist. The runtime never holds more than this many
  /// decoded functions at once.
  final int slots;

  /// How many slots currently hold a decoded function. 0 while the module is
  /// sealed.
  final int live;

  /// The most slots that were live at any instant since the process started.
  final int peak;

  /// The largest single function's stream length, in bytes.
  final int largestFunctionBytes;

  /// Every function's instruction bytes added up: the size of the stream that
  /// used to be resident for the whole of every call.
  final int totalBytes;

  const VmpCodeResidency({
    required this.slots,
    required this.live,
    required this.peak,
    required this.largestFunctionBytes,
    required this.totalBytes,
  });

  /// Upper bound on the decoded instruction bytes that were ever simultaneously
  /// resident during the observation window.
  int get peakResidentBytes => peak * largestFunctionBytes;

  @override
  String toString() => 'VmpCodeResidency(slots: $slots, live: $live, '
      'peak: $peak, largest: $largestFunctionBytes bytes, '
      'total: $totalBytes bytes, '
      'peakResident: $peakResidentBytes bytes)';
}

/// Result of [Vmp.codeResidue]: instruction-stream plaintext left behind.
///
/// All three counts must be zero. See the doc comment on [Vmp.codeResidue] for why
/// the body-region pair is the sharper check.
class VmpCodeResidue {
  /// Non-zero bytes across the decoded code slots.
  final int slotResidue;

  /// Non-zero bytes left in the body's code region at the last seal.
  final int bodyRegionResidue;

  /// The worst [bodyRegionResidue] seen over the life of the process.
  final int bodyRegionResiduePeak;

  /// Non-zero bytes in the runtime-keyed instruction store. Ciphertext while the
  /// module is open, all zeroes once it seals.
  final int storeResidue;

  const VmpCodeResidue({
    required this.slotResidue,
    required this.bodyRegionResidue,
    required this.bodyRegionResiduePeak,
    required this.storeResidue,
  });

  @override
  String toString() => 'VmpCodeResidue(slots: $slotResidue, '
      'bodyRegion: $bodyRegionResidue (peak $bodyRegionResiduePeak), '
      'store: $storeResidue)';
}

/// The runtime singleton.
///
/// The private VM is a single non-reentrant interpreter guarded by a native
/// lock, so every call is synchronous and serialised. Dart's event loop is not
/// blocked: an FFI call occupies the calling isolate only.
class Vmp {
  Vmp._();

  static NativeVmp? _native;
  static Uint8List? _image;
  static Object? _initError;
  static final WireWriter _args = WireWriter();

  static const int _defaultOutBytes = 64 * 1024;

  /// Loads the runtime and initialises the module. Safe to call repeatedly;
  /// the first result is cached.
  ///
  /// Throws [VmpUnavailable] when the runtime cannot be reached or the ABI does
  /// not match, and [VmpFault] when the module itself fails to load or
  /// authenticate.
  static void initialize() {
    if (_native != null) return;
    final cached = _initError;
    if (cached != null) {
      if (cached is VmpUnavailable) throw cached;
      if (cached is VmpFault) throw cached;
      throw VmpUnavailable('$cached');
    }
    try {
      _native = NativeVmp.open();
    } catch (e) {
      _initError = VmpUnavailable(
          'could not reach the runtime at ${runtimeLoadPath()}: $e\n'
          'On Windows the runtime is linked into the application executable, so '
          'there is no dartvmp.dll to load: if this is a Flutter test host, set '
          '$kLibraryPathEnvVar to a library built by tool/build_native.ps1. On '
          'Android the runtime is packaged as libdartvmp.so, so a missing one '
          'means the plugin was added after the last `flutter clean`.');
      throw _initError as VmpUnavailable;
    }

    // Ask the native side for the container it actually holds, so the Dart test
    // suite can verify the shipped image offline.
    final probe = malloc<Uint8>(_defaultOutBytes);
    final outLen = malloc<Uint64>();
    try {
      final rc = _native!.init(probe, _defaultOutBytes, outLen);
      if (rc != VmpStatus.ok) {
        final f = VmpFault(rc, '<init>', _lastError());
        _initError = f;
        throw f;
      }
      final n = outLen.value;
      _image = Uint8List.fromList(probe.asTypedList(n));
    } finally {
      malloc.free(probe);
      malloc.free(outLen);
    }
  }

  /// True once [initialize] has succeeded.
  static bool get isAvailable => _native != null;

  /// The container bytes embedded in the runtime, or null before [initialize].
  static Uint8List? get image => _image;

  /// Names of strings that must NOT appear in the shipped container. The
  /// compiler's manifest records the real ones; this list is the subset the
  /// demo asserts on directly.
  static const List<String> markedProbes = <String>[
    'DVMP_LICENSE_SALT',
    'sk-dartvmp-demo',
  ];

  /// Checks the embedded container: it must carry the DVMP magic and must not
  /// contain any of [markedProbes] in the clear.
  static VmpImageEvidence verifyImage() {
    initialize();
    final img = _image!;
    final header =
        img.length >= 32 ? Uint8List.sublistView(img, 0, 32) : Uint8List(0);
    final hasMagic = img.length >= 4 &&
        img[0] == 0x44 &&
        img[1] == 0x56 &&
        img[2] == 0x4D &&
        img[3] == 0x50;
    // Latin-1 keeps a 1:1 byte->char mapping, so this is a raw byte search.
    final asText = String.fromCharCodes(img);
    final leaks = <String>[
      for (final p in markedProbes)
        if (asText.contains(p)) p,
    ];
    return VmpImageEvidence(
      imageBytes: img.length,
      header: header,
      hasMagic: hasMagic,
      leakedProbes: leaks,
    );
  }

  /// Number of protected functions in the shipped module.
  static int functionCount() {
    initialize();
    return _native!.functionCount();
  }

  /// Build id compiled into the loaded runtime's module image.
  ///
  /// Available in every build. A host compares it against the build id recorded
  /// in its generated stubs: the two are written by the same compiler run, so a
  /// mismatch means the library and the stubs came from different runs - which is
  /// the one failure mode that makes a passing leak-probe suite meaningless,
  /// because it would be checking bytecode the application does not use.
  static int buildId() {
    initialize();
    return _native!.buildId();
  }

  /// Whether the runtime currently holds the decrypted module body.
  ///
  /// Diagnostics only. This is the observable behind the design's central claim,
  /// and the suite asserts it is `false` once a call has returned: the plaintext
  /// window is the call, not the process lifetime. An earlier revision wiped only
  /// a scratch copy when sealing, so the decoded body stayed resident forever
  /// while every test still passed.
  static bool plaintextResident() {
    initialize();
    final probe = _native!.plaintextProbe;
    if (probe == null) return false;
    final live = malloc<Uint32>();
    try {
      if (probe(live) != VmpStatus.ok) return false;
      return live.value != 0;
    } finally {
      malloc.free(live);
    }
  }

  /// Non-zero bytes remaining in the decrypted-body buffer, or null when the
  /// runtime does not expose the diagnostic.
  ///
  /// The body must be *entirely* zero once a call returns. This is the check with
  /// teeth, and it is deliberately about content volume rather than content: the
  /// `unsealed` flag can read 0 while the buffer still holds the whole decoded
  /// module, which is precisely the state an audit's memory dump found after
  /// every test in this suite passed.
  static int? bodyResidue() {
    initialize();
    final probe = _native!.bodyResidue;
    if (probe == null) return null;
    final nonzero = malloc<Uint32>();
    final any = malloc<Uint32>();
    try {
      if (probe(nonzero, any) != VmpStatus.ok) return null;
      return nonzero.value;
    } finally {
      malloc.free(nonzero);
      malloc.free(any);
    }
  }

  /// Whether instrumentation was detected in this process, or null when the runtime
  /// does not export the diagnostic.
  ///
  /// Detection narrows the decoded-function cache to a single slot - the plaintext
  /// window becomes one function wide instead of four - and does nothing else. It never
  /// changes an answer, because a debugger check that altered results would break real
  /// users the moment it false-positived.
  static bool? instrumented() {
    initialize();
    final probe = _native!.instrumentedProbe;
    if (probe == null) return null;
    final flag = malloc<Uint32>();
    final reason = malloc<Pointer<Utf8>>();
    try {
      if (probe(flag, reason) != VmpStatus.ok) return null;
      _lastInstrumentationReason = reason.value == nullptr
          ? ''
          : reason.value.toDartString();
      return flag.value != 0;
    } finally {
      malloc.free(flag);
      malloc.free(reason);
    }
  }

  static String _lastInstrumentationReason = '';

  /// Why the last [instrumented] call returned true.
  static String instrumentationReason() => _lastInstrumentationReason;

  /// Entry-point integrity: how many of the nine ABI entry points begin with an
  /// unconditional branch, which is what an inline hook (Frida's Interceptor, Dobby, or
  /// a hand-made patch) puts there.
  ///
  /// This is the check that answers the *cheapest* attack on this system - not reading
  /// the protected logic, but patching the answer. It is deliberately weak in the honest
  /// direction: it finds a hook that begins with a branch, not one that saves the
  /// prologue first, and it is itself patchable. Its value is that the trivial hook is
  /// no longer free.
  ///
  /// Returns null when the runtime does not export the diagnostic (a release build of
  /// the runtime compiles the probes out). `hooked` is how many entry points look
  /// patched and `mask` identifies which (bit *i* is the *i*-th entry in the ABI order
  /// used by `dvmp_integrity.c`). `scanned` is how many were examined and `selftestOk`
  /// is the decoder's own known-encoding check - if that is false, treat the whole
  /// result as uninformative, because a decoder that cannot tell a branch from a
  /// prologue would report a clean process either way.
  static ({int hooked, int mask, int scanned, bool selftestOk})? integrity() {
    initialize();
    final probe = _native!.integrityProbe;
    if (probe == null) return null;
    final hooked = malloc<Uint32>();
    final scanned = malloc<Uint32>();
    final selftest = malloc<Uint32>();
    try {
      final count = probe(hooked, scanned, selftest);
      return (
        hooked: count,
        mask: hooked.value,
        scanned: scanned.value,
        selftestOk: selftest.value != 0,
      );
    } finally {
      malloc.free(hooked);
      malloc.free(scanned);
      malloc.free(selftest);
    }
  }

  /// Forces the instrumentation verdict. Diagnostics only, and absent from a release
  /// runtime - a shipped library that can be told "you are being debugged" can be told
  /// anything.
  ///
  /// Exists so the reaction to detection is testable: the reaction is a cache size,
  /// which is otherwise only reachable with a debugger attached.
  static bool forceInstrumented(bool on, {String reason = 'forced by a test'}) {
    initialize();
    final force = _native!.antidebugForce;
    if (force == null) return false;
    final s = reason.toNativeUtf8();
    try {
      force(on ? 1 : 0, s);
      return true;
    } finally {
      malloc.free(s);
    }
  }

  /// Clears every call-policy usage counter. Diagnostics only.
  ///
  /// A test that verifies a policy refuses calls past its budget needs this,
  /// because the alternative is to leave the counter exhausted for every later
  /// test in the same process. Returns false when the runtime does not export it
  /// (a release build does not, by design).
  static bool resetCallPolicies() {
    initialize();
    final probe = _native!.guardReset;
    if (probe == null) return false;
    return probe() == VmpStatus.ok;
  }

  /// Decoded instruction bytes of a protected function, or null if the runtime
  /// refuses to serve them.
  ///
  /// Diagnostics only, and it refuses while the module is sealed - which is the
  /// state between calls. That refusal is the point: it is how the test suite
  /// proves the plaintext window is actually *closed* between calls rather than
  /// merely re-encrypted. A probe that happily served decoded bytecode at any
  /// time would be a debugger's best friend and would mask the very property it
  /// looks like it checks.
  static List<int>? decodedCodeProbe(int funcId, {int maxBytes = 64}) {
    initialize();
    final probe = _native!.codeProbe;
    if (probe == null) return null;
    final out = malloc<Uint8>(maxBytes);
    final outLen = malloc<Uint32>();
    try {
      final rc = probe(funcId, out, maxBytes, outLen);
      if (rc != VmpStatus.ok) return null;
      return List<int>.from(out.asTypedList(outLen.value));
    } finally {
      malloc.free(out);
      malloc.free(outLen);
    }
  }

  /// Instruction-stream residency, as four counters, or null when the runtime
  /// does not expose the diagnostic.
  ///
  /// The decoded instruction stream is not resident in bulk. Opening the module
  /// re-encrypts it under a key that exists only in this process, and the
  /// interpreter materialises one function at a time into a small fixed number of
  /// slots. These counters are how that claim is checked from Dart, because it is
  /// otherwise invisible:
  ///
  ///   * `slots`   - how many slots exist (the budget)
  ///   * `live`    - how many hold decoded code right now; 0 while sealed
  ///   * `peak`    - the high-water mark since the process started
  ///   * `largest` - the largest function's stream length
  ///   * `total`   - every function's instruction bytes added up
  ///
  /// `peak * largest` is an upper bound on the decoded code that was *ever*
  /// simultaneously resident, and the test compares it against `total`. Before
  /// this existed, one snapshot taken at any moment during a call returned every
  /// protected function at once.
  ///
  /// Diagnostics only: the counters are counts, so reading them cannot become a
  /// way to read protected code.
  static VmpCodeResidency? codeResidency() {
    initialize();
    final probe = _native!.chunkProbe;
    if (probe == null) return null;
    final slots = malloc<Uint32>();
    final live = malloc<Uint32>();
    final peak = malloc<Uint32>();
    final largest = malloc<Uint32>();
    final total = malloc<Uint32>();
    try {
      probe(slots, live, peak, largest, total);
      return VmpCodeResidency(
        slots: slots.value,
        live: live.value,
        peak: peak.value,
        largestFunctionBytes: largest.value,
        totalBytes: total.value,
      );
    } finally {
      malloc.free(slots);
      malloc.free(live);
      malloc.free(peak);
      malloc.free(largest);
      malloc.free(total);
    }
  }

  /// Residue left behind by the instruction stream, or null when the runtime does
  /// not expose the diagnostic.
  ///
  /// Every count must be zero while the module is sealed:
  ///
  ///   * `slots`      - non-zero bytes across the decoded code slots.
  ///   * `bodyRegion` - non-zero bytes left in the body's code region at the last
  ///                    seal, with `bodyRegionPeak` the worst value over the
  ///                    process.
  ///   * `store`      - non-zero bytes in the runtime-keyed instruction store.
  ///
  /// `bodyRegion` is the sharper of the first two and the reason this exists.
  /// Sealing is the only instant at which "the decoded instruction stream was still
  /// sitting in the body" is observable from outside a call, so it is where the
  /// residency model is *measured* rather than asserted. `open` wipes that region
  /// after moving it into the store, so a healthy runtime reports 0 here for the
  /// life of the process - whereas the design this replaced kept the whole stream in
  /// place for the duration of every call and would report the module's entire
  /// instruction length.
  ///
  /// `store` is the check that the store does not outlive the call either. It is
  /// the one buffer here for which non-zero is not by itself suspicious (it is
  /// ciphertext while open), which is exactly why the sealed-time value is the one
  /// under test.
  static VmpCodeResidue? codeResidue() {
    initialize();
    final probe = _native!.codeResidue;
    if (probe == null) return null;
    final slots = malloc<Uint32>();
    final bodyRegion = malloc<Uint32>();
    final peak = malloc<Uint32>();
    final store = malloc<Uint32>();
    try {
      probe(slots, bodyRegion, peak, store);
      return VmpCodeResidue(
        slotResidue: slots.value,
        bodyRegionResidue: bodyRegion.value,
        bodyRegionResiduePeak: peak.value,
        storeResidue: store.value,
      );
    } finally {
      malloc.free(slots);
      malloc.free(bodyRegion);
      malloc.free(peak);
      malloc.free(store);
    }
  }

  /// Proof that the runtime's instruction store is not sealed under anything that
  /// ships.
  ///
  /// The shipped container has to carry its own seed - offline distribution means
  /// the binary holds its own key material - so that seed is readable by anyone.
  /// The instruction store must NOT be sealed under it: it uses fresh entropy drawn
  /// on every open, written into no header. If the two ever match, a memory dump
  /// plus the on-disk binary is enough to recover every protected function offline.
  ///
  /// Diagnostics only, like [verifyImage]: a shipped application has no reason to
  /// read the runtime's internal key state.
  static VmpSessionEvidence sessionProbe() {
    initialize();
    final probe = _native!.sessionProbe;
    if (probe == null) {
      throw VmpUnavailable(
          'dartvmp_session_probe is not exported by ${runtimeLoadPath()}: '
          'this is a release runtime built with -DDVMP_DIAGNOSTICS=OFF, which '
          'is the intended configuration for a shipped app.');
    }
    final masterSeed = malloc<Uint64>();
    final storeKey = malloc<Uint64>();
    final storeSalt = malloc<Uint64>();
    try {
      final rc = probe(masterSeed, storeKey, storeSalt);
      if (rc != VmpStatus.ok) {
        throw VmpFault(rc, '<sessionProbe>', _lastError());
      }
      return VmpSessionEvidence(
        masterSeed: masterSeed.value,
        storeKey: storeKey.value,
        storeSalt: storeSalt.value,
      );
    } finally {
      malloc.free(masterSeed);
      malloc.free(storeKey);
      malloc.free(storeSalt);
    }
  }

  /// The name of protected function [id], or a placeholder.
  ///
  /// For diagnostics. It reads the runtime's *masked* name table through the
  /// native lookup, so the name is un-masked one byte at a time on demand and no
  /// table of names is resident. That is why generated stubs never pass a name:
  /// everything a fault message needs is derivable here, and a name at a call site
  /// would be a plain string in the shipped application.
  static String nameOf(int id) {
    initialize();
    for (final f in functions()) {
      if (f.id == id) return f.name;
    }
    return '<fn $id>';
  }

  /// Metadata for every protected function, ordered by name.
  static List<VmpFunctionInfo> functions() {    initialize();
    final out = <VmpFunctionInfo>[];
    final name = malloc<Pointer<Utf8>>();
    final arity = malloc<Uint32>();
    final id = malloc<Uint32>();
    try {
      for (var i = 0; i < functionCount(); i++) {
        if (_native!.functionInfo(i, name, arity, id) == VmpStatus.ok) {
          out.add(VmpFunctionInfo(
              id.value, name.value.toDartString(), arity.value));
        }
      }
    } finally {
      malloc.free(name);
      malloc.free(arity);
      malloc.free(id);
    }
    return out;
  }

  /// Bytes currently held by the runtime's guarded allocations. Useful in tests
  /// to show that the decrypted buffer exists and is bounded.
  static int secureBytesLive() {
    initialize();
    return _native!.secureBytesLive();
  }

  /// Invokes protected function [id].
  ///
  /// The id is the whole identity of the target: generated stubs call this with a
  /// numeric literal and no name, because a name argument would become a string
  /// literal in the shipped `libapp.so` - one per call site, handing over the
  /// protection surface that the runtime's masked name table exists to hide. The
  /// name is looked up *from* the id when a fault message needs one, and that
  /// lookup goes through the native masked table.
  ///
  /// Throws [VmpFault] on any native fault and [VmpWireError] when an argument
  /// cannot be represented.
  static Object? call(int id, List<Object?> args) {
    initialize();
    final native = _native!;

    _args.reset();
    for (final a in args) {
      _args.value(a);
    }
    final argBytes = _args.takeBytes();

    final argBuf = malloc<Uint8>(argBytes.isEmpty ? 1 : argBytes.length);
    final outLen = malloc<Uint32>();
    var outCap = _defaultOutBytes;
    var outBuf = malloc<Uint8>(outCap);
    try {
      if (argBytes.isNotEmpty) {
        argBuf.asTypedList(argBytes.length).setAll(0, argBytes);
      }
      outLen.value = outCap;
      var rc = native.call(
          id, argBuf, argBytes.length, outBuf, outLen);
      if (rc == VmpStatus.badArgument && outLen.value > outCap) {
        // The return value did not fit: retry once with the reported size.
        malloc.free(outBuf);
        outCap = outLen.value;
        outBuf = malloc<Uint8>(outCap);
        outLen.value = outCap;
        rc = native.call(id, argBuf, argBytes.length, outBuf, outLen);
      }
      if (rc != VmpStatus.ok) {
        throw VmpFault(rc, nameOf(id), _lastError());
      }
      final n = outLen.value;
      final raw = Uint8List.fromList(outBuf.asTypedList(n));
      return WireReader(raw).value();
    } finally {
      malloc.free(argBuf);
      malloc.free(outBuf);
      malloc.free(outLen);
    }
  }

  /// Invokes a protected function by name. Intended for tests and diagnostics;
  /// release code should use the generated stubs, which dispatch by id.
  static Object? callNamed(String name, List<Object?> args) {
    initialize();
    final native = _native!;
    _args.reset();
    for (final a in args) {
      _args.value(a);
    }
    final argBytes = _args.takeBytes();
    final argBuf = malloc<Uint8>(argBytes.isEmpty ? 1 : argBytes.length);
    final outLen = malloc<Uint32>();
    var outCap = _defaultOutBytes;
    var outBuf = malloc<Uint8>(outCap);
    final namePtr = name.toNativeUtf8();
    try {
      if (argBytes.isNotEmpty) {
        argBuf.asTypedList(argBytes.length).setAll(0, argBytes);
      }
      outLen.value = outCap;
      var rc = native.callNamed(
          namePtr, argBuf, argBytes.length, outBuf, outLen);
      if (rc == VmpStatus.badArgument && outLen.value > outCap) {
        malloc.free(outBuf);
        outCap = outLen.value;
        outBuf = malloc<Uint8>(outCap);
        outLen.value = outCap;
        rc = native.callNamed(namePtr, argBuf, argBytes.length, outBuf, outLen);
      }
      if (rc != VmpStatus.ok) {
        throw VmpFault(rc, name, _lastError());
      }
      final n = outLen.value;
      return WireReader(Uint8List.fromList(outBuf.asTypedList(n))).value();
    } finally {
      malloc.free(namePtr);
      malloc.free(argBuf);
      malloc.free(outBuf);
      malloc.free(outLen);
    }
  }

  static String _lastError() {
    try {
      final p = _native?.lastError();
      if (p == null || p == nullptr) return '';
      return p.toDartString();
    } catch (_) {
      return '';
    }
  }

  /// Path of the runtime file, when the platform keeps it as a separate file.
  /// Returns null when the runtime is statically linked into the runner (which
  /// is what happens on Windows and Linux desktop).
  static String? runtimeFilePath() {
    if (Platform.isAndroid) {
      // Flutter extracts packaged .so files here.
      return 'libdartvmp.so';
    }
    if (Platform.isIOS || Platform.isMacOS) return 'dartvmp.framework/dartvmp';
    return null;
  }

  /// True when the file returned by [runtimeFilePath] exists on disk.
  static bool runtimeFileExists() {
    final p = runtimeFilePath();
    if (p == null) return false;
    return File(p).existsSync();
  }
}
