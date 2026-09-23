/*
 * dartvmp.h - Public C ABI of the DartVMP native runtime.
 *
 * This header is the *only* contract between the Dart side (lib/src/*.dart)
 * and the native side (src/*.c). It is intentionally tiny: three functions
 * and one struct. Everything else in src/ is an implementation detail that
 * the compiler toolchain (tool/vmpc) mirrors in Dart.
 *
 * THREAT MODEL NOTE
 * -----------------
 * The protected bytecode is compiled offline and shipped *encrypted* inside
 * this shared object. The VM image only ever exists in plaintext inside a
 * guarded heap allocation that is:
 *   1. allocated with page granularity,          (vmp_secure_alloc)
 *   2. made non-dumpable / non-readable-on-fork, (vmp_secure_harden)
 *   3. wiped with a volatile barrier,            (vmp_secure_wipe)
 *   4. released with VirtualFree/MAP_FREE.       (vmp_secure_free)
 *
 * A debugger attached *while a protected call is in flight* can still read
 * the plaintext image. That is unavoidable for any in-process interpreter and
 * is why the anti-debug / anti-hook layer (dartvmp_antidebug.c) exists.
 */
#ifndef DARTVMP_H_
#define DARTVMP_H_

#include <stddef.h>
#include <stdint.h>

#if defined(_WIN32)
#define DARTVMP_API __declspec(dllexport)
#else
#define DARTVMP_API __attribute__((visibility("default")))
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------ */
/* ABI version - bumped whenever the bytecode container format or the  */
/* wire format changes. The compiler tool embeds the same constant.    */
/* ------------------------------------------------------------------ */
#define DARTVMP_ABI_VERSION 1u

/* Hard limits enforced by the interpreter (defence against malformed or */
/* tampered bytecode).                                                    */
#define DARTVMP_MAX_STRING (1u << 20)  /* 1 MiB per string            */
#define DARTVMP_MAX_DEPTH 64u          /* call depth                  */
#define DARTVMP_MAX_STEPS (1u << 26)   /* ~67M bytecode ops per call  */

/* Status codes returned by dartvmp_call(). */
typedef enum DartVmpStatus {
  DARTVMP_OK = 0,
  DARTVMP_ERR_NOT_INITIALIZED = -1,
  DARTVMP_ERR_BAD_ARGUMENT = -2,
  DARTVMP_ERR_MODULE_MAGIC = -3,
  DARTVMP_ERR_MODULE_VERSION = -4,
  DARTVMP_ERR_MODULE_AUTH = -5, /* auth tag mismatch => tampered image   */
  DARTVMP_ERR_MODULE_CORRUPT = -6,
  DARTVMP_ERR_FUNCTION_NOT_FOUND = -7,
  DARTVMP_ERR_STEP_LIMIT = -8,
  DARTVMP_ERR_STACK_OVERFLOW = -9,
  DARTVMP_ERR_STACK_UNDERFLOW = -10,
  DARTVMP_ERR_TYPE = -11,
  DARTVMP_ERR_DIV_ZERO = -12,
  DARTVMP_ERR_INDEX_RANGE = -13,
  DARTVMP_ERR_DEPTH_EXCEEDED = -14,
  DARTVMP_ERR_OUT_OF_MEMORY = -15,
  DARTVMP_ERR_INVALID_OPCODE = -16,
  DARTVMP_ERR_JUMP_RANGE = -17,
  DARTVMP_ERR_DEBUGGER = -18,
  DARTVMP_ERR_INTERNAL = -19,
  /*
   * The function's call policy refused this call; see `guard_mode` below.
   *
   * Distinct on purpose: the caller has to be able to tell "your function said
   * no" from "the runtime refused to run it", and a policy failure that looked
   * like a normal negative answer would be a licence check silently answering
   * "invalid", which is exactly the kind of protection-induced behaviour change
   * this design forbids.
   */
  DARTVMP_ERR_TOO_MANY_CALLS = -20,
} DartVmpStatus;

/*
 * Result of a protected call.
 *
 *   type      - one of the DVMP_T_* wire tags (see src/dvmp_wire.h)
 *   i64       - payload for DVMP_T_INT / DVMP_T_BOOL / unit (0)
 *   str/len   - payload for DVMP_T_STR; points into the call-scoped arena
 *               and is ONLY valid until the next dartvmp_call().
 *   steps     - how many bytecode instructions were executed (diagnostics)
 */
typedef struct DartVmpResult {
  int32_t type;
  int32_t status;
  int64_t i64;
  const uint8_t *str;
  uint32_t len;
  uint64_t steps;
} DartVmpResult;

/* ------------------------------------------------------------------ */
/* Public API                                                          */
/* ------------------------------------------------------------------ */

/*
 * One-time initialisation. Safe to call more than once.
 * `probe` may be NULL; when non-NULL the runtime copies at most `probe_len`
 * bytes from the *decrypted* module image into it, which the Dart side uses
 * to prove that the shipped image is offline-encrypted.
 *
 * Returns DARTVMP_OK on success, otherwise a negative DartVmpStatus.
 */
DARTVMP_API int32_t dartvmp_init(const uint8_t *probe, uint32_t probe_len,
                                 uint64_t *probe_out_len);

/*
 * Execute protected function `func_id`.
 *
 *   args/args_len - wire-encoded argument record stream (src/dvmp_wire.h)
 *   out/out_len   - receives the wire-encoded return value. If `out` is NULL
 *                   only the required size is reported in *out_len.
 *
 * Returns a DartVmpStatus. On DARTVMP_OK, *out_len holds the number of bytes
 * written (or required).
 */
DARTVMP_API int32_t dartvmp_call(uint32_t func_id, const uint8_t *args,
                                 uint32_t args_len, uint8_t *out,
                                 uint32_t *out_len);

/* Execute by *name* - used by tests and by the host-app registration path
 * when function ids are not stable across builds. */
DARTVMP_API int32_t dartvmp_call_named(const char *name, const uint8_t *args,
                                       uint32_t args_len, uint8_t *out,
                                       uint32_t *out_len);

/* Number of protected functions in the shipped module. */
DARTVMP_API uint32_t dartvmp_function_count(void);

/*
 * Build id compiled into this runtime's module image.
 *
 * Exposed in release builds as well as diagnostic ones: it is a compile-time
 * constant of the generated header and discloses nothing that the header does not
 * already carry in masked form, while letting a host verify that the module it is
 * talking to is the one it was built against.
 */
DARTVMP_API uint32_t dartvmp_build_id(void);

/*
 * Metadata for the i-th protected function (0-based, sorted by name).
 * Returns DARTVMP_OK and fills the out params, or a negative status.
 * `name` is a NUL-terminated ASCII identifier, valid for the process
 * lifetime (it lives in the *encrypted* static image's metadata section,
 * decrypted once at init).
 */
DARTVMP_API int32_t dartvmp_function_info(uint32_t index, const char **name,
                                          uint32_t *arity, uint32_t *func_id);

/*
 * Human-readable description of a status code, plus the last internal error
 * detail recorded by the VM (file:line style diagnostic). Never NULL.
 */
DARTVMP_API const char *dartvmp_status_name(int32_t status);
DARTVMP_API const char *dartvmp_last_error(void);

/* Diagnostics: bytes of the decrypted image currently resident, and the
 * number of secure buffers alive. Useful for asserting "wipe after use". */
DARTVMP_API uint32_t dartvmp_secure_bytes_live(void);

/*
 * Copies the first `n` bytes of the unmasked container into `out` and reports
 * the compiled-in build id.
 *
 * This exists so a test can prove the runtime holds the image the compiler
 * emitted for *this* build - a stale object file or a mismatched generated
 * header otherwise shows up only as an opaque "wrong magic" failure. It reveals
 * nothing that is not already in the shipped binary in masked form.
 */
#if defined(DVMP_DIAGNOSTICS)
DARTVMP_API int32_t dartvmp_image_probe(uint8_t *out, uint32_t n,
                                        uint32_t *out_len,
                                        uint32_t *build_id);

/*
 * Reports the key state behind the two halves of the module's lifecycle:
 *
 *   master_seed - the seed stored in the shipped container. Public by design;
 *                 offline distribution means the binary carries its own key
 *                 material.
 *   store_key   - the key of the runtime-only instruction store: fresh entropy,
 *                 redrawn on every open, written into no header and into nothing
 *                 that ships.
 *   store_salt  - the opcode-permutation salt inside the store, derived from
 *                 store_key and forced non-zero.
 *
 * A test asserts master_seed != store_key and that store_key rotates across
 * calls. If the first ever fails, the instruction store is sealed under something
 * readable on disk, and a dump plus the shipped binary recovers it offline - a
 * regression no functional test would notice, because every call still returns the
 * right answer. If the second fails, a captured store opens the next call's.
 *
 * This used to report the header seed of `m->work`, a decoy second container.
 * That buffer is gone; see the note in dvmp_module.c on why a re-sealed container
 * could no longer be built honestly once the body's code region started being
 * wiped.
 */
DARTVMP_API int32_t dartvmp_session_probe(uint64_t *master_seed,
                                          uint64_t *store_key,
                                          uint64_t *store_salt);

/*
 * Reports whether the decrypted body is currently resident (1) or wiped (0).
 *
 * This is the observable behind the design's central claim - that the plaintext
 * exists only for the duration of a call - so the test suite can assert it rather
 * than trust the prose. It reports state, never content, so it cannot become
 * another route to the protected bytes.
 */
DARTVMP_API int32_t dartvmp_plaintext_probe(uint32_t *live);

/*
 * Reports how many bytes of the decrypted-body buffer are non-zero.
 *
 * The body must be entirely zero while the module is sealed, so this is the check
 * that has teeth: the `unsealed` flag can read 0 while the buffer is still full of
 * plaintext - which is exactly what an earlier revision did, and why a
 * flag-based test passed while a memory dump found the decoded bytecode sitting
 * in one page. Deliberately reports a *count*, never content, so it cannot become
 * another route to the protected bytes.
 */
DARTVMP_API int32_t dartvmp_body_residue(uint32_t *nonzero, uint32_t *any);

/*
 * Clears every call-policy usage counter, so a test can assert both that a policy
 * refuses calls past its budget and that the function still computes correctly.
 * Diagnostics only: it is compiled out with -DDVMP_DIAGNOSTICS=OFF, because a
 * shipped library that can reset its own rate limits has no rate limits.
 */
DARTVMP_API int32_t dartvmp_guard_reset(void);

/*
 * Diagnostics that expose the decoded constants the interpreter is working
 * with, so a test can diff them against the compiler's own view:
 *
 *   dartvmp_mask_probe - the image mask and masked word for a given index.
 *   dartvmp_code_probe - the first `n` decoded instruction bytes of a function.
 *
 * Between them, a "wrong opcode" or "mask drift" bug becomes a precise diff
 * instead of an opaque fault. Neither reveals anything the shipped binary does
 * not already contain.
 */
DARTVMP_API void dartvmp_mask_probe(uint32_t index, uint64_t *mask,
                                    uint64_t *word);
DARTVMP_API int32_t dartvmp_code_probe(uint32_t func, uint8_t *out, uint32_t n,
                                       uint32_t *out_len);
/*
 * Copies one function's parsed descriptor out (arity, locals, slot window base,
 * code offset and length). Lets a test diff the runtime's view of the module
 * against the compiler's, which is otherwise only inferable from a downstream
 * type error.
 */
DARTVMP_API int32_t dartvmp_desc_probe(uint32_t func, uint32_t *arity,
                                       uint32_t *locals, uint32_t *slot_base,
                                       uint32_t *code_off, uint32_t *code_len);
/*
 * Reads one frame slot's tag and bits from the live interpreter after a call.
 * Diagnostics only: this is how a test sees which parameter a function actually
 * received, instead of inferring it from a downstream type error.
 */
DARTVMP_API int32_t dartvmp_slot_probe(uint32_t slot, int64_t *tag,
                                       int64_t *bits);

/*
 * Diagnostics for the instruction-stream residency model.
 *
 * The decoded instruction stream is not resident in bulk: `open` re-encrypts it
 * under a process-only key and the interpreter materialises one function at a time
 * into a small fixed number of slots. These two entry points are how a test
 * asserts that, because the property is otherwise invisible from Dart:
 *
 *   dartvmp_code_chunk_probe - slot count, how many hold decoded code right now,
 *                              the peak since the process started, the largest
 *                              function's stream length, and the module's total
 *                              instruction bytes. `peak * largest` is an upper
 *                              bound on the decoded code that was ever
 *                              simultaneously resident, and the claim being
 *                              checked is that it is below `total`.
 *   dartvmp_code_residue     - four counts, all of which must be zero while the
 *                              module is sealed: non-zero bytes across the decoded
 *                              slots, in the body's code region at the last seal
 *                              (plus that value's peak over the process), and in
 *                              the instruction store. The body-region pair is the
 *                              sharper check: sealing is the only instant at which
 *                              "the stream was still sitting in the body" is
 *                              observable from outside a call, and the design this
 *                              replaced would have reported the module's entire
 *                              instruction length there. The store count is the
 *                              check that the runtime-keyed store does not outlive
 *                              the call either.
 *
 * Neither reveals a byte of protected code: the chunk probe reports counts and
 * the residue probe reports counts, so a test can prove the plaintext window is
 * shut without becoming a way to read it. Both are compiled out with
 * -DDVMP_DIAGNOSTICS=OFF.
 */
DARTVMP_API void dartvmp_code_chunk_probe(uint32_t *slots, uint32_t *live,
                                          uint32_t *peak, uint32_t *largest,
                                          uint32_t *total);
DARTVMP_API void dartvmp_code_residue(uint32_t *slots, uint32_t *body_region,
                                      uint32_t *body_region_peak,
                                      uint32_t *store);

/*
 * SHA-256 of `len` bytes into `out` (32 bytes), so the published NIST vectors can be
 * run against the implementation the container's keystream is built on.
 *
 * This exists because a hand-written hash has a failure mode that is invisible from
 * inside the build: if it is subtly wrong, the Dart generator is changed to match it,
 * the container still round-trips, every test still passes, and the mask is applied
 * with a function of unknown strength. The vectors are the only thing that
 * distinguishes "SHA-256" from "some mixing".
 *
 * Diagnostics only; compiled out with -DDVMP_DIAGNOSTICS=OFF.
 */
DARTVMP_API int32_t dartvmp_sha256_probe(const uint8_t *data, uint32_t len,
                                         uint8_t *out);

/*
 * Diagnostics only; the operand width the decoder assigns to `op`, or DVMP_OP_MAX
 * (0x26) when `op` is not an opcode of this build.
 *
 * This is the runtime's half of a differential check against the assembler's
 * `kOperandBytes` (tool/vmpc/lib/src/opcodes.dart), run by
 * tool/verify_wire_widths.py for every byte 0..255. The two tables have to agree
 * exactly: they drive the same sequential walk from opposite ends (the assembler emits
 * the operands, the decoder steps over them), and an opcode added on one side only
 * makes the decode silently desynchronise rather than fail. Answering DVMP_OP_MAX for a
 * non-opcode is what lets the check compare the *size* of the opcode set too.
 */
DARTVMP_API uint32_t dartvmp_wire_probe(uint32_t op);

/*
 * Reports the instrumentation verdict and the reason for it, and (in a diagnostics
 * build only) forces the verdict so the *reaction* to detection can be tested.
 *
 * The reaction is what matters and it is deliberately mild: detection narrows the
 * decoded-function cache to one slot. It never changes an answer, because a debugger
 * check that alters results breaks real users the moment it false-positives. Refusing
 * to initialise at all is available via -DDVMP_ANTIDEBUG_REFUSE, opt-in.
 *
 * Compiling the force hook in would let anyone who can call the library declare the
 * environment trusted, so it is behind the same switch as the probes.
 */
DARTVMP_API int32_t dartvmp_instrumented_probe(uint32_t *instrumented,
                                               const char **reason);
DARTVMP_API void dartvmp_antidebug_force(int on, const char *reason);

/*
 * Entry-point integrity. The cheapest attack on this system is not to read the
 * protected logic but to patch the *answer*, and both the common tools (Frida's
 * Interceptor, Dobby) and a hand-made patch put a branch where the target's first
 * instruction was. This scan looks for exactly that at each of the nine ABI entry
 * points.
 *
 * `init` runs it once and folds the verdict into the same reaction instrumentation
 * gets: a one-slot decoded-function cache, never a different answer. This probe
 * re-scans on demand, which is what lets a test patch an entry point and observe the
 * verdict change - the init-time value necessarily cannot.
 *
 * Returns the number of entry points found patched. `hooked_mask` receives the same
 * value as a bitmask indexed by dvmp_integrity.c's entry list, `scanned` the number of
 * entry points covered, and `selftest_ok` the decoder's own known-encoding vectors -
 * a decoder that cannot be seen to reject anything is not a check.
 */
/*
 * The call policy the *runtime* holds for `func`, as opposed to what the container declares
 * or the manifest recorded. `mode` is 0 none / 1 rate / 2 once; `used` and `window_start`
 * are the live usage of the current rate window. Returns 0 on success.
 *
 * Exists because those three views disagreed once and the symptom was silence: the policy
 * was declared, encoded and independently decoded, and never enforced.
 */
DARTVMP_API uint32_t dartvmp_guard_probe(uint32_t func, uint32_t *mode,
                                         uint32_t *budget, uint32_t *window_ms,
                                         uint32_t *used, uint64_t *window_start);

DARTVMP_API uint32_t dartvmp_integrity_probe(uint32_t *hooked_mask, uint32_t *scanned,
                                             uint32_t *selftest_ok);

#endif /* DVMP_DIAGNOSTICS */

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* DARTVMP_H_ */
