/*
 * dvmp_internal.h - shared internals of the DartVMP native runtime.
 *
 * Not installed and not part of the public ABI (see dartvmp.h). Everything the
 * interpreter needs lives behind this header so the translation units can stay
 * small enough to audit.
 */
#ifndef DVMP_INTERNAL_H_
#define DVMP_INTERNAL_H_

#include <stdint.h>
#include <stddef.h>

#include "dartvmp.h"
#include "dvmp_wire.h"
/* For DVMP_ALWAYS_INLINE / DVMP_VMPACKER_TARGET / DVMP_NO_BUILTIN. Included here,
 * not only in the .c files that mark a target, because `dvmp_fnv1a64_core` below is
 * declared with DVMP_ALWAYS_INLINE and that macro has to be visible where it is
 * defined. dvmp_vmpacker.h includes nothing, so there is no cycle. */
#include "dvmp_vmpacker.h"

/* ------------------------------------------------------------------ */
/* Secure memory (dvmp_secure.c)                                       */
/* ------------------------------------------------------------------ */

/*
 * Allocates a page-rounded buffer suitable for holding decrypted bytecode.
 *
 * On POSIX the mapping is made private and anonymous; on Windows it is a
 * non-shareable VirtualAlloc region. Both are page aligned so that the
 * protection of the *instruction pages* can be tightened individually.
 */
void *vmp_secure_alloc(size_t size);
/* Releases a buffer from vmp_secure_alloc(). */
void vmp_secure_free(void *p, size_t size);

/*
 * Overwrites `size` bytes at `p` and prevents the compiler from eliding the
 * store. Used for the "wipe after use" guarantee.
 */
void vmp_secure_wipe(void *p, size_t size);

/*
 * Asks the OS not to include this mapping in core dumps and, where supported,
 * not to leak it across fork(). Best effort: failures are ignored because the
 * protection is defence in depth, not a correctness requirement.
 */
void vmp_secure_harden(void *p, size_t size);

/* Bytes currently held by live secure allocations (diagnostics / tests). */
uint32_t vmp_secure_bytes_live(void);

/* Secure memset that also works through a volatile pointer. */
void vmp_secure_zero(void *p, size_t size);

/* ------------------------------------------------------------------ */
/* SHA-256 and the keyed keystream (dvmp_sha256.c)                     */
/* ------------------------------------------------------------------ */

/*
 * SHA-256 of `len` bytes into `out` (32 bytes). Self-contained: no libcrypto, no
 * allocation, so it is safe on the container-open path and in an Android build with
 * nothing but libc.
 */
void dvmp_sha256(const uint8_t *data, size_t len, uint8_t out[32]);

/*
 * The keystream word for the static image and the entry-name blob:
 *
 *     SHA256(le64(key) || le64(index))[0..8), read little-endian
 *
 * Two properties, both required, and neither is provided by a mix function:
 * knowing one word does not reveal `key` (the map is not invertible), and knowing
 * one word does not reveal any other word (each index is an independent keyed
 * function rather than a step of a stream). See the header of dvmp_sha256.c for what
 * this does and does not buy.
 */
uint64_t dvmp_mask_keystream(uint64_t key, uint64_t index);

/* Hashes arbitrary input, so the test suite can check the published NIST vectors
 * against this implementation instead of trusting it. Diagnostics only. */
int32_t dvmp_sha256_probe(const uint8_t *data, uint32_t len, uint8_t out[32]);

/* ------------------------------------------------------------------ */
/* Anti-debug / anti-hook (dvmp_antidebug.c)                           */
/* ------------------------------------------------------------------ */

/*
 * Returns non-zero when the process looks instrumented. Cheap enough to call
 * once per protected invocation; the caller decides whether to abort.
 *
 * Detection is *advisory*: it cannot see a kernel-level debugger, and any
 * list of Frida signatures goes stale. Its value is raising the cost of the
 * trivial `frida -U -f com.example` workflow, nothing more.
 */
int vmp_is_instrumented(void);

/* Human-readable reason for the last positive vmp_is_instrumented(). */
const char *vmp_instrumentation_reason(void);

/*
 * Forces the instrumentation verdict, for tests.
 *
 * The reaction below is only exercised when something is actually attached, which a
 * test suite cannot arrange - so without this the "instrumentation detected" path is
 * untestable and therefore unverified. Diagnostics only: compiled out with
 * -DDVMP_DIAGNOSTICS=OFF, because a shipped library that can be told "you are being
 * debugged" is a shipped library that can be told anything.
 *
 * `reason` may be NULL to clear.
 */
void vmp_antidebug_force(int on, const char *reason);

/* ------------------------------------------------------------------ */
/* Entry-point integrity (dvmp_integrity.c)                            */
/* ------------------------------------------------------------------ */

/*
 * The cheapest attack on this system is not to read the protected logic but to patch
 * the answer - return `true` from the licence check, or intercept the entry point that
 * produces it. Both the common tools (Frida's Interceptor, Dobby) and a hand-made
 * patch leave the same mark: a branch where the target's first instruction used to be.
 *
 * `dvmp_words_look_hooked` decodes that from a raw byte buffer rather than from a
 * function pointer, so the decoder is testable against known encodings on any host.
 *
 * Honest ceiling: this finds a hook that *begins* with a branch. A hook that saves the
 * prologue first, or that patches the caller, is not found, and the check itself can be
 * patched by anyone who knows it is there. It raises the cost of the trivial patch.
 */
int dvmp_words_look_hooked(const uint8_t *words, uint32_t len);

/* Scans `count` entry points, returning the number found hooked; `hooked_out` (may be
 * NULL) receives a bitmask indexed by position in `entries`. */
uint32_t dvmp_integrity_scan(const void *const *entries, uint32_t count,
                             uint32_t *hooked_out);

/* Runs the decoder's known-encoding vectors. Returns 1 when every one decodes as
 * expected, 0 otherwise - a decoder that cannot be seen to fail is not a check. */
int dvmp_integrity_selftest(void);

/* Number of ABI entry points the scan covers, for callers that report it. */
uint32_t dvmp_integrity_entry_count(void);

/* Scans the canonical list of ABI entry points. Returns the number found hooked and,
 * through `hooked_out` (may be NULL), the same value as a bitmask. */
uint32_t dvmp_integrity_check_entries(uint32_t *hooked_out);

#if defined(DVMP_DIAGNOSTICS)
/* Diagnostics: re-scans (so a test can patch an entry point and see the verdict change,
 * which the init-time value cannot do) and reports the decoder's self-test. */
uint32_t dvmp_integrity_probe(uint32_t *hooked_mask, uint32_t *scanned,
                              uint32_t *selftest_ok);
#endif

/* ------------------------------------------------------------------ */
/* Value representation                                                */
/* ------------------------------------------------------------------ */

enum {
  DVMP_V_NIL = 0,
  DVMP_V_INT = 1,
  DVMP_V_BOOL = 2,
  DVMP_V_STR = 3,
  DVMP_V_LIST = 4,
  DVMP_V_MAP = 5,
  /* Not an object kind: builders are their own allocation (DvmpBuilder) and
   * are only ever reachable as an intermediate value on the eval stack. */
  DVMP_V_BUILDER = 6,
};

/* Heap object header. Everything the interpreter allocates on behalf of the
 * bytecode is one of these, so a single tag switch covers the whole heap. */
typedef struct DvmpObj {
  uint8_t kind;
  uint32_t len;   /* element count for LIST/MAP, byte length for STR */
  uint32_t cap;
} DvmpObj;

/*
 * Mutable string builder.
 *
 * `strPush` must be able to grow the buffer, which moves it - so the operand
 * on the stack cannot be a pointer to the character data. It is a handle to
 * this cell instead, and the cell address never changes. Without this the
 * compiler's `a + b + c` lowering would silently read freed bytes as soon as
 * a concatenation exceeded the initial capacity.
 */
/*
 * Builder handle.
 *
 * Carried on the eval stack as a `DVMP_TAG_OBJ` slot whose `bits` IS the
 * `DvmpBuilder *`; there is no `DvmpObj` header. An earlier version smuggled the
 * pointer through `DvmpObj.cap`, which is a `uint32_t` - so on a 64-bit target
 * every string concatenation truncated the pointer and dereferenced garbage,
 * which is a hard access violation rather than a guardable fault.
 */
typedef struct DvmpBuilder {
  uint8_t *data;
  uint32_t len;
  uint32_t cap;
} DvmpBuilder;

typedef struct DvmpListSlot {
  int64_t tag;
  int64_t bits;
} DvmpListSlot;

typedef struct DvmpMapEntry {
  int64_t ktag;
  int64_t kbits;
  int64_t vtag;
  int64_t vbits;
} DvmpMapEntry;

typedef union DvmpValue {
  int64_t i;
  DvmpObj *obj;
} DvmpValue;

/* Tags used in slots and on the operand stack. */
enum {
  DVMP_TAG_NIL = 0,
  DVMP_TAG_INT = 1,
  DVMP_TAG_BOOL = 2,
  DVMP_TAG_OBJ = 3,
  /*
   * A `DvmpBuilder *` that is NOT a `DvmpObj`. Builders are their own allocation
   * and only ever reachable as an intermediate on the eval stack, so they need
   * their own tag: with `DVMP_TAG_OBJ` the host's `strBuild`/`strPush` could be
   * handed a string and would read it as a builder - treating `kind`/`len` as the
   * data pointer - which a crafted container turns into a wild-pointer
   * dereference.
   */
  DVMP_TAG_BUILDER = 4,
};

/* Collection limits: a malformed or hostile bytecode image must not be able to
 * make the interpreter allocate without bound. */
#define DVMP_MAX_LIST 65536u
#define DVMP_MAX_MAP 65536u

typedef struct DvmpSlot {
  int64_t tag;
  int64_t bits;
} DvmpSlot;

/* ------------------------------------------------------------------ */
/* Arena (dvmp_value.c)                                                */
/* ------------------------------------------------------------------ */

/*
 * Bump allocator with a chunk list. Every protected call resets it, so the
 * runtime never leaks and never needs a tracing collector: protected functions
 * are pure and their object graphs die with the call.
 */
typedef struct DvmpArenaChunk {
  struct DvmpArenaChunk *next;
  size_t used;
  size_t cap;
  /* payload follows */
} DvmpArenaChunk;

typedef struct DvmpArena {
  DvmpArenaChunk *head;
  size_t total;
} DvmpArena;

void dvmp_arena_init(DvmpArena *a);
void *dvmp_arena_alloc(DvmpArena *a, size_t size);
/* Intention-revealing no-op; see the note in dvmp_value.c. */
void dvmp_arena_free(DvmpArena *a, void *p);
void dvmp_arena_reset(DvmpArena *a);
void dvmp_arena_destroy(DvmpArena *a);

/* ------------------------------------------------------------------ */
/* Wire format (dvmp_value.c)                                          */
/* ------------------------------------------------------------------ */

typedef struct DvmpReader {
  const uint8_t *p;
  uint32_t len;
  uint32_t pos;
  int error;
} DvmpReader;

typedef struct DvmpWriter {
  uint8_t *p;
  uint32_t cap;
  uint32_t len;
  int overflow;
} DvmpWriter;

int dvmp_read_value(DvmpReader *r, DvmpArena *a, DvmpSlot *out);
void dvmp_write_value(DvmpWriter *w, DvmpArena *a, DvmpSlot v);

void dvmp_write_u8(DvmpWriter *w, uint8_t v);
void dvmp_write_i64(DvmpWriter *w, int64_t v);
void dvmp_write_bytes(DvmpWriter *w, const uint8_t *p, uint32_t n);

/* Value constructors. */
DvmpSlot dvmp_nil(void);
DvmpSlot dvmp_int(int64_t v);
DvmpSlot dvmp_bool(int v);
DvmpSlot dvmp_obj_slot(DvmpObj *o);
DvmpObj *dvmp_new_str(DvmpArena *a, const uint8_t *bytes, uint32_t len);
DvmpObj *dvmp_new_list(DvmpArena *a, uint32_t cap);
DvmpObj *dvmp_new_map(DvmpArena *a, uint32_t cap);
DvmpBuilder *dvmp_new_builder(DvmpArena *a, uint32_t hint);
int dvmp_builder_append(DvmpArena *a, DvmpBuilder *b, const uint8_t *data,
                        uint32_t len);
int dvmp_str_eq_c(DvmpObj *o, const char *c);
const char *dvmp_obj_str(DvmpObj *o);
int dvmp_list_push(DvmpArena *a, DvmpObj **list, DvmpSlot v);
int dvmp_list_get(DvmpObj *l, int64_t index, DvmpSlot *out);
int dvmp_map_set(DvmpArena *a, DvmpObj **map, DvmpSlot k, DvmpSlot v);
int dvmp_map_get(DvmpObj *m, DvmpSlot k, DvmpSlot *out);

/* Hashes shared with the Dart compiler (dvmp_value.c). The seed parameter
 * makes FNV-1a usable as a keyed MAC for the container auth tag. */
uint32_t dvmp_crc32(const uint8_t *p, uint32_t n);

#if defined(DVMP_DIAGNOSTICS)
/*
 * The decoder's operand width for `op`, or DVMP_OP_MAX when `op` is not one of this
 * build's opcodes (dvmp_module.c). It exists so tool/verify_wire_widths.py can compare
 * the runtime's walk against the assembler's `kOperandBytes` for every byte 0..255
 * instead of comparing two hand-copied tables - the failure it is there to catch is an
 * opcode added to one side only, which desynchronises the decode silently.
 */
uint32_t dvmp_module_wire_width(uint32_t op);
#endif

/*
 * FNV-1a, defined inline in this header so `dvmp_body_tag` can absorb it.
 *
 * There is exactly one copy of the loop: `dvmp_fnv1a64` is a wrapper around this.
 * Two copies of a hash that has to agree with `Packer.pack` in Dart bit for bit is
 * a correctness hazard, not a style question.
 *
 * Why it has to be inline *here* rather than just left to the optimiser:
 * `dvmp_body_tag` is a VMPacker target, and VMPacker 1.3 cannot execute a `bl`
 * (it keeps the link-time address and does not re-derive it from the load bias, so
 * the call lands at a fixed, wrong address - measured on device as "fault addr
 * 0x6d60", which is exactly where `dvmp_fnv1a64` sits in the unslid image). A call
 * left inside a virtualized function is therefore a crash, not a missed
 * optimisation. clang emitted the call for both of this function's hash passes
 * until this was forced.
 */
DVMP_ALWAYS_INLINE uint64_t dvmp_fnv1a64_core(const uint8_t *p, uint32_t n,
                                              uint64_t seed) {
  uint64_t h = seed;
  for (uint32_t i = 0; i < n; i++) {
    h ^= (uint64_t)p[i];
    h *= 0x100000001B3ull;
  }
  return h;
}

/* The out-of-line entry point, kept for dvmp_host.c and for the host tests. */
uint64_t dvmp_fnv1a64(const uint8_t *p, uint32_t n, uint64_t seed);

/* ------------------------------------------------------------------ */
/* Module (dvmp_module.c)                                              */
/* ------------------------------------------------------------------ */

typedef struct DvmpFuncDesc {
  const uint8_t *name;
  uint32_t name_len;
  uint16_t arity;
  uint16_t locals;
  uint16_t max_stack;
  /*
   * Base of this function's slot window in the shared frame-slot array: the
   * compiler emits `load`/`store` with *absolute* indices, so a frame's slots
   * are `[slot_base, slot_base + arity + locals)`.
   *
   * The window includes the argument slots, and `dvmp_vm_run` sets
   * `f->slot_base` to this value - it is NOT `argc`. Getting that wrong makes
   * the callee's prologue `store slot=arity` land outside its own window.
   */
  uint16_t slot_base;
  uint32_t code_len;
  /*
   * Offset of the function's code *relative to the start of the code region*.
   *
   * Deliberately an offset, not a pointer. The code region moves whenever
   * `unseal` rewrites `m->body`, so a cached absolute pointer goes stale and the
   * interpreter ends up executing whatever happens to be at the old address.
   * `dvmp_vm_run` derives the pointer from `m->code + code_off` at call time.
   */
  uint32_t code_off;
  /*
   * Call policy for this function (DVMP_GUARD_*), and the rate budget when the
   * mode is RATE. Declared in the protected source; see dvmp_wire.h.
   */
  uint8_t guard_mode;
  uint16_t guard_budget;   /* calls allowed per window */
  uint32_t guard_window_ms; /* window length */
} DvmpFuncDesc;

/*
 * Runtime state for the call policies, indexed by function id.
 *
 * Deliberately NOT part of `DvmpFuncDesc`. Descriptors are rebuilt from the body on
 * every open - they have to be, because `seal` wipes the body - so anything stored
 * in one is reset per call. Keeping the usage counters there silently made every
 * policy a no-op: the counter returned to zero before each call, so a rate budget
 * never filled and a `once` guard could never fire. The *budget* is data from the
 * module; the *usage* is process state, and the two have different lifetimes.
 */
#define DVMP_MAX_GUARD_STATE 64u

typedef struct DvmpGuardState {
  uint32_t used;
  uint64_t window_start;
} DvmpGuardState;

/*
 * Number of functions whose decoded code can be resident at once.
 *
 * Four, and the number is a performance knob with no bearing on correctness: a
 * miss reloads from `code_store`, and `dvmp_code_ensure` revalidates the slot's
 * identity on every call, so a working set larger than this runs correctly and
 * merely pays a decrypt-and-un-permute per function entry.
 *
 * It is sized against the shape of real code rather than against the module: the
 * common pattern is one hot function with a couple of callees, which fits in two
 * slots, and a deeper call chain evicts the least recently loaded rather than the
 * least recently *used*, so an A-calls-B loop settles into two slots and never
 * misses again. Four slots at the largest function's size is the resident cost -
 * for this module 4 x 215 bytes, against 958 bytes for the whole stream; in a real
 * application the ratio is what matters, and it scales with the number of
 * functions rather than with the size of the program.
 */
#define DVMP_CODE_SLOTS 4u
/* `code_slots[].func` when the slot holds nothing. Not a legal function index. */
#define DVMP_CODE_NOFUNC 0xFFFFFFFFu

typedef struct DvmpCodeSlot {
  uint8_t *buf;    /* decoded, un-permuted code for one function */
  uint32_t cap;    /* bytes allocated for `buf` */
  uint32_t func;   /* function index in the slot, or DVMP_CODE_NOFUNC */
  uint32_t len;    /* decoded length of that function's stream */
} DvmpCodeSlot;

typedef struct DvmpModule {
  int ready;

  /*
   * 1 while the plaintext body is resident, i.e. between open and seal.
   *
   * The body is *always* canonical (un-permuted) - see the INVARIANT note in
   * dvmp_module.c - so this flag only tracks the plaintext window, not the
   * body's encoding.
   */
  int unsealed;

  /* Master image: the container exactly as shipped. Immutable, and the only
   * input to opening the plaintext window. */
  uint8_t *master;
  uint32_t master_len;

  /* Plaintext body: the decoded string table, constant pool and descriptors.
   * NON-ZERO ONLY between unseal and reseal. The instruction stream is NOT here
   * - it lives in `code_store`, encrypted, and is materialised one function at a
   * time into `code_slots`. */
  uint8_t *body;
  uint32_t body_len;

  /* Parsed views into `body`. Valid only while `unsealed` is set. */
  const uint8_t *strings;
  uint32_t strings_len;
  const int64_t *consts;
  uint32_t const_count;
  const uint8_t *str_tab; /* str_count * {u32 off, u32 len} */
  uint32_t str_count;
  DvmpFuncDesc *funcs;
  uint32_t func_count;
  /* Allocated capacity of `funcs`, in records. The array is allocated once and
   * reused across opens; see the note in `parse_body_views`. */
  uint32_t funcs_cap;
  /* Always NULL. It used to point at the decoded instruction stream inside
   * `body`; the stream is no longer resident there, and leaving this as a
   * convenience alias is how a future edit starts reading plaintext that is
   * supposed to be gone. `dvmp_code_ensure` is the only way to reach code. */
  const uint8_t *code;
  /* Length of the code region (not a pointer). Kept for validating each
   * function's `code_off`/`code_len` against the region they came from. */
  uint32_t code_len;

  /*
   * The instruction streams, encrypted under a key that exists only in this
   * process, laid out exactly like the region they came from so a function's
   * bytes are at `code_store + desc.code_off`.
   *
   * This is the whole point of the layout: `open` decrypts the shipped container,
   * verifies it, and then RE-ENCRYPTS the code under `code_key` and wipes the
   * plaintext copy out of `body`. So from that moment until `seal` there is no
   * decoded instruction stream anywhere in the process except the handful of
   * functions actually executing - see `code_slots`. Before this, a single
   * snapshot taken at any moment during a call yielded every protected function
   * at once.
   *
   * It is rebuilt with fresh entropy on every open, so a store recovered from one
   * call does not decrypt the next one's.
   */
  uint8_t *code_store;
  uint32_t code_store_len;
  uint64_t code_key;  /* runtime-only; never written anywhere */
  uint64_t code_salt; /* opcode-permutation salt for the store, forced non-zero */
  /*
   * The last pair actually used, kept for diagnostics only.
   *
   * `code_key` and `code_salt` are zeroed by `seal`, which is the right thing for
   * them and the wrong thing for a test: a caller between two calls sees 0 and
   * cannot tell "the store was sealed under runtime entropy" from "the store was
   * never encrypted". These two are not the live key - nothing reads them - so
   * retaining them cannot widen the plaintext window, and they let the suite assert
   * that the key (a) is not the shipped seed and (b) rotates on every open. Both
   * are properties no functional test would catch if they regressed.
   */
  uint64_t code_key_last;
  uint64_t code_salt_last;

  /* The decoded-function cache. See dvmp_code_ensure. */
  DvmpCodeSlot code_slots[DVMP_CODE_SLOTS];
  uint32_t code_slot_next; /* round-robin victim selector */
  uint32_t code_slots_live;
  uint32_t code_slots_peak; /* high-water mark, diagnostics only */
  /*
   * How many slots may actually hold decoded code.
   *
   * DVMP_CODE_SLOTS normally; 1 when instrumentation was detected. This is the whole
   * of the shipping reaction to a debugger: the window narrows from four functions to
   * one, and nothing else changes. A narrower window is a real cost to an attacker
   * who is single-stepping and dumping memory, and it cannot change an answer - which
   * matters because a false positive on a real device must not break the application.
   */
  uint32_t code_slots_usable;
  /* 1 when the process looked instrumented at init, or when an ABI entry point was
   * found patched. Diagnostics and the cache size above are the only consumers;
   * nothing in the interpreter reads it. */
  int instrumented;
  /* Bitmask of ABI entry points whose first instruction is an unconditional branch
   * (indexed by dvmp_integrity.c's list). Zero in a clean process. */
  uint32_t hooked_entries;
  /*
   * Non-zero bytes found in the body's *code region* at the last seal, and the
   * maximum over every seal so far.
   *
   * This is the observable that separates the residency model from the one it
   * replaced, and it is measured at the only instant where the difference is
   * visible from outside: sealing. `open` wipes the body's copy of the instruction
   * stream after moving it into `code_store`, so by seal time that region is all
   * zeroes and this is 0. The earlier design kept the decoded stream there for the
   * whole call, so this would have been the module's entire instruction length -
   * and a single dump during the call would have returned all of it.
   *
   * A maximum rather than the latest value, deliberately: a detector that a later
   * clean seal can reset is a detector that reports 0 for a process that leaked.
   */
  uint32_t code_region_residue;
  uint32_t code_region_residue_peak;

  /* Metadata: compiled-in (not secret), used for name lookups. */
  const DvmpEntryMeta *entries;
  uint32_t entry_count;

  /*
   * Call-policy usage, indexed by function id and kept OUT of the descriptors.
   *
   * Descriptors are rebuilt from the body on every open - necessarily, because
   * `seal` wipes the body - so per-descriptor counters are reset per call, which
   * made every policy a silent no-op. The budget is module data; the usage is
   * process state.
   */
  DvmpGuardState guard_state[DVMP_MAX_GUARD_STATE];

  /* Largest `arity` in the module. Each frame permanently reserves that many
   * slots at its base for the arguments of any call it makes, which is what
   * makes a callee's `store slot=0..arity-1` prologue safe for every caller. */
  uint32_t max_arity;

  /* Seed of the shipped container - the key that opens `master` into `body`.
   * Public by necessity (offline distribution), so it protects against static
   * analysis and nothing else. */
  uint64_t seed;

  uint32_t body_crc;
  uint64_t auth_tag;
} DvmpModule;

/* Loads, authenticates and parses the shipped image. Returns a DartVmpStatus.
 * Seals the plaintext again before returning. */
int32_t dvmp_module_init(void);
void dvmp_module_shutdown(void);
DvmpModule *dvmp_module(void);

/* Opens the plaintext window. Idempotent. */
int32_t dvmp_module_unseal(void);
/* Closes the window: wipes the plaintext body and rebuilds the working image
 * under a fresh random seed. Idempotent. */
void dvmp_module_reseal(void);

/*
 * Runs `fn(ctx)` with the module unsealed and guarantees a re-seal afterwards.
 * Every path that executes bytecode goes through this.
 */
int32_t dvmp_module_with_plaintext(int32_t (*fn)(void *), void *ctx);

const DvmpEntryMeta *dvmp_module_entries(uint32_t *count);
/* Returns the function id for `name`, or -1. */
int dvmp_module_find(const char *name);
/*
 * Copies the i-th entry's name into `out` (NUL-terminated, never longer than
 * `cap` - 1 bytes) and returns its length.
 *
 * The name table ships masked, so this un-masks on demand rather than pointing
 * into a decrypted buffer. Callers that only need a transient view should pass
 * a small stack buffer: keeping a long-lived plaintext copy of every name would
 * rebuild exactly the readable protection-surface list that masking removes.
 */
uint32_t dvmp_module_name_copy(uint32_t index, char *out, uint32_t cap);

/* Build id compiled into the generated image (dvmp_module.c). */
uint32_t dvmp_module_build_id(void);

/* Copies the first `n` decoded code bytes of `func` out, for diagnostics. */
int32_t dvmp_module_code_probe(uint32_t func, uint8_t *out, uint32_t n,
                               uint32_t *out_len);

/*
 * Instruction fetch (dvmp_module.c).
 *
 * Returns the base of `func`'s decoded instruction stream, materialising it into
 * one of `code_slots` if it is not already resident, or NULL if the module is not
 * open or the request does not match a function in it.
 *
 * CONTRACT - the interpreter depends on all three parts of this:
 *
 *   1. The returned pointer is the base of the *function*, not of the current
 *      instruction, so operand reads go through `pc + 1`.
 *   2. It stays valid until the next call to this function. Nothing else may
 *      release it, and no host builtin re-enters the interpreter (see the note in
 *      dartvmp.c on why the VM is deliberately not re-entrant), so an instruction
 *      can read its operands through it without pinning.
 *   3. A NULL return means the module is corrupt or closed, never "try again" -
 *      the caller must fault rather than retry, because a silent retry would turn
 *      a decode failure into an infinite loop.
 */
const uint8_t *dvmp_code_ensure(uint32_t func, uint32_t code_off,
                                uint32_t code_len);

/* Diagnostics: how many slots exist, how many hold decoded code right now, the
 * resident high-water mark since the process started, the largest function's
 * stream length, and the total instruction bytes in the module.
 *
 * The last two are there so a caller can state the comparison the design is
 * about - `peak * largest` against `total` - without reconstructing either from
 * elsewhere. All five are counts and lengths; none is a byte of protected code. */
void dvmp_module_chunk_probe(uint32_t *slots, uint32_t *live, uint32_t *peak,
                             uint32_t *largest, uint32_t *total);

/* Diagnostics: four counts, all of which must be zero while the module is sealed.
 *
 *   slots            - non-zero bytes across the decoded code slots
 *   body_region      - non-zero bytes in the body's code region at the last seal
 *   body_region_peak - the worst `body_region` over the process
 *   store            - non-zero bytes in the instruction store
 *
 * The body-region pair is the sharper check of the residency model: it is measured
 * at seal, which is the only instant at which "the decoded stream was still sitting
 * in the body" is observable from outside a call. `store` is the check that the
 * runtime-keyed store does not outlive the call either.
 *
 * Every value is a count, so none of them can become a way to read the protected
 * bytes. */
void dvmp_module_code_residue(uint32_t *slots, uint32_t *body_region,
                              uint32_t *body_region_peak, uint32_t *store);

/* Diagnostics: 1 while the decrypted body is resident. The suite asserts this is
 * 0 after a call returns - the observable behind "the plaintext window is the
 * call, not the process lifetime". */
int32_t dvmp_module_plaintext_probe(uint32_t *live);

/* Diagnostics: non-zero byte count in the body buffer, and a 1/0 summary. The
 * buffer must be entirely zero while the module is sealed; a *content-free*
 * residue report is what lets the suite check that without becoming another way
 * to read protected bytes. */
int32_t dvmp_module_body_residue(uint32_t *nonzero, uint32_t *any);

/* Diagnostics: clear every call-policy usage counter. Compiled out of a release
 * build, because a shipped library must not offer a way to reset its own rate
 * limits. */
int32_t dvmp_module_guard_reset(void);

#if defined(DVMP_DIAGNOSTICS)
/* What the runtime holds for a function's call policy: mode, budget, window, and how much
 * of the budget is used in the current window. Diagnostics only. */
int32_t dvmp_module_guard_probe(uint32_t func, uint32_t *mode, uint32_t *budget,
                                uint32_t *window_ms, uint32_t *used,
                                uint64_t *window_start);
#endif

/* Copies one function's parsed descriptor out, for diagnostics. */
int32_t dvmp_module_desc_probe(uint32_t func, uint32_t *arity, uint32_t *locals,
                               uint32_t *slot_base, uint32_t *code_off,
                               uint32_t *code_len);

/* Reads one frame slot from the live VM, for diagnostics. */
int32_t dvmp_module_slot_probe(uint32_t slot, int64_t *tag, int64_t *bits);

/* Copies the first `n` unmasked container bytes out, for diagnostics. */
int32_t dvmp_module_image_probe(uint8_t *out, uint32_t n, uint32_t *out_len,
                                uint32_t *build_id);

/* Seed of the shipped container vs. the key and salt of the runtime-only
 * instruction store. Diagnostics: lets a test assert that the store is not sealed
 * under anything on disk and that its key rotates across calls - a regression no
 * functional test would catch, because every call would still return the right
 * answer. */
int32_t dvmp_module_session_probe(uint64_t *master_seed, uint64_t *store_key,
                                  uint64_t *store_salt);

/* Mask and masked-word reference values for image word `index`, so a test can
 * diff the runtime's constants against the generator's. */
void dvmp_module_mask_probe(uint32_t index, uint64_t *mask, uint64_t *word);

/* ------------------------------------------------------------------ */
/* Interpreter (dvmp_vm.c)                                             */
/* ------------------------------------------------------------------ */

typedef struct DvmpFrame {
  uint32_t func;
  uint32_t pc;
  uint32_t slot_base;
  uint32_t stack_base;
} DvmpFrame;

typedef struct DvmpVm {
  DvmpArena arena;
  DvmpSlot slots[DVMP_MAX_SLOTS];
  DvmpSlot stack[DVMP_MAX_STACK];
  uint32_t sp;
  DvmpFrame frames[DVMP_MAX_DEPTH];
  uint32_t fp;
  uint32_t slot_top;
  uint64_t steps;
  /* Argument tags the caller pushed, nibble i = tag of eval-stack slot i.
   * Diagnostics only; see dvmp_vm_run. */
  uint32_t entry_tag_mask;
} DvmpVm;

void dvmp_vm_init(DvmpVm *vm);
void dvmp_vm_destroy(DvmpVm *vm);

/*
 * Runs `func` with `argc` values already placed on `vm->stack`. On success the
 * return value is written to `*out`.
 */
int32_t dvmp_vm_run(DvmpVm *vm, uint32_t func, uint32_t argc, DvmpSlot *out);

/* Host builtin result codes (dvmp_host.c). */
#define DVMP_HOST_OK 0
#define DVMP_HOST_ERROR (-1)
/* The builtin raised a deliberate fault (e.g. `abort`); the VM reports it as a
 * runtime error rather than pushing a value. */
#define DVMP_HOST_ABORTED (-2)

/*
 * Executes host builtin `id`, consuming exactly `argc` operands from
 * `vm->stack` (validated against the builtin's own arity table, so a tampered
 * instruction stream cannot confuse the two). On DVMP_HOST_OK the result is
 * written to `*ret`.
 */
int dvmp_host_call(DvmpVm *vm, uint32_t id, uint32_t argc, DvmpSlot *ret);

/* Diagnostics: last VM fault detail, in the form "func+pc: message". */
void dvmp_vm_set_error(const char *fmt, ...);
const char *dvmp_vm_last_error(void);
/* Clears the diagnostic buffer so a message cannot outlive its operation. */
void dvmp_vm_clear_error(void);
/* Appends "fn=/pc=/sp=/depth=" context to the current diagnostic. */
void dvmp_vm_fault_context(const DvmpVm *vm, const DvmpFrame *f);

/* Publishes the live VM so diagnostics can read its slots. */
void dvmp_vm_publish(DvmpVm *vm);
/* Reads a frame slot's tag/bits from the live VM. Diagnostics only. */
int32_t dvmp_vm_probe_slot(uint32_t slot, int64_t *tag, int64_t *bits);

#endif /* DVMP_INTERNAL_H_ */
