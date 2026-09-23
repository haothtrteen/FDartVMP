/*
 * dvmp_module.c - container loading, decryption and the seal/unseal lifecycle.
 *
 * LIFECYCLE
 * ---------
 *   init   : unmask static image -> authenticate -> decrypt -> verify CRC ->
 *            un-permute the instruction stream -> parse -> re-seal
 *   call   : unseal (plaintext window opens) -> execute -> re-seal (window
 *            closes, and the image is re-encrypted under a *fresh* seed)
 *   exit   : wipe every buffer
 *
 * The invariant this file exists to maintain:
 *
 *     the decoded instruction stream is plaintext ONLY for the functions the
 *     interpreter is executing, and the string table and constant pool are
 *     plaintext ONLY between dvmp_module_unseal() and dvmp_module_reseal()
 *
 * `m->master` holds the container exactly as shipped and is never modified. On
 * open, the metadata - string table, constant pool, descriptors - is decoded into
 * `m->body`, and the instruction stream is re-encrypted under a runtime-only key
 * into `m->code_store` with the body's copy wiped; the interpreter materialises at
 * most `DVMP_CODE_SLOTS` functions out of that store at a time. Sealing wipes all
 * three. Because the store's key is fresh entropy on every open, an attacker who
 * dumps the heap between calls gets a different ciphertext than the one in the
 * binary, and nothing decoded at all.
 */
#include "dvmp_internal.h"
#include "dvmp_vmpacker.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
#include <windows.h>
#else
#include <time.h>
#include <unistd.h>
#endif

/* The generated image, force-included by CMake (see src/CMakeLists.txt). It
 * defines kDvmpImage_words[], kDvmpImage_WORD_COUNT, kDvmpImage_MASK_KEY,
 * DVMP_IMAGE_LEN, DVMP_BUILD_ID and kDvmpEntries[].
 *
 * It must be included AFTER dvmp_internal.h (which pulls in dvmp_wire.h): the
 * image's `static_assert` and its `DvmpEntryMeta` table both reference
 * declarations from there, and clang - which the Android NDK uses - treats an
 * unknown type name as a hard error, unlike MSVC which merely warns. */
#if defined(DVMP_MODULE_INCLUDE)
#include DVMP_MODULE_INCLUDE
#else
#error "DVMP_MODULE_INCLUDE is not defined; build through CMake"
#endif

#ifndef DVMP_BUILD_ID
#error \
    "vmp_module.inc was not generated: run `dart run tool/vmpc/bin/vmpc.dart build`"
#endif

/* Defined below the seal/open helpers that call it. */
static int find_code_region(const uint8_t *body, uint32_t body_len,
                            const uint8_t **code, uint32_t *code_len);

/* Defined below the parser's callers: `module_open_locked` rebuilds the parsed
 * views on every open, because `seal` wipes the body they point into. */
static int parse_body_views(DvmpModule *m);

static DvmpModule g_mod;
static uint64_t g_call_counter = 0;

/* ------------------------------------------------------------------ */
/* Keystream + opcode permutation                                      */
/* Mirrors tool/vmpc/lib/src/packer.dart byte for byte.                 */
/* ------------------------------------------------------------------ */

typedef struct SplitMix {
  uint64_t state;
} SplitMix;

static void sm_init(SplitMix *s, uint64_t seed) {
  s->state = seed ^ 0x9E3779B97F4A7C15ull;
}

/*
 * SplitMix64.
 *
 * The right shifts use `>>` on `uint64_t` operands, which is a *logical* shift -
 * zeros shift in. The Dart generator must therefore use `>>>`, not `>>`: Dart's
 * `>>` is arithmetic, so on the many iterations where the state is negative it
 * sign-extends. The two produce entirely different keystreams, and the only
 * symptom is a CRC or tag mismatch three layers away from the cause. This is why
 * tool/vmpc/lib/src/packer.dart and this function are cross-checked by
 * tool/vmpc/test/image_contract_test.dart.
 */
static uint64_t sm_next(SplitMix *s) {
  s->state += 0x9E3779B97F4A7C15ull;
  uint64_t z = s->state;
  z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
  z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
  return z ^ (z >> 31);
}

DVMP_VMPACKER_LINKAGE DVMP_VMPACKER_TARGET void apply_keystream(
    uint8_t *p, uint32_t n, uint64_t seed) {
  SplitMix s;
  sm_init(&s, seed);
  uint32_t i = 0;
  while (i < n) {
    uint64_t word = sm_next(&s);
    for (int b = 0; b < 8 && i < n; b++, i++) {
      p[i] ^= (uint8_t)((word >> (8 * b)) & 0xFF);
    }
  }
}

DVMP_VMPACKER_LINKAGE DVMP_VMPACKER_TARGET uint64_t keystream_seed(uint64_t seed) {
  return seed ^ 0xA5A5A5A5A5A5A5A5ull;
}

/*
 * The body authentication tag, mirroring Packer.pack exactly:
 *
 *     tagSource = permutedBody || le64(seed ^ 0x5DEECE66D)
 *     tag       = fnv1a64(tagSource) ^ (seed * 0x100000001B3)
 *
 * The seed is appended and then folded in twice, which is redundant against a
 * keyed-hash attack but is what makes a *resealed* image (fresh seed, same body)
 * carry a different tag from the shipped one. That is the property the
 * "memory dump does not match the binary" claim rests on, so the two
 * implementations have to agree bit for bit.
 */
DVMP_VMPACKER_LINKAGE DVMP_VMPACKER_TARGET uint64_t dvmp_body_tag(
    const uint8_t *body, uint32_t body_len,
                              uint64_t seed) {
  uint64_t h = dvmp_fnv1a64(body, body_len, 0xCBF29CE484222325ull);
  uint8_t tail[8];
  const uint64_t t = seed ^ 0x5DEECE66Dull;
  for (int i = 0; i < 8; i++) {
    tail[i] = (uint8_t)((t >> (8 * i)) & 0xFF);
  }
  h = dvmp_fnv1a64(tail, 8, h);
  return h ^ (seed * 0x100000001B3ull);
}

/* Operand width of each opcode in the *decoded* instruction set. */
static const uint8_t kWidth[DVMP_OP_MAX] = {
    0, 4, 2, 2, 0, 0, 0, 0, 0, 0, /* 00..09 */
    2, 2, 0, 0, 0, 0, 0, 0, 0, 0, /* 0A..13 */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 14..1D */
    4, 4, 4, 2, 0, 0, 4, 0,       /* 1E..25 */
};

/*
 * The opcode permutation: a keyed Fisher-Yates shuffle of the byte range 0..255,
 * keeping the first DVMP_OP_MAX entries as the wire values.
 *
 * Why this is not the affine map it replaced: the old mapping was
 * `(op * 167 + (seed & 0xFF)) & 0xFF`, and the seed sits in the container header,
 * so an attacker who had decrypted the container knew the salt and had exactly
 * 128 candidates left for the multiplier. Testing all 128 against the container
 * CRC recovers the mapping in minutes, which is what made virtualizing
 * `unpermute_code` pointless - the answer fell out anyway.
 *
 * A random permutation has no such parameterisation: recovering it means finding
 * an assignment consistent with the whole instruction stream, which is a
 * constraint search, not a loop over a small set. The shuffle is driven by the
 * same SplitMix64 stream as the body cipher, under a distinct domain constant so
 * the two do not share keystream.
 *
 * BE HONEST ABOUT THE CEILING. The seed is public (it is in the header, and the
 * program has to be able to read its own container offline) and this function is
 * shipped, so an attacker who reads it recomputes the mapping directly. What item 1
 * buys is that the mapping can no longer be *brute forced* from the container
 * alone, and that recovering it now means reimplementing this construction - which
 * is why `unpermute_code` is on the VMPacker target list. Nothing here makes the
 * mapping secret; see "Where the plaintext actually is" in the README.
 *
 * Kept as a thin loop over two caller-supplied tables rather than building them
 * here: `permute_code` and `unpermute_code` are VMPacker targets, and the
 * translator refuses functions past a size/instruction ceiling.
 *
 * `DVMP_ALWAYS_INLINE` is not an optimisation. Both callers are virtualized, so this
 * helper must not survive as an out-of-line body - an attacker would call that copy
 * and skip the trampolines entirely. See dvmp_vmpacker.h.
 */
DVMP_ALWAYS_INLINE void op_tables(uint64_t seed, uint8_t *perm, uint8_t *inv) {
  uint8_t pool[256];
  for (uint32_t i = 0; i < 256u; i++) pool[i] = (uint8_t)i;

  SplitMix s;
  sm_init(&s, seed ^ 0x4F50434F44455031ull); /* "OPCODEP1" */
  uint64_t word = 0;
  uint32_t have = 0;
  for (uint32_t i = 0; i < (uint32_t)DVMP_OP_MAX; i++) {
    if (have == 0) {
      word = sm_next(&s);
      have = 8;
    }
    /* One keystream *byte* per draw, not a 64-bit word modulo the range. Dart's
     * `%` is Euclidean - it returns a non-negative result even for a negative
     * operand - while C's on the same negative-looking 64-bit pattern is not the
     * same number at all. Consuming a byte sidesteps the question entirely and
     * keeps the two implementations provably identical. */
    const uint32_t r = (uint32_t)(word & 0xFFu);
    word >>= 8;
    have--;

    const uint32_t j = i + (r % (256u - i));
    const uint8_t t = pool[i];
    pool[i] = pool[j];
    pool[j] = t;
    perm[i] = pool[i];
  }

  /* `inv[wire]` is the opcode, or DVMP_OP_MAX when the byte is not one of this
   * build's wire values.
   *
   * Written as a scatter over the shuffled pool - which still holds every byte
   * 0..255, with the first DVMP_OP_MAX entries being the wire values - rather than
   * as `for (i) inv[i] = 0xFF;` followed by the permutation writes. That is not a
   * style choice, and the reason is worth recording because it cost an hour: a
   * 256-byte *constant* fill is recognised as memset and inlined by clang as
   * `movi v0.16b, #0xff` plus eight `stp q0, q0, [sp]`. Nine SIMD instructions, and
   * VMPacker 1.3 has no SIMD translation, so `unpermute_code` - which is where this
   * inlines - came back as "Translated: 216/225, translation aborted". Neither
   * -fno-vectorize nor -fno-slp-vectorize disables it: that expansion is the
   * loop-idiom / inline-memset path, not the vectoriser.
   *
   * A data-dependent scatter cannot become a memset or be vectorised, so the table
   * is built without SIMD by construction rather than by flag. It also removes a
   * loop: `perm` and `inv` are two views of one shuffle. `inv == NULL` in
   * `permute_code`, where the constant folds the whole thing away. */
  if (inv != NULL) {
    for (uint32_t i = 0; i < 256u; i++) {
      inv[pool[i]] =
          (i < (uint32_t)DVMP_OP_MAX) ? (uint8_t)i : (uint8_t)DVMP_OP_MAX;
    }
  }
}

/*
 * Applies / reverses the per-opcode permutation over the instruction stream.
 * The walk is strictly sequential: operand widths come from the *decoded*
 * opcode, so decoding must start at offset 0 and any desynchronisation shows
 * up as an out-of-range opcode rather than as silent nonsense.
 *
 * Both functions cost one 256-element shuffle per call - a few hundred cycles,
 * paid once per function materialisation (and once per function per open for the
 * store), against an interpreter that then runs thousands of instructions. Not
 * worth caching: a cached table would be a second copy of the mapping in memory
 * for the attacker to find, which is the thing this is trying to avoid.
 */
DVMP_VMPACKER_LINKAGE DVMP_VMPACKER_TARGET void permute_code(uint8_t *code,
    uint32_t code_len, uint64_t seed) {
  uint8_t perm[DVMP_OP_MAX];
  /* NULL: this direction only needs `perm`, and the constant lets op_tables fold
   * the inverse table away entirely - which is also what keeps this function small
   * enough for VMPacker's translator. */
  op_tables(seed, perm, NULL);

  uint32_t pc = 0;
  while (pc < code_len) {
    const uint8_t op = code[pc];
    /* Out-of-range bytes are copied through untouched and stepped over one byte
     * at a time. That is deliberate: it keeps this function total (no branch out
     * of a table) and it means the *inverse* is where a corrupt stream is caught,
     * since `unpermute_code` is the one that has to produce something executable. */
    if (op < DVMP_OP_MAX) code[pc] = perm[op];
    pc += 1u + (op < DVMP_OP_MAX ? kWidth[op] : 0u);
  }
}

DVMP_VMPACKER_LINKAGE DVMP_VMPACKER_TARGET int unpermute_code(uint8_t *code,
    uint32_t code_len, uint64_t seed) {
  uint8_t perm[DVMP_OP_MAX];
  uint8_t inv[256];
  op_tables(seed, perm, inv);

  uint32_t pc = 0;
  while (pc < code_len) {
    const uint8_t wire = code[pc];
    const uint8_t op = inv[wire];
    if (op >= DVMP_OP_MAX) {
      dvmp_vm_set_error("opcode 0x%02x out of range at +%u", wire, pc);
      return -1;
    }
    code[pc] = op;
    pc += 1u + kWidth[op];
  }
  if (pc != code_len) {
    dvmp_vm_set_error("instruction stream overran its buffer (%u of %u)", pc,
                      code_len);
    return -1;
  }
  return 0;
}

/* ------------------------------------------------------------------ */
/* Container helpers                                                   */
/* ------------------------------------------------------------------ */

static uint32_t rd_u32(const uint8_t *p) {
  return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
         ((uint32_t)p[3] << 24);
}

static uint64_t rd_u64(const uint8_t *p) {
  uint64_t v = 0;
  for (int i = 7; i >= 0; i--) {
    v = (v << 8) | p[i];
  }
  return v;
}

static void wr_u32(uint8_t *p, uint32_t v) {
  p[0] = (uint8_t)(v & 0xFF);
  p[1] = (uint8_t)((v >> 8) & 0xFF);
  p[2] = (uint8_t)((v >> 16) & 0xFF);
  p[3] = (uint8_t)((v >> 24) & 0xFF);
}

static void wr_u64(uint8_t *p, uint64_t v) {
  for (int i = 0; i < 8; i++) {
    p[i] = (uint8_t)((v >> (8 * i)) & 0xFF);
  }
}

/*
 * Mask used by the generator for the static image; must match the Dart side.
 *
 * This was SplitMix64-finalise(key + index + G0) until the known-plaintext recovery
 * in `tool/recover_from_shipped.py` showed what that costs: the finaliser is a
 * bijection, the container's first eight bytes are known, and one XOR plus one
 * inversion therefore yields the key - and because it was a stream, the key yielded
 * all 196 words. It is now a truncated hash of the key *and the index*, so a known
 * word reveals neither the key nor any other word. The full reasoning, and what this
 * still does not protect against, is in dvmp_sha256.c.
 *
 * The signature and the indexing are unchanged on purpose: the name blob uses the
 * same primitive with a different key and a byte-granular index (see
 * `name_blob_byte`), and both call sites stay correct without modification.
 */
DVMP_VMPACKER_LINKAGE DVMP_VMPACKER_TARGET uint64_t mask_word(uint64_t key,
    uint64_t index) {
  return dvmp_mask_keystream(key, index);
}

static uint64_t random_seed(void) {
  uint64_t entropy = 0;
#if defined(_WIN32)
  LARGE_INTEGER li;
  QueryPerformanceCounter(&li);
  entropy = (uint64_t)li.QuadPart ^ ((uint64_t)GetTickCount64() << 21);
#else
  FILE *f = fopen("/dev/urandom", "rb");
  if (f != NULL) {
    if (fread(&entropy, 1, sizeof(entropy), f) != sizeof(entropy)) entropy = 0;
    fclose(f);
  }
  if (entropy == 0) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    entropy = (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
  }
#endif
  /* Always mixed with a monotonic counter so two calls in the same clock tick
   * cannot produce the same seed even if the entropy source is unavailable. */
  entropy ^= ((uint64_t)(uintptr_t)&g_mod << 13) ^ (++g_call_counter);
  return entropy;
}

/* ------------------------------------------------------------------ */
/* Lifecycle                                                           */
/* ------------------------------------------------------------------ */

DvmpModule *dvmp_module(void) { return &g_mod; }

/* Defined with the instruction-stream machinery further down; `module_release`
 * has to be able to free what they allocate, so they are declared here rather
 * than moved - the residency code reads as one block on purpose. */
static void code_slots_free(DvmpModule *m);
static void code_slots_clear(DvmpModule *m);
static void code_store_clear(DvmpModule *m);

static void module_release(DvmpModule *m) {
  if (m->master != NULL) {
    vmp_secure_free(m->master, m->master_len);
    m->master = NULL;
  }
  if (m->body != NULL) {
    vmp_secure_free(m->body, m->body_len);
    m->body = NULL;
  }
  if (m->code_store != NULL) {
    vmp_secure_free(m->code_store, m->code_store_len);
    m->code_store = NULL;
    m->code_store_len = 0;
  }
  code_slots_free(m);
  if (m->funcs != NULL) {
    vmp_secure_free(m->funcs, (size_t)m->funcs_cap * sizeof(DvmpFuncDesc));
    m->funcs = NULL;
    m->funcs_cap = 0;
  }
  m->ready = 0;
}

void dvmp_module_shutdown(void) {
  module_release(&g_mod);
  memset(&g_mod, 0, sizeof(g_mod));
}

/* ------------------------------------------------------------------ */
/* Instruction stream                                                  */
/* ------------------------------------------------------------------ */

/*
 * The code region is NOT one contiguous plaintext run inside the body, and it has
 * not been since the residency work below. What happens instead:
 *
 *   open  : decrypt the body, verify the tag and the CRC, un-permute the stream,
 *           then re-encrypt the *code region only* under a key that exists solely
 *           in this process (`m->code_key`), into `m->code_store`, and wipe the
 *           plaintext stream out of `m->body`
 *   call  : the interpreter materialises one function at a time out of the store
 *           into `m->code_slots`, on the first instruction that needs it
 *   seal  : wipe the store, wipe the slots, wipe the metadata
 *
 * WHY THIS EXISTS. The earlier design kept the whole decoded stream in `m->body`
 * for the duration of every call, so one snapshot taken at any point during a call
 * returned every protected function at once - the entire algorithm, in one read,
 * with no reassembly. Bounding that to `DVMP_CODE_SLOTS` functions is the
 * difference between dumping a program and dumping a function.
 *
 * WHAT IT DOES NOT DO, stated plainly because the argument for it is easy to
 * overstate. It does not stop a debugger: an attacker who can pause the process
 * can pause it once per function and reassemble, and the reassembly is mechanical
 * because the descriptors in the (resident) metadata carry every function's offset
 * and length. It raises the cost of a memory-dump attack from one snapshot to N
 * plus a reassembly step, and it makes a *single* incidental dump - a crash
 * report, a swap file, a screenshot of a hex editor - worth a bounded amount
 * instead of everything. A static attacker is unaffected, because the shipped
 * container is decryptable offline by construction; see the README's first
 * principle.
 *
 * The three shapes this took before it worked are worth naming, because each is
 * a plausible design that fails silently:
 *   * one encode/decode helper shared by the store writer and the slot loader,
 *     which had opposite intent, so the store was written decoded;
 *   * a module-wide "is plaintext" flag consulted instead of the slot's own
 *     identity, so every slot after the first returned whatever it already held;
 *   * a region offset translated twice, because the store offset and the body
 *     offset look alike.
 * The defence against all three is the same and is in `dvmp_code_ensure`: the
 * slot records the *function index* it holds and revalidates it on every fetch,
 * so a wrong slot is a miss and never a wrong answer. Correctness does not depend
 * on the cache hitting.
 */

/* Wipes every slot and marks it empty. Safe on a module that never opened. */
static void code_slots_clear(DvmpModule *m) {
  for (uint32_t i = 0; i < DVMP_CODE_SLOTS; i++) {
    if (m->code_slots[i].buf != NULL && m->code_slots[i].cap != 0) {
      vmp_secure_wipe(m->code_slots[i].buf, m->code_slots[i].cap);
    }
    m->code_slots[i].func = DVMP_CODE_NOFUNC;
    m->code_slots[i].len = 0;
  }
  m->code_slots_live = 0;
  m->code_slot_next = 0;
}

/* Frees the slots. Only for module_release. */
static void code_slots_free(DvmpModule *m) {
  for (uint32_t i = 0; i < DVMP_CODE_SLOTS; i++) {
    if (m->code_slots[i].buf != NULL) {
      vmp_secure_free(m->code_slots[i].buf, m->code_slots[i].cap);
      m->code_slots[i].buf = NULL;
    }
    m->code_slots[i].cap = 0;
    m->code_slots[i].func = DVMP_CODE_NOFUNC;
    m->code_slots[i].len = 0;
  }
  m->code_slots_live = 0;
  m->code_slot_next = 0;
  m->code_slots_peak = 0;
}

/* Wipes the store. Safe on a module that never opened. */
static void code_store_clear(DvmpModule *m) {
  if (m->code_store != NULL && m->code_store_len != 0) {
    vmp_secure_wipe(m->code_store, m->code_store_len);
  }
  m->code_key = 0;
  m->code_salt = 0;
}

/*
 * Builds `m->code_store` from the plaintext code region of `m->body`, then wipes
 * that region out of the body.
 *
 * Called from `module_open_locked` after the tag and the CRC have both passed, so
 * the bytes being encrypted are known-good. Requires `m->funcs` to be parsed,
 * which is why it runs after `parse_body_views`.
 *
 * Per function, in order:
 *   1. copy the decoded stream out of the body into the store
 *   2. re-permute it under `code_salt`   - a fresh salt per open, so the bytes a
 *      dump would reveal are not even the shipped opcode numbering
 *   3. encrypt it under a per-function keystream derived from `code_key`
 *
 * Step 3 uses a different key per function (`code_key ^ index`) rather than one
 * stream across the region. One stream would be cheaper and would also mean that
 * materialising function 5 tells an attacker the keystream XOR at function 5's
 * offset - the classic two-time-pad leak, with function 7's bytes as the payoff.
 */
DVMP_NO_BUILTIN DVMP_VMPACKER_LINKAGE DVMP_VMPACKER_TARGET int code_store_build(
    DvmpModule *m, const uint8_t *code, uint32_t code_len) {
  if (code_len == 0) return -1;
  if (m->func_count == 0) return -1;

  /* Allocate exactly once. The store and the slots are sized from the module,
   * which does not change between opens, so a reopen reuses them - and the
   * allocation happens here rather than in `init` because this is the first point
   * at which both the region length and every function's length are known. */
  if (m->code_store == NULL) {
    m->code_store = (uint8_t *)vmp_secure_alloc(code_len);
    if (m->code_store == NULL) return -1;
    m->code_store_len = code_len;
  }
  if (m->code_store_len < code_len) return -1;

  uint32_t max_len = 0;
  for (uint32_t i = 0; i < m->func_count; i++) {
    if (m->funcs[i].code_len > max_len) max_len = m->funcs[i].code_len;
    if ((uint64_t)m->funcs[i].code_off + m->funcs[i].code_len > code_len) {
      return -1;
    }
  }
  if (max_len == 0) return -1;
  /* Instrumentation detected means one slot: a narrower plaintext window, never a
   * different answer. */
  m->code_slots_usable = m->instrumented ? 1u : DVMP_CODE_SLOTS;
  for (uint32_t i = 0; i < DVMP_CODE_SLOTS; i++) {
    DvmpCodeSlot *s = &m->code_slots[i];
    if (s->cap >= max_len && s->buf != NULL) continue;
    if (s->buf != NULL) vmp_secure_free(s->buf, s->cap);
    s->buf = (uint8_t *)vmp_secure_alloc(max_len);
    if (s->buf == NULL) {
      s->cap = 0;
      return -1;
    }
    s->cap = max_len;
    s->func = DVMP_CODE_NOFUNC;
    s->len = 0;
  }

  /* Fresh entropy per open: the store does not survive a call, so there is no
   * reason to reuse a key across one. `| 1` keeps the salt non-zero, because a
   * zero salt is the identity permutation and would quietly ship the public
   * opcode numbering inside the store. */
  m->code_key = random_seed();
  m->code_salt = (m->code_key & 0xFFull) | 1ull;
  m->code_key_last = m->code_key;
  m->code_salt_last = m->code_salt;

  for (uint32_t i = 0; i < m->func_count; i++) {
    const DvmpFuncDesc *f = &m->funcs[i];
    uint8_t *dst = m->code_store + f->code_off;
    memcpy(dst, code + f->code_off, f->code_len);
    permute_code(dst, f->code_len, m->code_salt);
    apply_keystream(dst, f->code_len, keystream_seed(m->code_key ^ (uint64_t)i));
  }

  /*
   * Drop the plaintext stream. The metadata above it stays - the interpreter
   * reads strings and constants on the `push_k` / `push_s` paths of every
   * instruction, so it has to be resident, and pretending otherwise would mean
   * decrypting the constant pool per instruction for no security gain (it is
   * already re-derived from the shipped image on every open).
   */
  {
    const uint32_t code_at = (uint32_t)(code - m->body);
    vmp_secure_wipe(m->body + code_at, code_len);
  }
  return 0;
}

/*
 * Instruction fetch, and the only way to reach decoded code.
 *
 * `code_off` and `code_len` come from the caller's descriptor and are validated
 * against the region before use: the store is indexed by `code_off`, so a bad
 * descriptor would otherwise read whatever is at that offset and execute it.
 *
 * The slot is chosen round-robin and identified by function index. Both halves
 * matter: round-robin means a two-function ping-pong settles into two slots and
 * stops missing, which an `index % SLOTS` mapping does not (functions 0 and 4
 * would share a slot and evict each other on every call); and identifying the
 * slot by index rather than by a "loaded" flag is what makes a collision a reload
 * instead of a wrong answer.
 */
const uint8_t *dvmp_code_ensure(uint32_t func, uint32_t code_off,
                                uint32_t code_len) {
  DvmpModule *m = &g_mod;
  if (m->code_store == NULL || !m->unsealed) return NULL;
  if (func >= m->func_count) return NULL;
  if (code_len == 0 || (uint64_t)code_off + code_len > m->code_store_len) {
    return NULL;
  }

  /* Fast path: scan for the slot that already holds this function. Four
   * comparisons against a full reload, and it is the path a loop inside one
   * function takes on every instruction after the first. */
  for (uint32_t i = 0; i < m->code_slots_usable; i++) {
    DvmpCodeSlot *s = &m->code_slots[i];
    if (s->func == func && s->len == code_len && s->buf != NULL) return s->buf;
  }

  DvmpCodeSlot *s = &m->code_slots[m->code_slot_next];
  m->code_slot_next = (m->code_slot_next + 1) % m->code_slots_usable;
  if (s->buf == NULL || s->cap < code_len) return NULL;

  memcpy(s->buf, m->code_store + code_off, code_len);
  apply_keystream(s->buf, code_len, keystream_seed(m->code_key ^ (uint64_t)func));
  /*
   * Un-permuting is also the integrity check: the walk is driven by the decoded
   * opcode widths, so it fails if any opcode is out of range and fails if the
   * stream does not end exactly on `code_len`. A wrong key, a wrong offset or a
   * corrupted store therefore cannot produce a *plausible* stream - it produces a
   * failed walk, which is why this returns NULL rather than executing whatever
   * came out.
   */
  if (unpermute_code(s->buf, code_len, m->code_salt) != 0) {
    s->func = DVMP_CODE_NOFUNC;
    s->len = 0;
    vmp_secure_wipe(s->buf, s->cap);
    return NULL;
  }
  if (s->func == DVMP_CODE_NOFUNC) m->code_slots_live++;
  s->func = func;
  s->len = code_len;
  if (m->code_slots_live > m->code_slots_peak) {
    m->code_slots_peak = m->code_slots_live;
  }
  return s->buf;
}

void dvmp_module_chunk_probe(uint32_t *slots, uint32_t *live, uint32_t *peak,
                             uint32_t *largest, uint32_t *total) {
  const DvmpModule *m = &g_mod;
  if (slots != NULL) *slots = m->code_slots_usable;
  if (live != NULL) *live = m->code_slots_live;
  if (peak != NULL) *peak = m->code_slots_peak;
  if (largest != NULL) {
    uint32_t best = 0;
    for (uint32_t i = 0; i < m->func_count; i++) {
      if (m->funcs != NULL && m->funcs[i].code_len > best) {
        best = m->funcs[i].code_len;
      }
    }
    *largest = best;
  }
  /* The whole region, so a test can state the comparison that matters -
   * `peak * largest < total` - without having to reconstruct it. Reported as a
   * length, never as bytes. */
  if (total != NULL) *total = m->code_store_len;
}

void dvmp_module_code_residue(uint32_t *slots, uint32_t *body_region,
                              uint32_t *body_region_peak, uint32_t *store) {
  const DvmpModule *m = &g_mod;
  if (slots != NULL) {
    uint32_t n = 0;
    for (uint32_t i = 0; i < DVMP_CODE_SLOTS; i++) {
      const DvmpCodeSlot *s = &m->code_slots[i];
      if (s->buf == NULL || s->cap == 0 || s->func == DVMP_CODE_NOFUNC) continue;
      for (uint32_t b = 0; b < s->cap; b++) {
        if (s->buf[b] != 0) n++;
      }
    }
    *slots = n;
  }
  if (body_region != NULL) *body_region = m->code_region_residue;
  if (body_region_peak != NULL) *body_region_peak = m->code_region_residue_peak;
  if (store != NULL) {
    /*
     * The store is ciphertext while the module is open and all zeroes once it is
     * sealed, because `seal` wipes it. Reporting it is what makes "the store does
     * not outlive the call" checkable - and it is the one buffer here for which
     * "non-zero" is not by itself suspicious, which is exactly why the *sealed*
     * value is the one under test.
     */
    uint32_t n = 0;
    if (m->code_store != NULL) {
      for (uint32_t i = 0; i < m->code_store_len; i++) {
        if (m->code_store[i] != 0) n++;
      }
    }
    *store = n;
  }
}

/* ------------------------------------------------------------------ */
/* Seal / open                                                         */
/* ------------------------------------------------------------------ */
/*
 * INVARIANT
 * ---------
 *   m->master      holds the container exactly as shipped. Immutable, and the
 *                  only input to opening the plaintext window.
 *   m->body        holds the metadata - string table, constant pool, descriptors
 *                  - while the module is open, and nothing else. Its code region
 *                  is wiped by `open` once the stream has been moved into the
 *                  store, so it is never a place to find bytecode.
 *   m->code_store  holds the instruction streams encrypted under `code_key`,
 *                  which exists only in this process and is drawn fresh on every
 *                  open.
 *   m->code_slots  hold at most DVMP_CODE_SLOTS decoded functions, and only while
 *                  the interpreter is running.
 *
 * TWO DIRECTIONS, TWO KEYS - and this is the point of the whole file
 * ----------------------------------------------------------------
 *   open : m->master -> m->body + m->code_store.  The key is the seed in the
 *          shipped header, which an attacker can read. It has to be: offline
 *          distribution means the binary carries its own key material.
 *   seal : everything is wiped. There is no second container to keep, because
 *          there is nothing to keep it from: the store is rebuilt from `master`
 *          on the next open, and `master` is not secret.
 *
 * WHAT THE RUNTIME-KEYED STORE DOES AND DOES NOT BUY, because the older wording
 * here overstated it. It means the bytes a *partial* capture finds - one buffer,
 * one page, a swapped-out region, a crash dump of a single allocation - are not
 * the shipped ciphertext and cannot be opened with anything on disk. It does not
 * defeat a full-process capture: `code_key` and `code_salt` live in the same
 * address space as the store, so whoever reads one can read the other. That was
 * equally true of the working container this store replaced, whose session key and
 * nonce were also resident; the difference is that the store is smaller, is the
 * only such buffer, and is the reason no decoded function survives a call.
 *
 * An earlier revision permuted the body in place while sealing. That looked
 * simpler, but it made "the body" mean two different things depending on when
 * you looked, and the second open permuted an already-permuted body with a
 * different seed. The failure surfaced three layers away as an inexplicable CRC
 * mismatch. Keeping the body canonical while it exists is worth the one extra
 * copy per call.
 */

/*
 * Closes the plaintext window: wipe the metadata, the store and every decoded
 * slot.
 *
 * This function used to rebuild `m->work`, a second complete container under a
 * runtime-only key. That became impossible to do honestly once `open` started
 * wiping the body's code region: the container would have been built from a body
 * with its instruction stream zeroed, so its CRC and tag would describe something
 * that no longer existed. Nothing ever decrypted it, so no test noticed - which is
 * exactly the shape of false invariant this file has been bitten by before (a
 * documented lock that was never implemented, a documented wipe that only covered
 * a copy). The store now plays the role `work` was there for, and it plays it
 * correctly, so the decoy is gone rather than left lying.
 */
static void module_seal_locked(void) {
  DvmpModule *m = &g_mod;
  const uint32_t body_len = m->body_len;

  /*
   * Sample the body's code region before anything is wiped, and keep the worst
   * value ever seen.
   *
   * Sealing is the only instant at which "the decoded instruction stream was still
   * sitting in the body" is observable from outside a call, so this is where the
   * residency model is measured rather than asserted. `open` wipes this region
   * after moving it into the store, so a healthy runtime reports 0 here for the
   * life of the process; the design this replaced kept the whole stream in place
   * for the duration of every call and would report the module's full instruction
   * length. A peak rather than the latest sample, because a detector a later clean
   * seal can reset is one that reports 0 for a process that leaked.
   */
  {
    const uint8_t *code = NULL;
    uint32_t code_len = 0;
    if (find_code_region(m->body, body_len, &code, &code_len) == 0 &&
        code != NULL) {
      uint32_t nz = 0;
      for (uint32_t i = 0; i < code_len; i++) {
        if (code[i] != 0) nz++;
      }
      m->code_region_residue = nz;
      if (nz > m->code_region_residue_peak) m->code_region_residue_peak = nz;
    }
  }

  /*
   * Wipe the body. This is the step whose absence made the documented invariant
   * false: an earlier revision re-sealed from a *copy* and wiped only the copy, so
   * `m->body` kept the canonical body - string table, constant pool, descriptors
   * and decoded instruction stream - for the lifetime of the process. "The
   * plaintext exists only between open and seal" was true of the working copy and
   * of nothing else, and a single read of the process found the protected alphabet
   * string and `add`'s decoded opcodes resting in one page even with the module
   * nominally sealed.
   *
   * The reason this is safe is that `open` rebuilds the body from `m->master`,
   * which is immutable. Nothing reads `m->body` while the module is closed, so the
   * body does not need to survive the seal at all.
   */
  vmp_secure_wipe(m->body, body_len);

  /* Drop the parsed views with it. They point into the buffer just wiped, so
   * leaving them non-NULL would hand out dangling pointers to anything that reads
   * them while the module is closed - which is what `dvmp_module_code_probe`
   * used to do. */
  m->code = NULL;
  m->strings = NULL;
  m->consts = NULL;
  m->str_tab = NULL;

  /* And the instruction streams, which are the part a dump would be worth
   * taking: encrypted in the store, decoded only in the slots. */
  code_store_clear(m);
  code_slots_clear(m);
}

/*
 * Locates the instruction stream inside a *plaintext* body.
 *
 * The section lengths cannot come from `m->` here: at init time this runs before
 * those fields are populated, so they are still zero and the computed offset
 * lands in the middle of the string table. Everything is therefore read from the
 * body itself, which also makes the function independent of struct state.
 *
 * Body layout (see dvmp_wire.h):
 *   u32 strings_len | strings | u32 const_count | i64 consts[]
 *   u32 str_count   | {u32 off, u32 len}[]      | u32 fn_count
 *   fn_desc[fn_count] (DVMP_DESC_SIZE each)   | u32 code_len | code[]
 */
static int find_code_region(const uint8_t *body, uint32_t body_len,
                            const uint8_t **code, uint32_t *code_len) {
  uint32_t off = 0;
  if (off + 4u > body_len) goto bad;
  const uint32_t strings_len = rd_u32(body + off);
  off += 4u;
  if ((uint64_t)off + strings_len > body_len) goto bad;
  off += strings_len;

  if (off + 4u > body_len) goto bad;
  const uint32_t const_count = rd_u32(body + off);
  off += 4u;
  if ((uint64_t)off + (uint64_t)const_count * 8u > body_len) goto bad;
  off += const_count * 8u;

  if (off + 4u > body_len) goto bad;
  const uint32_t str_count = rd_u32(body + off);
  off += 4u;
  if ((uint64_t)off + (uint64_t)str_count * 8u > body_len) goto bad;
  off += str_count * 8u;

  if (off + 4u > body_len) goto bad;
  const uint32_t fn_count = rd_u32(body + off);
  off += 4u;
  /* Stride from DVMP_DESC_SIZE, not a literal. This walk has to agree with
   * `parse_body_views` below *and* with the generator; when the record grew to
   * carry the call policy, this one literal was missed and the symptom was a
   * module whose code region appeared to be zero bytes long. */
  if ((uint64_t)off + (uint64_t)fn_count * DVMP_DESC_SIZE > body_len) goto bad;
  off += fn_count * DVMP_DESC_SIZE;

  if (off + 4u > body_len) goto bad;
  const uint32_t len = rd_u32(body + off);
  off += 4u;
  if ((uint64_t)off + len > body_len) goto bad;

  if (code != NULL) *code = body + off;
  if (code_len != NULL) *code_len = len;
  return 0;

bad:
  dvmp_vm_set_error(
      "code region not found: bodyLen=%u stringsLen=%u consts=%u strs=%u "
      "funcs=%u off=%u",
      body_len, strings_len, const_count, str_count, fn_count, off);
  return -1;
}

/*
 * Opens the plaintext window: authenticate the shipped container, decode its
 * metadata into `m->body`, and move its instruction stream into the runtime-keyed
 * store.
 *
 * The input is always `m->master`, which is immutable, so every open starts from
 * the canonical shipped form and the decode is a true inverse rather than a
 * second pass over already-transformed bytes.
 */
DVMP_VMPACKER_LINKAGE DVMP_VMPACKER_TARGET int32_t module_open_locked(void) {
  DvmpModule *m = &g_mod;
  const uint32_t body_len = m->body_len;

  if (m->master_len < DVMP_HEADER_SIZE + (uint64_t)body_len + DVMP_TAG_SIZE) {
    dvmp_vm_set_error("master buffer too small: %u < %u", m->master_len,
                      (uint32_t)(DVMP_HEADER_SIZE + body_len + DVMP_TAG_SIZE));
    return DARTVMP_ERR_MODULE_CORRUPT;
  }
  const uint8_t *w = m->master;
  if (w[DVMP_OFF_MAGIC + 0] != DVMP_MAGIC0 ||
      w[DVMP_OFF_MAGIC + 1] != DVMP_MAGIC1 ||
      w[DVMP_OFF_MAGIC + 2] != DVMP_MAGIC2 ||
      w[DVMP_OFF_MAGIC + 3] != DVMP_MAGIC3) {
    return DARTVMP_ERR_MODULE_MAGIC;
  }
  if (rd_u32(w + DVMP_OFF_BODY_LEN) != body_len) {
    dvmp_vm_set_error("body length mismatch: master=%u expected=%u",
                      rd_u32(w + DVMP_OFF_BODY_LEN), body_len);
    return DARTVMP_ERR_MODULE_CORRUPT;
  }

  /* The body is never mutated by sealing, so this always starts from the
   * canonical form and is a true inverse. */
  memcpy(m->body, w + DVMP_HEADER_SIZE, body_len);
  const uint64_t seed = rd_u64(w + DVMP_OFF_SEED);
  apply_keystream(m->body, body_len, keystream_seed(seed));

  {
    /* Authenticate the exact bytes that were stored, before decoding anything:
     * this is the layer that detects a patched image. */
    const uint64_t want = rd_u64(w + DVMP_HEADER_SIZE + body_len);
    const uint64_t got = dvmp_body_tag(m->body, body_len, seed);
    if (got != want) {
      dvmp_vm_set_error("body auth tag mismatch: got=%016llx want=%016llx",
                        (unsigned long long)got, (unsigned long long)want);
      vmp_secure_wipe(m->body, body_len);
      return DARTVMP_ERR_MODULE_AUTH;
    }
    m->seed = seed;
  }

  /* Restore the private instruction set, then rebuild every parsed view.
   *
   * The views have to be rebuilt here rather than only at init because `seal`
   * wipes `m->body` and NULLs them: the interpreter reads `m->strings`,
   * `m->consts` and `m->str_tab` on the `push_k` / `push_s` paths, so a module
   * that reopened without re-deriving them would fault on the first string
   * constant. `parse_body_views` is the same routine `dvmp_module_init` uses, so
   * there is one definition of the body layout.
   */
  {
    const uint8_t *code = NULL;
    uint32_t code_len = 0;
    if (find_code_region(m->body, body_len, &code, &code_len) != 0) {
      vmp_secure_wipe(m->body, body_len);
      return DARTVMP_ERR_MODULE_CORRUPT;
    }
    if (unpermute_code((uint8_t *)(uintptr_t)code, code_len, seed) != 0) {
      vmp_secure_wipe(m->body, body_len);
      return DARTVMP_ERR_MODULE_CORRUPT;
    }
    m->code = code;
    m->code_len = code_len;
    if (parse_body_views(m) != 0) {
      vmp_secure_wipe(m->body, body_len);
      return DARTVMP_ERR_MODULE_CORRUPT;
    }
  }

  {
    /* The CRC covers the canonical body, so it is the end-to-end check: it can
     * only pass if the tag, the cipher and the opcode permutation all agreed. */
    const uint32_t got = dvmp_crc32(m->body, body_len);
    const uint32_t want = rd_u32(w + DVMP_OFF_BODY_CRC);
    if (got != want) {
      dvmp_vm_set_error("body CRC mismatch: got=%08x want=%08x len=%u", got,
                        want, body_len);
      vmp_secure_wipe(m->body, body_len);
      return DARTVMP_ERR_MODULE_CORRUPT;
    }
  }

  /*
   * Everything above ran on a body that is now known-good. Move the instruction
   * stream into the runtime-keyed store and wipe it from the body, so the
   * plaintext stream stops existing here and starts being materialised one
   * function at a time. This runs last on purpose: it destroys the decoded
   * stream, so it must not happen before the CRC that proves the whole decode
   * was correct.
   */
  {
    const uint8_t *code = NULL;
    uint32_t code_len = 0;
    if (find_code_region(m->body, body_len, &code, &code_len) != 0 ||
        code_store_build(m, code, code_len) != 0) {
      dvmp_vm_set_error("could not move the instruction stream into the store "
                        "(codeLen=%u storeLen=%u funcs=%u)",
                        m->code_len, m->code_store_len, m->func_count);
      vmp_secure_wipe(m->body, body_len);
      return DARTVMP_ERR_MODULE_CORRUPT;
    }
    m->code = NULL;
  }

  return DARTVMP_OK;
}

int32_t dvmp_module_unseal(void) {
  DvmpModule *m = &g_mod;
  if (!m->ready) return DARTVMP_ERR_NOT_INITIALIZED;
  if (m->unsealed) return DARTVMP_OK;
  const int32_t rc = module_open_locked();
  if (rc == DARTVMP_OK) m->unsealed = 1;
  return rc;
}

void dvmp_module_reseal(void) {
  DvmpModule *m = &g_mod;
  if (!m->ready || !m->unsealed) return;
  /* Sealing cannot fail: wiping is unconditional, and there is no second
   * container left to build. The failure branch that used to live here existed
   * because a re-seal could run out of memory while allocating its scratch copy,
   * and it left the module marked *open* on failure - which meant the next
   * instruction fetch read a zeroed body and executed 
op`s. That whole
   * failure mode is gone with the copy. */
  module_seal_locked();
  m->unsealed = 0;
}

/*
 * Runs `fn` with the module unsealed, guaranteeing that the plaintext window
 * closes even if the callee fails. Every code path that can execute bytecode
 * must go through this.
 */
int32_t dvmp_module_with_plaintext(int32_t (*fn)(void *), void *ctx) {
  DvmpModule *m = &g_mod;
  if (!m->ready) return DARTVMP_ERR_NOT_INITIALIZED;

  int32_t rc = dvmp_module_unseal();
  if (rc != DARTVMP_OK) return rc;

  rc = fn(ctx);

  /* Always re-seal: leaving the plaintext resident after an error is exactly
   * the state an attacker wants us to leave behind. */
  dvmp_module_reseal();
  return rc;
}

/* ------------------------------------------------------------------ */
/* init                                                                */
/* ------------------------------------------------------------------ */

/* Unmasks the generated static image into a freshly allocated secure buffer
 * and returns its length, or 0 on failure. */
static uint32_t unmask_image_into(uint8_t **out) {
  const uint32_t raw_len = (uint32_t)DVMP_IMAGE_LEN;
  if (raw_len < DVMP_HEADER_SIZE + DVMP_TAG_SIZE) return 0;

  uint8_t *dst = (uint8_t *)vmp_secure_alloc(raw_len);
  if (dst == NULL) return 0;

  const uint32_t words = (uint32_t)kDvmpImage_WORD_COUNT;
  const uint64_t key = (uint64_t)kDvmpImage_MASK_KEY;
  for (uint32_t i = 0; i < words; i++) {
    /* `lo` holds image bytes 0..3 and `hi` holds 4..7, matching the generator.
     * Both halves are uint32_t, so the shift has to be applied before the
     * promotion to 64 bits. */
    const uint32_t lo = kDvmpImage_words[i].lo;
    const uint32_t hi = kDvmpImage_words[i].hi;
    const uint64_t packed = (uint64_t)(lo | ((uint64_t)hi << 32));
    const uint64_t w = packed ^ mask_word(key, (uint64_t)i * 8u);
    for (int b = 0; b < 8; b++) {
      const uint32_t at = i * 8u + (uint32_t)b;
      if (at < raw_len) dst[at] = (uint8_t)((w >> (8 * b)) & 0xFF);
    }
  }
  *out = dst;
  return raw_len;
}

/*
 * Walks the body layout and populates every parsed view, with the bounds checks
 * the interpreter relies on. Returns 0 on success, -1 on a malformed body.
 *
 * Called from two places, and that is the point: `dvmp_module_init` after the
 * first open, and `module_open_locked` on every subsequent one - because `seal`
 * wipes the body, so nothing parsed survives a call. Keeping one routine means the
 * layout is described once; duplicating it is how an open path ends up with a
 * `m->strings` that is NULL, which surfaces as an access violation inside the
 * `push_s` handler rather than as a parse error.
 *
 * Body layout (see dvmp_wire.h):
 *   u32 strings_len | strings | u32 const_count | i64 consts[]
 *   u32 str_count   | {u32 off, u32 len}[]      | u32 fn_count
 *   fn_desc[fn_count] (DVMP_DESC_SIZE each)   | u32 code_len | code[]
 */
static int parse_body_views(DvmpModule *m) {
  const uint32_t body_len = m->body_len;
  uint32_t off = 0;

  if (off + 4u > body_len) return -1;
  m->strings_len = rd_u32(m->body + off);
  off += 4u;
  /* Compared in 64-bit: `body_len - off` underflows when body_len < 4, which made
   * the check pass and the next read run off the end. */
  if ((uint64_t)off + m->strings_len > body_len) return -1;
  m->strings = m->body + off;
  off += m->strings_len;

  if (off + 4u > body_len) return -1;
  m->const_count = rd_u32(m->body + off);
  off += 4u;
  if ((uint64_t)off + (uint64_t)m->const_count * 8u > body_len) return -1;
  m->consts = (const int64_t *)(const void *)(m->body + off);
  off += m->const_count * 8u;

  if (off + 4u > body_len) return -1;
  m->str_count = rd_u32(m->body + off);
  off += 4u;
  if ((uint64_t)off + (uint64_t)m->str_count * 8u > body_len) return -1;
  m->str_tab = m->body + off;
  off += m->str_count * 8u;

  if (off + 4u > body_len) return -1;
  m->func_count = rd_u32(m->body + off);
  off += 4u;
  /* The module's function count has to match the compiled-in entry table: the
   * interpreter indexes `m->funcs` with ids that came from `kDvmpEntries`. */
  if (m->func_count != m->entry_count) return -1;
  if ((uint64_t)off + (uint64_t)m->func_count * DVMP_DESC_SIZE > body_len) {
    return -1;
  }

  /*
   * The descriptor array is allocated ONCE and reused, not reallocated per open.
   *
   * It used to be a bare `calloc` on every call to this function, and this
   * function runs on every open - so every protected call leaked one descriptor
   * array. Nothing noticed because the array is not on the guarded allocator and
   * `Vmp.secureBytesLive()` therefore never counted it: the leak was invisible to
   * the only leak-shaped check in the suite, and the concurrency harness (3200
   * calls) only reached about a megabyte. An application calling a protected
   * function in a loop would have grown without bound.
   *
   * Reusing it is also simply faster: this is on the per-call path, and the
   * function count cannot change between opens of the same module. The contents
   * are still rebuilt from the body every time - the array is a cache of *derived*
   * data, and `memset` before the parse keeps that true even if a later edit makes
   * a field conditional.
   */
  if (m->funcs == NULL || m->funcs_cap < m->func_count) {
    if (m->funcs != NULL) {
      vmp_secure_free(m->funcs, (size_t)m->funcs_cap * sizeof(DvmpFuncDesc));
      m->funcs = NULL;
      m->funcs_cap = 0;
    }
    /* On the guarded allocator rather than plain `calloc`: the descriptors carry
     * every function's name pointer and code offset, which is protection-surface
     * metadata, and putting them here is also what lets the suite's
     * `secureBytesLive()` check notice a per-call allocation. */
    const size_t bytes = (size_t)m->func_count * sizeof(DvmpFuncDesc);
    m->funcs = (DvmpFuncDesc *)vmp_secure_alloc(bytes);
    if (m->funcs == NULL) return -1;
    m->funcs_cap = m->func_count;
  } else {
    memset(m->funcs, 0, (size_t)m->funcs_cap * sizeof(DvmpFuncDesc));
  }

  for (uint32_t i = 0; i < m->func_count; i++) {
    const uint8_t *d = m->body + off + (uint64_t)i * DVMP_DESC_SIZE;
    /*
     * Field offsets, in the order the generator writes them. See
     * `DVMP_DESC_SIZE` in dvmp_wire.h for the layout table.
     *
     * These are stated as explicit indices rather than a struct cast for the same
     * reason the generator writes them field by field: the two languages have to
     * agree on a byte layout, and a `struct` here would silently gain padding that
     * the generator knows nothing about. The size constant checks the record
     * *length*; only this table can be wrong about the *order*, and when it was
     * (the policy bytes were inserted and this parser was not updated) init failed
     * with "module body is corrupt" and nothing pointing at the layout.
     */
    const uint32_t name_off = rd_u32(d + DVMP_DESC_OFF_NAME_OFF);
    const uint32_t name_len = rd_u32(d + DVMP_DESC_OFF_NAME_LEN);
    /*
     * The two reserved bytes have to be zero. They exist so that a field moving
     * cannot be silent: every previous layout change here shipped at least one
     * place that still read the old offset, and the symptom was always something
     * else - an empty code region, a bad CRC - rather than a layout error. A
     * non-zero reserved field means the generator and this parser disagree about
     * the record, which is a hard failure by construction.
     */
    if (d[DVMP_DESC_OFF_RESERVED] != 0 ||
        d[DVMP_DESC_OFF_RESERVED2] != 0 ||
        d[DVMP_DESC_OFF_RESERVED2 + 1] != 0) {
      dvmp_vm_set_error("descriptor %u has a non-zero reserved field; the "
                        "generator and the runtime disagree about the layout",
                        i);
      return -1;
    }
    m->funcs[i].guard_mode =
        (uint8_t)(d[DVMP_DESC_OFF_GUARD_MODE] & DVMP_GUARD_MASK);
    const uint32_t guard_budget = (uint32_t)d[DVMP_DESC_OFF_GUARD_BUDGET] |
                                  ((uint32_t)d[DVMP_DESC_OFF_GUARD_BUDGET + 1] << 8);
    const uint32_t guard_window = (uint32_t)d[DVMP_DESC_OFF_GUARD_WINDOW] |
                                  ((uint32_t)d[DVMP_DESC_OFF_GUARD_WINDOW + 1] << 8);
    m->funcs[i].guard_budget = (uint16_t)guard_budget;
    m->funcs[i].guard_window_ms = (uint16_t)guard_window;
    /* A RATE guard with no budget or no window would refuse every call: that is a
     * miscompile, not a policy. */
    if (m->funcs[i].guard_mode == DVMP_GUARD_RATE &&
        (guard_budget == 0 || guard_window == 0)) {
      return -1;
    }
    m->funcs[i].arity =
        (uint16_t)((uint32_t)d[DVMP_DESC_OFF_ARITY] |
                   ((uint32_t)d[DVMP_DESC_OFF_ARITY + 1] << 8));
    m->funcs[i].locals =
        (uint16_t)((uint32_t)d[DVMP_DESC_OFF_LOCALS] |
                   ((uint32_t)d[DVMP_DESC_OFF_LOCALS + 1] << 8));
    m->funcs[i].max_stack =
        (uint16_t)((uint32_t)d[DVMP_DESC_OFF_MAX_STACK] |
                   ((uint32_t)d[DVMP_DESC_OFF_MAX_STACK + 1] << 8));
    m->funcs[i].slot_base =
        (uint16_t)((uint32_t)d[DVMP_DESC_OFF_SLOT_BASE] |
                   ((uint32_t)d[DVMP_DESC_OFF_SLOT_BASE + 1] << 8));
    if (m->funcs[i].slot_base >= DVMP_MAX_SLOTS) return -1;
    m->funcs[i].code_len = rd_u32(d + DVMP_DESC_OFF_CODE_LEN);
    const uint32_t code_off = rd_u32(d + DVMP_DESC_OFF_CODE_OFF);
    if ((uint64_t)name_off + name_len > m->strings_len) return -1;
    if (m->funcs[i].max_stack == 0 || m->funcs[i].max_stack > DVMP_MAX_STACK) {
      return -1;
    }
    if (m->funcs[i].arity > 8) return -1;
    m->funcs[i].name = m->strings + name_off;
    m->funcs[i].name_len = name_len;
    if ((uint64_t)code_off + m->funcs[i].code_len > body_len) return -1;
    /* Recorded as a delta; validated against the code region below. */
    m->funcs[i].code_off = code_off;
  }
  off += m->func_count * DVMP_DESC_SIZE;

  if (off + 4u > body_len) return -1;
  m->code_len = rd_u32(m->body + off);
  off += 4u;
  if ((uint64_t)off + m->code_len > body_len) return -1;
  m->code = m->body + off;

  /* Now that the region is known, turn each absolute offset into a delta and
   * check it actually lands inside the region. */
  for (uint32_t i = 0; i < m->func_count; i++) {
    if (m->funcs[i].code_off < off) return -1;
    m->funcs[i].code_off -= off;
    if ((uint64_t)m->funcs[i].code_off + m->funcs[i].code_len > m->code_len) {
      return -1;
    }
  }
  return 0;
}

int32_t dvmp_module_init(void) {
  DvmpModule *m = &g_mod;
  if (m->ready) return DARTVMP_OK;

  memset(m, 0, sizeof(*m));

  /*
   * Instrumentation verdict, taken here rather than by the caller.
   *
   * `dartvmp_init_locked` has to ask the same question (to decide whether to refuse),
   * but it cannot store the answer: this function memsets the whole module a few lines
   * up, so anything written before the call is gone, and the first `open` - which is
   * inside this call - would size its cache as if nothing were attached. Asking again
   * here is one cheap check and removes the ordering trap.
   *
   * The entry-point scan is folded into the same verdict, on purpose: both mean "the
   * process is being interfered with", and both react the same way - a narrower
   * plaintext window, never a different answer. It is four bytes per ABI function,
   * read once.
   */
  uint32_t hooked = 0;
  (void)dvmp_integrity_check_entries(&hooked);
  m->instrumented = (vmp_is_instrumented() || hooked != 0) ? 1 : 0;
  m->hooked_entries = hooked;

  /* Phase 1: bring the shipped container into a plaintext working buffer so it
   * can be authenticated before a single field is trusted. */
  uint8_t *probe = NULL;
  const uint32_t probe_len = unmask_image_into(&probe);
  if (probe_len == 0) return DARTVMP_ERR_OUT_OF_MEMORY;

  const uint8_t *h = probe;
  if (h[0] != DVMP_MAGIC0 || h[1] != DVMP_MAGIC1 || h[2] != DVMP_MAGIC2 ||
      h[3] != DVMP_MAGIC3) {
    vmp_secure_free(probe, probe_len);
    return DARTVMP_ERR_MODULE_MAGIC;
  }
  const uint32_t version =
      (uint32_t)h[DVMP_OFF_VERSION] | ((uint32_t)h[DVMP_OFF_VERSION + 1] << 8);
  if (version != DVMP_CONTAINER_VERSION) {
    /* Report the bytes actually seen plus the mask/key values used: a stale
     * object file or a generator/runtime mismatch otherwise surfaces as an
     * opaque version error. */
    dvmp_vm_set_error(
        "header=[%02x %02x %02x %02x %02x %02x %02x %02x] ver=%u key=%llx "
        "m0=%llx m8=%llx w0=%llx",
        h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7], version,
        (unsigned long long)(uint64_t)kDvmpImage_MASK_KEY,
        (unsigned long long)mask_word((uint64_t)kDvmpImage_MASK_KEY, 0),
        (unsigned long long)mask_word((uint64_t)kDvmpImage_MASK_KEY, 8),
        (unsigned long long)(
            (uint64_t)kDvmpImage_words[0].lo |
            ((uint64_t)kDvmpImage_words[0].hi << 32)));
    vmp_secure_free(probe, probe_len);
    return DARTVMP_ERR_MODULE_VERSION;
  }

  const uint32_t body_len = rd_u32(h + DVMP_OFF_BODY_LEN);
  const uint32_t entry_count = rd_u32(h + DVMP_OFF_ENTRY_COUNT);
  if (body_len == 0 ||
      DVMP_HEADER_SIZE + (uint64_t)body_len + DVMP_TAG_SIZE > probe_len) {
    dvmp_vm_set_error("container length fields inconsistent: bodyLen=%u "
                      "probeLen=%u entryCount=%u",
                      body_len, probe_len, entry_count);
    vmp_secure_free(probe, probe_len);
    return DARTVMP_ERR_MODULE_CORRUPT;
  }
  if (entry_count != (uint32_t)DVMP_ENTRY_COUNT) {
    /* Compiler and runtime disagree about the module; refuse rather than run
     * a mismatched function table. */
    dvmp_vm_set_error("entry count mismatch: header=%u runtime=%u",
                      entry_count, (uint32_t)DVMP_ENTRY_COUNT);
    vmp_secure_free(probe, probe_len);
    return DARTVMP_ERR_MODULE_CORRUPT;
  }

  m->master_len = probe_len;
  m->master = probe;
  m->seed = rd_u64(h + DVMP_OFF_SEED);
  m->body_len = body_len;
  m->body_crc = rd_u32(h + DVMP_OFF_BODY_CRC);
  m->auth_tag = rd_u64(h + DVMP_HEADER_SIZE + body_len);
  m->entry_count = entry_count;
  m->entries = kDvmpEntries;
  m->max_arity = 1;
  for (uint32_t i = 0; i < entry_count; i++) {
    if (kDvmpEntries[i].arity > m->max_arity) {
      m->max_arity = kDvmpEntries[i].arity;
    }
  }

  m->body = (uint8_t *)vmp_secure_alloc(body_len);
  if (m->body == NULL) {
    module_release(m);
    return DARTVMP_ERR_OUT_OF_MEMORY;
  }
  /* The code store and its slots are allocated by `code_store_build`, on the
   * first open, because that is the first point at which the code region's length
   * and every function's length are known. Allocating them from `body_len` here
   * would mean, for a store that mirrors the code region, either over-allocating
   * by the size of the metadata or duplicating the layout walk. */
  m->ready = 1;

  /* Phase 2: decrypt + authenticate + parse. */
  int32_t rc = module_open_locked();
  if (rc != DARTVMP_OK) {
    m->ready = 0;
    module_release(m);
    return rc;
  }
  m->unsealed = 1;

  /*
   * No second `parse_body_views` here.
   *
   * `module_open_locked` has already parsed and validated the body by the time it
   * returns OK - it has to, because it needs the descriptors to build the code
   * store. Re-parsing was not only wasted work on the init path: it re-pointed
   * `m->code` at the body's code region, which by then has been wiped, and it was a
   * second allocation of the descriptor array that nothing ever freed. Both are
   * gone; `m->code` is NULL for the whole lifetime of the module now, which is what
   * the header says it is.
   */
  if (m->code != NULL) {
    /* Unreachable by construction, and asserted because the alternative is a
     * pointer that reads as valid and lands in a zeroed buffer. */
    dvmp_vm_set_error("internal: the code pointer is resident after open");
    m->ready = 0;
    module_release(m);
    return DARTVMP_ERR_INTERNAL;
  }

  vmp_secure_harden(m->body, m->body_len);
  vmp_secure_harden(m->master, m->master_len);

  /* Close the plaintext window before returning to the caller. */
  dvmp_module_reseal();
  return DARTVMP_OK;
}

const DvmpEntryMeta *dvmp_module_entries(uint32_t *count) {
  if (count != NULL) *count = g_mod.entry_count;
  return g_mod.entries;
}

/* The build id compiled into the generated image. Exposed through a function
 * so the generated include stays private to this translation unit. */
uint32_t dvmp_module_build_id(void) { return (uint32_t)DVMP_BUILD_ID; }

/*
 * Copies the first 
` bytes of decoded code for function `func` into `out`.
 *
 * The interpreter's faults carry a function index and pc but no way to see what
 * it actually decoded, which makes "the opcode stream is wrong" versus "the
 * interpreter mis-executes a correct stream" impossible to distinguish. This
 * closes that gap by exposing the decoded bytes to the test suite.
 */
int32_t dvmp_module_code_probe(uint32_t func, uint8_t *out, uint32_t n,
                               uint32_t *out_len) {
  if (!g_mod.ready || func >= g_mod.func_count) {
    return DARTVMP_ERR_FUNCTION_NOT_FOUND;
  }
  /*
   * Refuse while the module is sealed, because there is nothing decoded to read:
   * `seal` wipes the store and the slots. Before the wipe existed this served
   * plaintext opcodes at any time, which is what made the leak persistent rather
   * than per-call - a diagnostic that silently widens the plaintext window is
   * worse than no diagnostic.
   */
  if (!g_mod.unsealed) {
    dvmp_vm_set_error("code probe refused: the module is sealed");
    return DARTVMP_ERR_NOT_INITIALIZED;
  }
  /*
   * Route through the loader rather than reading a base pointer, so the probe
   * reports exactly what the interpreter would execute. It used to add `code +
   * code_off` itself; with the stream no longer resident that would have been a
   * second, divergent definition of "the decoded code" - and a probe that agrees
   * with itself instead of with the interpreter is worse than none.
   *
   * The side effect is that probing materialises the function, which is correct
   * here (the probe only answers while the module is open) and is what makes the
   * residency assertions in the test suite measurable: a probe is the only way to
   * force a slot to be filled from outside the interpreter.
   */
  const DvmpFuncDesc *f = &g_mod.funcs[func];
  const uint8_t *code = dvmp_code_ensure(func, f->code_off, f->code_len);
  if (code == NULL) {
    dvmp_vm_set_error("code probe could not materialise function %u", func);
    return DARTVMP_ERR_MODULE_CORRUPT;
  }
  const uint32_t copy = n < f->code_len ? n : f->code_len;
  if (out != NULL) memcpy(out, code, copy);
  if (out_len != NULL) *out_len = copy;
  return DARTVMP_OK;
}

/*
 * Reference values for the generator/runtime contract.
 *
 * A mismatch between the Dart generator and this file shows up otherwise only
 * as "wrong magic" or "tag mismatch", with no indication of *which* constant
 * drifted. The test suite diffs this against the same table produced by
 * tool/vmpc, which turns a class of opaque failures into a precise one.
 */
void dvmp_module_mask_probe(uint32_t index, uint64_t *mask, uint64_t *word) {
  const uint64_t key = (uint64_t)kDvmpImage_MASK_KEY;
  if (mask != NULL) *mask = mask_word(key, (uint64_t)index * 8u);
  if (word != NULL) {
    if (index < (uint32_t)kDvmpImage_WORD_COUNT) {
      *word = (uint64_t)kDvmpImage_words[index].lo |
              ((uint64_t)kDvmpImage_words[index].hi << 32);
    } else {
      *word = 0;
    }
  }
}

int32_t dvmp_module_image_probe(uint8_t *out, uint32_t n, uint32_t *out_len,
                                uint32_t *build_id) {
  if (!g_mod.ready || g_mod.master == NULL) return DARTVMP_ERR_NOT_INITIALIZED;
  const uint32_t copy = n < g_mod.master_len ? n : g_mod.master_len;
  if (out != NULL) memcpy(out, g_mod.master, copy);
  if (out_len != NULL) *out_len = copy;
  if (build_id != NULL) *build_id = dvmp_module_build_id();
  return DARTVMP_OK;
}

/*
 * Evidence that the instruction store is not sealed under the shipped seed.
 *
 * The point being tested is not that the store's bytes differ from the shipped
 * container's - they obviously do, that is what a stream cipher does. It is that
 * the store's *key* is not recoverable from anything on disk: it is fresh runtime
 * entropy, redrawn on every open, and nothing in `master` or in any header
 * encodes it. So this reports the shipped seed and the store's key material, and
 * the caller asserts they differ and that the key rotates across calls. If the
 * store were ever sealed under the shipped seed, a dump plus the on-disk binary
 * would be enough to recover the instruction stream offline - a regression no
 * functional test would catch, because every call would still return the right
 * answer.
 *
 * This used to report the seed serialised into `m->work`'s header, alongside the
 * session key and the nonce it was masked with. `work` is gone: once `open` began
 * wiping the body's code region, a re-sealed container could only have been built
 * from a body with its instruction stream zeroed, so its CRC and tag would have
 * described something that no longer existed. Reporting a decoy's header seed
 * would have kept the *test* green while the thing it described was fiction.
 */
int32_t dvmp_module_session_probe(uint64_t *master_seed, uint64_t *store_key,
                                  uint64_t *store_salt) {
  if (!g_mod.ready || g_mod.master == NULL) return DARTVMP_ERR_NOT_INITIALIZED;
  if (master_seed != NULL) *master_seed = rd_u64(g_mod.master + DVMP_OFF_SEED);
  /*
   * The live key is zeroed by `seal`, which is correct and also useless to a
   * caller standing between two calls: it cannot tell "sealed under runtime
   * entropy" from "never encrypted". So this reports the pair actually used, which
   * is not read by anything and therefore cannot widen the plaintext window.
   */
  if (store_key != NULL) *store_key = g_mod.code_key_last;
  if (store_salt != NULL) *store_salt = g_mod.code_salt_last;
  return DARTVMP_OK;
}

/*
 * Whether the decrypted body is currently resident.
 *
 * The strongest observable the suite has for "the plaintext window is closed":
 * `unsealed` is set only while the body is decrypted, so a test can assert it is
 * clear after a call returns. Reporting state rather than content keeps this from
 * becoming another way to read protected bytes - `dvmp_module_code_probe` covers
 * that, and refuses while sealed.
 */
int32_t dvmp_module_plaintext_probe(uint32_t *live) {
  if (!g_mod.ready) return DARTVMP_ERR_NOT_INITIALIZED;
  if (live != NULL) *live = (uint32_t)g_mod.unsealed;
  return DARTVMP_OK;
}

/*
 * How many bytes of the body buffer are non-zero, and whether it is non-zero at
 * all. Diagnostics.
 *
 * Reported as a *count* rather than as content, which is what makes this safe to
 * expose: it answers "is there still something in the body buffer" without
 * revealing what. That distinction matters, because the obvious weaker check -
 * reading the `unsealed` flag - cannot detect the bug this exists to catch. An
 * earlier revision left `m->body` fully decoded for the lifetime of the process
 * while `unsealed` was correctly 0, so a flag-based test passed while a memory
 * dump found the protected alphabet string and `add`'s opcodes in one page.
 */
int32_t dvmp_module_body_residue(uint32_t *nonzero, uint32_t *any) {
  if (!g_mod.ready || g_mod.body == NULL) return DARTVMP_ERR_NOT_INITIALIZED;
  uint32_t n = 0;
  for (uint32_t i = 0; i < g_mod.body_len; i++) {
    if (g_mod.body[i] != 0) n++;
  }
  if (nonzero != NULL) *nonzero = n;
  if (any != NULL) *any = (n != 0) ? 1u : 0u;
  return DARTVMP_OK;
}

/*
 * Clears every call-policy usage counter. Diagnostics only.
 *
 * The suite needs both halves of a policy: that it refuses calls past the budget,
 * and that the function still computes correctly. Without a reset those are
 * mutually exclusive, because the test that deliberately exhausts the budget runs
 * before the ones that check correctness. It is compiled out of a release build
 * via `DVMP_DIAGNOSTICS`, because a shipped library must not offer a way to clear
 * its own rate limits - that would be a one-call bypass, which is worse than no
 * guard at all.
 */
#if defined(DVMP_DIAGNOSTICS)
/*
 * Reports what the runtime actually holds for a function's call policy, separately from
 * what the container declares and what the manifest recorded.
 *
 * Those three can disagree, and when they did the symptom was nothing at all: the policy
 * was declared, encoded, decoded by an independent tool, and never enforced. With this
 * probe the disagreement is a number a test can assert on.
 */
int32_t dvmp_module_guard_probe(uint32_t func, uint32_t *mode, uint32_t *budget,
                                uint32_t *window_ms, uint32_t *used,
                                uint64_t *window_start) {
  const DvmpModule *m = &g_mod;
  if (!m->ready) return DARTVMP_ERR_NOT_INITIALIZED;
  if (func >= m->func_count) return DARTVMP_ERR_FUNCTION_NOT_FOUND;
  if (mode != NULL) *mode = (uint32_t)m->funcs[func].guard_mode;
  if (budget != NULL) *budget = (uint32_t)m->funcs[func].guard_budget;
  if (window_ms != NULL) *window_ms = (uint32_t)m->funcs[func].guard_window_ms;
  if (used != NULL) *used = m->guard_state[func].used;
  if (window_start != NULL) *window_start = m->guard_state[func].window_start;
  return DARTVMP_OK;
}
#endif

int32_t dvmp_module_guard_reset(void) {
  if (!g_mod.ready) return DARTVMP_ERR_NOT_INITIALIZED;
  memset(g_mod.guard_state, 0, sizeof(g_mod.guard_state));
  return DARTVMP_OK;
}

/*
 * Entry-name table access.
 *
 * The generated table is masked (see the generator's `_namesTable`), so a name
 * is recovered by XORing the blob byte at `abs` with the keystream byte for that
 * position. Two properties are deliberate:
 *
 *   * the mask primitive is the same SplitMix64 finaliser the image mask uses
 *     (`mask_word` with a different key), so there is one mixing step to keep
 *     bit-compatible with Dart rather than two;
 *   * every access decodes only the bytes it needs. `entry_name_eq` never
 *     materialises a name at all - it compares as it decodes - and
 *     `dvmp_module_name_copy` writes straight into the caller's buffer. Nothing
 *     here builds a plaintext copy of the whole table, so dumping this process
 *     does not yield the protection surface as a readable list.
 */
static uint8_t name_blob_byte(uint32_t abs) {
  const uint64_t key = (uint64_t)DVMP_NAMES_MASK_KEY;
  const uint64_t w = mask_word(key, (uint64_t)abs & ~(uint64_t)7);
  return (uint8_t)((w >> (8u * (abs & 7u))) & 0xFFu);
}

static uint8_t name_byte(uint32_t abs) {
  return (uint8_t)(kDvmpNameBlob[abs] ^ name_blob_byte(abs));
}

static int name_slot_offset(uint32_t index, uint32_t *out) {
  if (index >= (uint32_t)DVMP_OFFSET_TABLE_LEN) return -1;
  if (index >= (uint32_t)DVMP_ENTRY_COUNT) return -1;
  const uint32_t off = (uint32_t)kDvmpNameOffsets[index];
  if (off >= (uint32_t)DVMP_NAME_BLOB_LEN) return -1;
  /*
   * Validate the whole *record*, not just where it starts.
   *
   * The length byte is part of the same table, and a table that disagrees with
   * this runtime - a stale generated header linked against a newer library, or a
   * hand-edited header - would otherwise let `entry_name_eq` and
   * `dvmp_module_name_copy` read up to 255 bytes past a 104-byte array. The table
   * is a compile-time constant rather than attacker-supplied data, so this guards
   * against inconsistent build artifacts rather than against a crafted container;
   * it is cheap either way, and the alternative is an out-of-bounds read with no
   * diagnostic to explain it.
   */
  const uint32_t len = name_byte(off);
  if (len >= (uint32_t)DVMP_MAX_NAME_LEN) return -1;
  if ((uint64_t)off + 1u + (uint64_t)len > (uint64_t)DVMP_NAME_BLOB_LEN) {
    return -1;
  }
  *out = off;
  return 0;
}

static int entry_name_eq(uint32_t index, const char *query) {
  uint32_t off = 0;
  if (name_slot_offset(index, &off) != 0) return 0;
  const uint32_t len = name_byte(off);
  uint32_t differ = 0;
  /*
   * Compare byte by byte as we decode, without ever materialising a name.
   *
   * The walk is bounded by the *name's* length, and it stops as soon as the query
   * ends. An earlier version looped until both sides produced a NUL, with the
   * bound checked after the read: once the query's terminator was consumed while
   * the name still had bytes, it kept reading `query[i]` past the end of the
   * caller's buffer - up to DVMP_MAX_NAME_LEN bytes, reachable from
   * `Vmp.callNamed` with any query shorter than the name being compared. Over a
   * `toNativeUtf8` allocation that stays inside the heap and cannot produce a
   * wrong match, but a native host passing a slice or a bounded buffer would
   * fault, and it is a straightforward out-of-bounds read either way.
   */
  for (uint32_t i = 0; i <= len; i++) {
    const uint8_t got = (uint8_t)query[i];
    const uint8_t want = (i < len) ? name_byte(off + 1u + i) : 0u;
    differ |= (uint32_t)(want ^ got);
    /* Stop at whichever string ends first: the accumulated difference already
     * records the length mismatch. */
    if (got == 0u) break;
  }
  return (int)((((differ | (0u - differ)) >> 31) ^ 1u) & 1u);
}

uint32_t dvmp_module_name_copy(uint32_t index, char *out, uint32_t cap) {
  uint32_t off = 0;
  if (out == NULL || cap == 0) return 0;
  if (name_slot_offset(index, &off) != 0) {
    out[0] = '\0';
    return 0;
  }
  const uint32_t len = name_byte(off);
  const uint32_t copy = (len < cap - 1u) ? len : cap - 1u;
  for (uint32_t i = 0; i < copy; i++) {
    out[i] = (char)name_byte(off + 1u + i);
  }
  out[copy] = '\0';
  return copy;
}

int32_t dvmp_module_find(const char *name) {
  for (uint32_t i = 0; i < g_mod.entry_count; i++) {
    if (entry_name_eq(i, name)) {
      return (int)g_mod.entries[i].id;
    }
  }
  return -1;
}

/*
 * Copies one function's parsed descriptor out, so a test can diff the runtime's
 * view of the module against the compiler's. Descriptor drift (a wrong slot base
 * or code offset) otherwise shows up only as a type error deep inside a builtin.
 */
/*
 * Reads a frame slot's tag, for diagnosing which parameter a function actually
 * received. `slot` is the absolute index the bytecode uses.
 */
int32_t dvmp_module_slot_probe(uint32_t slot, int64_t *tag, int64_t *bits) {
  return dvmp_vm_probe_slot(slot, tag, bits);
}

int32_t dvmp_module_desc_probe(uint32_t func, uint32_t *arity, uint32_t *locals,
                               uint32_t *slot_base, uint32_t *code_off,
                               uint32_t *code_len) {
  if (!g_mod.ready || func >= g_mod.func_count) {
    return DARTVMP_ERR_FUNCTION_NOT_FOUND;
  }
  const DvmpFuncDesc *d = &g_mod.funcs[func];
  if (arity != NULL) *arity = d->arity;
  if (locals != NULL) *locals = d->locals;
  if (slot_base != NULL) *slot_base = d->slot_base;
  if (code_off != NULL) *code_off = d->code_off;
  if (code_len != NULL) *code_len = d->code_len;
  return DARTVMP_OK;
}
