/*
 * dvmp_integrity.c - detecting a patched entry point.
 *
 * WHAT THIS IS FOR, AND WHAT IT IS WORTH
 * --------------------------------------
 * The cheapest attack on this system does not touch the container, the bytecode or the
 * interpreter: it patches the *answer*. Return `true` from the licence check, or
 * intercept the ABI entry point that produces it. No amount of VM obfuscation changes
 * that - an attacker who only wants to bypass a check never needs to read the check.
 *
 * The two ways that attack is done in practice both leave the same mark: a branch where
 * the intercepted function's first instruction used to be.
 *
 *   * Frida's Interceptor (and Dobby, and any inline hook) overwrite those bytes with a
 *     branch to a trampoline it allocated elsewhere in the process;
 *   * a manual patch does the same thing by hand, for the same reason: the entry point
 *     is four bytes and replacing them redirects everything.
 *
 * So this scans the ABI entry points for a branch at offset zero. Its ceiling, stated
 * exactly, is:
 *
 *   * it finds a hook that *begins* with a branch. One that saves the prologue and
 *     branches later, or that patches the caller instead, is not found;
 *   * it is itself patchable - an attacker who knows it is there can make it say
 *     "clean";
 *   * a direct branch whose target is inside this module is NOT reported, because that
 *     is what a tail call looks like (see below).
 *
 * Raising the cost of the trivial patch is the whole claim.
 *
 * WHY THE BRANCH TARGET MATTERS, MEASURED
 * ---------------------------------------
 * The first version of this file reported any entry point beginning with an
 * unconditional branch, and on the Windows test build it flagged three clean functions
 * as hooked: `dartvmp_last_error`, `dartvmp_secure_bytes_live` and `dartvmp_build_id`.
 * They are one-line wrappers, and MSVC ends such a function with `jmp` rather than a
 * call/return pair, so their first bytes are `E9 <rel32>` followed by `CC` padding -
 * byte-for-byte what a hook looks like in the first four bytes.
 *
 * What separates them is where the branch goes. A tail call goes to another function in
 * the same library; a hook goes to a trampoline in a different allocation. So the check
 * asks that question, and the answer is cheap on both platforms. The false positive is
 * now a standing test: `dvmp_integrity_selftest()` requires every real ABI entry point
 * to classify as clean, which is exactly the assertion that would have caught it.
 *
 * The reaction follows the rule the rest of this runtime follows: record the verdict,
 * narrow the plaintext window, and **never change an answer**. `-DDVMP_ANTIDEBUG_REFUSE`
 * remains the opt-in "refuse to run" behaviour and covers this too, because a component
 * that can break the application is worse than one that reports.
 */
#include "dvmp_internal.h"
#include "dartvmp.h"

#if defined(_WIN32)
#include <windows.h>
#elif defined(__ANDROID__) || defined(__linux__)
#include <link.h>
#endif

/* ------------------------------------------------------------------ */
/* Same-module query                                                   */
/* ------------------------------------------------------------------ */

#if defined(__ANDROID__) || defined(__linux__)
struct dvmp_range_probe {
  const void *probe;
  uintptr_t base;
  int found;
};

/* Callback for dl_iterate_phdr: records the load base of the object whose PT_LOAD
 * segments contain `probe`. A plain function, not a lambda - this file is C. */
static int dvmp_range_cb(struct dl_phdr_info *info, size_t size, void *data) {
  struct dvmp_range_probe *w = (struct dvmp_range_probe *)data;
  (void)size;
  for (int i = 0; i < info->dlpi_phnum; i++) {
    const ElfW(Phdr) *ph = &info->dlpi_phdr[i];
    if (ph->p_type != PT_LOAD) continue;
    const uintptr_t lo = (uintptr_t)info->dlpi_addr + (uintptr_t)ph->p_vaddr;
    const uintptr_t hi = lo + (uintptr_t)ph->p_memsz;
    if ((uintptr_t)w->probe >= lo && (uintptr_t)w->probe < hi) {
      w->base = (uintptr_t)info->dlpi_addr;
      w->found = 1;
      return 1; /* stop the walk */
    }
  }
  return 0;
}
#endif

/*
 * Is `target` inside the same loaded module as `addr`?
 *
 * Returns 1 when the platform cannot answer, so an unknown case is reported as "inside"
 * and therefore not as a hook: a check that cries wolf on clean builds gets switched
 * off, while a check that is occasionally blind stays on and still catches the common
 * case. That trade is deliberate and is the reason the Windows false positive was worth
 * a rewrite rather than a note.
 */
static int dvmp_same_module(const void *addr, const void *target) {
#if defined(_WIN32)
  MEMORY_BASIC_INFORMATION a, b;
  if (VirtualQuery(addr, &a, sizeof(a)) == 0) return 1;
  if (VirtualQuery(target, &b, sizeof(b)) == 0) return 1;
  return a.AllocationBase == b.AllocationBase;
#elif defined(__ANDROID__) || defined(__linux__)
  struct dvmp_range_probe want = {addr, 0, 0};
  struct dvmp_range_probe tgt = {target, 0, 0};
  (void)dl_iterate_phdr(dvmp_range_cb, &want);
  (void)dl_iterate_phdr(dvmp_range_cb, &tgt);
  if (!want.found || !tgt.found) return 1;
  return want.base == tgt.base;
#else
  (void)addr;
  (void)target;
  return 1;
#endif
}

/* ------------------------------------------------------------------ */
/* Instruction decoding                                                */
/* ------------------------------------------------------------------ */

/*
 * How many bytes of the entry point the scan reads. Enough for the branch forms above
 * and small enough that a legitimately short function cannot be misread.
 */
#define DVMP_ENTRY_SCAN_BYTES 16u

/* What the scan found at offset zero. */
enum {
  DVMP_ENTRY_CLEAN = 0,
  DVMP_ENTRY_DIRECT = 1,   /* unconditional branch to a computed target */
  DVMP_ENTRY_INDIRECT = 2, /* branch through a register or a memory slot  */
};

static uint32_t dvmp_rd32(const uint8_t *p) {
  return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
         ((uint32_t)p[3] << 24);
}

/*
 * Classifies the first instruction(s) of the buffer, writing the branch destination
 * through `target` for DVMP_ENTRY_DIRECT.
 *
 * Deliberately pure - the instruction bytes in, a classification out - because that is
 * what makes the decoder testable against known encodings on any host, which
 * `dvmp_integrity_selftest` does. The *decision* (hooked or not) needs the address as
 * well, and lives in `dvmp_entry_is_hooked` below.
 */
static int dvmp_classify_branch(const uint8_t *words, uint32_t len,
                                uintptr_t *target) {
  if (words == NULL || len < 4) return DVMP_ENTRY_CLEAN;
#if defined(__aarch64__) || defined(_M_ARM64)
  const uint32_t w = dvmp_rd32(words);
  if ((w & 0xFFFFFC1Fu) == 0xD61F0000u) return DVMP_ENTRY_INDIRECT; /* BR  */
  if ((w & 0xFC000000u) == 0x14000000u) {                          /* B   */
    int64_t imm = (int64_t)(w & 0x03FFFFFFu);
    if (imm & 0x02000000) imm |= ~(int64_t)0x03FFFFFF; /* sign-extend 26 bits */
    if (target != NULL) *target = (uintptr_t)((int64_t)(uintptr_t)words + imm * 4);
    return DVMP_ENTRY_DIRECT;
  }
#elif defined(__x86_64__) || defined(_M_X64)
  if (words[0] == 0xFF && words[1] == 0x25) return DVMP_ENTRY_INDIRECT; /* jmp [rip+d] */
  if (len >= 12 && words[0] == 0x48 && words[1] == 0xB8 && words[10] == 0xFF &&
      words[11] == 0xE0) {
    return DVMP_ENTRY_INDIRECT; /* movabs rax, imm64 ; jmp rax */
  }
  if (words[0] == 0xE9) { /* jmp rel32 */
    const int32_t rel = (int32_t)dvmp_rd32(words + 1);
    if (target != NULL) *target = (uintptr_t)((int64_t)(uintptr_t)words + 5 + rel);
    return DVMP_ENTRY_DIRECT;
  }
#else
  (void)words;
  (void)len;
  (void)target;
#endif
  return DVMP_ENTRY_CLEAN;
}

/* Classifies a raw buffer without an address - the self-test's entry point. */
int dvmp_words_look_hooked(const uint8_t *words, uint32_t len) {
  return dvmp_classify_branch(words, len, NULL) != DVMP_ENTRY_CLEAN;
}

/*
 * The decision: is this function's entry patched?
 *
 * An indirect branch at offset zero is treated as hooked - none of this library's entry
 * points starts that way, and it is the shape a stub-based hook leaves. A direct branch
 * is only a hook when it leaves the module, because a tail call is a direct branch too.
 */
static int dvmp_entry_is_hooked(const void *fn) {
  const uint8_t *p = (const uint8_t *)fn;
  uintptr_t target = 0;
  const int kind = dvmp_classify_branch(p, DVMP_ENTRY_SCAN_BYTES, &target);
  if (kind == DVMP_ENTRY_INDIRECT) return 1;
  if (kind == DVMP_ENTRY_DIRECT) {
    return dvmp_same_module(fn, (const void *)target) ? 0 : 1;
  }
  return 0;
}

/* ------------------------------------------------------------------ */
/* The scan                                                            */
/* ------------------------------------------------------------------ */

uint32_t dvmp_integrity_scan(const void *const *entries, uint32_t count,
                             uint32_t *hooked_out) {
  uint32_t hooked = 0;
  if (entries != NULL) {
    for (uint32_t i = 0; i < count && i < 32u; i++) {
      if (entries[i] == NULL) continue;
      if (dvmp_entry_is_hooked(entries[i])) hooked |= (1u << i);
    }
  }
  if (hooked_out != NULL) *hooked_out = hooked;
  return hooked;
}

/*
 * The entry points this scans: the nine documented ABI functions, in the order the
 * bitmask indexes them. Kept here rather than at the call site so that "what gets
 * checked" has one definition - a list assembled by the caller is a list that can drift
 * from the ABI it claims to cover.
 */
static const void *const kAbiEntries[9] = {
    (const void *)(uintptr_t)dartvmp_init,
    (const void *)(uintptr_t)dartvmp_call,
    (const void *)(uintptr_t)dartvmp_call_named,
    (const void *)(uintptr_t)dartvmp_function_count,
    (const void *)(uintptr_t)dartvmp_function_info,
    (const void *)(uintptr_t)dartvmp_last_error,
    (const void *)(uintptr_t)dartvmp_status_name,
    (const void *)(uintptr_t)dartvmp_secure_bytes_live,
    (const void *)(uintptr_t)dartvmp_build_id,
};

uint32_t dvmp_integrity_entry_count(void) {
  return (uint32_t)(sizeof(kAbiEntries) / sizeof(kAbiEntries[0]));
}

uint32_t dvmp_integrity_check_entries(uint32_t *hooked_out) {
  return dvmp_integrity_scan(kAbiEntries, dvmp_integrity_entry_count(), hooked_out);
}

#if defined(DVMP_DIAGNOSTICS)
uint32_t dvmp_integrity_probe(uint32_t *hooked_mask, uint32_t *scanned,
                              uint32_t *selftest_ok) {
  uint32_t hooked = 0;
  uint32_t count = 0;
  const uint32_t n = dvmp_integrity_entry_count();
  (void)dvmp_integrity_scan(kAbiEntries, n, &hooked);
  for (uint32_t i = 0; i < n; i++) {
    if (hooked & (1u << i)) count++;
  }
  if (hooked_mask != NULL) *hooked_mask = hooked;
  if (scanned != NULL) *scanned = n;
  if (selftest_ok != NULL) *selftest_ok = (uint32_t)dvmp_integrity_selftest();
  return count;
}
#endif

/* ------------------------------------------------------------------ */
/* Self-test                                                           */
/* ------------------------------------------------------------------ */

/*
 * Two halves, because they fail differently.
 *
 * 1. The decoder, on known encodings. A decoder that cannot tell a branch from a
 *    prologue would report every process clean, which is the failure mode this project
 *    treats as worse than no check at all.
 * 2. The decision, on the real entry points: every one of them must classify as clean.
 *    That is the half that would have caught the tail-call false positive on the Windows
 *    build (`dartvmp_last_error` and two others are `jmp` thunks), and it is the reason
 *    the self-test is a measurement of this binary rather than of invented constants.
 */
int dvmp_integrity_selftest(void) {
  /* 1. Known encodings. The "clean" vectors are real prologues from this library. */
  const uint8_t a64_hook_b[16] = {0x00, 0x00, 0x00, 0x14};    /* b   #0     */
  const uint8_t a64_hook_br[16] = {0x10, 0x00, 0x1F, 0xD6};   /* br  x16    */
  const uint8_t a64_clean_stp[16] = {0xFD, 0x7B, 0xBF, 0xA9}; /* stp x29,x30 */
  const uint8_t a64_clean_sub[16] = {0xFF, 0x03, 0x01, 0xD1}; /* sub sp,sp,#0x40 */
  const uint8_t x64_hook_e9[16] = {0xE9, 0x00, 0x00, 0x00, 0x00};
  const uint8_t x64_hook_ff25[16] = {0xFF, 0x25, 0x00, 0x00, 0x00, 0x00};
  const uint8_t x64_hook_movabs[16] = {0x48, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xE0};
  const uint8_t x64_clean_push[16] = {0x55, 0x48, 0x89, 0xE5};

#if defined(__aarch64__) || defined(_M_ARM64)
  if (!dvmp_words_look_hooked(a64_hook_b, sizeof(a64_hook_b))) return 0;
  if (!dvmp_words_look_hooked(a64_hook_br, sizeof(a64_hook_br))) return 0;
  if (dvmp_words_look_hooked(a64_clean_stp, sizeof(a64_clean_stp))) return 0;
  if (dvmp_words_look_hooked(a64_clean_sub, sizeof(a64_clean_sub))) return 0;
  (void)x64_hook_e9;
  (void)x64_clean_push;
#elif defined(__x86_64__) || defined(_M_X64)
  if (!dvmp_words_look_hooked(x64_hook_e9, sizeof(x64_hook_e9))) return 0;
  if (!dvmp_words_look_hooked(x64_hook_ff25, sizeof(x64_hook_ff25))) return 0;
  if (!dvmp_words_look_hooked(x64_hook_movabs, sizeof(x64_hook_movabs))) return 0;
  if (dvmp_words_look_hooked(x64_clean_push, sizeof(x64_clean_push))) return 0;
  (void)a64_hook_b;
  (void)a64_clean_stp;
#else
  (void)a64_hook_b;
  (void)x64_hook_e9;
#endif

  /* 2. Every real entry point must classify clean. A hook-shaped-but-legitimate
   * function (a tail-call thunk) would fail here, which is the point. */
  for (uint32_t i = 0; i < dvmp_integrity_entry_count(); i++) {
    if (dvmp_entry_is_hooked(kAbiEntries[i])) return 0;
  }
  return 1;
}
