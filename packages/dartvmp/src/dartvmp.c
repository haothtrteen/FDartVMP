/*
 * dartvmp.c - the public C entry points (see dartvmp.h).
 *
 * Every one of these is a thin shell around dvmp_module_with_plaintext(), which
 * is what guarantees the plaintext window opened for a call is always closed
 * again - including on the error paths. `dartvmp_call` and `dartvmp_init` also
 * hold a process-wide lock, because the module and the interpreter are single
 * instances shared by every isolate in the process.
 */
#include "dvmp_internal.h"

#include <stdio.h>
#include <string.h>

#if defined(_WIN32)
/* CRITICAL_SECTION / INIT_ONCE for the process-wide call lock. */
#include <windows.h>
#else
#include <pthread.h>
#endif

/* ------------------------------------------------------------------ */
/* Status names                                                        */
/* ------------------------------------------------------------------ */

const char *dartvmp_status_name(int32_t status) {
  switch (status) {
    case DARTVMP_OK:
      return "OK";
    case DARTVMP_ERR_NOT_INITIALIZED:
      return "module not initialised";
    case DARTVMP_ERR_BAD_ARGUMENT:
      return "bad argument";
    case DARTVMP_ERR_MODULE_MAGIC:
      return "module image has the wrong magic";
    case DARTVMP_ERR_MODULE_VERSION:
      return "module container version mismatch";
    case DARTVMP_ERR_MODULE_AUTH:
      return "module authentication tag mismatch (tampered image)";
    case DARTVMP_ERR_MODULE_CORRUPT:
      return "module body is corrupt";
    case DARTVMP_ERR_FUNCTION_NOT_FOUND:
      return "protected function not found";
    case DARTVMP_ERR_STEP_LIMIT:
      return "instruction budget exhausted";
    case DARTVMP_ERR_STACK_OVERFLOW:
      return "operand stack overflow";
    case DARTVMP_ERR_STACK_UNDERFLOW:
      return "operand stack underflow";
    case DARTVMP_ERR_TYPE:
      return "type error in protected code";
    case DARTVMP_ERR_DIV_ZERO:
      return "division by zero in protected code";
    case DARTVMP_ERR_INDEX_RANGE:
      return "index out of range in protected code";
    case DARTVMP_ERR_DEPTH_EXCEEDED:
      return "call depth exceeded";
    case DARTVMP_ERR_OUT_OF_MEMORY:
      return "out of memory";
    case DARTVMP_ERR_INVALID_OPCODE:
      return "invalid opcode";
    case DARTVMP_ERR_JUMP_RANGE:
      return "jump target out of range";
    case DARTVMP_ERR_DEBUGGER:
      return "instrumentation detected";
    default:
      return "internal error";
  }
}

const char *dartvmp_last_error(void) { return dvmp_vm_last_error(); }

uint32_t dartvmp_secure_bytes_live(void) { return vmp_secure_bytes_live(); }

/*
 * Copies the first `n` bytes of the *unmasked* container image into `out`.
 *
 * Diagnostics only: it lets the Dart test suite prove that the image the
 * runtime holds really is the container the compiler emitted at this build id,
 * rather than an image from a stale object file. It exposes no plaintext that
 * the shipped binary does not already contain in masked form.
 */
/* ------------------------------------------------------------------ */
/* Diagnostics                                                         */
/* ------------------------------------------------------------------ */

/*
 * These entry points exist so the test suite can diff the runtime's constants
 * and decoded bytecode against the compiler's. They are compiled out when
 * DVMP_DIAGNOSTICS is off (the default for a release build, and what the Android
 * plugin build uses), so the shipped shared object exports only the execution
 * ABI. `tool/verify_protection.ps1` asserts that.
 */
#if defined(DVMP_DIAGNOSTICS)

int32_t dartvmp_image_probe(uint8_t *out, uint32_t n, uint32_t *out_len,
                            uint32_t *build_id) {
  return dvmp_module_image_probe(out, n, out_len, build_id);
}

void dartvmp_mask_probe(uint32_t index, uint64_t *mask, uint64_t *word) {
  dvmp_module_mask_probe(index, mask, word);
}

int32_t dartvmp_code_probe(uint32_t func, uint8_t *out, uint32_t n,
                           uint32_t *out_len) {
  return dvmp_module_code_probe(func, out, n, out_len);
}

int32_t dartvmp_desc_probe(uint32_t func, uint32_t *arity, uint32_t *locals,
                           uint32_t *slot_base, uint32_t *code_off,
                           uint32_t *code_len) {
  return dvmp_module_desc_probe(func, arity, locals, slot_base, code_off,
                                code_len);
}

int32_t dartvmp_slot_probe(uint32_t slot, int64_t *tag, int64_t *bits) {
  return dvmp_module_slot_probe(slot, tag, bits);
}

int32_t dartvmp_session_probe(uint64_t *master_seed, uint64_t *store_key,
                              uint64_t *store_salt) {
  return dvmp_module_session_probe(master_seed, store_key, store_salt);
}

int32_t dartvmp_guard_reset(void) { return dvmp_module_guard_reset(); }

int32_t dartvmp_plaintext_probe(uint32_t *live) {
  return dvmp_module_plaintext_probe(live);
}

int32_t dartvmp_body_residue(uint32_t *nonzero, uint32_t *any) {
  return dvmp_module_body_residue(nonzero, any);
}

void dartvmp_code_chunk_probe(uint32_t *slots, uint32_t *live, uint32_t *peak,
                              uint32_t *largest, uint32_t *total) {
  dvmp_module_chunk_probe(slots, live, peak, largest, total);
}

int32_t dartvmp_sha256_probe(const uint8_t *data, uint32_t len, uint8_t *out) {
  return dvmp_sha256_probe(data, len, out);
}

int32_t dartvmp_instrumented_probe(uint32_t *instrumented, const char **reason) {
  if (instrumented != NULL) *instrumented = (uint32_t)vmp_is_instrumented();
  if (reason != NULL) *reason = vmp_instrumentation_reason();
  return DARTVMP_OK;
}

void dartvmp_antidebug_force(int on, const char *reason) {
  vmp_antidebug_force(on, reason);
  /*
   * Also update the module's recorded verdict.
   *
   * `dvmp_module_init` reads the verdict once and returns early on every later call -
   * deliberately, because re-running the detection per call would put three /proc reads
   * and a socket probe on the hot path - so a hook that only set the process-wide flag
   * would change what `vmp_is_instrumented()` reports and nothing about the *reaction*,
   * which is the thing under test. This reproduces the state a real detection leaves
   * behind, rather than faking the check itself.
   */
  DvmpModule *m = dvmp_module();
  if (m != NULL) m->instrumented = on ? 1 : 0;
}

void dartvmp_code_residue(uint32_t *slots, uint32_t *body_region,
                          uint32_t *body_region_peak, uint32_t *store) {
  dvmp_module_code_residue(slots, body_region, body_region_peak, store);
}

uint32_t dartvmp_guard_probe(uint32_t func, uint32_t *mode, uint32_t *budget,
                              uint32_t *window_ms, uint32_t *used,
                              uint64_t *window_start) {
  const int32_t rc = dvmp_module_guard_probe(func, mode, budget, window_ms, used,
                                             window_start);
  return rc == DARTVMP_OK ? 0u : 1u;
}

uint32_t dartvmp_integrity_probe(uint32_t *hooked_mask, uint32_t *scanned,
                                 uint32_t *selftest_ok) {
  return dvmp_integrity_probe(hooked_mask, scanned, selftest_ok);
}

#endif /* DVMP_DIAGNOSTICS */

static int32_t dartvmp_init_locked(const uint8_t *probe, uint32_t probe_len,
                                   uint64_t *probe_out_len);

/* ------------------------------------------------------------------ */
/* Process-wide serialisation                                          */
/* ------------------------------------------------------------------ */

/*
 * The runtime has exactly one module and one interpreter, and `unseal`/`reseal`
 * rewrite the body in place, so two threads inside a call at the same time
 * corrupt each other. Dart's isolates are separate threads sharing this library,
 * so this is reachable from ordinary application code (`Isolate.run`, `compute`).
 *
 * This lock used to be documented and not implemented: the headers claimed calls
 * were "guarded by a native lock" and "serialised here" while no mutex, atomic or
 * lock of any kind existed. The observed failure was a concurrent run returning
 * wrong results and error codes and then dying with an access violation, with a
 * torn arena object visible in the diagnostics.
 *
 * One lock, held across init and across a whole call. There is no re-entrancy,
 * because protected code cannot call back into the host.
 */
#if defined(_WIN32)
/*
 * A hand-rolled mutex, deliberately not `CRITICAL_SECTION`.
 *
 * `CRITICAL_SECTION` needs construction, and the first attempt used
 * `InitOnceExecuteOnce` for that. Two OS threads then failed to be mutually
 * excluded: 16 threads x 400 calls produced exactly the torn-arena crash the lock
 * exists to prevent, with a single thread clean. Rather than debug the init-once
 * callback inside a library that Dart's isolate spawner is concurrently loading,
 * this uses the primitive with no initialization step at all - `InterlockedCompareExchange`
 * on a plain LONG, which is valid from the first instruction and needs no
 * constructor, no loader cooperation and no once-guarantee.
 *
 * The yield matters: a protected call re-seals the module and runs an interpreter,
 * so it holds the lock for a long time and a pure spin would burn a core per
 * waiter. `SwitchToThread` (not `Sleep(1)`) keeps the handover cheap without
 * adding a millisecond of latency to every contended acquire.
 */
static volatile LONG g_lock = 0;

static void vmp_lock(void) {
  while (InterlockedCompareExchange(&g_lock, 1, 0) != 0) {
    SwitchToThread();
  }
}

static void vmp_unlock(void) { InterlockedExchange(&g_lock, 0); }

#else

static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static void vmp_lock(void) { pthread_mutex_lock(&g_lock); }
static void vmp_unlock(void) { pthread_mutex_unlock(&g_lock); }

#endif

/* ------------------------------------------------------------------ */
/* Call policy                                                         */
/* ------------------------------------------------------------------ */

/* Monotonic milliseconds. Only differences are used, so the epoch is irrelevant. */
static uint64_t now_ms(void) {
#if defined(_WIN32)
  return (uint64_t)GetTickCount64();
#else
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (uint64_t)ts.tv_sec * 1000ull + (uint64_t)(ts.tv_nsec / 1000000);
#endif
}

/*
 * Enforces a function's declared call policy. Returns DARTVMP_OK to proceed, or
 * DARTVMP_ERR_TOO_MANY_CALLS.
 *
 * The point of this is the oracle problem. A protected function that answers a
 * yes/no question - a licence check is the canonical case - is useful to an
 * attacker purely as a validator: call it a million times and watch. Nothing about
 * the interpreter stops that, because answering is the function's job. What can be
 * changed is the price of each answer.
 *
 * Two properties are deliberate:
 *
 *  - The refusal is a distinct status, never a wrong answer. Poisoning the result
 *    would break the business code, and the stated rule for this system is that
 *    protection must be invisible to it.
 *  - The budget is declared in the protected source, so the guard ships with the
 *    function rather than depending on the caller remembering to configure it.
 *
 * An attacker who patches this out wins: they own the process. That is stated in
 * the README rather than hidden. What the guard removes is the *cheap* attack -
 * using the shipped library as a fast oracle needs no reversing, and this makes it
 * need some.
 */
static int32_t guard_check(DvmpModule *m, uint32_t func_id) {
  if (func_id >= m->func_count) return DARTVMP_OK;
  if (func_id >= DVMP_MAX_GUARD_STATE) return DARTVMP_OK;
  const DvmpFuncDesc *d = &m->funcs[func_id];
  if (d->guard_mode == DVMP_GUARD_NONE) return DARTVMP_OK;

  /*
   * Usage lives in `m->guard_state`, not in the descriptor.
   *
   * It was in the descriptor first, and the policy never fired: `open` rebuilds
   * the descriptors from the body on every call (it must - `seal` wipes the body),
   * so the counter was zeroed before each call and no budget could ever be
   * exhausted. The failure was completely silent: the mode and budget read back
   * correctly, and the only symptom was that nothing was ever refused.
   */
  DvmpGuardState *st = &m->guard_state[func_id];

  if (d->guard_mode == DVMP_GUARD_ONCE) {
    if (st->used > 0) {
      dvmp_vm_set_error("call policy: function %u may be called once per process",
                        func_id);
      return DARTVMP_ERR_TOO_MANY_CALLS;
    }
    st->used = 1;
    return DARTVMP_OK;
  }

  /* DVMP_GUARD_RATE: a fixed window with a call budget. */
  const uint64_t now = now_ms();
  if (st->window_start == 0 ||
      now - st->window_start >= (uint64_t)d->guard_window_ms) {
    st->window_start = now;
    st->used = 0;
  }
  if (st->used >= (uint32_t)d->guard_budget) {
    dvmp_vm_set_error(
        "call policy: function %u exceeded %u call(s) per %u ms", func_id,
        (unsigned)d->guard_budget, (unsigned)d->guard_window_ms);
    return DARTVMP_ERR_TOO_MANY_CALLS;
  }
  st->used++;
  return DARTVMP_OK;
}

/* ------------------------------------------------------------------ */
/* init                                                                */
/* ------------------------------------------------------------------ */

int32_t dartvmp_init(const uint8_t *probe, uint32_t probe_len,
                     uint64_t *probe_out_len) {
  /*
   * Held across initialisation: two threads racing `dvmp_init` would each build a
   * module into the same `g_mod`, so one would leak the other's buffers and both
   * would believe they had succeeded.
   */
  vmp_lock();
  const int32_t rc = dartvmp_init_locked(probe, probe_len, probe_out_len);
  vmp_unlock();
  return rc;
}

static int32_t dartvmp_init_locked(const uint8_t *probe, uint32_t probe_len,
                                   uint64_t *probe_out_len) {
  /*
   * Instrumentation detection, and what it is allowed to do about it.
   *
   * The verdict is recorded on the module and the *only* default consequence is that
   * the decoded-function cache drops to a single slot (`dvmp_code_ensure`): under a
   * debugger the plaintext window becomes one function wide instead of four, and the
   * interpreter still returns bit-identical answers. That constraint is not a
   * preference - the project's first rule is that protection must not change what
   * business code does, and a debugger check that changes an answer, or refuses to
   * start, is a check that breaks real users the moment it false-positives (a
   * misconfigured `TracerPid`, an emulator, a vendor's monitoring agent, a
   * Frida-looking port).
   *
   * Refusing outright is still available and still what a product may want, but it is
   * opt-in via DVMP_ANTIDEBUG_REFUSE, so the trade is made deliberately rather than by
   * default. The layer itself is compiled in only with -DDVMP_ANTIDEBUG (off by
   * default, and on for the Android release build - see the plugin's build.gradle).
   */
  const int instrumented = vmp_is_instrumented();
  if (instrumented) {
#if defined(DVMP_ANTIDEBUG_REFUSE)
    dvmp_vm_set_error("instrumentation detected: %s", vmp_instrumentation_reason());
    return DARTVMP_ERR_DEBUGGER;
#endif
  }

  /*
   * Entry-point integrity, for the opt-in refuse path only.
   *
   * `dvmp_module_init` performs the same scan (it has to, because the instrumentation
   * verdict is taken there and the decoded-function cache is sized from it), so this
   * is not a second check with its own list - it is the same one, read early enough to
   * refuse before any state is built. See dvmp_integrity.c for what it detects and for
   * the honest ceiling on that.
   */
  uint32_t hooked = 0;
  (void)dvmp_integrity_check_entries(&hooked);
  if (hooked != 0) {
#if defined(DVMP_ANTIDEBUG_REFUSE)
    dvmp_vm_set_error("an entry point has been patched (mask 0x%08x)", hooked);
    return DARTVMP_ERR_DEBUGGER;
#endif
  }

  const int32_t rc = dvmp_module_init();
  if (rc != DARTVMP_OK) {
    /* Normalise the diagnostic: the caller usually has nothing else to go on. */
    if (dvmp_vm_last_error()[0] == '\0') {
      dvmp_vm_set_error("module init failed: %s", dartvmp_status_name(rc));
    }
    return rc;
  }

  if (probe != NULL && probe_len > 0) {
    DvmpModule *m = dvmp_module();
    const uint32_t n = probe_len < m->master_len ? probe_len : m->master_len;
    /* Copy from the container in the clear. This is what lets the Dart side
     * prove the shipped image is encrypted: it can look for a known string from
     * the *protected source* and must not find it. */
    memcpy((void *)(uintptr_t)probe, m->master, n);
    if (probe_out_len != NULL) *probe_out_len = n;
  } else if (probe_out_len != NULL) {
    *probe_out_len = 0;
  }
  return DARTVMP_OK;
}

uint32_t dartvmp_function_count(void) {
  uint32_t n = 0;
  dvmp_module_entries(&n);
  return n;
}

/*
 * The build id compiled into the module image.
 *
 * Exposed unconditionally rather than behind DVMP_DIAGNOSTICS: it is a
 * compile-time constant of the generated header, it reveals nothing the header
 * does not already carry in masked form, and it is the value a test needs in
 * order to prove the header and the loaded library came from the same compiler
 * run. That check is what keeps the suite from validating a stale artifact while
 * every leak probe still passes.
 */
uint32_t dartvmp_build_id(void) { return dvmp_module_build_id(); }

int32_t dartvmp_function_info(uint32_t index, const char **name,
                              uint32_t *arity, uint32_t *func_id) {
  uint32_t n = 0;
  const DvmpEntryMeta *e = dvmp_module_entries(&n);
  if (e == NULL || index >= n) return DARTVMP_ERR_FUNCTION_NOT_FOUND;
  if (name != NULL) {
    /*
     * The name table ships masked, so the pointer we hand out points at a
     * reusable scratch buffer rather than into static metadata. The contract is
     * "valid until the next call": Dart's Vmp.functions() reads it immediately,
     * and a longer-lived copy would rebuild the readable list of protected
     * names that the masking exists to avoid.
     */
    static char g_name_scratch[64];
    dvmp_module_name_copy(index, g_name_scratch, (uint32_t)sizeof(g_name_scratch));
    *name = g_name_scratch;
  }
  if (arity != NULL) *arity = e[index].arity;
  if (func_id != NULL) *func_id = e[index].id;
  return DARTVMP_OK;
}

/* ------------------------------------------------------------------ */
/* Calls                                                               */
/* ------------------------------------------------------------------ */

typedef struct CallCtx {
  uint32_t func;
  const uint8_t *args;
  uint32_t args_len;
  uint8_t *out;
  uint32_t *out_len;
  DvmpVm *vm;
  DvmpSlot result;
} CallCtx;

static int32_t call_locked(void *p) {
  CallCtx *ctx = (CallCtx *)p;
  DvmpModule *m = dvmp_module();

  if (ctx->func >= m->func_count) return DARTVMP_ERR_FUNCTION_NOT_FOUND;
  const DvmpFuncDesc *fn = &m->funcs[ctx->func];

  DvmpVm *vm = ctx->vm;
  /*
   * Reset the arena BEFORE deserialising the arguments, because they are
   * allocated from it. Resetting afterwards (which is what `dvmp_vm_run` used to
   * do) frees every argument string just before the callee reads it.
   */
  dvmp_arena_reset(&vm->arena);
  vm->sp = 0;
  vm->fp = 0;
  vm->slot_top = 0;
  vm->steps = 0;

  /* Deserialise the arguments onto the eval stack in DECLARATION ORDER:
   * argument 0 is pushed first and therefore ends up *deepest*.
   *
   * The compiler gives every function the prologue
   *
   *     store slot=slot_base ; store slot=slot_base+1 ; ... ; <body>
   *
   * and each `store` pops the current top of stack. Since STORE instructions are
   * emitted in parameter order, the FIRST store (parameter 0) sees the LAST
   * pushed value - so the callee reads the arguments off in reverse, and pushing
   * in declaration order lines the two up.
   *
   * Pushing in reverse instead silently swaps every pair of parameters, which is
   * only visible much later as a type error inside a builtin. `argtags` in the
   * VM's fault context reports the tags in stack order for exactly this reason.
   */
  DvmpReader r;
  r.p = ctx->args;
  r.len = ctx->args_len;
  r.pos = 0;
  r.error = 0;
  DvmpSlot argv[8];
  if (fn->arity > 8) return DARTVMP_ERR_BAD_ARGUMENT;
  for (uint32_t i = 0; i < fn->arity; i++) {
    if (dvmp_read_value(&r, &vm->arena, &argv[i]) != 0) {
      return DARTVMP_ERR_BAD_ARGUMENT;
    }
  }
  if (r.error != 0) return DARTVMP_ERR_BAD_ARGUMENT;
  /* Trailing bytes mean the caller and the callee disagree about the
   * signature: refuse instead of silently ignoring them. */
  if (r.pos != r.len) return DARTVMP_ERR_BAD_ARGUMENT;

  for (uint32_t i = 0; i < fn->arity; i++) {
    vm->stack[vm->sp++] = argv[i];
  }

  ctx->vm = vm;
  return dvmp_vm_run(vm, ctx->func, fn->arity, &ctx->result);
}

static int32_t finish_call(CallCtx *ctx, int32_t rc) {
  if (rc != DARTVMP_OK) return rc;

  DvmpWriter w;
  w.p = ctx->out;
  w.cap = (ctx->out == NULL) ? 0 : *ctx->out_len;
  w.len = 0;
  w.overflow = 0;
  dvmp_write_value(&w, &ctx->vm->arena, ctx->result);

  if (ctx->out == NULL) {
    if (ctx->out_len != NULL) *ctx->out_len = w.len;
    return DARTVMP_OK;
  }
  if (w.overflow) {
    /* Report the required size so the caller can retry with a bigger buffer. */
    if (ctx->out_len != NULL) *ctx->out_len = w.len;
    return DARTVMP_ERR_BAD_ARGUMENT;
  }
  if (ctx->out_len != NULL) *ctx->out_len = w.len;
  return DARTVMP_OK;
}

static int32_t dartvmp_call_locked(uint32_t func_id, const uint8_t *args,
                                   uint32_t args_len, uint8_t *out,
                                   uint32_t *out_len);

int32_t dartvmp_call(uint32_t func_id, const uint8_t *args, uint32_t args_len,
                     uint8_t *out, uint32_t *out_len) {
  /* The whole call, not just the interpreter step: the plaintext window is
   * process-wide state, so two calls cannot overlap even in principle. */
  vmp_lock();
  const int32_t rc =
      dartvmp_call_locked(func_id, args, args_len, out, out_len);
  vmp_unlock();
  return rc;
}

static int32_t dartvmp_call_locked(uint32_t func_id, const uint8_t *args,
                                   uint32_t args_len, uint8_t *out,
                                   uint32_t *out_len) {
  DvmpModule *m = dvmp_module();
  if (!m->ready) return DARTVMP_ERR_NOT_INITIALIZED;
  if (func_id >= m->entry_count) return DARTVMP_ERR_FUNCTION_NOT_FOUND;
  if (args == NULL && args_len != 0) return DARTVMP_ERR_BAD_ARGUMENT;

  /* Declared policy, enforced before any work. See guard_check. */
  {
    const int32_t grc = guard_check(m, func_id);
    if (grc != DARTVMP_OK) return grc;
  }

  CallCtx ctx;
  memset(&ctx, 0, sizeof(ctx));
  ctx.func = func_id;
  ctx.args = args;
  ctx.args_len = args_len;
  ctx.out = out;
  ctx.out_len = out_len;

  /* The interpreter is not re-entrant: one shared VM per process, and protected
   * code cannot call back into Dart. The caller holds `vmp_lock`, so this is
   * reached by one thread at a time - and the VM's construction happens under
   * that lock too, which is why it is a plain `static` here. */
  static DvmpVm vm;
  static int vm_ready = 0;
  if (!vm_ready) {
    dvmp_vm_init(&vm);
    dvmp_vm_publish(&vm);
    vm_ready = 1;
  }
  ctx.vm = &vm;

  const int32_t rc = dvmp_module_with_plaintext(call_locked, &ctx);
  if (rc != DARTVMP_OK) {
    /* Re-open the window just long enough to wipe the arena, so argument
     * strings do not outlive the call in freed heap. */
    dvmp_arena_reset(&vm.arena);
    return rc;
  }
  return finish_call(&ctx, rc);
}

int32_t dartvmp_call_named(const char *name, const uint8_t *args,
                           uint32_t args_len, uint8_t *out, uint32_t *out_len) {
  if (name == NULL) return DARTVMP_ERR_BAD_ARGUMENT;
  const int id = dvmp_module_find(name);
  if (id < 0) return DARTVMP_ERR_FUNCTION_NOT_FOUND;
  return dartvmp_call((uint32_t)id, args, args_len, out, out_len);
}
