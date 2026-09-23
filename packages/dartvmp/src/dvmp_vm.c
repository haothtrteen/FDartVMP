/*
 * dvmp_vm.c - the private interpreter.
 *
 * Shape
 * -----
 * A direct-threaded, stack-based interpreter over the instruction set in
 * dvmp_wire.h. There is no JIT, no cache and no host-language escape hatch
 * other than the audited builtin table in dvmp_host.c. Protected code can
 * therefore compute, but it cannot allocate outside the per-call arena, cannot
 * call arbitrary native code, and cannot run for longer than the step budget.
 *
 * Hardening choices worth calling out:
 *   * every operand is bounds-checked against the *function's* declared local
 *     count and max stack depth, so a corrupted image cannot walk off a frame
 *   * jump targets are validated against the code region before use
 *   * division traps on zero and on INT64_MIN / -1 instead of invoking
 *     undefined behaviour
 *   * the step counter is checked every instruction, which bounds the damage a
 *     malformed image can do to a UI-thread stall
 */
#include "dvmp_internal.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DVMP_ERRBUF 160
static char g_err[DVMP_ERRBUF];
static int g_err_stage;
static const char *g_err_kind;

/* Opcode and operand of the instruction that faulted, filled in as the
 * interpreter walks. Reported alongside the fault class so a "operand out of
 * range" can be attributed to a specific bytecode word. */
static uint8_t g_fault_op;
static uint32_t g_fault_operand;
static int g_fault_has_operand;

void dvmp_vm_set_error(const char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  vsnprintf(g_err, sizeof(g_err), fmt, ap);
  va_end(ap);
}

const char *dvmp_vm_last_error(void) { return g_err; }

/*
 * Clears the diagnostic buffer.
 *
 * Called at the start of every module unseal and every protected call, so a
 * message can never outlive the operation that produced it. Without this, a
 * fault reported by the Dart side can carry text from an earlier, already
 * handled failure - which is exactly how a healthy call once appeared to report
 * a CRC mismatch, and cost an hour of chasing a bug that did not exist.
 */
void dvmp_vm_clear_error(void) { g_err[0] = '\0'; }

/*
 * Appends the frame context (`function+pc`, stack depth) to whatever diagnostic
 * is already in the buffer.
 *
 * Faults inside the interpreter are otherwise nearly impossible to attribute:
 * the status code says *what* went wrong but not which function, and protected
 * code has no line numbers at run time because the source was evicted.
 */
void dvmp_vm_fault_context(const DvmpVm *vm, const DvmpFrame *f) {
  char suffix[160];
  if (g_fault_has_operand) {
    snprintf(suffix, sizeof(suffix),
             " [fn=%u pc=%u op=0x%02x operand=%u sp=%u depth=%u argtags=%u]",
             f != NULL ? f->func : 0u, f != NULL ? f->pc : 0u, g_fault_op,
             g_fault_operand, vm->sp, vm->fp, vm->entry_tag_mask);
  } else {
    snprintf(suffix, sizeof(suffix),
             " [fn=%u pc=%u op=0x%02x sp=%u depth=%u argtags=%u]",
             f != NULL ? f->func : 0u, f != NULL ? f->pc : 0u, g_fault_op,
             vm->sp, vm->fp, vm->entry_tag_mask);
  }
  const size_t used = strlen(g_err);
  if (used + strlen(suffix) + 1u < sizeof(g_err)) {
    memcpy(g_err + used, suffix, strlen(suffix) + 1u);
  }
}

/* Records the instruction being executed when a fault is raised. */
static void note_fault(uint8_t op, uint32_t operand, int has_operand) {
  g_fault_op = op;
  g_fault_operand = operand;
  g_fault_has_operand = has_operand;
}

/*
 * Records a coarse fault class.
 *
 * The class is only used when nothing more precise has been recorded for *this*
 * fault. `dvmp_vm_set_error` is last-writer-wins, and every fault path here
 * writes a specific message before jumping to its label, so the generic class is
 * effectively a fallback - which is what makes "operand type mismatch" appear
 * only when a builtin failed without saying why.
 */
static void set_stage(const char *kind) {
  g_err_kind = kind;
  g_err_stage++;
  if (g_err[0] == '\0') {
    snprintf(g_err, sizeof(g_err), "%s (stage %d)", kind, g_err_stage);
  }
}

void dvmp_vm_init(DvmpVm *vm) {
  memset(vm, 0, sizeof(*vm));
  dvmp_arena_init(&vm->arena);
}

void dvmp_vm_destroy(DvmpVm *vm) { dvmp_arena_destroy(&vm->arena); }

/* ------------------------------------------------------------------ */
/* Stack helpers                                                       */
/* ------------------------------------------------------------------ */

static inline int push(DvmpVm *vm, DvmpSlot v) {
  if (vm->sp >= DVMP_MAX_STACK) return -1;
  vm->stack[vm->sp++] = v;
  return 0;
}

static inline int pop(DvmpVm *vm, DvmpSlot *out) {
  if (vm->sp == 0) return -1;
  *out = vm->stack[--vm->sp];
  return 0;
}

/* Numeric coercion: bools behave like 0/1, everything else is a type error.
 * Deliberately strict - implicit string->int conversion in a protected
 * function is far more likely to be an attacker's confusion than a feature. */
static int as_int(DvmpSlot s, int64_t *out) {
  switch (s.tag) {
    case DVMP_TAG_INT:
      *out = s.bits;
      return 0;
    case DVMP_TAG_BOOL:
      *out = s.bits ? 1 : 0;
      return 0;
    default:
      return -1;
  }
}

static int truthy(DvmpSlot s) {
  switch (s.tag) {
    case DVMP_TAG_NIL:
      return 0;
    case DVMP_TAG_INT:
    case DVMP_TAG_BOOL:
      return s.bits != 0;
    case DVMP_TAG_OBJ: {
      DvmpObj *o = (DvmpObj *)(intptr_t)s.bits;
      if (o == NULL) return 0;
      if (o->kind == DVMP_V_STR) return o->len != 0;
      return o->len != 0;
    }
    default:
      return 0;
  }
}

/* Wrapping arithmetic, matching Dart's fixed-width int semantics for the
 * 64-bit case without relying on signed overflow being defined. */
static inline int64_t wrap_add(int64_t a, int64_t b) {
  return (int64_t)((uint64_t)a + (uint64_t)b);
}
static inline int64_t wrap_sub(int64_t a, int64_t b) {
  return (int64_t)((uint64_t)a - (uint64_t)b);
}
static inline int64_t wrap_mul(int64_t a, int64_t b) {
  return (int64_t)((uint64_t)a * (uint64_t)b);
}

static inline uint32_t rd_u32(const uint8_t *p) {
  return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
         ((uint32_t)p[3] << 24);
}

/* ------------------------------------------------------------------ */
/* Interpreter                                                         */
/* ------------------------------------------------------------------ */

/*
 * The process-wide VM, published for the diagnostic probe below.
 *
 * `dartvmp_call` owns the actual instance (a function-local static); this pointer
 * just lets a test read slots after a fault, which is the only practical way to
 * see which parameter a function really received.
 */
static DvmpVm *g_live_vm;

void dvmp_vm_publish(DvmpVm *vm) { g_live_vm = vm; }

int32_t dvmp_vm_probe_slot(uint32_t slot, int64_t *tag, int64_t *bits) {
  if (g_live_vm == NULL || slot >= DVMP_MAX_SLOTS) {
    return DARTVMP_ERR_BAD_ARGUMENT;
  }
  if (tag != NULL) *tag = g_live_vm->slots[slot].tag;
  if (bits != NULL) *bits = g_live_vm->slots[slot].bits;
  return DARTVMP_OK;
}

int32_t dvmp_vm_run(DvmpVm *vm, uint32_t func_index, uint32_t argc,
                    DvmpSlot *out) {
  DvmpModule *m = dvmp_module();

  /*
   * Optional single-step trace, enabled with DARTVMP_TRACE=<func>[:<pc>].
   *
   * Protected code has no line numbers at run time (the source was evicted) and
   * a fault reports only a function index and a pc, so a wrong operand or a
   * clobbered slot is otherwise invisible. Nothing here runs unless the variable
   * is set, so it costs one getenv on the release path.
   */
  static int trace_func = -2;
  static int trace_pc = -1;
  static int trace_ready = 0;
  if (!trace_ready) {
    const char *t = getenv("DARTVMP_TRACE");
    trace_ready = 1;
    if (t != NULL) {
      const char *colon = strchr(t, ':');
      trace_func = atoi(t);
      trace_pc = colon != NULL ? atoi(colon + 1) : -1;
    }
  }
  const int tracing = (trace_func >= 0 && (uint32_t)trace_func == func_index);

  if (!m->unsealed) return DARTVMP_ERR_NOT_INITIALIZED;
  /*
   * Clear the diagnostic buffer FIRST, before any early return.
   *
   * `dvmp_module_with_plaintext` only re-seals on the unseal path, so a fault
   * that returns early here would otherwise leave the *previous* call's message
   * in place - and a test then reports a stale "operand type mismatch" instead
   * of the real cause. Forgetting this cost several debugging rounds.
   */
  dvmp_vm_clear_error();
  g_err_kind = NULL;

  if (func_index >= m->func_count) return DARTVMP_ERR_FUNCTION_NOT_FOUND;

  const DvmpFuncDesc *fn = &m->funcs[func_index];
  if (argc != fn->arity) return DARTVMP_ERR_BAD_ARGUMENT;

  /*
   * NOTE: the arena is NOT reset here, and neither are `sp`, `fp` or
   * `slot_top`.
   *
   * `dartvmp_call` resets the arena and then *deserialises the arguments into
   * it*, so resetting again at this point frees the very objects the arguments
   * point at - the call then reads freed memory, and the symptom is a type error
   * inside whichever builtin touches an argument first (`hash` complaining that
   * a string is "not a string" was the tell). The caller owns the lifetime.
   */
  vm->steps = 0;
  g_err_kind = NULL;

  /*
   * Snapshot the argument tags the caller pushed, in stack order. A mismatch
   * between "which parameter received which argument" is otherwise only visible
   * as a type error deep inside a builtin, several frames later.
   */
  vm->entry_tag_mask = 0;
  for (uint32_t i = 0; i < argc && i < 4u; i++) {
    vm->entry_tag_mask |= (uint32_t)(vm->stack[i].tag & 0xFF) << (4u * i);
  }

  if (fn->locals > DVMP_MAX_SLOTS) {
    dvmp_vm_set_error("function declares %u locals, limit is %u", fn->locals,
                      (uint32_t)DVMP_MAX_SLOTS);
    return DARTVMP_ERR_INTERNAL;
  }
  if (vm->sp != argc) {
    dvmp_vm_set_error("entry stack mismatch: sp=%u argc=%u", vm->sp, argc);
    return DARTVMP_ERR_INTERNAL;
  }

  /*
   * SLOT LAYOUT
   * -----------
   * `load`/`store` carry *absolute* slot indices, and each function's window
   * (`[slot_base, slot_base + arity + locals)`) is assigned by the compiler and
   * carried in the descriptor. A frame therefore just adopts that base - it is
   * not `argc`, and it is not derived from the call depth.
   *
   * The arguments are left ON THE EVAL STACK, and the function's own prologue
   * pops them into its window:
   *
   *     store slot=slot_base ; store slot=slot_base+1 ; ... ; <body>
   *
   * so nothing is copied here. Copying them into slots as well would make the
   * prologue's very first `store` underflow.
   */
  const uint32_t window_end = (uint32_t)fn->slot_base + fn->arity + fn->locals;
  if (window_end > DVMP_MAX_SLOTS) {
    dvmp_vm_set_error("slot window [%u,%u) exceeds %u slots", fn->slot_base,
                      window_end, (uint32_t)DVMP_MAX_SLOTS);
    return DARTVMP_ERR_INTERNAL;
  }
  vm->slot_top = window_end;
  vm->frames[0].func = func_index;
  vm->frames[0].pc = 0;
  vm->frames[0].slot_base = fn->slot_base;
  /*
   * The root frame's `stack_base` is 0, not `argc`: `call_locked` pushed the
   * arguments before entering, so 0 is the depth *before* them. That is the
   * invariant RET relies on (see the CALL case), and it has to hold for the
   * entry frame too - otherwise `add(20, 22)` unwinds to -2.
   */
  vm->frames[0].stack_base = 0;
  vm->fp = 1;

  for (;;) {
    if (++vm->steps > DARTVMP_MAX_STEPS) {
      set_stage("step budget exhausted");
      return DARTVMP_ERR_STEP_LIMIT;
    }

    DvmpFrame *f = &vm->frames[vm->fp - 1];
    const DvmpFuncDesc *cf = &m->funcs[f->func];
    if (f->pc >= cf->code_len) {
      /* Running off the end of a function means the image is malformed: the
       * compiler always terminates every path. */
      set_stage("fell off the end of a function");
      return DARTVMP_ERR_MODULE_CORRUPT;
    }

    /*
     * `code` is the function's base and `f->pc` indexes into it, which is what
     * every operand read below assumes (`next = f->pc + 1`).
     *
     * Fetching the *current instruction* here instead is a real bug worth naming:
     * the pointer then agrees with `next` only at `pc == 0`, so each function's
     * first instruction decodes correctly and everything after it reads operands
     * from the wrong offset. It survives review because a wrong slot usually still
     * lands inside the frame window, so the symptom is a plausible-looking fault
     * rather than a crash - function 0's first `load` reported slot 2850 instead
     * of 0.
     *
     * Derived per instruction rather than cached in the descriptor because the
     * stream is not resident: `dvmp_code_ensure` materialises the function into a
     * slot and revalidates that slot on every fetch. That is affordable because the
     * hit path is four compares, and it is required for correctness because a
     * callee can evict the caller's slot - the caller re-fetches at the top of its
     * next instruction and reloads, rather than reading a wiped buffer.
     *
     * The pointer stays valid for the rest of this iteration: nothing else calls
     * `dvmp_code_ensure` in between, and the only opcode that leaves the
     * interpreter (`DVMP_OP_HOST`) reads its operands *before* dispatching and does
     * not read `code` afterwards - see the note in dartvmp.c on why the VM is
     * deliberately not re-entrant. An opcode that dispatched first and read
     * operands afterwards would break that, so keep operand reads above the call.
     */
    const uint8_t *code =
        dvmp_code_ensure(f->func, cf->code_off, cf->code_len);
    if (code == NULL) {
      set_stage("could not materialise the function's code");
      return DARTVMP_ERR_MODULE_CORRUPT;
    }
    const uint8_t op = code[f->pc];
    uint32_t next = f->pc + 1;
    DvmpSlot a, b;
    int64_t x, y;
    note_fault(op, 0, 0);

    if (tracing && (trace_pc < 0 || (uint32_t)trace_pc == f->pc)) {
      fflush(stderr);
    }

    if (op == 0x0a || op == 0x0b) {
    }

    switch (op) {
      case DVMP_OP_NOP:
        break;
      case DVMP_OP_PUSH_I: {
        if (next + 4 > cf->code_len) goto truncated;
        /* `code` is the function's base, not the current instruction, so operand
         * offsets go through `next`. Reading `code + 1` is only correct in a design
         * where the fetch returns a pointer to the instruction itself; here it read
         * the wrong operand, which surfaced as "load slot 2850 outside window". */
        if (push(vm, dvmp_int((int64_t)(int32_t)rd_u32(code + next))) != 0)
          goto overflow;
        next += 4;
        break;
      }

      case DVMP_OP_PUSH_K: {
        if (next + 2 > cf->code_len) goto truncated;
        const uint32_t idx =
            (uint32_t)code[next] | ((uint32_t)code[next + 1] << 8);
        if (idx >= m->const_count) {
          dvmp_vm_set_error("const index %u >= %u", idx, m->const_count);
          goto badindex;
        }
        if (push(vm, dvmp_int(m->consts[idx])) != 0) goto overflow;
        next += 2;
        break;
      }

      case DVMP_OP_PUSH_S: {
        if (next + 2 > cf->code_len) goto truncated;
        const uint32_t idx =
            (uint32_t)code[next] | ((uint32_t)code[next + 1] << 8);
        if (idx >= m->str_count) {
          dvmp_vm_set_error("string index %u >= %u", idx, m->str_count);
          goto badindex;
        }
        const uint32_t off = rd_u32(m->str_tab + (uint64_t)idx * 8u);
        const uint32_t len = rd_u32(m->str_tab + (uint64_t)idx * 8u + 4u);
        if ((uint64_t)off + len > m->strings_len) goto badindex;
        DvmpObj *s = dvmp_new_str(&vm->arena, m->strings + off, len);
        if (s == NULL) goto oom;
        if (push(vm, dvmp_obj_slot(s)) != 0) goto overflow;
        next += 2;
        break;
      }

      case DVMP_OP_PUSH_NIL:
        if (push(vm, dvmp_nil()) != 0) goto overflow;
        break;
      case DVMP_OP_PUSH_TRUE:
        if (push(vm, dvmp_bool(1)) != 0) goto overflow;
        break;
      case DVMP_OP_PUSH_FALSE:
        if (push(vm, dvmp_bool(0)) != 0) goto overflow;
        break;

      case DVMP_OP_POP:
        if (pop(vm, &a) != 0) goto underflow;
        break;

      case DVMP_OP_DUP:
        if (vm->sp == 0) goto underflow;
        if (push(vm, vm->stack[vm->sp - 1]) != 0) goto overflow;
        break;

      case DVMP_OP_SWAP:
        if (vm->sp < 2) goto underflow;
        a = vm->stack[vm->sp - 1];
        vm->stack[vm->sp - 1] = vm->stack[vm->sp - 2];
        vm->stack[vm->sp - 2] = a;
        break;

      case DVMP_OP_LOAD: {
        if (next + 2 > cf->code_len) goto truncated;
        const uint32_t slot =
            (uint32_t)code[next] | ((uint32_t)code[next + 1] << 8);
        note_fault(op, slot, 1);        /*
         * `load`/`store` operands are absolute indices into the shared slot
         * array, and a function's window is `arity + locals` wide (arguments
         * first). Bounds-checking against `locals` alone would reject every
         * function that takes parameters.
         */
        if (slot >= cf->slot_base + (uint32_t)cf->arity + cf->locals) {
          dvmp_vm_set_error("load slot %u outside window [%u,%u)", slot,
                            cf->slot_base,
                            cf->slot_base + (uint32_t)cf->arity + cf->locals);
          goto badindex;
        }
        if (slot >= DVMP_MAX_SLOTS) goto badindex;
        if (push(vm, vm->slots[slot]) != 0) goto overflow;
        next += 2;
        break;
      }

      case DVMP_OP_STORE: {
        if (next + 2 > cf->code_len) goto truncated;
        const uint32_t slot =
            (uint32_t)code[next] | ((uint32_t)code[next + 1] << 8);
        note_fault(op, slot, 1);
        if (slot >= cf->slot_base + (uint32_t)cf->arity + cf->locals) {
          dvmp_vm_set_error("store slot %u outside window [%u,%u)", slot,
                            cf->slot_base,
                            cf->slot_base + (uint32_t)cf->arity + cf->locals);
          goto badindex;
        }
        if (slot >= DVMP_MAX_SLOTS) goto badindex;
        if (pop(vm, &a) != 0) goto underflow;
        vm->slots[slot] = a;
        next += 2;
        break;
      }

      case DVMP_OP_ADD: {
        if (pop(vm, &b) != 0 || pop(vm, &a) != 0) goto underflow;
        /* `+` is overloaded on strings, exactly like Dart. */
        if (a.tag == DVMP_TAG_OBJ || b.tag == DVMP_TAG_OBJ) {
          DvmpObj *oa = (DvmpObj *)(intptr_t)a.bits;
          DvmpObj *ob = (DvmpObj *)(intptr_t)b.bits;
          if (a.tag == DVMP_TAG_OBJ && oa != NULL && oa->kind == DVMP_V_STR &&
              b.tag == DVMP_TAG_OBJ && ob != NULL && ob->kind == DVMP_V_STR) {
            DvmpObj *s = dvmp_new_str(&vm->arena, NULL, oa->len + ob->len);
            if (s == NULL) goto oom;
            memcpy(s + 1, oa + 1, oa->len);
            memcpy((uint8_t *)(s + 1) + oa->len, ob + 1, ob->len);
            if (push(vm, dvmp_obj_slot(s)) != 0) goto overflow;
            break;
          }
          goto typeerr;
        }
        if (as_int(a, &x) != 0 || as_int(b, &y) != 0) goto typeerr;
        if (push(vm, dvmp_int(wrap_add(x, y))) != 0) goto overflow;
        break;
      }

      case DVMP_OP_SUB:
      case DVMP_OP_MUL:
      case DVMP_OP_DIV:
      case DVMP_OP_MOD:
      case DVMP_OP_AND:
      case DVMP_OP_OR:
      case DVMP_OP_XOR:
      case DVMP_OP_SHL:
      case DVMP_OP_SHR: {
        if (pop(vm, &b) != 0 || pop(vm, &a) != 0) goto underflow;
        if (as_int(a, &x) != 0 || as_int(b, &y) != 0) goto typeerr;
        int64_t r = 0;
        switch (op) {
          case DVMP_OP_SUB:
            r = wrap_sub(x, y);
            break;
          case DVMP_OP_MUL:
            r = wrap_mul(x, y);
            break;
          case DVMP_OP_DIV:
            if (y == 0) goto divzero;
            /* INT64_MIN / -1 overflows; Dart raises here, C would be UB. */
            if (x == INT64_MIN && y == -1) goto divzero;
            r = x / y;
            break;
          case DVMP_OP_MOD:
            if (y == 0) goto divzero;
            if (x == INT64_MIN && y == -1) {
              r = 0;
            } else {
              r = x % y;
            }
            /*
             * Dart's `%` is EUCLIDEAN: the result always has the sign of the
             * *divisor*, so `-11 % 32 == 21`. C's `%` takes the sign of the
             * dividend, giving -11 instead. That single difference silently
             * changed a key-derivation loop: `(acc >> 3) % 32` fed a negative
             * index into `strAt`, and the alphabet lookup landed on the wrong
             * character from the second iteration onward.
             *
             * The correction is exact and branch-cheap: if the C remainder is
             * non-zero and has the opposite sign to the divisor, add the divisor.
             */
            if (r != 0 && ((r < 0) != (y < 0))) {
              r += y;
            }
            break;
          case DVMP_OP_AND:
            r = x & y;
            break;
          case DVMP_OP_OR:
            r = x | y;
            break;
          case DVMP_OP_XOR:
            r = x ^ y;
            break;
          case DVMP_OP_SHL: {
            /* Dart masks the shift count to 63 for its 64-bit ints. */
            const uint32_t s = (uint32_t)((uint64_t)y & 63u);
            r = (int64_t)((uint64_t)x << s);
            break;
          }
          case DVMP_OP_SHR: {
            const uint32_t s = (uint32_t)((uint64_t)y & 63u);
            r = x >> s; /* arithmetic shift, matches Dart's >> */
            break;
          }
          default:
            goto internalerr;
        }
        if (push(vm, dvmp_int(r)) != 0) goto overflow;
        break;
      }

      case DVMP_OP_NEG: {
        if (pop(vm, &a) != 0) goto underflow;
        if (as_int(a, &x) != 0) goto typeerr;
        if (push(vm, dvmp_int((int64_t)(0u - (uint64_t)x))) != 0) goto overflow;
        break;
      }

      case DVMP_OP_NOT: {
        if (pop(vm, &a) != 0) goto underflow;
        if (as_int(a, &x) != 0) goto typeerr;
        if (push(vm, dvmp_int(~x)) != 0) goto overflow;
        break;
      }

      case DVMP_OP_CMPLT:
      case DVMP_OP_CMPLE:
      case DVMP_OP_CMPGT:
      case DVMP_OP_CMPGE:
      case DVMP_OP_CMPEQ:
      case DVMP_OP_CMPNE: {
        if (pop(vm, &b) != 0 || pop(vm, &a) != 0) goto underflow;
        int r;
        if (op == DVMP_OP_CMPEQ || op == DVMP_OP_CMPNE) {
          /* Structural equality for strings, identity for containers, value
           * equality for scalars. */
          int eq;
          if (a.tag == DVMP_TAG_OBJ && b.tag == DVMP_TAG_OBJ) {
            DvmpObj *oa = (DvmpObj *)(intptr_t)a.bits;
            DvmpObj *ob = (DvmpObj *)(intptr_t)b.bits;
            if (oa == ob) {
              eq = 1;
            } else if (oa != NULL && ob != NULL && oa->kind == DVMP_V_STR &&
                       ob->kind == DVMP_V_STR) {
              eq = (oa->len == ob->len) &&
                   (memcmp(oa + 1, ob + 1, oa->len) == 0);
            } else {
              eq = 0;
            }
          } else {
            eq = (a.tag == b.tag) && (a.bits == b.bits);
          }
          r = (op == DVMP_OP_CMPEQ) ? eq : !eq;
        } else {
          if (as_int(a, &x) != 0 || as_int(b, &y) != 0) goto typeerr;
          switch (op) {
            case DVMP_OP_CMPLT:
              r = x < y;
              break;
            case DVMP_OP_CMPLE:
              r = x <= y;
              break;
            case DVMP_OP_CMPGT:
              r = x > y;
              break;
            default:
              r = x >= y;
              break;
          }
        }
        if (push(vm, dvmp_bool(r)) != 0) goto overflow;
        break;
      }

      case DVMP_OP_JMP:
      case DVMP_OP_JMP_IF_FALSE:
      case DVMP_OP_JMP_IF_TRUE: {
        if (next + 4 > cf->code_len) goto truncated;
        const uint32_t target = rd_u32(code + next);
        next += 4;
        int take = 1;
        if (op != DVMP_OP_JMP) {
          if (pop(vm, &a) != 0) goto underflow;
          const int t = truthy(a);
          take = (op == DVMP_OP_JMP_IF_FALSE) ? !t : t;
        }
        if (take) {
          if (target >= cf->code_len) {
            dvmp_vm_set_error("jump to %u outside function code (%u bytes)",
                              target, cf->code_len);
            goto badjump;
          }
          next = target;
        }
        break;
      }

      case DVMP_OP_CALL: {
        if (next + 2 > cf->code_len) goto truncated;
        const uint32_t idx =
            (uint32_t)code[next] | ((uint32_t)code[next + 1] << 8);
        next += 2;
        if (idx >= m->func_count) goto badindex;
        const DvmpFuncDesc *callee = &m->funcs[idx];
        if (vm->sp < callee->arity) goto underflow;
        if (vm->fp >= DVMP_MAX_DEPTH) {
          set_stage("call depth exceeded");
          return DARTVMP_ERR_DEPTH_EXCEEDED;
        }
        /*
         * `stack_base` is the eval-stack depth BEFORE this call's arguments were
         * pushed. RET restores `sp` to exactly that, so the result lands where
         * the call expression expected it and the consumed argument slots are
         * gone. (Recording the depth *including* the arguments leaves them
         * below the result and the caller's stack grows without bound.)
         */
        const uint32_t callee_base = callee->slot_base;
        const uint32_t callee_end =
            callee_base + (uint32_t)callee->arity + callee->locals;
        if (callee_end > DVMP_MAX_SLOTS) {
          set_stage("frame slot budget exhausted");
          return DARTVMP_ERR_DEPTH_EXCEEDED;
        }
        f->pc = next;
        DvmpFrame *nf = &vm->frames[vm->fp++];
        nf->func = idx;
        nf->pc = 0;
        nf->slot_base = callee_base;
        nf->stack_base = vm->sp - callee->arity;
        /* The callee starts in a different function, almost certainly a
         * different chunk; re-seal the caller's unless they happen to share
         * one. */
        continue; /* frame switched; skip the pc write below */
      }

      case DVMP_OP_RET:
      case DVMP_OP_RET_VOID: {
        DvmpSlot rv = dvmp_nil();
        if (op == DVMP_OP_RET) {
          if (pop(vm, &rv) != 0) goto underflow;
        }
        /*
         * Discard the callee's temporaries, and wind the eval stack back to
         * where it was before the call's arguments were pushed. The prologue has
         * already consumed those arguments, so `stack_base` is exactly the depth
         * the result belongs at.
         */
        vm->sp = f->stack_base;
        vm->fp--;
        if (vm->fp == 0) {
          *out = rv;
          return DARTVMP_OK;
        }
        /* Restore the slot watermark to the outer frame's window end. */
        {
          const DvmpFuncDesc *outer = &m->funcs[vm->frames[vm->fp - 1].func];
          vm->slot_top = (uint32_t)outer->slot_base + outer->arity +
                         outer->locals;
        }
        if (push(vm, rv) != 0) goto overflow;
        break;
      }

      case DVMP_OP_HOST: {
        if (next + 4 > cf->code_len) goto truncated;
        const uint32_t id =
            (uint32_t)code[next] | ((uint32_t)code[next + 1] << 8);
        const uint32_t hargc =
            (uint32_t)code[next + 2] | ((uint32_t)code[next + 3] << 8);
        next += 4;
        if (id == 0 || id > DVMP_HOST_MAX) {
          dvmp_vm_set_error("host id %u out of range (max %u)", id,
                            (uint32_t)DVMP_HOST_MAX);
          goto badindex;
        }
        const int hrc = dvmp_host_call(vm, id, hargc, &a);
        if (hrc == DVMP_HOST_ABORTED) {
          set_stage("explicit abort");
          return DARTVMP_ERR_TYPE;
        }
        if (hrc != DVMP_HOST_OK) goto hostfail;
        if (push(vm, a) != 0) goto overflow;
        break;
      }

      case DVMP_OP_ABORT: {
        if (pop(vm, &a) != 0) goto underflow;
        DvmpObj *o = (a.tag == DVMP_TAG_OBJ) ? (DvmpObj *)(intptr_t)a.bits : NULL;
        dvmp_vm_set_error("bytecode aborted: %s",
                          (o != NULL && o->kind == DVMP_V_STR)
                              ? (const char *)(o + 1)
                              : "no message");
        set_stage("explicit abort");
        return DARTVMP_ERR_TYPE;
      }

      default:
        dvmp_vm_set_error("unimplemented opcode 0x%02x at %u+%u", op, f->func,
                          f->pc);
        goto invalidop;
    }

    f->pc = next;
    continue;

  overflow:
    set_stage("operand stack overflow");
    dvmp_vm_fault_context(vm, f);
    return DARTVMP_ERR_STACK_OVERFLOW;
  underflow:
    set_stage("operand stack underflow");
    dvmp_vm_fault_context(vm, f);
    return DARTVMP_ERR_STACK_UNDERFLOW;
  truncated:
    set_stage("instruction stream truncated");
    dvmp_vm_fault_context(vm, f);
    return DARTVMP_ERR_MODULE_CORRUPT;
  badindex:
    set_stage("operand out of range");
    dvmp_vm_fault_context(vm, f);
    return DARTVMP_ERR_MODULE_CORRUPT;  badjump:
    set_stage("jump target out of range");
    dvmp_vm_fault_context(vm, f);
    return DARTVMP_ERR_JUMP_RANGE;
  typeerr:
    set_stage("type error");
    dvmp_vm_fault_context(vm, f);
    return DARTVMP_ERR_TYPE;
  divzero:
    set_stage("division by zero");
    dvmp_vm_fault_context(vm, f);
    return DARTVMP_ERR_DIV_ZERO;
  oom:
    set_stage("arena budget exhausted");
    dvmp_vm_fault_context(vm, f);
    return DARTVMP_ERR_OUT_OF_MEMORY;
  invalidop:
    set_stage("invalid opcode");
    dvmp_vm_fault_context(vm, f);
    return DARTVMP_ERR_INVALID_OPCODE;
  internalerr:
    set_stage("internal error");
    dvmp_vm_fault_context(vm, f);
    return DARTVMP_ERR_INTERNAL;
  hostfail:
    /*
     * `dvmp_host_call` has already written a precise message; append the frame
     * context and report a type error. Reporting DARTVMP_ERR_INTERNAL here (or
     * overwriting the message) turns every builtin fault into "internal VMP
     * error", which is what made the list/string tests hard to diagnose.
     */
    dvmp_vm_fault_context(vm, f);
    return DARTVMP_ERR_TYPE;
  }
}
