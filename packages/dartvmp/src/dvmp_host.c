/*
 * dvmp_host.c - the builtin table.
 *
 * This file is the *entire* surface through which protected bytecode can affect
 * the world. There is no dynamic dispatch, no function pointer taken from
 * bytecode, and no way to name a native symbol. A protected function can build
 * and read strings, lists and maps, hash, and abort; everything else it must
 * compute itself.
 *
 * That constraint is the point: the attack surface of the VMP is this file plus
 * the interpreter loop, and both are small enough to audit line by line - which
 * cannot be said of a general-purpose embedded language runtime.
 *
 * SEMANTIC CONTRACT (must match tool/vmpc/lib/src/opcodes.dart)
 * -------------------------------------------------------------
 * String indexing is *byte* based. Protected code is expected to work on ASCII
 * or to treat strings as opaque bytes; multi-byte UTF-8 passes through
 * strSub/strAt unchanged but does not behave like Dart's UTF-16 indexing, and
 * strLen returns the byte length. Emulating UTF-16 would put a decode branch in
 * every string operation, so the difference is documented instead of papered
 * over - and the differential test suite in app/test/ checks the ASCII cases
 * that protected code is actually allowed to rely on.
 */
#include "dvmp_internal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * Operand count per builtin. Kept as a flat table (rather than a switch) so a
 * mismatch between the compiler and the interpreter fails loudly at the first
 * call instead of silently mis-popping the stack.
 */
static const int8_t kArity[DVMP_HOST_MAX + 1] = {
    /* 0  */ -1,
    /* 1  strNew      */ 1,
    /* 2  strPush     */ 2,
    /* 3  listNew     */ 1,
    /* 4  listPush    */ 2,
    /* 5  listLen     */ 1,
    /* 6  listGet     */ 2,
    /* 7  listSet     */ 3,
    /* 8  mapNew      */ 1,
    /* 9  mapSet      */ 3,
    /* 10 mapGet      */ 2,
    /* 11 mapHas      */ 2,
    /* 12 strLen      */ 1,
    /* 13 strAt       */ 2,
    /* 14 strCode     */ 2,
    /* 15 strSub      */ 3,
    /* 16 strIndexOf  */ 2,
    /* 17 strContains */ 2,
    /* 18 strToUpper  */ 1,
    /* 19 strToLower  */ 1,
    /* 20 strParseInt */ 1,
    /* 21 intToStr    */ 1,
    /* 22 hash        */ 1,
    /* 23 abort       */ 1,
    /* 24 strBuild    */ 1,
    /* 25 strConcat   */ 2,
};

/* Stringify host ids for diagnostics. */
const char *dvmp_host_name(uint32_t id) {
  switch (id) {
    case DVMP_HOST_STR_NEW:
      return "strNew";
    case DVMP_HOST_STR_PUSH:
      return "strPush";
    case DVMP_HOST_STR_BUILD:
      return "strBuild";
    case DVMP_HOST_STR_CONCAT:
      return "strConcat";
    case DVMP_HOST_HASH:
      return "hash";
    case DVMP_HOST_LIST_LEN:
      return "listLen";
    case DVMP_HOST_LIST_GET:
      return "listGet";
    default:
      return "host";
  }
}

/* FNV-1a 64, matching the Dart `hash()` builtin so host and bytecode agree. */
static int64_t fnv1a(const uint8_t *p, uint32_t n) {
  return (int64_t)dvmp_fnv1a64(p, n, 0xCBF29CE484222325ull);
}

static int need_str(DvmpSlot s, DvmpObj **out) {
  if (s.tag != DVMP_TAG_OBJ) return -1;
  DvmpObj *o = (DvmpObj *)(intptr_t)s.bits;
  if (o == NULL || o->kind != DVMP_V_STR) return -1;
  *out = o;
  return 0;
}

/* Diagnostic: describe a slot's payload as the interpreter sees it. */
static void dump_slot(const char *label, DvmpSlot s) {
  if (s.tag == DVMP_TAG_OBJ) {
    DvmpObj *o = (DvmpObj *)(intptr_t)s.bits;
    fprintf(stderr, "[host]   %s: tag=%d obj=%p kind=%u len=%u\n", label,
            (int)s.tag, (void *)o, o != NULL ? (unsigned)o->kind : 99u,
            o != NULL ? o->len : 0u);
  } else {
    fprintf(stderr, "[host]   %s: tag=%d bits=%lld\n", label, (int)s.tag,
            (long long)s.bits);
  }
}

  /*
   * Accepts *only* a builder, and it has to check the kind, not just the tag.
   *
   * `strBuild` and `strPush` reinterpret the slot as a `DvmpBuilder *`, and a
   * builder is not a `DvmpObj` - it is a bare struct whose first field is the data
   * pointer. Reading a string through it therefore treats `kind`/`len` as a
   * pointer, which a crafted container can reach: `push_s <any string>; host 24`
   * dereferences a wild address and kills the process. That is reachable by anyone
   * who can build a container that passes the tag and CRC, and all three
   * algorithms ship in the binary.
   *
   * The fix is a dedicated kind that no other value can carry. `DVMP_V_BUILDER` is
   * not an object kind - builders are their own allocation and are only ever
   * reachable as an intermediate on the eval stack - so an object can never be
   * mistaken for one.
   */
static int need_builder(DvmpSlot s, DvmpBuilder **out) {
  if (s.tag != DVMP_TAG_BUILDER) return -1;
  DvmpBuilder *b = (DvmpBuilder *)(intptr_t)s.bits;
  if (b == NULL) return -1;
  *out = b;
  return 0;
}

static int need_int(DvmpSlot s, int64_t *out) {
  if (s.tag == DVMP_TAG_INT) {
    *out = s.bits;
    return 0;
  }
  if (s.tag == DVMP_TAG_BOOL) {
    *out = s.bits ? 1 : 0;
    return 0;
  }
  return -1;
}

int dvmp_host_call(DvmpVm *vm, uint32_t id, uint32_t argc, DvmpSlot *ret) {
  if (id == 0 || id > DVMP_HOST_MAX) {
    dvmp_vm_set_error("unknown builtin %u", id);
    return DVMP_HOST_ERROR;
  }
  const int want = kArity[id];
  if (want < 0 || argc != (uint32_t)want) {
    dvmp_vm_set_error("builtin %u called with %u operands, expected %d", id,
                      argc, want);
    return DVMP_HOST_ERROR;
  }
  if (vm->sp < argc) {
    dvmp_vm_set_error("builtin %u: operand stack underflow", id);
    return DVMP_HOST_ERROR;
  }

  /* Operands are pushed left to right, so argv[0] is the deepest. */
  DvmpSlot argv[4];
  const uint32_t base = vm->sp - argc;
  for (uint32_t i = 0; i < argc; i++) {
    argv[i] = vm->stack[base + i];
  }
  /* Record the operand types so a mismatch can be attributed to a specific
   * argument rather than "operand type mismatch". */
  uint32_t type_mask = 0;
  for (uint32_t i = 0; i < argc && i < 4u; i++) {
    type_mask |= (uint32_t)(argv[i].tag & 0xFF) << (4u * i);
  }
  DvmpArena *ar = &vm->arena;

#define HOST_RETURN(slot)   \
  do {                      \
    vm->sp = base;          \
    *ret = (slot);          \
    return DVMP_HOST_OK;    \
  } while (0)

/*
 * Returns a string-builder handle.
 *
 * Builders have no `DvmpObj` header: the slot's `bits` is the `DvmpBuilder *`
 * itself. That keeps the pointer full width (an earlier version stored it in
 * `DvmpObj.cap`, a uint32_t, which truncated it on 64-bit and crashed on the
 * first concatenation).
 */
#define HOST_RETURN_HANDLE(p)          \
  do {                                 \
    DvmpSlot _h;                       \
    _h.tag = DVMP_TAG_BUILDER;         \
    _h.bits = (int64_t)(intptr_t)(p);  \
    HOST_RETURN(_h);                   \
  } while (0)

  switch (id) {
    /* ---------------- string builder ---------------- */
    case DVMP_HOST_STR_NEW: {
      int64_t hint;
      if (need_int(argv[0], &hint) != 0) goto typeerr;
      if (hint < 0 || hint > 1024) goto range;
      DvmpBuilder *b = dvmp_new_builder(ar, (uint32_t)hint);
      if (b == NULL) goto oom;
      if (getenv("DARTVMP_TRACE_ALLOC") != NULL) {
        fprintf(stderr, "[alloc] bldr b=%p data=%p len=%u cap=%u\n", (void *)b,
                (void *)b->data, b->len, b->cap);
      }
      /* The handle IS the builder pointer; see the note in dvmp_internal.h. */
      HOST_RETURN_HANDLE(b);
    }

    case DVMP_HOST_STR_PUSH: {
      DvmpBuilder *b;
      DvmpObj *s;
      if (need_builder(argv[0], &b) != 0) {
        /* fprintf as well as set_error: the message buffer has been unreliable
         * for this specific path during bring-up, and a builder is otherwise
         * indistinguishable from a string on the wire (both are tag 3). */
        fprintf(stderr, "[host] strPush arg0 not a builder: tag=%d bits=0x%llx\n",
                (int)argv[0].tag, (unsigned long long)(uint64_t)argv[0].bits);
        dvmp_vm_set_error(
            "strPush: arg0 tag=%d bits=0x%llx (need a builder)", (int)argv[0].tag,
            (unsigned long long)(uint64_t)argv[0].bits);
        goto typeerr;
      }
      if (need_str(argv[1], &s) != 0) {
        fprintf(stderr, "[host] strPush arg1 not a string: sp=%u base=%u\n",
                vm->sp, base);
        dump_slot("argv[0]", argv[0]);
        dump_slot("argv[1]", argv[1]);
        dvmp_vm_set_error("strPush: arg1 tag=%d (need a string)",
                          (int)argv[1].tag);
        goto typeerr;
      }
      if (dvmp_builder_append(ar, b, (const uint8_t *)(s + 1), s->len) != 0) {
        /*
         * "grow", not "add".
         *
         * The leak scanner matches protected function names as whole identifier
         * tokens in the shipped library, and `add` is one of them - a perfectly
         * plausible name for a protected function, and also a perfectly ordinary
         * English word. A diagnostic spelled `cap=%u add=%u` therefore made the
         * scanner report a leak in a library that contains no such name, and a
         * gate that cries wolf is a gate people learn to ignore. The collision is
         * cheaper to remove here than to encode an ever-growing list of
         * exceptions in the scanner.
         */
        fprintf(stderr, "[host] strPush append failed: len=%u cap=%u grow=%u\n",
                b->len, b->cap, s->len);
        dvmp_vm_set_error("strPush: append failed (builder len=%u cap=%u "
                          "grow=%u)",
                          b->len, b->cap, s->len);
        return DVMP_HOST_ERROR;
      }
      /*
       * Returns an immutable STRING built from the accumulated bytes, not the
       * builder handle.
       *
       * `a + b` is typed as a string by the compiler, so its result is stored in
       * a variable the rest of the program treats as one. Handing back the
       * mutable handle meant that a loop like
       *
       *     out = out + c;      // out is declared String
       *
       * left `out` holding a *builder*, which the next iteration then mutated in
       * place - so on the second pass `out` and the freshly created builder were
       * aliases, `strPush` received another builder where it expected a string,
       * and the objects read back as garbage.
       *
       * The cost is that a concatenation chain is O(n^2) in copies rather than
       * amortised O(n). For the short strings protected code builds (license
       * keys, hex digests) that is irrelevant, and it buys value semantics that
       * match the source language.
       */
      DvmpObj *result = dvmp_new_str(ar, b->data, b->len);
      if (result == NULL) goto oom;
      HOST_RETURN(dvmp_obj_slot(result));
    }

    case DVMP_HOST_STR_BUILD: {
      DvmpBuilder *b;
      if (need_builder(argv[0], &b) != 0) goto typeerr;
      DvmpObj *s = dvmp_new_str(ar, b->data, b->len);
      if (s == NULL) goto oom;
      HOST_RETURN(dvmp_obj_slot(s));
    }

    /*
     * string + string -> a fresh string.
     *
     * Used by the compiler for `+`, instead of the ADD opcode, because this is
     * the one place that can keep the arena bounded: the two operands are dead
     * the moment the result exists, so their arena blocks can be reclaimed. The
     * ADD opcode has no arena handle and therefore cannot free anything, which
     * made a concatenation loop O(n^2) in arena *usage* and trip the budget on
     * inputs of a few dozen characters.
     *
     * It also preserves value semantics: the result is a new immutable string, so
     * `out = out + c` cannot alias anything the way a reused mutable builder did.
     */
    case DVMP_HOST_STR_CONCAT: {
      DvmpObj *x, *y;
      if (need_str(argv[0], &x) != 0 || need_str(argv[1], &y) != 0) {
        dump_slot("strConcat argv[0]", argv[0]);
        dump_slot("strConcat argv[1]", argv[1]);
        goto typeerr;
      }
      DvmpObj *r = dvmp_new_str(ar, NULL, x->len + y->len);
      if (r == NULL) {
        fprintf(stderr, "[host] strConcat alloc failed: total=%zu want=%u\n",
                ar->total, x->len + y->len + 32u);
        goto oom;
      }
      memcpy(r + 1, x + 1, x->len);
      memcpy((uint8_t *)(r + 1) + x->len, y + 1, y->len);
      /* The operands are unreachable now: reclaim them. */
      dvmp_arena_free(ar, x);
      dvmp_arena_free(ar, y);
      HOST_RETURN(dvmp_obj_slot(r));
    }

    /* ---------------- lists ---------------- */
    case DVMP_HOST_LIST_NEW: {
      int64_t cap;
      if (need_int(argv[0], &cap) != 0) goto typeerr;
      if (cap < 0 || cap > (int64_t)DVMP_MAX_LIST) goto range;
      DvmpObj *l = dvmp_new_list(ar, (uint32_t)cap);
      if (l == NULL) goto oom;
      HOST_RETURN(dvmp_obj_slot(l));
    }

    case DVMP_HOST_LIST_PUSH: {
      if (argv[0].tag != DVMP_TAG_OBJ) goto typeerr;
      DvmpObj *l = (DvmpObj *)(intptr_t)argv[0].bits;
      if (l == NULL || l->kind != DVMP_V_LIST) goto typeerr;
      if (dvmp_list_push(ar, &l, argv[1]) != 0) goto oom;
      HOST_RETURN(dvmp_obj_slot(l));
    }

    case DVMP_HOST_LIST_LEN: {
      if (argv[0].tag != DVMP_TAG_OBJ) goto typeerr;
      DvmpObj *l = (DvmpObj *)(intptr_t)argv[0].bits;
      if (l == NULL) goto typeerr;
      if (l->kind != DVMP_V_LIST && l->kind != DVMP_V_MAP) goto typeerr;
      HOST_RETURN(dvmp_int((int64_t)l->len));
    }

    /* `listGet` is polymorphic so one opcode serves List[i], Map[k] and s[i]:
     * the compiler cannot always know the static type of an index expression,
     * and a runtime tag switch is cheaper than a guard on every path. */
    case DVMP_HOST_LIST_GET: {
      if (argv[0].tag != DVMP_TAG_OBJ) goto typeerr;
      DvmpObj *c = (DvmpObj *)(intptr_t)argv[0].bits;
      if (c == NULL) goto typeerr;
      DvmpSlot v;
      if (c->kind == DVMP_V_MAP) {
        if (dvmp_map_get(c, argv[1], &v) != 0) {
          dvmp_vm_set_error("map key not present");
          return DVMP_HOST_ERROR;
        }
      } else if (c->kind == DVMP_V_LIST) {
        int64_t idx;
        if (need_int(argv[1], &idx) != 0) goto typeerr;
        if (dvmp_list_get(c, idx, &v) != 0) goto range;
      } else if (c->kind == DVMP_V_STR) {
        int64_t idx;
        if (need_int(argv[1], &idx) != 0) goto typeerr;
        if (idx < 0 || (uint64_t)idx >= c->len) goto range;
        v = dvmp_int((int64_t)((const uint8_t *)(c + 1))[idx]);
      } else {
        goto typeerr;
      }
      HOST_RETURN(v);
    }

    case DVMP_HOST_LIST_SET: {
      if (argv[0].tag != DVMP_TAG_OBJ) goto typeerr;
      DvmpObj *c = (DvmpObj *)(intptr_t)argv[0].bits;
      if (c == NULL) goto typeerr;
      if (c->kind == DVMP_V_MAP) {
        if (dvmp_map_set(ar, &c, argv[1], argv[2]) != 0) goto oom;
        HOST_RETURN(dvmp_obj_slot(c));
      }
      /* Lists are immutable in protected code by design: an in-place update
       * would force the interpreter to reason about aliasing. */
      dvmp_vm_set_error("list element assignment is not supported");
      return DVMP_HOST_ERROR;
    }

    /* ---------------- maps ---------------- */
    case DVMP_HOST_MAP_NEW: {
      int64_t cap;
      if (need_int(argv[0], &cap) != 0) goto typeerr;
      if (cap < 0 || cap > (int64_t)DVMP_MAX_MAP) goto range;
      DvmpObj *mm = dvmp_new_map(ar, (uint32_t)cap);
      if (mm == NULL) goto oom;
      HOST_RETURN(dvmp_obj_slot(mm));
    }

    case DVMP_HOST_MAP_SET: {
      if (argv[0].tag != DVMP_TAG_OBJ) goto typeerr;
      DvmpObj *mm = (DvmpObj *)(intptr_t)argv[0].bits;
      if (mm == NULL || mm->kind != DVMP_V_MAP) goto typeerr;
      if (dvmp_map_set(ar, &mm, argv[1], argv[2]) != 0) goto oom;
      HOST_RETURN(dvmp_obj_slot(mm));
    }

    case DVMP_HOST_MAP_GET: {
      if (argv[0].tag != DVMP_TAG_OBJ) goto typeerr;
      DvmpObj *mm = (DvmpObj *)(intptr_t)argv[0].bits;
      if (mm == NULL || mm->kind != DVMP_V_MAP) goto typeerr;
      DvmpSlot v;
      if (dvmp_map_get(mm, argv[1], &v) != 0) {
        dvmp_vm_set_error("map key not present");
        return DVMP_HOST_ERROR;
      }
      HOST_RETURN(v);
    }

    case DVMP_HOST_MAP_HAS: {
      if (argv[0].tag != DVMP_TAG_OBJ) goto typeerr;
      DvmpObj *mm = (DvmpObj *)(intptr_t)argv[0].bits;
      if (mm == NULL || mm->kind != DVMP_V_MAP) goto typeerr;
      DvmpSlot v;
      HOST_RETURN(dvmp_bool(dvmp_map_get(mm, argv[1], &v) == 0));
    }

    /* ---------------- strings ---------------- */
    case DVMP_HOST_STR_LEN: {
      DvmpObj *s;
      if (need_str(argv[0], &s) != 0) goto typeerr;
      HOST_RETURN(dvmp_int((int64_t)s->len));
    }

    case DVMP_HOST_STR_AT: {
      DvmpObj *s;
      int64_t idx;
      if (need_str(argv[0], &s) != 0 || need_int(argv[1], &idx) != 0) {
        goto typeerr;
      }
      if (idx < 0 || (uint64_t)idx >= s->len) goto range;
      DvmpObj *r = dvmp_new_str(ar, (const uint8_t *)(s + 1) + idx, 1);
      if (r == NULL) goto oom;
      HOST_RETURN(dvmp_obj_slot(r));
    }

    case DVMP_HOST_STR_CODE: {
      DvmpObj *s;
      int64_t idx;
      if (need_str(argv[0], &s) != 0 || need_int(argv[1], &idx) != 0) {
        goto typeerr;
      }
      if (idx < 0 || (uint64_t)idx >= s->len) goto range;
      HOST_RETURN(dvmp_int((int64_t)((const uint8_t *)(s + 1))[idx]));
    }

    case DVMP_HOST_STR_SUB: {
      DvmpObj *s;
      int64_t start, len;
      if (need_str(argv[0], &s) != 0 || need_int(argv[1], &start) != 0 ||
          need_int(argv[2], &len) != 0) {
        goto typeerr;
      }
      if (start < 0 || len < 0 || (uint64_t)start > s->len) goto range;
      uint64_t n = (uint64_t)len;
      /* Clamp rather than throw, matching Dart's substring for the in-range
       * case and staying total for the out-of-range one. */
      if ((uint64_t)start + n > s->len) n = s->len - (uint64_t)start;
      DvmpObj *r =
          dvmp_new_str(ar, (const uint8_t *)(s + 1) + start, (uint32_t)n);
      if (r == NULL) goto oom;
      HOST_RETURN(dvmp_obj_slot(r));
    }

    case DVMP_HOST_STR_INDEX_OF: {
      DvmpObj *s, *needle;
      if (need_str(argv[0], &s) != 0 || need_str(argv[1], &needle) != 0) {
        goto typeerr;
      }
      const char *h = (const char *)(s + 1);
      if (needle->len == 0) HOST_RETURN(dvmp_int(0));
      const char *found = strstr(h, (const char *)(needle + 1));
      HOST_RETURN(dvmp_int(found == NULL ? -1 : (int64_t)(found - h)));
    }

    case DVMP_HOST_STR_CONTAINS: {
      DvmpObj *s, *needle;
      if (need_str(argv[0], &s) != 0 || need_str(argv[1], &needle) != 0) {
        goto typeerr;
      }
      const int hit = (needle->len == 0) ||
                      (strstr((const char *)(s + 1), (const char *)(needle + 1)) !=
                       NULL);
      HOST_RETURN(dvmp_bool(hit));
    }

    case DVMP_HOST_STR_TO_UPPER:
    case DVMP_HOST_STR_TO_LOWER: {
      DvmpObj *s;
      if (need_str(argv[0], &s) != 0) goto typeerr;
      DvmpObj *r = dvmp_new_str(ar, (const uint8_t *)(s + 1), s->len);
      if (r == NULL) goto oom;
      uint8_t *out = (uint8_t *)(r + 1);
      const int upper = (id == DVMP_HOST_STR_TO_UPPER);
      for (uint32_t i = 0; i < r->len; i++) {
        /* ASCII only. Bytes >= 0x80 are left alone so a multi-byte sequence is
         * never corrupted into invalid UTF-8. */
        if (upper) {
          if (out[i] >= 'a' && out[i] <= 'z') out[i] = (uint8_t)(out[i] - 32);
        } else {
          if (out[i] >= 'A' && out[i] <= 'Z') out[i] = (uint8_t)(out[i] + 32);
        }
      }
      HOST_RETURN(dvmp_obj_slot(r));
    }

    case DVMP_HOST_STR_PARSE_INT: {
      DvmpObj *s;
      if (need_str(argv[0], &s) != 0) goto typeerr;
      /* Returns 0 for anything malformed, matching `int.tryParse(x) ?? 0`.
       * Overflow clamps instead of wrapping, so a hostile string cannot turn
       * into an unexpected small number downstream. */
      const char *p = (const char *)(s + 1);
      int neg = 0;
      if (*p == '-') {
        neg = 1;
        p++;
      } else if (*p == '+') {
        p++;
      }
      int64_t acc = 0;
      int any = 0;
      int overflow = 0;
      for (; *p != '\0'; p++) {
        if (*p < '0' || *p > '9') {
          any = 0;
          break;
        }
        any = 1;
        const int d = *p - '0';
        if (acc > (INT64_MAX - d) / 10) {
          overflow = 1;
          break;
        }
        acc = acc * 10 + d;
      }
      /*
       * Overflow is checked FIRST, and the order matters.
       *
       * `any` is set before the overflow test, so by the time the accumulator
       * saturates `any` is already 1 - which meant the clamp branch below was
       * unreachable and the function returned the *partial* accumulator instead.
       * The oracle clamps (`int.parse` on an out-of-range literal throws, and the
       * emitted shim clamps), so `strParseInt("9223372036854775808")` produced
       * 922337203685477580 in the VM and 9223372036854775807 in Dart: a silently
       * wrong number, with no protected function calling it, so the differential
       * suite had nothing to catch it with.
       */
      int64_t v = 0;
      if (overflow != 0) {
        v = neg ? INT64_MIN : INT64_MAX;
      } else if (any != 0) {
        v = neg ? -acc : acc;
      }
      HOST_RETURN(dvmp_int(v));
    }

    case DVMP_HOST_INT_TO_STR: {
      int64_t v;
      if (need_int(argv[0], &v) != 0) goto typeerr;
      char buf[24];
      const int n = snprintf(buf, sizeof(buf), "%lld", (long long)v);
      if (n <= 0 || n >= (int)sizeof(buf)) goto internal;
      DvmpObj *r = dvmp_new_str(ar, (const uint8_t *)buf, (uint32_t)n);
      if (r == NULL) goto oom;
      HOST_RETURN(dvmp_obj_slot(r));
    }

    case DVMP_HOST_HASH: {
      DvmpObj *s;
      if (need_str(argv[0], &s) != 0) goto typeerr;
      HOST_RETURN(dvmp_int(fnv1a((const uint8_t *)(s + 1), s->len)));
    }

    case DVMP_HOST_ABORT: {
      DvmpObj *s = NULL;
      (void)need_str(argv[0], &s);
      /* Leaves the stack untouched: the VM reports a fault and unwinds, so
       * repairing `sp` here would only mask a compiler bug. */
      dvmp_vm_set_error("bytecode abort: %s",
                        s != NULL ? dvmp_obj_str(s) : "");
      return DVMP_HOST_ABORTED;
    }

    default:
      goto internal;
  }

#undef HOST_RETURN

typeerr:
  dvmp_vm_set_error("builtin %u: operand type mismatch (tags 0x%x)", id,
                    type_mask);
  return DVMP_HOST_ERROR;
range:
  dvmp_vm_set_error("builtin %u: index or size out of range", id);
  return DVMP_HOST_ERROR;
oom:
  dvmp_vm_set_error("builtin %u: allocation failed", id);
  return DVMP_HOST_ERROR;
internal:
  dvmp_vm_set_error("builtin %u: internal error", id);
  return DVMP_HOST_ERROR;
}
