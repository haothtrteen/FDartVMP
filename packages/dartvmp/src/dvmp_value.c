/*
 * dvmp_value.c - arena, heap objects and the FFI wire format.
 *
 * Everything a protected function can allocate lives in a single arena that is
 * reset at the start of every call. Protected functions are pure: no object
 * escapes the call, so there is no collector, no reference counting and no way
 * for bytecode to leak host memory.
 */
#include "dvmp_internal.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

/* ------------------------------------------------------------------ */
/* Arena                                                               */
/* ------------------------------------------------------------------ */

#define DVMP_ARENA_CHUNK (16u * 1024u)
#define DVMP_ARENA_MAX_TOTAL (8u * 1024u * 1024u)

void dvmp_arena_init(DvmpArena *a) {
  a->head = NULL;
  a->total = 0;
}

void dvmp_arena_reset(DvmpArena *a) {
  DvmpArenaChunk *c = a->head;
  while (c != NULL) {
    DvmpArenaChunk *next = c->next;
    vmp_secure_wipe(c, sizeof(DvmpArenaChunk) + c->cap);
    free(c);
    c = next;
  }
  a->head = NULL;
  a->total = 0;
}

void dvmp_arena_destroy(DvmpArena *a) { dvmp_arena_reset(a); }

/*
 * Arena "free".
 *
 * Deliberately a no-op. The arena is fully reset at the start of every protected
 * call (dvmp_arena_reset), and protected functions are pure, so nothing outlives
 * the call and the whole arena is reclaimed at once. A general free list would
 * add per-object bookkeeping for no observable benefit - the budget check in
 * dvmp_arena_alloc is what bounds a runaway allocation loop.
 *
 * It exists so callers can state intent. `strConcat` calls it on its two
 * operands, which really are unreachable afterwards, but they remain in the
 * arena until the call ends: with the concatenation lowering that is O(n) in
 * arena usage rather than O(n^2), which is what actually mattered.
 */
void dvmp_arena_free(DvmpArena *a, void *p) {
  (void)a;
  (void)p;
}

void *dvmp_arena_alloc(DvmpArena *a, size_t size) {
  if (size == 0) return NULL;
  /* 16-byte alignment keeps 8-byte fields naturally aligned on every ABI we
   * target, including 32-bit ARM. */
  size = (size + 15u) & ~(size_t)15u;

  DvmpArenaChunk *c = a->head;
  if (c == NULL || c->cap - c->used < size) {
    if (a->total + size > DVMP_ARENA_MAX_TOTAL) {
      return NULL; /* budget exhausted: the bytecode is looping on allocations */
    }
    size_t cap = size > DVMP_ARENA_CHUNK ? size : DVMP_ARENA_CHUNK;
    c = (DvmpArenaChunk *)malloc(sizeof(DvmpArenaChunk) + cap);
    if (c == NULL) return NULL;
    c->next = a->head;
    c->used = 0;
    c->cap = cap;
    a->head = c;
    a->total += cap;
  }
  void *p = (uint8_t *)(c + 1) + c->used;
  c->used += size;
  memset(p, 0, size);
  return p;
}

/* ------------------------------------------------------------------ */
/* Value constructors                                                  */
/* ------------------------------------------------------------------ */

DvmpSlot dvmp_nil(void) {
  DvmpSlot s;
  s.tag = DVMP_TAG_NIL;
  s.bits = 0;
  return s;
}

DvmpSlot dvmp_int(int64_t v) {
  DvmpSlot s;
  s.tag = DVMP_TAG_INT;
  s.bits = v;
  return s;
}

DvmpSlot dvmp_bool(int v) {
  DvmpSlot s;
  s.tag = DVMP_TAG_BOOL;
  s.bits = v ? 1 : 0;
  return s;
}

DvmpSlot dvmp_obj_slot(DvmpObj *o) {
  DvmpSlot s;
  s.tag = o == NULL ? DVMP_TAG_NIL : DVMP_TAG_OBJ;
  s.bits = (int64_t)(intptr_t)o;
  return s;
}

static uint8_t obj_kind(DvmpObj *o) { return o == NULL ? 0xFF : o->kind; }

DvmpObj *dvmp_new_str(DvmpArena *a, const uint8_t *bytes, uint32_t len) {
  DvmpObj *o = (DvmpObj *)dvmp_arena_alloc(a, sizeof(DvmpObj) + len + 1u);
  if (o == NULL) return NULL;
  o->kind = DVMP_V_STR;
  o->len = len;
  o->cap = len + 1u;
  uint8_t *dst = (uint8_t *)(o + 1);
  if (bytes != NULL && len > 0) {
    memcpy(dst, bytes, len);
  }
  dst[len] = 0; /* NUL terminated so host APIs can treat it as a C string */
  if (getenv("DARTVMP_TRACE_ALLOC") != NULL) {
    fprintf(stderr, "[alloc] str  obj=%p kind=%u len=%u\n", (void *)o,
            (unsigned)o->kind, len);
  }
  return o;
}

DvmpObj *dvmp_new_list(DvmpArena *a, uint32_t cap) {
  if (cap > DVMP_MAX_LIST) return NULL;
  if (cap == 0) cap = 4;
  DvmpObj *o = (DvmpObj *)dvmp_arena_alloc(
      a, sizeof(DvmpObj) + (size_t)cap * sizeof(DvmpListSlot));
  if (o == NULL) return NULL;
  o->kind = DVMP_V_LIST;
  o->len = 0;
  o->cap = cap;
  return o;
}

DvmpObj *dvmp_new_map(DvmpArena *a, uint32_t cap) {
  if (cap > DVMP_MAX_MAP) return NULL;
  if (cap == 0) cap = 4;
  DvmpObj *o = (DvmpObj *)dvmp_arena_alloc(
      a, sizeof(DvmpObj) + (size_t)cap * sizeof(DvmpMapEntry));
  if (o == NULL) return NULL;
  o->kind = DVMP_V_MAP;
  o->len = 0;
  o->cap = cap;
  return o;
}

const char *dvmp_obj_str(DvmpObj *o) {
  if (obj_kind(o) != DVMP_V_STR) return "";
  return (const char *)(o + 1);
}

int dvmp_str_eq_c(DvmpObj *o, const char *c) {
  if (obj_kind(o) != DVMP_V_STR || c == NULL) return 0;
  return strcmp((const char *)(o + 1), c) == 0;
}

/* ------------------------------------------------------------------ */
/* String builder                                                      */
/* ------------------------------------------------------------------ */

DvmpBuilder *dvmp_new_builder(DvmpArena *a, uint32_t hint) {
  DvmpBuilder *b = (DvmpBuilder *)dvmp_arena_alloc(a, sizeof(DvmpBuilder));
  if (b == NULL) return NULL;
  if (hint == 0) hint = 4;
  /* The `strNew(n)` hint is a *part count*, not a byte count, so scaling it is
   * deliberate: it makes the common `a + b + c` case need zero reallocations
   * while keeping the initial allocation small. */
  uint64_t cap = (uint64_t)hint * 16u;
  if (cap > DARTVMP_MAX_STRING) cap = DARTVMP_MAX_STRING;
  b->data = (uint8_t *)dvmp_arena_alloc(a, (size_t)cap);
  if (b->data == NULL) return NULL;
  b->len = 0;
  b->cap = (uint32_t)cap;
  return b;
}

int dvmp_builder_append(DvmpArena *a, DvmpBuilder *b, const uint8_t *data,
                        uint32_t len) {
  if (b == NULL || (data == NULL && len != 0)) return -1;
  if ((uint64_t)b->len + len > DARTVMP_MAX_STRING) return -1;
  if (b->len + len > b->cap) {
    uint64_t ncap = b->cap;
    while (ncap < (uint64_t)b->len + len) {
      ncap *= 2u;
      if (ncap > DARTVMP_MAX_STRING) ncap = DARTVMP_MAX_STRING;
      if (ncap < (uint64_t)b->len + len) return -1; /* clamped, still too small */
    }
    uint8_t *nd = (uint8_t *)dvmp_arena_alloc(a, (size_t)ncap);
    if (nd == NULL) return -1;
    if (b->len > 0) memcpy(nd, b->data, b->len);
    b->data = nd;
    b->cap = (uint32_t)ncap;
  }
  if (len > 0) memcpy(b->data + b->len, data, len);
  b->len += len;
  return 0;
}

static DvmpListSlot *list_slots(DvmpObj *o) {
  return (DvmpListSlot *)(o + 1);
}

static DvmpMapEntry *map_entries(DvmpObj *o) {
  return (DvmpMapEntry *)(o + 1);
}

static int slot_eq(DvmpSlot a, DvmpSlot b) {
  if (a.tag != b.tag) return 0;
  if (a.tag == DVMP_TAG_OBJ) {
    DvmpObj *x = (DvmpObj *)(intptr_t)a.bits;
    DvmpObj *y = (DvmpObj *)(intptr_t)b.bits;
    if (x == y) return 1;
    if (obj_kind(x) != DVMP_V_STR || obj_kind(y) != DVMP_V_STR) return 0;
    if (x->len != y->len) return 0;
    return memcmp(x + 1, y + 1, x->len) == 0;
  }
  return a.bits == b.bits;
}

/* ------------------------------------------------------------------ */
/* List / map operations (used by both the wire reader and the host)    */
/* ------------------------------------------------------------------ */

int dvmp_list_push(DvmpArena *a, DvmpObj **list, DvmpSlot v) {
  DvmpObj *l = *list;
  if (obj_kind(l) != DVMP_V_LIST) return -1;
  if (l->len == l->cap) {
    uint32_t ncap = l->cap * 2u;
    if (ncap > DVMP_MAX_LIST) ncap = DVMP_MAX_LIST;
    if (ncap <= l->cap) return -1;
    DvmpObj *nl = dvmp_new_list(a, ncap);
    if (nl == NULL) return -1;
    memcpy(nl + 1, l + 1, (size_t)l->len * sizeof(DvmpListSlot));
    nl->len = l->len;
    *list = nl;
    l = nl;
  }
  DvmpListSlot *s = &list_slots(l)[l->len++];
  s->tag = v.tag;
  s->bits = v.bits;
  return 0;
}

int dvmp_list_get(DvmpObj *l, int64_t index, DvmpSlot *out) {
  if (obj_kind(l) != DVMP_V_LIST) return -1;
  if (index < 0 || (uint64_t)index >= l->len) return -1;
  const DvmpListSlot *s = &list_slots(l)[index];
  out->tag = s->tag;
  out->bits = s->bits;
  return 0;
}

int dvmp_map_set(DvmpArena *a, DvmpObj **map, DvmpSlot k, DvmpSlot v) {
  DvmpObj *m = *map;
  if (obj_kind(m) != DVMP_V_MAP) return -1;
  DvmpMapEntry *e = map_entries(m);
  for (uint32_t i = 0; i < m->len; i++) {
    DvmpSlot ek = {e[i].ktag, e[i].kbits};
    if (slot_eq(ek, k)) {
      e[i].vtag = v.tag;
      e[i].vbits = v.bits;
      return 0;
    }
  }
  if (m->len == m->cap) {
    uint32_t ncap = m->cap * 2u;
    if (ncap > DVMP_MAX_MAP) ncap = DVMP_MAX_MAP;
    if (ncap <= m->cap) return -1;
    DvmpObj *nm = dvmp_new_map(a, ncap);
    if (nm == NULL) return -1;
    memcpy(nm + 1, m + 1, (size_t)m->len * sizeof(DvmpMapEntry));
    nm->len = m->len;
    *map = nm;
    m = nm;
    e = map_entries(m);
  }
  e[m->len].ktag = k.tag;
  e[m->len].kbits = k.bits;
  e[m->len].vtag = v.tag;
  e[m->len].vbits = v.bits;
  m->len++;
  return 0;
}

int dvmp_map_get(DvmpObj *m, DvmpSlot k, DvmpSlot *out) {
  if (obj_kind(m) != DVMP_V_MAP) return -1;
  const DvmpMapEntry *e = map_entries(m);
  for (uint32_t i = 0; i < m->len; i++) {
    DvmpSlot ek = {e[i].ktag, e[i].kbits};
    if (slot_eq(ek, k)) {
      out->tag = e[i].vtag;
      out->bits = e[i].vbits;
      return 0;
    }
  }
  return -1;
}

/* ------------------------------------------------------------------ */
/* Wire format reader                                                  */
/* ------------------------------------------------------------------ */

static int rd_bytes(DvmpReader *r, uint8_t *out, uint32_t n) {
  if (r->error || r->pos + n > r->len) {
    r->error = 1;
    return -1;
  }
  if (out != NULL) memcpy(out, r->p + r->pos, n);
  r->pos += n;
  return 0;
}

static int rd_u32(DvmpReader *r, uint32_t *out) {
  uint8_t b[4];
  if (rd_bytes(r, b, 4) != 0) return -1;
  *out = (uint32_t)b[0] | ((uint32_t)b[1] << 8) | ((uint32_t)b[2] << 16) |
         ((uint32_t)b[3] << 24);
  return 0;
}

static int rd_value(DvmpReader *r, DvmpArena *a, DvmpSlot *out, uint32_t depth);

static int rd_list(DvmpReader *r, DvmpArena *a, DvmpSlot *out, uint32_t depth) {
  uint32_t n;
  if (rd_u32(r, &n) != 0) return -1;
  if (n > DVMP_MAX_LIST) {
    r->error = 1;
    return -1;
  }
  DvmpObj *l = dvmp_new_list(a, n == 0 ? 4 : n);
  if (l == NULL) {
    r->error = 1;
    return -1;
  }
  for (uint32_t i = 0; i < n; i++) {
    DvmpSlot v;
    if (rd_value(r, a, &v, depth + 1) != 0) return -1;
    if (dvmp_list_push(a, &l, v) != 0) {
      r->error = 1;
      return -1;
    }
  }
  *out = dvmp_obj_slot(l);
  return 0;
}

static int rd_map(DvmpReader *r, DvmpArena *a, DvmpSlot *out, uint32_t depth) {
  uint32_t n;
  if (rd_u32(r, &n) != 0) return -1;
  if (n > DVMP_MAX_MAP) {
    r->error = 1;
    return -1;
  }
  DvmpObj *m = dvmp_new_map(a, n == 0 ? 4 : n);
  if (m == NULL) {
    r->error = 1;
    return -1;
  }
  for (uint32_t i = 0; i < n; i++) {
    DvmpSlot k, v;
    if (rd_value(r, a, &k, depth + 1) != 0) return -1;
    if (rd_value(r, a, &v, depth + 1) != 0) return -1;
    if (dvmp_map_set(a, &m, k, v) != 0) {
      r->error = 1;
      return -1;
    }
  }
  *out = dvmp_obj_slot(m);
  return 0;
}

static int rd_value(DvmpReader *r, DvmpArena *a, DvmpSlot *out, uint32_t depth) {
  if (depth > 16) {
    r->error = 1;
    return -1;
  }
  uint8_t tag;
  if (rd_bytes(r, &tag, 1) != 0) return -1;
  switch (tag) {
    case DVMP_T_NIL:
      *out = dvmp_nil();
      return 0;
    case DVMP_T_BOOL: {
      uint8_t b;
      if (rd_bytes(r, &b, 1) != 0) return -1;
      *out = dvmp_bool(b != 0);
      return 0;
    }
    case DVMP_T_INT: {
      uint8_t b[8];
      if (rd_bytes(r, b, 8) != 0) return -1;
      uint64_t u = 0;
      for (int i = 7; i >= 0; i--) {
        u = (u << 8) | b[i];
      }
      *out = dvmp_int((int64_t)u);
      return 0;
    }
    case DVMP_T_STR: {
      uint32_t n;
      if (rd_u32(r, &n) != 0) return -1;
      if (n > DARTVMP_MAX_STRING || r->pos + n > r->len) {
        r->error = 1;
        return -1;
      }
      DvmpObj *s = dvmp_new_str(a, r->p + r->pos, n);
      r->pos += n;
      if (s == NULL) {
        r->error = 1;
        return -1;
      }
      *out = dvmp_obj_slot(s);
      return 0;
    }
    case DVMP_T_LIST:
      return rd_list(r, a, out, depth);
    case DVMP_T_MAP:
      return rd_map(r, a, out, depth);
    default:
      r->error = 1;
      return -1;
  }
}

int dvmp_read_value(DvmpReader *r, DvmpArena *a, DvmpSlot *out) {
  return rd_value(r, a, out, 0);
}

/* ------------------------------------------------------------------ */
/* Wire format writer                                                  */
/* ------------------------------------------------------------------ */

void dvmp_write_u8(DvmpWriter *w, uint8_t v) {
  if (w->overflow) return;
  if (w->len + 1 > w->cap) {
    w->overflow = 1;
    w->len += 1;
    return;
  }
  w->p[w->len++] = v;
}

void dvmp_write_bytes(DvmpWriter *w, const uint8_t *p, uint32_t n) {
  if (w->overflow) return;
  if (w->len + n > w->cap) {
    w->overflow = 1;
    w->len += n;
    return;
  }
  memcpy(w->p + w->len, p, n);
  w->len += n;
}

void dvmp_write_i64(DvmpWriter *w, int64_t v) {
  uint8_t b[8];
  uint64_t u = (uint64_t)v;
  for (int i = 0; i < 8; i++) {
    b[i] = (uint8_t)((u >> (8 * i)) & 0xFF);
  }
  dvmp_write_bytes(w, b, 8);
}

static void wr_u32(DvmpWriter *w, uint32_t v) {
  uint8_t b[4];
  b[0] = (uint8_t)(v & 0xFF);
  b[1] = (uint8_t)((v >> 8) & 0xFF);
  b[2] = (uint8_t)((v >> 16) & 0xFF);
  b[3] = (uint8_t)((v >> 24) & 0xFF);
  dvmp_write_bytes(w, b, 4);
}

static void wr_value(DvmpWriter *w, DvmpSlot v, uint32_t depth) {
  if (depth > 16 || w->overflow) {
    w->overflow = 1;
    return;
  }
  switch (v.tag) {
    case DVMP_TAG_NIL:
      dvmp_write_u8(w, DVMP_T_NIL);
      return;
    case DVMP_TAG_BOOL:
      dvmp_write_u8(w, DVMP_T_BOOL);
      dvmp_write_u8(w, v.bits ? 1 : 0);
      return;
    case DVMP_TAG_INT:
      dvmp_write_u8(w, DVMP_T_INT);
      dvmp_write_i64(w, v.bits);
      return;
    case DVMP_TAG_OBJ: {
      DvmpObj *o = (DvmpObj *)(intptr_t)v.bits;
      switch (obj_kind(o)) {
        case DVMP_V_STR:
          dvmp_write_u8(w, DVMP_T_STR);
          wr_u32(w, o->len);
          dvmp_write_bytes(w, (const uint8_t *)(o + 1), o->len);
          return;
        case DVMP_V_LIST: {
          dvmp_write_u8(w, DVMP_T_LIST);
          wr_u32(w, o->len);
          const DvmpListSlot *s = list_slots(o);
          for (uint32_t i = 0; i < o->len; i++) {
            DvmpSlot e = {s[i].tag, s[i].bits};
            wr_value(w, e, depth + 1);
          }
          return;
        }
        case DVMP_V_MAP: {
          dvmp_write_u8(w, DVMP_T_MAP);
          wr_u32(w, o->len);
          const DvmpMapEntry *e = map_entries(o);
          for (uint32_t i = 0; i < o->len; i++) {
            DvmpSlot k = {e[i].ktag, e[i].kbits};
            DvmpSlot val = {e[i].vtag, e[i].vbits};
            wr_value(w, k, depth + 1);
            wr_value(w, val, depth + 1);
          }
          return;
        }
        default:
          dvmp_write_u8(w, DVMP_T_NIL);
          return;
      }
    }
    default:
      dvmp_write_u8(w, DVMP_T_NIL);
      return;
  }
}

void dvmp_write_value(DvmpWriter *w, DvmpArena *a, DvmpSlot v) {
  (void)a;
  /*
   * A builder handle is a `DvmpBuilder *` with no `DvmpObj` header, so reading a
   * `kind` field out of one would be an out-of-bounds read past the struct. It
   * now carries its own tag, which makes the check below exact rather than
   * heuristic.
   *
   * The previous version of this function relied on "the VM's RET path checks" -
   * and nothing checked. A builder reaching the wire encoder as a *return value*
   * is therefore possible from a crafted image; it survived only because the low
   * byte of an aligned heap pointer can never be 1..6, so `obj_kind()` happened to
   * fall through to the nil case instead of reading a string of attacker-chosen
   * length. Encoding nil explicitly is the intended behaviour for a malformed
   * image, and it no longer depends on a coincidence about heap addresses.
   */
  if (v.tag == DVMP_TAG_BUILDER) {
    dvmp_write_u8(w, DVMP_T_NIL);
    return;
  }
  wr_value(w, v, 0);
}

/* ------------------------------------------------------------------ */
/* Hashes shared with the Dart compiler                                */
/* ------------------------------------------------------------------ */

uint32_t dvmp_crc32(const uint8_t *p, uint32_t n) {
  uint32_t crc = 0xFFFFFFFFu;
  for (uint32_t i = 0; i < n; i++) {
    crc ^= p[i];
    for (int k = 0; k < 8; k++) {
      crc = (crc & 1u) ? ((crc >> 1) ^ 0xEDB88320u) : (crc >> 1);
    }
  }
  return ~crc;
}

uint64_t dvmp_fnv1a64(const uint8_t *p, uint32_t n, uint64_t seed) {
  /* The loop itself lives in dvmp_internal.h: the VMPacker target `dvmp_body_tag`
   * has to inline it (a `bl` inside a virtualized function does not survive on
   * device), and keeping one copy of it here as well would be two definitions of a
   * hash that must match Dart bit for bit. This symbol is the out-of-line view of
   * it, kept for dvmp_host.c and for the host tests. */
  return dvmp_fnv1a64_core(p, n, seed);
}
