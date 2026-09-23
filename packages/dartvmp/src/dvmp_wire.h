/*
 * dvmp_wire.h - value wire format shared by the Dart marshaller and the VM.
 *
 * Every value is encoded as:
 *
 *     tag:u8  payload
 *
 *   DVMP_T_NIL   (0x00)  no payload
 *   DVMP_T_BOOL  (0x01)  u8        0 or 1
 *   DVMP_T_INT   (0x02)  i64       little-endian, two's complement
 *   DVMP_T_STR   (0x03)  u32 len, then len bytes of UTF-8
 *   DVMP_T_LIST  (0x04)  u32 count, then `count` encoded values
 *   DVMP_T_MAP   (0x05)  u32 count, then `count` * (encoded key, encoded value)
 *
 * The encoding is deliberately *not* self-describing beyond the tag byte so
 * that a reverse engineer looking at a captured FFI buffer sees an opaque
 * stream. The Dart implementation lives in packages/dartvmp/lib/src/wire.dart
 * and MUST be kept byte-compatible with this file.
 */
#ifndef DVMP_WIRE_H_
#define DVMP_WIRE_H_

#include <stdint.h>

enum {
  DVMP_T_NIL = 0x00,
  DVMP_T_BOOL = 0x01,
  DVMP_T_INT = 0x02,
  DVMP_T_STR = 0x03,
  DVMP_T_LIST = 0x04,
  DVMP_T_MAP = 0x05,
};

/* ------------------------------------------------------------------ */
/* Module container format (produced by tool/vmpc, consumed by the VM)  */
/* ------------------------------------------------------------------ */

#define DVMP_MAGIC0 'D'
#define DVMP_MAGIC1 'V'
#define DVMP_MAGIC2 'M'
#define DVMP_MAGIC3 'P'

#define DVMP_CONTAINER_VERSION 1u

/* Header, stored in the clear so that init can validate cheaply. */
#define DVMP_HEADER_SIZE 32u

/* Header field offsets. All integers little-endian. */
#define DVMP_OFF_MAGIC 0u   /* 4 x u8  "DVMP"                       */
#define DVMP_OFF_VERSION 4u /* u16     container version            */
#define DVMP_OFF_FLAGS 6u   /* u16     reserved, must be 0          */
#define DVMP_OFF_SEED 8u    /* u64     key-stream seed              */
#define DVMP_OFF_BODY_LEN 16u /* u32   length of encrypted body     */
#define DVMP_OFF_BODY_CRC 20u /* u32   CRC32 of the plaintext body  */
#define DVMP_OFF_ENTRY_COUNT 24u /* u32 number of exported functions */
#define DVMP_OFF_RESERVED 28u    /* u32 must be 0                    */

/* After the header comes the encrypted body (body_len bytes) followed by an
 * 8-byte authentication tag. */
#define DVMP_TAG_SIZE 8u

/* Sentinel meaning "no instruction-stream chunk is decoded". The stream is not
 * chunked (see dvmp_module.c), so this is what the chunk probe always reports. */
#define DVMP_NO_CHUNK 0xFFFFFFFFu

/* ------------------------------------------------------------------ */
/* Call policy ("guard")                                               */
/* ------------------------------------------------------------------ */
/*
 * An opt-in per-function call budget, for functions whose *answer* is the thing
 * an attacker wants - a licence check being the canonical case. A function like
 * that is an oracle by construction: it is exported, so it can be called in a
 * loop, and each call answers a yes/no question about a guess.
 *
 * The budget is declared in the protected source:
 *
 *     // @vmp guard:rate=8/1000     at most 8 calls per 1000 ms
 *     // @vmp guard:once            at most one call per process
 *
 * and enforced here. When it is exhausted the call is REFUSED with
 * DARTVMP_ERR_TOO_MANY_CALLS. It never returns a wrong answer: the design rule is
 * that protection must not change what the business code sees, and a poisoned
 * result would do exactly that.
 *
 * This cannot stop an attacker who patches the guard out - they own the process.
 * What it stops is the cheap attack: calling the shipped library a million times
 * and watching the answers. Defeating the guard requires patching the binary,
 * which is the same work as reversing it.
 */
#define DVMP_GUARD_NONE 0u
#define DVMP_GUARD_RATE 1u
#define DVMP_GUARD_ONCE 2u

/*
 * The call policy is a little-endian u32 at descriptor offset 8:
 *
 *     [8]       mode        DVMP_GUARD_*
 *     [9]       budget      calls allowed per window (RATE only)
 *     [10..12)  window_ms   window length in milliseconds (RATE only)
 *
 * Self-describing rather than bit-packed. An earlier single-byte form split four
 * bits for the budget and four for a window *exponent*, which capped the budget at
 * 15 and forced power-of-two windows - so the first real policy (64 calls per 2 s)
 * could not be expressed, and a requested 2000 ms became 2048 without saying so.
 */
#define DVMP_GUARD_MASK 0x3u

/*
 * Bytes per function descriptor in the body.
 *
 * 32, and every field in it is written and read by offset constants declared
 * below rather than by literals. The record has been 24, 26 and 28 bytes in
 * earlier revisions and each change produced the same failure: one of the five
 * places that stride over descriptors - the generator, the body parser, the code
 * region walk, and the two independent Python decoders in `tool/` - kept an old
 * literal, and the symptom was never "descriptor misaligned" but something three
 * layers away, such as an empty code region or a body CRC mismatch.
 */
#define DVMP_DESC_SIZE 32u

/*
 * Field offsets inside one descriptor record. Little-endian throughout.
 *
 *   [0..4)   name_off          u32   into the string blob
 *   [4..8)   name_len          u32
 *   [8]      guard_mode        u8    DVMP_GUARD_{NONE,RATE,ONCE}
 *   [9]      reserved          u8    must be 0
 *   [10..12) guard_budget      u16   calls allowed per window (RATE only)
 *   [12..14) guard_window_ms   u16   window length in ms   (RATE only)
 *   [14..16) arity             u16   argument count
 *   [16..18) locals            u16   frame slots beyond the arguments
 *   [18..20) max_stack         u16   peak operand-stack depth
 *   [20..22) slot_base         u16   base slot of this function's frame window
 *   [22..24) reserved2         u16   must be 0
 *   [24..28) code_len          u32   bytes of instruction stream
 *   [28..32) code_off          u32   absolute offset of those bytes in the body
 *
 * The two reserved fields are asserted zero by both the body parser and the
 * analysis tools. They cost four bytes and buy the one check that turns the whole
 * class of "a field moved and everything shifted" bugs into a hard failure at the
 * first open instead of a plausible-looking module.
 */
#define DVMP_DESC_OFF_NAME_OFF 0u
#define DVMP_DESC_OFF_NAME_LEN 4u
#define DVMP_DESC_OFF_GUARD_MODE 8u
#define DVMP_DESC_OFF_RESERVED 9u
#define DVMP_DESC_OFF_GUARD_BUDGET 10u
#define DVMP_DESC_OFF_GUARD_WINDOW 12u
#define DVMP_DESC_OFF_ARITY 14u
#define DVMP_DESC_OFF_LOCALS 16u
#define DVMP_DESC_OFF_MAX_STACK 18u
#define DVMP_DESC_OFF_SLOT_BASE 20u
#define DVMP_DESC_OFF_RESERVED2 22u
#define DVMP_DESC_OFF_CODE_LEN 24u
#define DVMP_DESC_OFF_CODE_OFF 28u

/* ------------------------------------------------------------------ */
/* Encrypted body layout, once decrypted and de-obfuscated             */
/* ------------------------------------------------------------------ */
/*
 *   u32 strings_len
 *   u8  strings[strings_len]        // packed UTF-8, offsets in table
 *   u32 const_count
 *   i64 consts[const_count]         // integer constant pool
 *   u32 str_count
 *   struct { u32 off; u32 len; } strs[str_count]   // offsets into strings[]
 *   u32 fn_count
 *   struct { ... } fns[fn_count]    // DVMP_DESC_SIZE bytes each; the field
 *                                   // table is the DVMP_DESC_OFF_* block above
 *   u32 code_len
 *   u8  code[code_len]              // opcode-permuted, per-function streams
 */

#define DVMP_BODY_OFF_STRINGS 0u /* relative offsets, see vmp_module.c */

/* ------------------------------------------------------------------ */
/* Opcode set (the "public" numbering). The shipper permutes these via   */
/* DVMP_OP_PERM, so the numbering on the wire is build-specific.         */
/* ------------------------------------------------------------------ */
enum DvmpOp {
  DVMP_OP_NOP = 0x00,
  DVMP_OP_PUSH_I = 0x01,  /* s32 immediate                            */
  DVMP_OP_PUSH_K = 0x02,  /* u16 index into constant pool             */
  DVMP_OP_PUSH_S = 0x03,  /* u16 index into string table              */
  DVMP_OP_PUSH_NIL = 0x04,
  DVMP_OP_PUSH_TRUE = 0x05,
  DVMP_OP_PUSH_FALSE = 0x06,
  DVMP_OP_POP = 0x07,
  DVMP_OP_DUP = 0x08,
  DVMP_OP_SWAP = 0x09,
  DVMP_OP_LOAD = 0x0A, /* u16 local slot                           */
  DVMP_OP_STORE = 0x0B,
  DVMP_OP_ADD = 0x0C,
  DVMP_OP_SUB = 0x0D,
  DVMP_OP_MUL = 0x0E,
  DVMP_OP_DIV = 0x0F,
  DVMP_OP_MOD = 0x10,
  DVMP_OP_NEG = 0x11,
  DVMP_OP_AND = 0x12,
  DVMP_OP_OR = 0x13,
  DVMP_OP_XOR = 0x14,
  DVMP_OP_SHL = 0x15,
  DVMP_OP_SHR = 0x16,
  DVMP_OP_NOT = 0x17,
  DVMP_OP_CMPLT = 0x18,
  DVMP_OP_CMPLE = 0x19,
  DVMP_OP_CMPGT = 0x1A,
  DVMP_OP_CMPGE = 0x1B,
  DVMP_OP_CMPEQ = 0x1C,
  DVMP_OP_CMPNE = 0x1D,
  DVMP_OP_JMP = 0x1E,       /* s32 absolute target                  */
  DVMP_OP_JMP_IF_FALSE = 0x1F,
  DVMP_OP_JMP_IF_TRUE = 0x20,
  DVMP_OP_CALL = 0x21, /* u16 function index                      */
  DVMP_OP_RET = 0x22,
  DVMP_OP_RET_VOID = 0x23,
  DVMP_OP_HOST = 0x24, /* u16 host function id                     */
  DVMP_OP_ABORT = 0x25, /* raises a VM fault with a message         */
  DVMP_OP_MAX = 0x26,
};

/*
 * Host ("builtin") function ids. These are the only operations through which
 * protected bytecode can reach the outside world. The interpreter pops the
 * arguments according to the table in vmp_host.c - the bytecode carries only
 * the id, so an attacker reading the instruction stream learns the *shape* of
 * the computation but not which string constant or key is involved beyond the
 * string-table index it references.
 */
enum DvmpHostFn {
  DVMP_HOST_STR_NEW = 1,     /* (n)             -> builder  */
  DVMP_HOST_STR_PUSH = 2,    /* (b, s)          -> b        */
  DVMP_HOST_LIST_NEW = 3,    /* (n)             -> list     */
  DVMP_HOST_LIST_PUSH = 4,   /* (l, v)          -> l        */
  DVMP_HOST_LIST_LEN = 5,    /* (l)             -> int      */
  DVMP_HOST_LIST_GET = 6,    /* (l, i)          -> value    */
  DVMP_HOST_LIST_SET = 7,    /* (l, i, v)       -> v        */
  DVMP_HOST_MAP_NEW = 8,     /* (n)             -> map      */
  DVMP_HOST_MAP_SET = 9,     /* (m, k, v)       -> m        */
  DVMP_HOST_MAP_GET = 10,    /* (m, k)          -> value    */
  DVMP_HOST_MAP_HAS = 11,    /* (m, k)          -> bool     */
  DVMP_HOST_STR_LEN = 12,    /* (s)             -> int      */
  DVMP_HOST_STR_AT = 13,     /* (s, i)          -> string   */
  DVMP_HOST_STR_CODE = 14,   /* (s, i)          -> int      */
  DVMP_HOST_STR_SUB = 15,    /* (s, start, len) -> string   */
  DVMP_HOST_STR_INDEX_OF = 16, /* (s, needle)   -> int      */
  DVMP_HOST_STR_CONTAINS = 17, /* (s, needle)   -> bool     */
  DVMP_HOST_STR_TO_UPPER = 18, /* (s)           -> string   */
  DVMP_HOST_STR_TO_LOWER = 19, /* (s)           -> string   */
  DVMP_HOST_STR_PARSE_INT = 20, /* (s)          -> int      */
  DVMP_HOST_INT_TO_STR = 21, /* (i)             -> string   */
  DVMP_HOST_HASH = 22,       /* (s)             -> int      */
  DVMP_HOST_ABORT = 23,      /* (s)             -> never    */
  DVMP_HOST_STR_BUILD = 24,  /* (b)             -> string   */
  DVMP_HOST_STR_CONCAT = 25, /* (a, b)          -> string   */
  DVMP_HOST_MAX = 25,
};

/*
 * Opcode permutation applied *before* the stream cipher. Recovering the
 * instruction stream therefore requires reversing BOTH layers, and the
 * permutation depends on the seed that is generated per build.
 *
 * It is a keyed Fisher-Yates shuffle of the byte range 0..255 driven by the same
 * SplitMix64 stream as the body cipher, keeping the first DVMP_OP_MAX entries as
 * the wire values - see `op_tables` in dvmp_module.c, which is the normative
 * definition. The shuffle is `static` rather than a macro set because there is no
 * closed form to publish here: a permutation has no small parameter space.
 *
 * It replaced `perm[op] = ((op * 167) + (seed & 0xFF)) & 0xFF`. That mapping was
 * recoverable in ~128 attempts - the salt is in the container header and the
 * multiplier is odd - and the container CRC is a perfect oracle for testing a
 * candidate, so the mapping fell out of the shipped container in minutes.
 * tool/recover_opcodes.py is the reverse test: it must fail on current output.
 *
 * The seed is still public. See the ceiling note in dvmp_module.c.
 */

/* ------------------------------------------------------------------ */
/* Interpreter limits                                                  */
/* ------------------------------------------------------------------ */

#define DVMP_MAX_SLOTS 1024u
#define DVMP_MAX_STACK 256u
#define DVMP_MAX_DEPTH 64u

/*
 * Descriptor for one protected function. The compiler emits a
 * `kDvmpEntries[]` table of these into the generated include so that
 * `dartvmp_call_named` and the introspection API work without parsing the
 * encrypted body themselves.
 *
 * There is deliberately no `name` field. Names used to be string literals here,
 * which put a readable list of the protection surface in `.rodata`; they now
 * live masked in `kDvmpNameBlob[]` and are un-masked on demand. See
 * `dvmp_module_name_copy()` and the generator's `_namesTable`.
 */
typedef struct DvmpEntryMeta {
  uint32_t id;
  uint32_t arity;
} DvmpEntryMeta;

#endif /* DVMP_WIRE_H_ */
