/// Opcode numbering for the DartVMP private instruction set.
///
/// These numbers are the *compiler's* view. What actually ships in the binary
/// is a keyed permutation of the whole 0..255 range (see
/// `Packer.opcodePermutation`), followed by a stream cipher, so the numbering
/// below never appears on the wire.
///
/// MUST stay in sync with `packages/dartvmp/src/dvmp_wire.h`.
library;

class Op {
  static const int nop = 0x00;
  static const int pushI = 0x01; // i32 immediate
  static const int pushK = 0x02; // u16 const-pool index
  static const int pushS = 0x03; // u16 string-table index
  static const int pushNil = 0x04;
  static const int pushTrue = 0x05;
  static const int pushFalse = 0x06;
  static const int pop = 0x07;
  static const int dup = 0x08;
  static const int swap = 0x09;
  static const int load = 0x0A; // u16 local slot
  static const int store = 0x0B; // u16 local slot
  static const int add = 0x0C;
  static const int sub = 0x0D;
  static const int mul = 0x0E;
  static const int div = 0x0F;
  static const int mod = 0x10;
  static const int neg = 0x11;
  static const int band = 0x12;
  static const int bor = 0x13;
  static const int bxor = 0x14;
  static const int shl = 0x15;
  static const int shr = 0x16;
  static const int bnot = 0x17;
  static const int cmplt = 0x18;
  static const int cmple = 0x19;
  static const int cmpgt = 0x1A;
  static const int cmpge = 0x1B;
  static const int cmpeq = 0x1C;
  static const int cmpne = 0x1D;
  static const int jmp = 0x1E; // i32 absolute
  static const int jmpIfFalse = 0x1F; // i32 absolute
  static const int jmpIfTrue = 0x20; // i32 absolute
  static const int call = 0x21; // u16 function index
  static const int ret = 0x22;
  static const int retVoid = 0x23;
  static const int host = 0x24; // u16 host function id, u16 arg count
  static const int abort = 0x25;
  static const int max = 0x26;
}

/// Operand byte widths, indexed by opcode. A negative value marks an opcode
/// whose operand width depends on a second field (none today).
const List<int> kOperandBytes = <int>[
  0, // 00 nop
  4, // 01 push_i
  2, // 02 push_k
  2, // 03 push_s
  0, 0, 0, // 04..06 push_nil/true/false
  0, 0, 0, // 07..09 pop/dup/swap
  2, 2, // 0A..0B load/store
  0, 0, 0, 0, 0, // 0C..10 add..mod
  0, // 11 neg
  0, 0, 0, 0, 0, 0, // 12..17 and/or/xor/shl/shr/not
  0, 0, 0, 0, 0, 0, // 18..1D cmp*
  4, 4, 4, // 1E..20 jmp / jmp_if_false / jmp_if_true
  2, // 21 call
  0, 0, // 22..23 ret / ret_void
  4, // 24 host (u16 id + u16 argc)
  0, // 25 abort
];

/// Host (native) builtin identifiers. The VM implements these in C; they are
/// the *only* bridge through which protected bytecode can touch the host,
/// which keeps the attack surface auditable.
class HostFn {
  static const int strNew = 1; // n -> string builder handle
  static const int strPush = 2; // (builder, s) -> builder
  static const int listNew = 3; // n -> list handle
  static const int listPush = 4; // (list, v) -> list
  static const int listLen = 5; // list -> int
  static const int listGet = 6; // (list, i) -> value
  static const int listSet = 7; // (list, i, v) -> value
  static const int mapNew = 8; // n -> map handle
  static const int mapSet = 9; // (map, k, v) -> map
  static const int mapGet = 10; // (map, k) -> value
  static const int mapHas = 11; // (map, k) -> bool
  static const int strLen = 12; // s -> int (bytes)
  static const int strAt = 13; // (s, i) -> 1-char string
  static const int strCode = 14; // (s, i) -> int
  static const int strSub = 15; // (s, start, len) -> string
  static const int strIndexOf = 16; // (s, needle) -> int (-1 if absent)
  static const int strContains = 17; // (s, needle) -> bool
  static const int strToUpper = 18; // s -> string (ASCII)
  static const int strToLower = 19; // s -> string (ASCII)
  static const int strParseInt = 20; // s -> int (0 when malformed)
  static const int intToStr = 21; // i -> string (decimal)
  static const int hash = 22; // s -> int (FNV-1a 64)
  static const int abort = 23; // s -> never (raises a VM fault)
  static const int strBuild = 24; // builder -> string
  static const int strConcat = 25; // (a, b) -> fresh string, reclaims operands
  static const int max = 25;

  /// Number of arguments consumed from the eval stack for each id.
  static const Map<int, int> arity = {
    strNew: 0, // argc is passed explicitly, see below
    strPush: 2,
    listNew: 0,
    listPush: 2,
    listLen: 1,
    listGet: 2,
    listSet: 3,
    mapNew: 0,
    mapSet: 3,
    mapGet: 2,
    mapHas: 2,
    strLen: 1,
    strAt: 2,
    strCode: 2,
    strSub: 3,
    strIndexOf: 2,
    strContains: 2,
    strToUpper: 1,
    strToLower: 1,
    strParseInt: 1,
    intToStr: 1,
    hash: 1,
    abort: 1,
    strBuild: 1,
    strConcat: 2,
  };
}

/// Number of operands encoded for each opcode, used by the disassembler.
const Map<int, String> kOpNames = {
  Op.nop: 'nop',
  Op.pushI: 'push_i',
  Op.pushK: 'push_k',
  Op.pushS: 'push_s',
  Op.pushNil: 'push_nil',
  Op.pushTrue: 'push_true',
  Op.pushFalse: 'push_false',
  Op.pop: 'pop',
  Op.dup: 'dup',
  Op.swap: 'swap',
  Op.load: 'load',
  Op.store: 'store',
  Op.add: 'add',
  Op.sub: 'sub',
  Op.mul: 'mul',
  Op.div: 'div',
  Op.mod: 'mod',
  Op.neg: 'neg',
  Op.band: 'band',
  Op.bor: 'bor',
  Op.bxor: 'bxor',
  Op.shl: 'shl',
  Op.shr: 'shr',
  Op.bnot: 'bnot',
  Op.cmplt: 'cmp_lt',
  Op.cmple: 'cmp_le',
  Op.cmpgt: 'cmp_gt',
  Op.cmpge: 'cmp_ge',
  Op.cmpeq: 'cmp_eq',
  Op.cmpne: 'cmp_ne',
  Op.jmp: 'jmp',
  Op.jmpIfFalse: 'jmp_if_false',
  Op.jmpIfTrue: 'jmp_if_true',
  Op.call: 'call',
  Op.ret: 'ret',
  Op.retVoid: 'ret_void',
  Op.host: 'host',
  Op.abort: 'abort',
};

const Map<int, String> kHostNames = {
  HostFn.strNew: 'strNew',
  HostFn.strPush: 'strPush',
  HostFn.listNew: 'listNew',
  HostFn.listPush: 'listPush',
  HostFn.listLen: 'listLen',
  HostFn.listGet: 'listGet',
  HostFn.listSet: 'listSet',
  HostFn.mapNew: 'mapNew',
  HostFn.mapSet: 'mapSet',
  HostFn.mapGet: 'mapGet',
  HostFn.mapHas: 'mapHas',
  HostFn.strLen: 'strLen',
  HostFn.strAt: 'strAt',
  HostFn.strCode: 'strCode',
  HostFn.strSub: 'strSub',
  HostFn.strIndexOf: 'strIndexOf',
  HostFn.strContains: 'strContains',
  HostFn.strToUpper: 'strToUpper',
  HostFn.strToLower: 'strToLower',
  HostFn.strParseInt: 'strParseInt',
  HostFn.intToStr: 'intToStr',
  HostFn.hash: 'hash',
  HostFn.abort: 'abort',
  HostFn.strBuild: 'strBuild',
  HostFn.strConcat: 'strConcat',
};
