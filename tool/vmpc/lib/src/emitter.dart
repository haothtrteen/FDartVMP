/// AST -> private bytecode compiler.
library;

import 'dart:convert';
import 'dart:typed_data';

import 'ast.dart';
import 'const_eval.dart';
import 'lexer.dart';
import 'opcodes.dart';

export 'const_eval.dart'
    show ConstValue, ConstInt, ConstStr, ConstBool, evalConstExpr;

class CompileError implements Exception {
  final String message;
  final int line;
  final int col;
  final String sourceName;
  CompileError(this.message, this.line, this.col, this.sourceName);

  @override
  String toString() => '$sourceName:$line:$col: compile error: $message';
}

/// Per-function instruction buffer with label patching.
class _Code {
  final List<int> bytes = <int>[];
  final Map<String, int> _labels = <String, int>{};
  final List<(int, String)> _fixups = <(int, String)>[];
  int _nextLabel = 0;

  int get pc => bytes.length;

  int get maxStack => _maxStack;
  int _maxStack = 0;
  int _stack = 0;

  // ---- emit helpers -------------------------------------------------

  void _push(int n) {
    _stack += n;
    if (_stack > _maxStack) _maxStack = _stack;
  }

  void _pop(int n) {
    _stack -= n;
  }

  /// Resets the modelled stack depth. Used at control-flow merges where the
  /// depth is repaired by construction (blocks always leave the stack clean).
  void _resetDepth() {
    _stack = 0;
  }

  void u8(int b) => bytes.add(b & 0xFF);

  void u16(int v) {
    bytes.add(v & 0xFF);
    bytes.add((v >> 8) & 0xFF);
  }

  void u32(int v) {
    bytes.add(v & 0xFF);
    bytes.add((v >> 8) & 0xFF);
    bytes.add((v >> 16) & 0xFF);
    bytes.add((v >> 24) & 0xFF);
  }

  /// Adjusts the modelled stack depth without emitting anything.
  void stackEffect({int pops = 0, int pushes = 0}) {
    _pop(pops);
    _push(pushes);
  }

  void op(int opcode) => u8(opcode);

  void noArg(int opcode, {int pops = 0, int pushes = 0}) {
    u8(opcode);
    _pop(pops);
    _push(pushes);
  }

  void imm16(int opcode, int v, {int pops = 0, int pushes = 0}) {
    u8(opcode);
    u16(v);
    _pop(pops);
    _push(pushes);
  }

  void immI32(int opcode, int v, {int pops = 0, int pushes = 0}) {
    u8(opcode);
    u32(v);
    _pop(pops);
    _push(pushes);
  }

  // ---- labels -------------------------------------------------------

  String newLabel([String? hint]) => 'L${_nextLabel++}${hint == null ? '' : '_$hint'}';

  void mark(String label) {
    if (_labels.containsKey(label)) {
      throw StateError('label $label already defined');
    }
    _labels[label] = pc;
    _resetDepth();
  }

  void jumpTo(int opcode, String label) {
    u8(opcode);
    _fixups.add((bytes.length, label));
    u32(0);
  }

  /// Resolves all pending jumps. Throws if a label was never marked.
  void finish() {
    for (final (at, label) in _fixups) {
      final target = _labels[label];
      if (target == null) {
        throw StateError('undefined label $label');
      }
      bytes[at] = target & 0xFF;
      bytes[at + 1] = (target >> 8) & 0xFF;
      bytes[at + 2] = (target >> 16) & 0xFF;
      bytes[at + 3] = (target >> 24) & 0xFF;
    }
    _fixups.clear();
  }
}

/// A compiled function plus everything needed to place it in the module.
class CompiledFunction {
  final String name;
  final int arity;
  final int locals;
  final int maxStack;
  final Uint8List code; // function-relative addresses
  final List<(int, String)> callFixups; // (operand offset, callee name)

  /// Offset of this function's slot window in the shared frame-slot array.
  ///
  /// The window is `arity + locals` slots wide: parameters occupy 0..arity-1 and
  /// locals follow immediately after, all emitted as *absolute* slot indices.
  /// The interpreter therefore sets `slot_base` to this value and the function's
  /// `load`/`store` operands resolve directly.
  final int globalSlot;

  /// Declared call policy, or null. See `injectMarkers` in dart_source.dart.
  ///
  /// Encoded into the module so the *runtime* enforces it: a policy that only the
  /// host applied would be trivially skipped by calling the library directly, which
  /// is precisely the attack it exists to blunt.
  final String? guard;

  CompiledFunction(this.name, this.arity, this.locals, this.maxStack,
      this.code, this.callFixups, this.globalSlot, [this.guard]);
}

/// Result of compiling a whole module.
class CompiledModule {
  final List<CompiledFunction> functions;

  /// String table, insertion ordered and de-duplicated.
  final List<String> strings;

  /// Integer constant pool.
  final List<int> consts;

  const CompiledModule(this.functions, this.strings, this.consts);
}

class _LoopCtx {
  final String continueLabel;
  final String breakLabel;
  _LoopCtx(this.continueLabel, this.breakLabel);
}

class _VarInfo {
  final int slot;
  final VType type;
  _VarInfo(this.slot, this.type);
}

/// One protected source file as the compiler sees it.
///
/// Name resolution is *per file*: a bare identifier may be a local, a constant
/// declared in this file, a constant imported from another protected file, a
/// function in this file, or an imported function. Anything else is an error -
/// there are no globals to fall back on.
class FileUnit {
  final VmpModule module;

  /// Functions declared in this file, name -> global function index. Filled in
  /// by [BytecodeCompiler]'s constructor, because ids depend on the whole
  /// module's declaration order.
  final Map<String, int> functions = <String, int>{};

  /// `prefix.name` -> global function index, from `import ... as prefix;`.
  final Map<String, int> importedFunctions = <String, int>{};

  /// Constants declared in this file. Populated by `loadProtectedUnit` (or by
  /// a test helper) before compilation.
  final Map<String, ConstValue> consts = <String, ConstValue>{};

  /// Imported constants, keyed by bare name or `prefix.name`.
  final Map<String, ConstValue> importedConsts = <String, ConstValue>{};

  FileUnit(this.module);

  String get path => module.sourceName;
}

/// Names that may be called as free functions but whose *reference* is not a
/// plain function call position (kept for parity with the parser's table).

/// Compiles one or more [FileUnit]s into a single [CompiledModule].
class BytecodeCompiler {
  final List<FileUnit> units;
  final List<FuncDecl> _allFunctions = <FuncDecl>[];
  final Map<String, int> _funcIndex = <String, int>{};

  final List<String> _strings = <String>[];
  final Map<String, int> _stringIndex = <String, int>{};
  final List<int> _consts = <int>[];
  final Map<int, int> _constIndex = <int, int>{};

  /// File currently being compiled; drives name resolution.
  late FileUnit _unit;

  // Per-function state.
  late _Code _c;
  late FuncDecl _fn;
  final List<Map<String, _VarInfo>> _scopes = <Map<String, _VarInfo>>[];
  int _nextSlot = 0;
  int _slotBase = 0;
  final List<_LoopCtx> _loops = <_LoopCtx>[];
  final List<(int, String)> _calls = <(int, String)>[];

  /// [orderedFunctions] fixes the global function ids. The caller is
  /// responsible for producing a deterministic order (the CLI uses
  /// `sources` order, depth-first through imports), so ids are stable across
  /// builds and the generated stubs keep matching the shipped module.
  ///
  /// [guards] carries declared call policies, keyed by function name; see
  /// `injectMarkers` in dart_source.dart.
  final Map<String, String> guards;

  BytecodeCompiler(this.units,
      {List<FuncDecl>? orderedFunctions, Map<String, String>? guards})
      : guards = (guards == null) ? const <String, String>{} : guards {
    if (orderedFunctions != null) {      _allFunctions.addAll(orderedFunctions);
    } else {
      for (final u in units) {
        _allFunctions.addAll(u.module.functions);
      }
    }
    for (var i = 0; i < _allFunctions.length; i++) {
      _funcIndex[_allFunctions[i].name] = i;
    }
    // Resolve per-file function maps against the global order.
    for (final u in units) {
      for (final f in u.module.functions) {
        final idx = _funcIndex[f.name];
        if (idx == null) {
          throw StateError('internal: ${f.name} missing from the global order');
        }
        u.functions[f.name] = idx;
      }
    }
  }

  /// The global function order, as handed to the constructor.
  List<FuncDecl> get functions => List.unmodifiable(_allFunctions);

  int _str(String s) {
    final existing = _stringIndex[s];
    if (existing != null) return existing;
    final i = _strings.length;
    _strings.add(s);
    _stringIndex[s] = i;
    return i;
  }

  int _konst(int v) {
    final existing = _constIndex[v];
    if (existing != null) return existing;
    final i = _consts.length;
    _consts.add(v);
    _constIndex[v] = i;
    return i;
  }

  Never _err(String msg, AstNode n) =>
      throw CompileError(msg, n.line, n.col, _unit.path);

  // -------------------------------------------------------------------
  // Constant resolution
  // -------------------------------------------------------------------

  ConstValue? _lookupConst(String name) {
    final local = _unit.consts[name];
    if (local != null) return local;
    final imported = _unit.importedConsts[name];
    if (imported != null) return imported;
    return null;
  }

  // -------------------------------------------------------------------
  // Entry point
  // -------------------------------------------------------------------

  CompiledModule compile() {
    // Slot allocation is global across functions, and each function's window is
    // `arity + locals` wide: parameters live in 0..arity-1 and locals follow.
    // The interpreter relies on those operands being *absolute* indices into the
    // shared slot array, so the window has to include the argument slots - see
    // `slot_base` in dvmp_vm.c.
    final out = <CompiledFunction>[];
    /*
     * Function names are NOT interned into the module's string table.
     *
     * They used to be, on the stated grounds that "the VM resolves
     * `dartvmp_call_named` against it". That was wrong, and measurably so: name
     * lookup goes through `dvmp_module_find` -> `entry_name_eq` -> `name_byte`, which
     * reads `kDvmpNameBlob` - the *compiled-in* masked table - and never touches the
     * container. Grepping the runtime for a reader of `DvmpFuncDesc.name` finds only
     * the assignment that writes it; nothing reads it.
     *
     * The cost of that dead weight was not nothing. The container is what an attacker
     * recovers (see tool/recover_from_shipped.py), and the names travelled inside it,
     * so `tool/walk_bytecode.py` could print `fn 4 [verifyLicense]` straight out of a
     * decrypted container and hand over the whole id -> purpose map. The map already
     * exists in `libdartvmp.so` in masked form; there is no reason to ship a second,
     * unmasked copy inside the ciphertext.
     *
     * Masking them instead was considered and rejected: anything inside the container
     * is plaintext to whoever decrypts the container, so masking there is decoration.
     * Removing them is the only version of this that changes what an attacker has.
     */
    assert(out.isEmpty);
    var slotBase = 0;
    for (final u in units) {
      _unit = u;
      for (final fn in u.module.functions) {
        final cf = _compileFunction(fn, slotBase);
        out.add(cf);
        slotBase += fn.arity + cf.locals;
      }
    }
    return CompiledModule(out, _strings, _consts);
  }

  CompiledFunction _compileFunction(FuncDecl fn, int slotBase) {
    _c = _Code();
    _fn = fn;
    _slotBase = slotBase;
    _nextSlot = 0;
    _scopes
      ..clear()
      ..add(<String, _VarInfo>{});
    _loops.clear();
    _calls.clear();

    for (var i = 0; i < fn.params.length; i++) {
      final p = fn.params[i];
      if (p.name == 'this' || p.name == 'super') {
        _err("'${p.name}' is not a legal parameter name", fn.body);
      }
      // Parameters occupy the first `arity` slots of the function's window.
      _declare(p.name, p.type, fn.body, slot: i);
    }
    _nextSlot = fn.params.length;
    /*
     * Prologue: pull the incoming arguments off the eval stack into parameter
     * slots.
     *
     * Emitted in REVERSE parameter order, because each `store` pops the current
     * top of stack. Call sites push arguments left to right, so argument 0 is
     * deepest and argument `arity-1` is on top - which means the LAST `store`
     * must fill parameter 0. Emitting them in forward order silently mirrored
     * every parameter list, and two int parameters even "worked" for `add`
     * because addition is commutative.
     */
    for (var i = fn.params.length; i > 0; i--) {
      _c.imm16(Op.store, slotBase + (i - 1), pops: 1);
    }

    _stmt(fn.body);
    if (fn.returnType == VType.void_) {
      _c.noArg(Op.retVoid);
    } else if (!_isTerminal(fn.body)) {
      _err('function ${fn.name} declares return type ${fn.returnType.dartName} '
          'but control can fall off the end without a return statement',
          fn.body);
    }
    _c.finish();

    if (_c.maxStack > 255) {
      _err('expression nesting too deep in ${fn.name} '
          '(max eval stack 255, got ${_c.maxStack})', fn.body);
    }
    return CompiledFunction(fn.name, fn.arity, _nextSlot,
        _c.maxStack == 0 ? 1 : _c.maxStack, Uint8List.fromList(_c.bytes),
        List.of(_calls), slotBase, guards[fn.name]);
  }

  void _declare(String name, VType type, AstNode at, {int? slot}) {
    final scope = _scopes.last;
    if (scope.containsKey(name)) {
      _err("'$name' is already declared in this scope", at);
    }
    final s = slot ?? _nextSlot++;
    scope[name] = _VarInfo(s, type);
  }

  /// Conservative "does control never reach past this statement?" analysis.
  ///
  /// Used to decide whether a non-void function is missing a return on some
  /// path. A false positive would reject legal code, so anything this does not
  /// fully understand counts as "falls through".
  bool _isTerminal(Stmt s) {
    switch (s) {
      case ReturnStmt _:
        return true;
      case Block b:
        return b.body.isNotEmpty && _isTerminal(b.body.last);
      case IfStmt f:
        return f.otherwise != null &&
            _isTerminal(f.then) &&
            _isTerminal(f.otherwise!);
      default:
        // `while (true) {}` without a break is terminal, but proving it needs
        // real flow analysis; treat it as falling through.
        return false;
    }
  }

  _VarInfo? _lookup(String name) {
    for (var i = _scopes.length - 1; i >= 0; i--) {
      final v = _scopes[i][name];
      if (v != null) return v;
    }
    return null;
  }

  // -------------------------------------------------------------------
  // Statements
  // -------------------------------------------------------------------

  void _stmt(Stmt s) {
    switch (s) {
      case Block b:
        _scopes.add(<String, _VarInfo>{});
        for (final st in b.body) {
          _stmt(st);
        }
        _scopes.removeLast();
        return;
      case VarDecl d:
        if (d.init != null) {
          _expr(d.init!);
        } else {
          _c.noArg(Op.pushNil, pushes: 1);
        }
        _declare(d.name, d.type, d);
        _c.imm16(Op.store, _slotBase + _lookup(d.name)!.slot, pops: 1);
        return;
      case AssignStmt a:
        _assign(a);
        return;
      case ExprStmt e:
        _expr(e.expr);
        _c.noArg(Op.pop, pops: 1);
        return;
      case IfStmt f:
        _if(f);
        return;
      case WhileStmt w:
        _while(w);
        return;
      case ForStmt f:
        _for(f);
        return;
      case ForInStmt f:
        _forIn(f);
        return;
      case ReturnStmt r:
        _return(r);
        return;
      case BreakStmt b:
        if (_loops.isEmpty) {
          _err('break outside of a loop', b);
        }
        _c.jumpTo(Op.jmp, _loops.last.breakLabel);
        return;
      case ContinueStmt cont:
        if (_loops.isEmpty) {
          _err('continue outside of a loop', cont);
        }
        _c.jumpTo(Op.jmp, _loops.last.continueLabel);
        return;
      default:
        _err('internal: unhandled statement ${s.runtimeType}', s);
    }
  }

  void _assign(AssignStmt a) {
    final target = a.target;
    if (target is Ident) {
      final v = _lookup(target.name);
      if (v == null) {
        _err("assignment to undeclared variable '${target.name}'", target);
      }
      _expr(a.value);
      _c.imm16(Op.store, _slotBase + v.slot, pops: 1);
      return;
    }
    if (target is Index) {
      // `listSet` is polymorphic in the interpreter: it accepts a List (with an
      // integer index) or a Map (with any key). Lists stay immutable, so a
      // List target is rejected here rather than silently mutating.
      if (_staticType(target.target) == VType.list_) {
        _err('assignment into a List is not supported in protected code; build '
            'a new list with a loop and return it', target);
      }
      _expr(target.target);
      _expr(target.index);
      _expr(a.value);
      _host(HostFn.listSet, 3, pops: 3, pushes: 1);
      _c.noArg(Op.pop, pops: 1);
      return;
    }
    _err('invalid assignment target', target);
  }

  void _if(IfStmt f) {
    final lElse = _c.newLabel('else');
    final lEnd = _c.newLabel('endif');
    _expr(f.cond);
    _c.jumpTo(Op.jmpIfFalse, lElse);
    _stmt(f.then);
    if (f.otherwise != null) {
      _c.jumpTo(Op.jmp, lEnd);
    }
    _c.mark(lElse);
    if (f.otherwise != null) {
      _stmt(f.otherwise!);
      _c.mark(lEnd);
    }
  }

  void _while(WhileStmt w) {
    final lTop = _c.newLabel('while');
    final lEnd = _c.newLabel('endwhile');
    _c.mark(lTop);
    _expr(w.cond);
    _c.jumpTo(Op.jmpIfFalse, lEnd);
    _loops.add(_LoopCtx(lTop, lEnd));
    _stmt(w.body);
    _loops.removeLast();
    _c.jumpTo(Op.jmp, lTop);
    _c.mark(lEnd);
  }

  void _for(ForStmt f) {
    final lTop = _c.newLabel('for');
    final lNext = _c.newLabel('fornext');
    final lEnd = _c.newLabel('endfor');
    _scopes.add(<String, _VarInfo>{});
    if (f.init != null) _stmt(f.init!);
    _c.mark(lTop);
    if (f.cond != null) {
      _expr(f.cond!);
      _c.jumpTo(Op.jmpIfFalse, lEnd);
    }
    _loops.add(_LoopCtx(lNext, lEnd));
    _stmt(f.body);
    _loops.removeLast();
    _c.mark(lNext);
    if (f.update != null) _stmt(f.update!);
    _c.jumpTo(Op.jmp, lTop);
    _c.mark(lEnd);
    _scopes.removeLast();
  }

  void _forIn(ForInStmt f) {
    //   seq = iterable            (slot a)
    //   i = 0                     (slot b)
    //   n = listLen(seq)          (slot c)
    //   while (i < n) { x = seq[i]; body; i++ }
    final seqSlot = _nextSlot++;
    final idxSlot = _nextSlot++;
    final lenSlot = _nextSlot++;
    final lTop = _c.newLabel('forin');
    final lNext = _c.newLabel('forinnext');
    final lEnd = _c.newLabel('endforin');

    _scopes.add(<String, _VarInfo>{});
    _expr(f.iterable);
    _c.imm16(Op.store, _slotBase + seqSlot, pops: 1);
    _c.immI32(Op.pushI, 0, pushes: 1);
    _c.imm16(Op.store, _slotBase + idxSlot, pops: 1);
    _c.imm16(Op.load, _slotBase + seqSlot, pushes: 1);
    _host(HostFn.listLen, 1, pushes: 1);
    _c.imm16(Op.store, _slotBase + lenSlot, pops: 1);

    _c.mark(lTop);
    _c.imm16(Op.load, _slotBase + idxSlot, pushes: 1);
    _c.imm16(Op.load, _slotBase + lenSlot, pushes: 1);
    _c.noArg(Op.cmplt, pops: 2, pushes: 1);
    _c.jumpTo(Op.jmpIfFalse, lEnd);

    _c.imm16(Op.load, _slotBase + seqSlot, pushes: 1);
    _c.imm16(Op.load, _slotBase + idxSlot, pushes: 1);
    _host(HostFn.listGet, 2, pushes: 1);
    _declare(f.name, f.declType, f);
    _c.imm16(Op.store, _slotBase + _lookup(f.name)!.slot, pops: 1);

    _loops.add(_LoopCtx(lNext, lEnd));
    _stmt(f.body);
    _loops.removeLast();

    _c.mark(lNext);
    _c.imm16(Op.load, _slotBase + idxSlot, pushes: 1);
    _c.immI32(Op.pushI, 1, pushes: 1);
    _c.noArg(Op.add, pops: 2, pushes: 1);
    _c.imm16(Op.store, _slotBase + idxSlot, pops: 1);
    _c.jumpTo(Op.jmp, lTop);
    _c.mark(lEnd);
    _scopes.removeLast();
  }

  void _return(ReturnStmt r) {
    final fn = _fn;
    if (r.value == null) {
      if (fn.returnType != VType.void_) {
        _err('function ${fn.name} must return a ${fn.returnType.dartName}', r);
      }
      _c.noArg(Op.retVoid);
      return;
    }
    if (fn.returnType == VType.void_) {
      _err('void function ${fn.name} cannot return a value', r);
    }
    _expr(r.value!);
    _c.noArg(Op.ret, pops: 1);
  }

  // -------------------------------------------------------------------
  // Expressions
  // -------------------------------------------------------------------

  void _host(int fn, int argc, {int pops = 0, int pushes = 0}) {
    _c.u8(Op.host);
    _c.u16(fn);
    _c.u16(argc);
    // Fold the stack effect into the code builder's model without emitting an
    // extra byte: `_push`/`_pop` go through `noArg`'s bookkeeping only.
    _c.stackEffect(pops: pops, pushes: pushes);
  }

  void _expr(Expr e) {
    switch (e) {
      case IntLit i:
        if (i.value >= -0x80000000 && i.value <= 0x7FFFFFFF) {
          _c.immI32(Op.pushI, i.value, pushes: 1);
        } else {
          _c.imm16(Op.pushK, _konst(i.value), pushes: 1);
        }
        return;
      case StrLit s:
        _c.imm16(Op.pushS, _str(s.value), pushes: 1);
        return;
      case BoolLit b:
        _c.noArg(b.value ? Op.pushTrue : Op.pushFalse, pushes: 1);
        return;
      case NullLit _:
        _c.noArg(Op.pushNil, pushes: 1);
        return;
      case Ident id:
        final v = _lookup(id.name);
        if (v != null) {
          _c.imm16(Op.load, _slotBase + v.slot, pushes: 1);
          return;
        }
        // Compile-time constants are inlined: the name disappears from the
        // module entirely and only the value reaches the (encrypted) string or
        // constant pool.
        final k = _lookupConst(id.name);
        if (k != null) {
          _pushConst(k, id);
          return;
        }
        _err("undeclared identifier '${id.name}' "
            '(protected functions may not reference globals, imports outside '
            'the protected set, or members)', id);
      case Unary u:
        _unary(u);
        return;
      case Binary b:
        _binary(b);
        return;
      case Cond c:
        _cond(c);
        return;
      case Call c:
        _call(c);
        return;
      case BuiltinCall b:
        _builtin(b);
        return;
      case Index i:
        _index(i);
        return;
      case ListLit l:
        _c.immI32(Op.pushI, l.items.length, pushes: 1);
        _host(HostFn.listNew, 1, pushes: 1);
        for (final item in l.items) {
          _expr(item);
          _host(HostFn.listPush, 2, pushes: 1);
        }
        return;
      case MapLit m:
        _c.immI32(Op.pushI, m.entries.length, pushes: 1);
        _host(HostFn.mapNew, 1, pushes: 1);
        for (final (k, v) in m.entries) {
          _expr(k);
          _expr(v);
          _host(HostFn.mapSet, 3, pushes: 1);
        }
        return;
      default:
        _err('internal: unhandled expression ${e.runtimeType}', e);
    }
  }

  void _unary(Unary u) {
    // Fold `-<literal>` so that INT64_MIN style constants stay exact.
    final operand = u.operand;
    if (u.op == Tok.minus && operand is IntLit) {
      final v = -operand.value;
      if (v >= -0x80000000 && v <= 0x7FFFFFFF) {
        _c.immI32(Op.pushI, v, pushes: 1);
      } else {
        _c.imm16(Op.pushK, _konst(v), pushes: 1);
      }
      return;
    }
    if (u.op == Tok.bang && operand is BoolLit) {
      _c.noArg(operand.value ? Op.pushFalse : Op.pushTrue, pushes: 1);
      return;
    }
    _expr(operand);
    switch (u.op) {
      case Tok.minus:
        _c.noArg(Op.neg, pops: 1, pushes: 1);
        return;
      case Tok.tilde:
        _c.noArg(Op.bnot, pops: 1, pushes: 1);
        return;
      case Tok.bang:
        _c.noArg(Op.pushFalse, pushes: 1);
        _c.noArg(Op.cmpeq, pops: 2, pushes: 1);
        return;
      default:
        _err('internal: unhandled unary ${u.op.name}', u);
    }
  }

  static int? _foldInt(Tok op, int a, int b) {
    switch (op) {
      case Tok.plus:
        return a + b;
      case Tok.minus:
        return a - b;
      case Tok.star:
        return a * b;
      case Tok.amp:
        return a & b;
      case Tok.pipe:
        return a | b;
      case Tok.caret:
        return a ^ b;
      default:
        return null;
    }
  }

  void _binary(Binary b) {
    // Constant folding keeps the shipped string table free of arithmetic
    // structure and shrinks the instruction stream a little.
    if (b.left is IntLit && b.right is IntLit) {
      final folded = _foldInt(b.op, (b.left as IntLit).value, (b.right as IntLit).value);
      if (folded != null) {
        if (folded >= -0x80000000 && folded <= 0x7FFFFFFF) {
          _c.immI32(Op.pushI, folded, pushes: 1);
        } else {
          _c.imm16(Op.pushK, _konst(folded), pushes: 1);
        }
        return;
      }
    }

    if (b.op == Tok.andAnd || b.op == Tok.orOr) {
      final lShort = _c.newLabel('sc');
      final lEnd = _c.newLabel('scend');
      _expr(b.left);
      _c.jumpTo(b.op == Tok.andAnd ? Op.jmpIfFalse : Op.jmpIfTrue, lShort);
      _expr(b.right);
      _c.jumpTo(Op.jmp, lEnd);
      _c.mark(lShort);
      _c.noArg(b.op == Tok.andAnd ? Op.pushFalse : Op.pushTrue, pushes: 1);
      _c.mark(lEnd);
      return;
    }

    _expr(b.left);
    _expr(b.right);
    /*
     * `+` on strings goes through a host call, not the ADD opcode.
     *
     * ADD has no arena handle and therefore cannot reclaim its operands, so a
     * concatenation loop grew the arena by the *sum* of every intermediate
     * length - O(n^2) in arena usage - and tripped the budget on inputs of a few
     * dozen characters. `strConcat` receives the arena and can release the two
     * operands once the result exists, which makes the same loop O(n).
     *
     * It also returns a fresh immutable string, so `out = out + c` cannot alias
     * anything - the failure mode that a reused mutable builder produced.
     */
    if (b.op == Tok.plus &&
        (_staticType(b.left) == VType.string_ ||
            _staticType(b.right) == VType.string_)) {
      _host(HostFn.strConcat, 2, pops: 2, pushes: 1);
      return;
    }
    switch (b.op) {
      case Tok.plus:
        _c.noArg(Op.add, pops: 2, pushes: 1);
        return;
      case Tok.minus:
        _c.noArg(Op.sub, pops: 2, pushes: 1);
        return;
      case Tok.star:
        _c.noArg(Op.mul, pops: 2, pushes: 1);
        return;
      case Tok.slash:
        _c.noArg(Op.div, pops: 2, pushes: 1);
        return;
      case Tok.percent:
        _c.noArg(Op.mod, pops: 2, pushes: 1);
        return;
      case Tok.amp:
        _c.noArg(Op.band, pops: 2, pushes: 1);
        return;
      case Tok.pipe:
        _c.noArg(Op.bor, pops: 2, pushes: 1);
        return;
      case Tok.caret:
        _c.noArg(Op.bxor, pops: 2, pushes: 1);
        return;
      case Tok.shl:
        _c.noArg(Op.shl, pops: 2, pushes: 1);
        return;
      case Tok.shr:
        _c.noArg(Op.shr, pops: 2, pushes: 1);
        return;
      case Tok.lt:
        _c.noArg(Op.cmplt, pops: 2, pushes: 1);
        return;
      case Tok.le:
        _c.noArg(Op.cmple, pops: 2, pushes: 1);
        return;
      case Tok.gt:
        _c.noArg(Op.cmpgt, pops: 2, pushes: 1);
        return;
      case Tok.ge:
        _c.noArg(Op.cmpge, pops: 2, pushes: 1);
        return;
      case Tok.eq:
        _c.noArg(Op.cmpeq, pops: 2, pushes: 1);
        return;
      case Tok.ne:
        _c.noArg(Op.cmpne, pops: 2, pushes: 1);
        return;
      default:
        _err('internal: unhandled binary operator ${b.op.name}', b);
    }
  }

  void _cond(Cond c) {
    final lElse = _c.newLabel('condelse');
    final lEnd = _c.newLabel('condend');
    _expr(c.cond);
    _c.jumpTo(Op.jmpIfFalse, lElse);
    _expr(c.then);
    _c.jumpTo(Op.jmp, lEnd);
    _c.mark(lElse);
    _expr(c.otherwise);
    _c.mark(lEnd);
  }

  void _pushConst(ConstValue k, AstNode at) {
    switch (k) {
      case ConstInt i:
        if (i.value >= -0x80000000 && i.value <= 0x7FFFFFFF) {
          _c.immI32(Op.pushI, i.value, pushes: 1);
        } else {
          _c.imm16(Op.pushK, _konst(i.value), pushes: 1);
        }
        return;
      case ConstStr s:
        _c.imm16(Op.pushS, _str(s.value), pushes: 1);
        return;
      case ConstBool b:
        _c.noArg(b.value ? Op.pushTrue : Op.pushFalse, pushes: 1);
        return;
    }
  }

  void _call(Call c) {
    // Resolution order: a function declared in this file, then one imported
    // from another protected file (bare or `prefix.name`). Nothing else is
    // callable - that is what keeps the callee set closed under compilation.
    final idx = _unit.functions[c.name] ?? _unit.importedFunctions[c.name];
    if (idx == null) {
      _err("call to unknown function '${c.name}': only functions declared in "
          'the protected set (this file or one it imports) and the builtins '
          'may be called', c);
    }
    final callee = _allFunctions[idx];
    if (c.args.length != callee.arity) {
      _err('${c.name} expects ${callee.arity} argument(s) but got '
          '${c.args.length}', c);
    }
    for (final a in c.args) {
      _expr(a);
    }
    _c.u8(Op.call);
    _calls.add((_c.bytes.length, c.name));
    _c.u16(idx); // already final: the global order is fixed up front
    if (callee.returnType == VType.void_) {
      _c.noArg(Op.pushNil, pushes: 1);
    }
  }

  static const Map<String, (int, int)> _builtinSig = {
    // name: (host id, arg count)
    'strLen': (HostFn.strLen, 1),
    'strAt': (HostFn.strAt, 2),
    'strCode': (HostFn.strCode, 2),
    'strSub': (HostFn.strSub, 3),
    'strIndexOf': (HostFn.strIndexOf, 2),
    'strContains': (HostFn.strContains, 2),
    'strToUpper': (HostFn.strToUpper, 1),
    'strToLower': (HostFn.strToLower, 1),
    'strParseInt': (HostFn.strParseInt, 1),
    'intToStr': (HostFn.intToStr, 1),
    'hash': (HostFn.hash, 1),
    'abort': (HostFn.abort, 1),
    'listLen': (HostFn.listLen, 1),
    'listAt': (HostFn.listGet, 2),
    'mapGet': (HostFn.mapGet, 2),
  };

  void _builtin(BuiltinCall b) {
    final sig = _builtinSig[b.name];
    if (sig == null) {
      _err("unknown builtin '${b.name}'", b);
    }
    final (id, argc) = sig;
    if (b.args.length != argc) {
      _err('${b.name} expects $argc argument(s) but got ${b.args.length}', b);
    }
    for (final a in b.args) {
      _expr(a);
    }
    _host(id, argc, pops: argc, pushes: id == HostFn.abort ? 0 : 1);
  }

  void _index(Index i) {
    final t = _staticType(i.target);
    _expr(i.target);
    _expr(i.index);
    if (t == VType.map_) {
      _host(HostFn.mapGet, 2, pops: 2, pushes: 1);
      return;
    }
    if (t == VType.string_) {
      _host(HostFn.strAt, 2, pops: 2, pushes: 1);
      return;
    }
    _host(HostFn.listGet, 2, pops: 2, pushes: 1);
  }

  // -------------------------------------------------------------------
  // Static type inference - just enough to pick the right accessor opcode.
  // -------------------------------------------------------------------

  VType _staticType(Expr e) {
    switch (e) {
      case IntLit _:
        return VType.int_;
      case StrLit _:
        return VType.string_;
      case BoolLit _:
        return VType.bool_;
      case NullLit _:
        return VType.dynamic_;
      case ListLit _:
        return VType.list_;
      case MapLit _:
        return VType.map_;
      case Ident id:
        return _lookup(id.name)?.type ?? VType.dynamic_;
      case BuiltinCall b:
        switch (b.name) {
          case 'strLen':
          case 'strCode':
          case 'strIndexOf':
          case 'strParseInt':
          case 'intToStr':
          case 'hash':
          case 'listLen':
            return b.name == 'intToStr' ? VType.string_ : VType.int_;
          case 'strAt':
          case 'strSub':
          case 'strToUpper':
          case 'strToLower':
            return VType.string_;
          case 'strContains':
            return VType.bool_;
          default:
            return VType.dynamic_;
        }
      case Index _:
        // An index into a Map yields a dynamic value; an index into a List is
        // only known statically at the point of use, never here.
        return VType.dynamic_;
      case Binary b:
        switch (b.op) {
          case Tok.plus:
            if (_staticType(b.left) == VType.string_ ||
                _staticType(b.right) == VType.string_) {
              return VType.string_;
            }
            return VType.int_;
          case Tok.lt:
          case Tok.le:
          case Tok.gt:
          case Tok.ge:
          case Tok.eq:
          case Tok.ne:
          case Tok.andAnd:
          case Tok.orOr:
            return VType.bool_;
          default:
            return VType.int_;
        }
      case Unary u:
        return u.op == Tok.bang ? VType.bool_ : VType.int_;
      case Cond c:
        final a = _staticType(c.then);
        final bb = _staticType(c.otherwise);
        return a == bb ? a : VType.dynamic_;
      case Call c:
        final idx = _unit.functions[c.name] ?? _unit.importedFunctions[c.name];
        if (idx == null) return VType.dynamic_;
        return _allFunctions[idx].returnType;
      default:
        return VType.dynamic_;
    }
  }
}

// ---------------------------------------------------------------------------
// Disassembler (used by the CLI, the tests and the docs)
// ---------------------------------------------------------------------------

String disassemble(CompiledModule m) {
  final sb = StringBuffer();
  sb.writeln('; strings (${m.strings.length})');
  for (var i = 0; i < m.strings.length; i++) {
    sb.writeln('  s$i = ${jsonEncode(m.strings[i])}');
  }
  sb.writeln('; consts (${m.consts.length})');
  for (var i = 0; i < m.consts.length; i++) {
    sb.writeln('  k$i = ${m.consts[i]}');
  }
  for (final f in m.functions) {
    sb.writeln('');
    sb.writeln(
        'fn ${f.name}(arity=${f.arity}, locals=${f.locals}, max_stack=${f.maxStack})');
    final code = f.code;
    var pc = 0;
    while (pc < code.length) {
      final at = pc;
      final op = code[pc++];
      final name = kOpNames[op] ?? '??${op.toRadixString(16)}';
      final width = (op < kOperandBytes.length) ? kOperandBytes[op] : 0;
      var operand = '';
      if (op == Op.host && pc + 4 <= code.length) {
        final id = code[pc] | (code[pc + 1] << 8);
        final argc = code[pc + 2] | (code[pc + 3] << 8);
        operand = ' ${kHostNames[id] ?? id} argc=$argc';
      } else if (op == Op.pushS && pc + 2 <= code.length) {
        final i = code[pc] | (code[pc + 1] << 8);
        operand = ' s$i';
      } else if (op == Op.pushK && pc + 2 <= code.length) {
        final i = code[pc] | (code[pc + 1] << 8);
        operand = ' k$i';
      } else if ((op == Op.load || op == Op.store) && pc + 2 <= code.length) {
        operand = ' slot=${code[pc] | (code[pc + 1] << 8)}';
      } else if (op == Op.call && pc + 2 <= code.length) {
        final i = code[pc] | (code[pc + 1] << 8);
        final f = m.functions[i];
        operand = ' fn#$i (${f.name})';
      } else if (op == Op.pushI && pc + 4 <= code.length) {
        operand = ' ${code[pc] | (code[pc + 1] << 8) | (code[pc + 2] << 16) | (code[pc + 3] << 24)}';
      } else if ((op == Op.jmp || op == Op.jmpIfFalse || op == Op.jmpIfTrue) &&
          pc + 4 <= code.length) {
        operand = ' -> ${code[pc] | (code[pc + 1] << 8) | (code[pc + 2] << 16) | (code[pc + 3] << 24)}';
      }
      sb.writeln('  ${at.toString().padLeft(5)}: $name$operand');
      pc += width;
    }
  }
  return sb.toString();
}

/// A compiled module serialised into the container body layout.
class EncodedBody {
  /// The canonical body: metadata sections followed by the framed instruction
  /// stream. `crc32(bytes)` is the container's integrity value, and this is what
  /// the runtime reconstructs.
  final Uint8List bytes;

  /// Offset of the framed instruction-stream region inside [bytes].
  final int codeOff;

  /// Length of the framed region.
  final int codeLen;

  /// Number of exported functions.
  final int entryCount;

  /// Per-function code offsets **relative to the unframed instruction stream**.
  ///
  /// Deliberately not a body offset: the runtime re-encodes chunks on every
  /// re-seal, so an absolute offset would go stale, and the framing padding is an
  /// encoding detail the descriptors should not have to know about. The runtime
  /// maps an unframed offset to a chunk with `chunkFrameOf` (duplicated in
  /// packages/dartvmp/src/dvmp_module.c).
  final List<(int, int)> codeOffsets;

  /// Chunk size used for the framing, or 0 when there is no code.
  final int chunkSize;

  const EncodedBody(this.bytes, this.codeOff, this.codeLen, this.entryCount,
      {this.codeOffsets = const [], this.chunkSize = 0});
}

/// Maps an unframed code offset to `(chunkIndex, offsetWithinChunkData)`.
///
/// The inverse of the padded layout built by [chunkFraming]: chunk `i` starts at
/// `i * chunkSize` in unframed terms, but at `i * (8 + chunkSize) + 8` in framed
/// terms, so the two indices drift apart by the tag bytes. Everything that
/// translates between the descriptor's view and the body's view goes through
/// here, on both sides of the FFI boundary.
({int chunk, int inChunk}) chunkFrameOf(int unframedOffset, int chunkSize) =>
    (chunk: unframedOffset ~/ chunkSize, inChunk: unframedOffset % chunkSize);

/// Splits a code stream into one padded chunk per [kVmpCodeChunkSize] window.
///
/// Returns `(chunks, paddedSize)`. The rule is that **padding never splits an
/// instruction**: the chunk boundary is moved forward to the end of the
/// instruction that would otherwise straddle it. That is not cosmetic - the
/// runtime decodes each chunk independently and derives operand widths from the
/// decoded opcode, so a chunk has to start on an instruction boundary and must
/// not end mid-instruction.
///
/// A small amount of unused space is the price, and it is small precisely because
/// instructions are short (at most 5 bytes).
({List<Uint8List> chunks, int paddedSize}) chunkFraming(
    Uint8List code, int chunkSize) {
  if (chunkSize < 8) {
    throw StateError('chunk size $chunkSize is too small to hold an '
        'instruction');
  }
  final total = code.length;
  final chunks = <Uint8List>[];
  var start = 0;
  while (start < total) {
    // Walk instructions from `start` and stop at the last one that still begins
    // before the ideal boundary.
    var pc = start;
    var last = start;
    while (pc < total && pc < start + chunkSize) {
      last = pc;
      final op = code[pc];
      final width = (op < kOperandBytes.length) ? kOperandBytes[op] : 0;
      final end = pc + 1 + width;
      if (end > start + chunkSize) break;
      pc = end;
    }
    var end = (pc >= start + chunkSize) ? pc : last + 1;
    if (end <= start) {
      // A single instruction longer than the chunk: impossible with the current
      // opcode set (5 bytes max) but worth failing loudly rather than emitting a
      // stream the runtime cannot decode.
      throw StateError('instruction at +$start does not fit in a $chunkSize-byte '
          'chunk');
    }
    if (end > total) end = total;
    final chunk = Uint8List(chunkSize);
    chunk.setRange(0, end - start, code, start);
    chunks.add(chunk);
    start = end;
  }
  return (chunks: chunks, paddedSize: chunks.length * chunkSize);
}

/// Encodes a compiled module into the packed binary layout (unencrypted).
/// Kept here so `encodeBody` stays unit-testable without touching crypto.
EncodedBody encodeBody(CompiledModule m) {
  final b = BytesBuilder();
  // strings
  final strBytes = BytesBuilder();
  final offsets = <(int, int)>[];
  for (final s in m.strings) {
    final enc = utf8.encode(s);
    offsets.add((strBytes.length, enc.length));
    strBytes.add(enc);
  }
  final strBlob = strBytes.takeBytes();
  b.add(_u32(strBlob.length));
  b.add(strBlob);
  // consts
  b.add(_u32(m.consts.length));
  for (final k in m.consts) {
    b.add(_i64(k));
  }
  // string offsets
  b.add(_u32(offsets.length));
  for (final (off, len) in offsets) {
    b.add(_u32(off));
    b.add(_u32(len));
  }
  // functions
  b.add(_u32(m.functions.length));
  // Code is placed after the descriptors; compute its absolute offset first.
  // Layout so far: [u32 strLen][strBlob][u32 constCount][consts]
  //                [u32 strCount][strOffsets][u32 fnCount]
  // Then: kVmpDescSize bytes of descriptor per function, [u32 framedLen], framed
  // code. Every place that strides over descriptors has to use the same number -
  // see `kVmpDescSize` and its C twin `DVMP_DESC_SIZE`.
  final descSize = kVmpDescSize * m.functions.length;
  final codeBase = b.length + descSize + 4;
  final codeBlob = BytesBuilder();
  final codeOffsets = <(int, int)>[];
  for (final f in m.functions) {
    // Relative to the *unframed* stream, which is what the runtime's chunk
    // mapping expects. See EncodedBody.codeOffsets.
    codeOffsets.add((codeBlob.length, f.code.length));
    codeBlob.add(f.code);
  }
  final code = codeBlob.takeBytes();

  // The body holds the instruction stream *decoded*. `Packer.pack` permutes a copy
  // of it under the seed-derived salt on the way into the container, and the
  // runtime un-permutes on the way out, so the CRC over this form is what proves
  // both layers ran. Permuting here as well would double it - a bug that was hit
  // twice from opposite directions, both times surfacing as "opcode out of range"
  // on the very first open.
  final storedCode = code;

  /*
   * The descriptor's name field is written as (0, 0): an empty name at offset 0.
   *
   * The field has to stay - it is part of the fixed 32-byte record the runtime
   * strides over - but it no longer points at anything. The runtime never reads it
   * (see the note in `compile()`), so the only thing it used to do was put the
   * function names in the container for anyone who decrypted it.
   *
   * `tool/verify_descriptors.py` asserts the name fields are zero, and
   * `tool/walk_bytecode.py` prints `[name_len=0]` where it used to print
   * `[verifyLicense]` - both so that a regression here is visible rather than merely
   * absent.
   */
  final nameOffsets = <(int, int)>[
    for (final _ in m.functions) (0, 0)
  ];

  // Built separately so the stride can be asserted against what was written,
  // rather than inferred later from a total that two different mistakes can
  // produce.
  final desc = BytesBuilder();
  for (var i = 0; i < m.functions.length; i++) {
    final f = m.functions[i];
    final (no, nl) = nameOffsets[i];
    desc.add(_u32(no));
    desc.add(_u32(nl));
    /*
     * Call policy, written as `mode:u8 | budget:u8 | window_ms:u16le`.
     *
     * A packed byte-pair was tried first - four bits of budget and four of a
     * window *exponent* - and it could not express the first policy anyone wanted
     * (64 calls per 2 s), while silently rounding requested windows up to powers
     * of two. A budget is a count and a window is a duration; four more bytes in
     * the record buys the ability to say what you mean.
     *
     * The order here is not cosmetic: Dart evaluates positional arguments left to
     * right, so the policy has to be added in the same order the runtime reads it.
     * A version that emitted it after `locals` put it at 16 and 17 instead, and the
     * runtime then read the field as a guard mode - the kind of cross-language
     * field-order bug that produces a plausible-looking module carrying a silently
     * wrong policy.
     *
     * An unrecognised spec is a build error, not a dropped directive: a policy that
     * silently fails to ship is worse than no policy, because it reads like one in
     * the source.
     */
    var guardMode = 0;
    var guardBudget = 0;
    var guardWindow = 0;
    if (f.guard != null) {
      guardMode = _guardMode(f.name, f.guard!);
      if (guardMode == 1) {
        final rm = RegExp(r'^rate=(\d+)/(\d+)$').firstMatch(f.guard!)!;
        guardBudget = int.parse(rm.group(1)!);
        guardWindow = int.parse(rm.group(2)!);
        if (guardBudget < 1 || guardBudget > 65535) {
          throw StateError('function ${f.name}: guard budget $guardBudget is out '
              'of range 1..65535 (it travels in a u16)');
        }
        if (guardWindow < 1 || guardWindow > 65535) {
          throw StateError('function ${f.name}: guard window $guardWindow ms is '
              'out of range 1..65535');
        }
      }
    }
    /*
     * Written strictly in `DVMP_DESC_OFF_*` order, with no packing and no field
     * sharing, so the C table in dvmp_wire.h can be read as a transcription of
     * this block. The two reserved bytes are written as zero and asserted zero by
     * the runtime: a field moving then fails loudly at the first open instead of
     * producing a module that runs with someone else's `locals`.
     */
    desc.add(_u8(guardMode)); // [8]  guard_mode
    desc.add(_u8(0)); // [9]  reserved
    desc.add(_u16(guardBudget)); // [10] guard_budget
    desc.add(_u16(guardWindow)); // [12] guard_window_ms
    desc.add(_u16(f.arity)); // [14] arity
    desc.add(_u16(f.locals)); // [16] locals
    desc.add(_u16(f.maxStack)); // [18] max_stack
    // Slot window base. The runtime assigns a frame per call, so this offset has
    // to be carried in the descriptor rather than recomputed by summing the
    // preceding functions' sizes (which would be wrong for recursive calls).
    desc.add(_u16(f.globalSlot)); // [20] slot_base
    desc.add(_u16(0)); // [22] reserved2
    final (co, cl) = codeOffsets[i];
    desc.add(_u32(cl)); // [24] code_len
    desc.add(_u32(codeBase + co)); // [28] code_off
  }
  /*
   * The stride assertion, stated where it can only mean one thing.
   *
   * `kVmpDescSize` is the record size the runtime parser and the container
   * contract assume. If the loop above writes a different number of bytes per
   * function, that is the bug, and this says so. Without it the symptom is the
   * `code base mismatch` below, which reports two totals and leaves the reader to
   * work out which of the two was wrong.
   */
  {
    final descBytes = desc.takeBytes();
    final expected = kVmpDescSize * m.functions.length;
    if (descBytes.length != expected) {
      throw StateError('descriptor stride mismatch: wrote ${descBytes.length} '
          'bytes for ${m.functions.length} function(s), but kVmpDescSize = '
          '$kVmpDescSize implies $expected. The runtime strides descriptors by '
          'DVMP_DESC_SIZE, so the two must agree.');
    }
    b.add(descBytes);
  }
  if (codeBase != b.length + 4) {
    throw StateError('internal: code base mismatch '
        '($codeBase vs ${b.length + 4})');
  }
  b.add(_u32(storedCode.length));
  b.add(storedCode);

  // Nothing here needs the function names to be in the string table any more. The old
  // assertion here ("every function name must live in the string table - the VM
  // resolves dartvmp_call_named against it") asserted a requirement that did not
  // exist: the VM resolves names from the compiled-in masked table, never from the
  // container, and the assertion's only effect was to keep the names in the ciphertext.
  return EncodedBody(b.takeBytes(), codeBase, storedCode.length,
      m.functions.length,
      codeOffsets: codeOffsets);
}

/// Keystream seed for instruction-stream chunk [i].
///
/// A constant derivation, deliberately not the module seed or a session key.
/// `chunk_seed_of` in packages/dartvmp/src/dvmp_module.c mirrors it; two earlier
/// revisions keyed this on state that the two sides disagreed about, and every
/// chunk then failed to decode. The chunk layer adds no confidentiality anyway -
/// the container cipher already covers the whole body under a per-build seed - it
/// exists so the instruction stream can be re-encoded in place one piece at a
/// time.
int chunkSeedOf(int i) => _mix64(0x5E1C0DE5A17B3F42, i);

/// SplitMix64 finaliser. Mirrors `mask_word` in dvmp_module.c and
/// `imageMaskWord` in c_emitter.dart.
///
/// Duplicated rather than imported: c_emitter.dart already imports this file, so
/// importing it back would be a cycle. `image_contract_test.dart` pins the two
/// implementations against each other.
///
/// `>>>` is required, not stylistic - see [applyChunkKeystream].
int _mix64(int key, int index) {
  var z = (key + index + 0x9E3779B97F4A7C15) & 0xFFFFFFFFFFFFFFFF;
  z = ((z ^ (z >>> 30)) * 0xBF58476D1CE4E5B9) & 0xFFFFFFFFFFFFFFFF;
  z = ((z ^ (z >>> 27)) * 0x94D049BB133111EB) & 0xFFFFFFFFFFFFFFFF;
  return (z ^ (z >>> 31)) & 0xFFFFFFFFFFFFFFFF;
}

/*
 * Call-policy modes, mirroring DVMP_GUARD_* in packages/dartvmp/src/dvmp_wire.h.
 *
 * `once` and `rate=BUDGET/WINDOW_MS`. The mode, the budget and the window are
 * three separate fields in the descriptor at fixed offsets - see the
 * `DVMP_DESC_OFF_*` table in dvmp_wire.h, which this file writes in order. There
 * is no packing and no shared byte: the first version split one byte into a 4-bit
 * budget and a 4-bit window exponent, which could not express the first policy
 * anyone actually wanted and silently rounded requested windows to powers of two.
 */
/// Bytes per function descriptor. Mirrors `DVMP_DESC_SIZE` in dvmp_wire.h.
///
/// 32 = name_off/name_len (8) + guard_mode (1) + reserved (1) + guard_budget (2) +
/// guard_window_ms (2) + arity/locals/max_stack/slot_base (8) + reserved2 (2) +
/// code_len/code_off (8). It is named rather than written as a literal because a
/// mismatch between the generator's layout computation and the runtime's stride
/// surfaces as an opaque "code base mismatch", which is what happened when it went
/// from 24 to 26 - and the two reserved fields now make the same class of mistake
/// fail loudly at the first open instead.
const int kVmpDescSize = 32;

int _guardMode(String fn, String spec) {
  if (spec == 'once') return 2;
  final m = RegExp(r'^rate=(\d+)/(\d+)$').firstMatch(spec);
  if (m == null) {
    throw StateError('function $fn has an unrecognised guard "$spec"; expected '
        '"once" or "rate=N/MS"');
  }
  return 1;
}

Uint8List _u8(int v) => Uint8List.fromList([v & 0xFF]);

int cbAbs(int base, int rel) => base + rel;

Uint8List _u16(int v) => Uint8List.fromList([v & 0xFF, (v >> 8) & 0xFF]);

Uint8List _u32(int v) => Uint8List.fromList(
    [v & 0xFF, (v >> 8) & 0xFF, (v >> 16) & 0xFF, (v >> 24) & 0xFF]);

Uint8List _i64(int v) {
  final out = Uint8List(8);
  var x = v;
  for (var i = 0; i < 8; i++) {
    out[i] = x & 0xFF;
    x >>= 8;
  }
  return out;
}
