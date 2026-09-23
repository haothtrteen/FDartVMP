/// Compile-time constant evaluation for the protected-source subset.
///
/// A protected file may declare `const` values. They are folded here and
/// inlined at every use site, so a constant's *name* never reaches the module
/// and its *value* lands in the encrypted string or integer pool instead.
///
/// Only scalars and operations on scalars are allowed: a `const List` would
/// need a runtime allocation and an arena slot, which is the opposite of what a
/// constant is for.
library;

import 'ast.dart';
import 'lexer.dart' show Tok;

/// A compile-time constant value.
sealed class ConstValue {
  const ConstValue();
}

class ConstInt extends ConstValue {
  final int value;
  const ConstInt(this.value);
}

class ConstStr extends ConstValue {
  final String value;
  const ConstStr(this.value);
}

class ConstBool extends ConstValue {
  final bool value;
  const ConstBool(this.value);
}

/// Folds [e] using [local] (constants declared in the same file) and
/// [imported] (`prefix.name` and bare names from imported protected files).
///
/// Returns null when the expression is not a compile-time constant; the caller
/// decides whether that is an error (a `const` declaration) or simply means the
/// expression must be emitted as runtime code.
ConstValue? evalConstExpr(
  Expr e,
  Map<String, ConstValue> local,
  Map<String, ConstValue> imported,
) {
  ConstValue? ev(Expr e) {
    if (e is IntLit) return ConstInt(e.value);
    if (e is StrLit) return ConstStr(e.value);
    if (e is BoolLit) return ConstBool(e.value);
    if (e is Ident) return local[e.name] ?? imported[e.name];
    if (e is Unary) {
      final v = ev(e.operand);
      switch (e.op) {
        case Tok.minus:
          if (v is ConstInt) return ConstInt(-v.value);
          return null;
        case Tok.tilde:
          if (v is ConstInt) return ConstInt(~v.value);
          return null;
        case Tok.bang:
          if (v is ConstBool) return ConstBool(!v.value);
          return null;
        default:
          return null;
      }
    }
    if (e is Binary) {
      final a = ev(e.left);
      final b = ev(e.right);
      if (a is ConstStr && b is ConstStr && e.op == Tok.plus) {
        return ConstStr(a.value + b.value);
      }
      if (a is ConstInt && b is ConstInt) {
        switch (e.op) {
          case Tok.plus:
            return ConstInt(a.value + b.value);
          case Tok.minus:
            return ConstInt(a.value - b.value);
          case Tok.star:
            return ConstInt(a.value * b.value);
          case Tok.amp:
            return ConstInt(a.value & b.value);
          case Tok.pipe:
            return ConstInt(a.value | b.value);
          case Tok.caret:
            return ConstInt(a.value ^ b.value);
          case Tok.shl:
            return ConstInt(a.value << (b.value & 63));
          case Tok.shr:
            return ConstInt(a.value >> (b.value & 63));
          default:
            return null;
        }
      }
      return null;
    }
    if (e is Cond) {
      final c = ev(e.cond);
      if (c is ConstBool) return ev(c.value ? e.then : e.otherwise);
      return null;
    }
    return null;
  }

  return ev(e);
}
