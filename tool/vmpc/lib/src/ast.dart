/// AST for the DartVMP restricted-Dart subset.
///
/// Kept deliberately small: every node here has a 1:1 lowering into the
/// private instruction set. Nodes that would need closures, generators or a
/// full object model are simply absent, which is what makes the
/// "compiler + interpreter" pair small enough to audit.
library;

import 'lexer.dart' show Tok;

/// Type tags understood by the front end. Only used for validation and
/// diagnostics - the VM is dynamically typed over 64-bit slots.
enum VType { int_, string_, bool_, void_, list_, map_, dynamic_ }

extension VTypeName on VType {
  String get dartName => switch (this) {
        VType.int_ => 'int',
        VType.string_ => 'String',
        VType.bool_ => 'bool',
        VType.void_ => 'void',
        VType.list_ => 'List',
        VType.map_ => 'Map',
        VType.dynamic_ => 'dynamic',
      };
}

class AstNode {
  final int line;
  final int col;
  const AstNode(this.line, this.col);
}

// ---------------------------------------------------------------------------
// Expressions
// ---------------------------------------------------------------------------

abstract class Expr extends AstNode {
  const Expr(super.line, super.col);
}

class IntLit extends Expr {
  final int value;
  const IntLit(this.value, super.line, super.col);
}

class StrLit extends Expr {
  final String value;
  const StrLit(this.value, super.line, super.col);
}

class BoolLit extends Expr {
  final bool value;
  const BoolLit(this.value, super.line, super.col);
}

class NullLit extends Expr {
  const NullLit(super.line, super.col);
}

/// `[a, b, c]`
class ListLit extends Expr {
  final List<Expr> items;
  const ListLit(this.items, super.line, super.col);
}

/// `{'a': 1, 'b': 2}`
class MapLit extends Expr {
  final List<(Expr, Expr)> entries;
  const MapLit(this.entries, super.line, super.col);
}

/// A reference to a local variable, parameter, or a top-level function name.
class Ident extends Expr {
  final String name;
  const Ident(this.name, super.line, super.col);
}

class Unary extends Expr {
  final Tok op;
  final Expr operand;
  const Unary(this.op, this.operand, super.line, super.col);
}

class Binary extends Expr {
  final Tok op;
  final Expr left;
  final Expr right;
  const Binary(this.op, this.left, this.right, super.line, super.col);
}

/// `cond ? a : b`
class Cond extends Expr {
  final Expr cond;
  final Expr then;
  final Expr otherwise;
  const Cond(this.cond, this.then, this.otherwise, super.line, super.col);
}

/// `name(args...)`, `obj.name(args...)`, `obj[idx]`
class Call extends Expr {
  /// Null for a free call `f(x)`.
  final Expr? target;
  final String name;
  final List<Expr> args;
  const Call(this.target, this.name, this.args, super.line, super.col);
}

/// `name(args)` where `name` is a `List`/`Map`/`String` builtin.
class BuiltinCall extends Expr {
  final String name;
  final List<Expr> args;
  const BuiltinCall(this.name, this.args, super.line, super.col);
}

/// `x = expr` in expression position is NOT supported; assignment is a
/// statement. This node only appears inside [AssignStmt].
class Index extends Expr {
  final Expr target;
  final Expr index;
  const Index(this.target, this.index, super.line, super.col);
}

// ---------------------------------------------------------------------------
// Statements
// ---------------------------------------------------------------------------

abstract class Stmt extends AstNode {
  const Stmt(super.line, super.col);
}

class Block extends Stmt {
  final List<Stmt> body;
  const Block(this.body, super.line, super.col);
}

/// `int x = 1;` / `var x = 1;` / `String s = 'a';`
class VarDecl extends Stmt {
  final VType type;
  final String name;
  final Expr? init;
  const VarDecl(this.type, this.name, this.init, super.line, super.col);
}

/// `x = expr;` or `x[i] = expr;` or `x.f = expr;`
class AssignStmt extends Stmt {
  final Expr target;
  final Expr value;
  const AssignStmt(this.target, this.value, super.line, super.col);
}

/// `expr;` (only calls and increments are meaningful, but any expr is legal)
class ExprStmt extends Stmt {
  final Expr expr;
  const ExprStmt(this.expr, super.line, super.col);
}

class IfStmt extends Stmt {
  final Expr cond;
  final Stmt then;
  final Stmt? otherwise;
  const IfStmt(this.cond, this.then, this.otherwise, super.line, super.col);
}

class WhileStmt extends Stmt {
  final Expr cond;
  final Stmt body;
  const WhileStmt(this.cond, this.body, super.line, super.col);
}

/// `for (init; cond; update) body`, any of the three may be null.
class ForStmt extends Stmt {
  final Stmt? init;
  final Expr? cond;
  final Stmt? update;
  final Stmt body;
  const ForStmt(this.init, this.cond, this.update, this.body, super.line,
      super.col);
}

/// `for (var x in xs) body` - list iteration only.
class ForInStmt extends Stmt {
  final VType declType;
  final String name;
  final Expr iterable;
  final Stmt body;
  const ForInStmt(this.declType, this.name, this.iterable, this.body,
      super.line, super.col);
}

class ReturnStmt extends Stmt {
  final Expr? value;
  const ReturnStmt(this.value, super.line, super.col);
}

class BreakStmt extends Stmt {
  const BreakStmt(super.line, super.col);
}

class ContinueStmt extends Stmt {
  const ContinueStmt(super.line, super.col);
}

// ---------------------------------------------------------------------------
// Top level
// ---------------------------------------------------------------------------

class Param {
  final VType type;
  final String name;
  const Param(this.type, this.name);
}

/// `import 'licensing.dart';`
///
/// Only used by the compiler to resolve cross-file references; it never
/// reaches the application, because the protected source itself never does.
/// Paths are resolved relative to the importing file.
class ImportDecl {
  final String uri;
  final String? prefix;
  final int line;
  const ImportDecl(this.uri, this.prefix, this.line);
}

/// `const String kSalt = 'x';`
///
/// Held in the compiler's constant environment and inlined at every use site,
/// so the name disappears from the module and the value lands in the (encrypted)
/// string table instead.
class ConstDecl {
  final VType type;
  final String name;
  final Expr value;
  final int line;
  const ConstDecl(this.type, this.name, this.value, this.line);
}

class FuncDecl {
  final VType returnType;
  final String name;
  final List<Param> params;
  final Block body;
  final int line;
  final int col;

  /// Name of the source file this function was extracted from, for the
  /// generated stub's doc comment.
  final String sourceName;

  const FuncDecl(this.returnType, this.name, this.params, this.body, this.line,
      this.col, this.sourceName);

  int get arity => params.length;
}

class VmpModule {
  final List<FuncDecl> functions;
  final String sourceName;
  final Map<String, String> metadata;

  /// Declarations that are not exported but that the compiler needs.
  final List<ImportDecl> imports;
  final List<ConstDecl> consts;

  /// Functions declared without a `@vmp` marker. They stay in the application
  /// source; the compiler reports them so an accidentally unmarked function is
  /// visible rather than silently unprotected.
  final List<FuncDecl> unmarked;

  const VmpModule(
    this.functions,
    this.sourceName,
    this.metadata, {
    this.imports = const [],
    this.consts = const [],
    this.unmarked = const [],
  });
}
