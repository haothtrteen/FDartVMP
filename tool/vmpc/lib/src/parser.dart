/// Recursive-descent parser for the restricted-Dart subset.
///
/// Only constructs that lower cheaply onto the private instruction set are
/// accepted. Everything else raises [ParseError] with a precise location so
/// that a developer running `dart run vmpc build` gets an actionable message
/// instead of a silently empty protected function.
library;

import 'ast.dart';
import 'lexer.dart';

class ParseError implements Exception {
  final String message;
  final int line;
  final int col;
  final String sourceName;
  ParseError(this.message, this.line, this.col, this.sourceName);

  @override
  String toString() => '$sourceName:$line:$col: $message';
}

/// Names that may be called as free functions. Everything here is provided by
/// the native runtime's host table, so it never appears as Dart code in the
/// final application binary.
const Set<String> kKnownBuiltins = {
  'strLen', 'strAt', 'strSub', 'strCode', 'strIndexOf', 'strContains',
  'strToUpper', 'strToLower', 'strParseInt', 'intToStr', 'hash', 'abort',
  'listLen', 'listAt', 'mapGet',
};

/// Marker used to opt a function into protection when annotations are not
/// used: `// @vmp`.
const String kVmpCommentMarker = '@vmp';

class Parser {
  final List<Token> toks;
  final String sourceName;
  int _p = 0;
  final Map<String, String> metadata = {};

  /// Set while parsing a position that can accept `x++` / `x--`.
  bool _postfixIncDecAllowed = false;

  /// Committed by the caller when [_parsePostfix] consumed a postfix increment.
  Stmt? _pendingIncDec;

  /// Parses [body] with postfix `++`/`--` accepted, returning the mutation if the
  /// body consumed one.
  ///
  /// The token position is saved and restored, so the body can probe speculatively
  /// and the caller can then re-parse the same text as an ordinary expression
  /// (which is how `x[i]++` and `x[i] = ...` are told apart).
  Stmt? _withIncDec(bool Function() body) {
    final savedAllowed = _postfixIncDecAllowed;
    final savedPending = _pendingIncDec;
    final savedPos = _p;
    _postfixIncDecAllowed = true;
    _pendingIncDec = null;
    body();
    final result = _pendingIncDec;
    _postfixIncDecAllowed = savedAllowed;
    _pendingIncDec = savedPending;
    if (result == null) _p = savedPos;
    return result;
  }

  Parser(this.toks, {required this.sourceName});

  factory Parser.fromSource(String src, {required String sourceName}) =>
      Parser(Lexer(src, sourceName: sourceName).tokenize(),
          sourceName: sourceName);

  Token get _cur => toks[_p];

  Never _fail(String msg, [Token? at]) {
    final t = at ?? _cur;
    throw ParseError(msg, t.line, t.col, sourceName);
  }

  bool _accept(Tok k) {
    if (_cur.kind == k) {
      _p++;
      return true;
    }
    return false;
  }

  Token _expect(Tok k, String what) {
    if (_cur.kind != k) {
      _fail('expected $what but found ${_describe(_cur)}');
    }
    final t = _cur;
    _p++;
    return t;
  }

  static String _describe(Token t) =>
      t.kind == Tok.eof ? 'end of input' : "'${t.text}'";

  // -------------------------------------------------------------------
  // Top level
  // -------------------------------------------------------------------

  /// Parses a whole protected-source file.
  ///
  /// A function is *exported* when it is preceded by either `@vmp` or a
  /// `// @vmp` line comment. Non-exported declarations are still parsed and
  /// reported through [VmpModule.unmarked], so a forgotten marker is visible
  /// instead of silently leaving a function unprotected.
  VmpModule parseModule() {
    final fns = <FuncDecl>[];
    final unmarked = <FuncDecl>[];
    final imports = <ImportDecl>[];
    final consts = <ConstDecl>[];
    while (_cur.kind != Tok.eof) {
      var marked = false;
      // Leading annotations / marker comments.
      while (_cur.kind == Tok.at) {
        _p++;
        final name = _expect(Tok.ident, 'annotation name').text;
        if (name == 'vmp' || name == 'protect') {
          marked = true;
        } else {
          _fail('unknown annotation @$name (only @vmp / @protect are known)');
        }
        if (_accept(Tok.lparen)) {
          _fail('parameterised annotations are not supported');
        }
      }
      if (_cur.kind == Tok.eof) break;

      final isImport = _cur.kind == Tok.ident && _cur.text == 'import';
      if (isImport || _cur.kind == Tok.const_) {
        if (marked) {
          _fail('an @vmp marker must be followed by a function declaration');
        }
        if (isImport) {
          imports.add(_parseImport());
        } else {
          consts.add(_parseConst());
        }
        continue;
      }

      final decl = _parseFunction();
      if (marked) {
        fns.add(decl);
      } else {
        unmarked.add(decl);
        metadata['unmarked:${decl.name}'] = '${decl.sourceName}:${decl.line}';
      }
    }
    if (fns.isEmpty) {
      _fail('no protected functions found in $sourceName: annotate at least '
          'one top-level function with @vmp or a leading "// @vmp" comment');
    }
    return VmpModule(fns, sourceName, metadata,
        imports: imports, consts: consts, unmarked: unmarked);
  }

  ImportDecl _parseImport() {
    final t = _cur;
    _p++; // 'import'
    final uriTok = _expect(Tok.strLit, 'an import URI string');
    String? prefix;
    if (_cur.kind == Tok.ident && _cur.text == 'as') {
      _p++;
      prefix = _expect(Tok.ident, 'an import prefix').text;
    }
    _expect(Tok.semi, "';'");
    return ImportDecl(uriTok.strValue!, prefix, t.line);
  }

  ConstDecl _parseConst() {
    final t = _cur;
    _p++; // 'const'
    final type = _parseType(allowVoid: false);
    final name = _expect(Tok.ident, 'constant name');
    _expect(Tok.assign, "'='");
    final value = _parseExpr();
    _expect(Tok.semi, "';'");
    return ConstDecl(type, name.text, value, t.line);
  }

  FuncDecl _parseFunction() {
    final start = _cur;
    final rt = _parseType(allowVoid: true);
    final nameTok = _expect(Tok.ident, 'function name');
    _expect(Tok.lparen, "'('");
    final params = <Param>[];
    if (!_accept(Tok.rparen)) {
      while (true) {
        final pt = _parseType(allowVoid: false);
        final pn = _expect(Tok.ident, 'parameter name');
        params.add(Param(pt, pn.text));
        if (_accept(Tok.comma)) continue;
        _expect(Tok.rparen, "')' or ','");
        break;
      }
    }
    final body = _parseBlock();
    return FuncDecl(rt, nameTok.text, params, body, start.line, start.col,
        sourceName);
  }

  VType _parseType({required bool allowVoid}) {
    final t = _cur;
    switch (t.kind) {
      case Tok.int_:
      case Tok.string_:
      case Tok.bool_:
      case Tok.void_:
      case Tok.list_:
      case Tok.map_:
        _p++;
        final base = switch (t.kind) {
          Tok.int_ => VType.int_,
          Tok.string_ => VType.string_,
          Tok.bool_ => VType.bool_,
          Tok.void_ => VType.void_,
          Tok.list_ => VType.list_,
          Tok.map_ => VType.map_,
          _ => VType.dynamic_,
        };
        if (base == VType.void_ && !allowVoid) {
          _fail('void is not a valid parameter or variable type', t);
        }
        // Reject generics loudly: `List<int>` would need runtime type args.
        if (_cur.kind == Tok.lt) {
          _fail('generic type arguments are not supported in protected code '
              '(use plain List / Map)', _cur);
        }
        return base;
      case Tok.ident:
        if (t.text == 'dynamic') {
          _p++;
          return VType.dynamic_;
        }
        _fail("unsupported type '${t.text}': protected functions may only use "
            'int, String, bool, List, Map, dynamic', t);
      default:
        _fail('expected a type but found ${_describe(t)}', t);
    }
  }

  // -------------------------------------------------------------------
  // Statements
  // -------------------------------------------------------------------

  Block _parseBlock() {
    final open = _expect(Tok.lbrace, "'{'");
    final body = <Stmt>[];
    while (_cur.kind != Tok.rbrace) {
      if (_cur.kind == Tok.eof) {
        _fail('unterminated block (opened at line ${open.line})');
      }
      body.add(_parseStatement());
    }
    _p++; // rbrace
    return Block(body, open.line, open.col);
  }

  Stmt _parseStatement() {
    final t = _cur;
    switch (t.kind) {
      case Tok.lbrace:
        return _parseBlock();
      case Tok.if_:
        return _parseIf();
      case Tok.while_:
        return _parseWhile();
      case Tok.for_:
        return _parseFor();
      case Tok.return_: {
        _p++;
        Expr? v;
        if (_cur.kind != Tok.semi) v = _parseExpr();
        _expect(Tok.semi, "';'");
        return ReturnStmt(v, t.line, t.col);
      }
      case Tok.break_: {
        _p++;
        _expect(Tok.semi, "';'");
        return BreakStmt(t.line, t.col);
      }
      case Tok.continue_: {
        _p++;
        _expect(Tok.semi, "';'");
        return ContinueStmt(t.line, t.col);
      }
      case Tok.int_:
      case Tok.string_:
      case Tok.bool_:
      case Tok.list_:
      case Tok.map_:
      case Tok.var_: {
        // Could still be `var` (declaration) - these type keywords can never
        // start an expression in this subset.
        if (t.kind == Tok.var_) {
          _p++;
          final name = _expect(Tok.ident, 'variable name');
          Expr? init;
          if (_accept(Tok.assign)) init = _parseExpr();
          _expect(Tok.semi, "';'");
          return VarDecl(VType.dynamic_, name.text, init, t.line, t.col);
        }
        final type = _parseType(allowVoid: false);
        final name = _expect(Tok.ident, 'variable name');
        Expr? init;
        if (_accept(Tok.assign)) init = _parseExpr();
        _expect(Tok.semi, "';'");
        return VarDecl(type, name.text, init, t.line, t.col);
      }
      case Tok.semi:
        _p++;
        return Block(const [], t.line, t.col);
      default:
        break;
    }

    // Expression statement, an assignment, a compound assignment, or `x++`.
    //
    // `x++` is probed first (with the token position restored if it does not
    // match) because it is a mutation and cannot be expressed as an ExprStmt.
    final incDec = _withIncDec(() {
      _parsePostfix();
      return true;
    });
    if (incDec != null) {
      _expect(Tok.semi, "';'");
      return incDec;
    }

    final e = _parsePostfix();
    final compound = _compoundOpToken(_cur.kind);
    if (compound != null) {
      final opTok = _cur;
      _p++;
      final v = _parseExpr();
      _expect(Tok.semi, "';'");
      if (e is! Ident && e is! Index) {
        _fail('invalid compound assignment target', opTok);
      }
      // Lowered to `target = target <op> value`. The read of `target` is
      // duplicated, which is harmless because protected functions are pure and
      // single-threaded.
      return AssignStmt(e, Binary(compound, e, v, opTok.line, opTok.col), t.line,
          t.col);
    }
    if (_accept(Tok.assign)) {
      final v = _parseExpr();
      _expect(Tok.semi, "';'");
      if (e is! Ident && e is! Index) {
        _fail('invalid assignment target', t);
      }
      return AssignStmt(e, v, t.line, t.col);
    }
    _expect(Tok.semi, "';'");
    return ExprStmt(e, t.line, t.col);
  }

  /// Maps a compound-assignment token onto the binary operator it stands for,
  /// or null when [k] does not start one.
  Tok? _compoundOpToken(Tok k) {
    switch (k) {
      case Tok.plusEq:
        return Tok.plus;
      case Tok.minusEq:
        return Tok.minus;
      case Tok.starEq:
        return Tok.star;
      case Tok.slashEq:
        return Tok.slash;
      case Tok.percentEq:
        return Tok.percent;
      case Tok.ampEq:
        return Tok.amp;
      case Tok.pipeEq:
        return Tok.pipe;
      case Tok.caretEq:
        return Tok.caret;
      case Tok.shlEq:
        return Tok.shl;
      case Tok.shrEq:
        return Tok.shr;
      default:
        return null;
    }
  }

  Stmt _parseIf() {
    final t = _expect(Tok.if_, "'if'");
    _expect(Tok.lparen, "'('");
    final cond = _parseExpr();
    _expect(Tok.rparen, "')'");
    final then = _parseStatement();
    Stmt? otherwise;
    if (_accept(Tok.else_)) otherwise = _parseStatement();
    return IfStmt(cond, then, otherwise, t.line, t.col);
  }

  Stmt _parseWhile() {
    final t = _expect(Tok.while_, "'while'");
    _expect(Tok.lparen, "'('");
    final cond = _parseExpr();
    _expect(Tok.rparen, "')'");
    final body = _parseStatement();
    return WhileStmt(cond, body, t.line, t.col);
  }

  Stmt _parseFor() {
    final t = _expect(Tok.for_, "'for'");
    _expect(Tok.lparen, "'('");

    // `for (var x in xs)` / `for (int x in xs)` - list iteration only.
    {
      final save = _p;
      VType? declType;
      String? declName;
      final a = _cur;
      if (a.kind == Tok.var_) {
        _p++;
        declType = VType.dynamic_;
      } else if (a.kind == Tok.int_ ||
          a.kind == Tok.string_ ||
          a.kind == Tok.bool_ ||
          a.kind == Tok.list_ ||
          a.kind == Tok.map_) {
        declType = _parseType(allowVoid: false);
      }
      if (declType != null && _cur.kind == Tok.ident) {
        declName = _cur.text;
        _p++;
        if (_cur.kind == Tok.in_) {
          _p++;
          final iterable = _parseExpr();
          _expect(Tok.rparen, "')'");
          final body = _parseStatement();
          return ForInStmt(declType, declName, iterable, body, t.line, t.col);
        }
      }
      _p = save;
    }

    Stmt? init;
    if (_cur.kind != Tok.semi) {
      init = _parseSimpleDeclOrExpr();
    }
    _expect(Tok.semi, "';'");
    Expr? cond;
    if (_cur.kind != Tok.semi) cond = _parseExpr();
    _expect(Tok.semi, "';'");
    Stmt? update;
    if (_cur.kind != Tok.rparen) {
      // The update clause uses statement grammar (minus the semicolon) so that
      // `i++` is accepted as the mutation it is.
      update = _withIncDec(() {
        _parsePostfix();
        return true;
      });
      if (update == null) {
        final u = _parseExpr();
        update = ExprStmt(u, u.line, u.col);
      }
    }
    _expect(Tok.rparen, "')'");
    final body = _parseStatement();
    return ForStmt(init, cond, update, body, t.line, t.col);
  }

  Stmt _parseSimpleDeclOrExpr() {
    final t = _cur;
    if (t.kind == Tok.var_) {
      _p++;
      final name = _expect(Tok.ident, 'variable name');
      Expr? init;
      if (_accept(Tok.assign)) init = _parseExpr();
      return VarDecl(VType.dynamic_, name.text, init, t.line, t.col);
    }
    if (t.kind == Tok.int_ ||
        t.kind == Tok.string_ ||
        t.kind == Tok.bool_ ||
        t.kind == Tok.list_ ||
        t.kind == Tok.map_) {
      final type = _parseType(allowVoid: false);
      final name = _expect(Tok.ident, 'variable name');
      Expr? init;
      if (_accept(Tok.assign)) init = _parseExpr();
      return VarDecl(type, name.text, init, t.line, t.col);
    }
    // The C-style for-loop init/update clauses use the same grammar as a
    // statement, minus the trailing semicolon - so `i++` is allowed here too.
    final incDec = _withIncDec(() {
      _parsePostfix();
      return true;
    });
    if (incDec != null) return incDec;

    final e = _parsePostfix();
    final compound = _compoundOpToken(_cur.kind);
    if (compound != null) {
      final opTok = _cur;
      _p++;
      final v = _parseExpr();
      if (e is! Ident && e is! Index) {
        _fail('invalid compound assignment target', opTok);
      }
      return AssignStmt(e, Binary(compound, e, v, opTok.line, opTok.col), t.line,
          t.col);
    }
    if (_accept(Tok.assign)) {
      final v = _parseExpr();
      if (e is! Ident && e is! Index) {
        _fail('invalid assignment target', t);
      }
      return AssignStmt(e, v, t.line, t.col);
    }
    return ExprStmt(e, t.line, t.col);
  }

  // -------------------------------------------------------------------
  // Expressions (precedence climbing)
  // -------------------------------------------------------------------

  Expr _parseExpr() => _parseConditional();

  Expr _parseConditional() {
    final c = _parseBinary(0);
    if (_accept(Tok.question)) {
      final a = _parseExpr();
      _expect(Tok.colon, "':'");
      final b = _parseExpr();
      return Cond(c, a, b, c.line, c.col);
    }
    return c;
  }

  static const List<List<Tok>> _prec = [
    [Tok.orOr],
    [Tok.andAnd],
    [Tok.pipe],
    [Tok.caret],
    [Tok.amp],
    [Tok.eq, Tok.ne],
    [Tok.lt, Tok.le, Tok.gt, Tok.ge],
    [Tok.shl, Tok.shr],
    [Tok.plus, Tok.minus],
    [Tok.star, Tok.slash, Tok.percent],
  ];

  Expr _parseBinary(int level) {
    if (level >= _prec.length) return _parseUnary();
    var left = _parseBinary(level + 1);
    while (_prec[level].contains(_cur.kind)) {
      final op = _cur;
      _p++;
      final right = _parseBinary(level + 1);
      left = Binary(op.kind, left, right, op.line, op.col);
    }
    return left;
  }

  Expr _parseUnary() {
    final t = _cur;
    switch (t.kind) {
      case Tok.minus:
      case Tok.tilde:
      case Tok.bang: {
        _p++;
        final e = _parseUnary();
        return Unary(t.kind, e, t.line, t.col);
      }
      default:
        return _parsePostfix();
    }
  }

  Expr _parsePostfix() {
    var e = _parsePrimary();
    while (true) {
      if (_cur.kind == Tok.dot) {
        // Two forms are meaningful: an imported name qualified by the prefix
        // (`import 'x.dart' as lib;` then `lib.helper()`), and nothing else.
        // Anything other than `ident.ident(args)` is rejected here rather than
        // producing a confusing "undeclared identifier" later.
        if (e is! Ident) {
          _fail('member access is not supported in protected code; use a '
              'builtin such as strLen/strAt/listLen/listAt/mapGet instead',
              _cur);
        }
        final dot = _cur;
        _p++;
        final member = _expect(Tok.ident, 'member name after "."');
        if (_cur.kind != Tok.lparen) {
          _fail('member access is not supported in protected code; only '
              'imported functions may be qualified (as `prefix.name(...)`). '
              'Use a builtin instead.', dot);
        }
        e = Ident('${e.name}.${member.text}', dot.line, dot.col);
        continue;
      }
      if (_cur.kind == Tok.lparen) {
        if (e is! Ident) {
          _fail('only free function calls are supported in protected code',
              _cur);
        }
        final name = e.name;
        final args = _parseArgs();
        final bare = name.contains('.') ? name.split('.').last : name;
        if (kKnownBuiltins.contains(bare) && !name.contains('.')) {
          e = BuiltinCall(bare, args, e.line, e.col);
        } else {
          e = Call(null, name, args, e.line, e.col);
        }
        continue;
      }
      if (_cur.kind == Tok.lbracket) {
        final open = _cur;
        _p++;
        final idx = _parseExpr();
        _expect(Tok.rbracket, "']'");
        e = Index(e, idx, open.line, open.col);
        continue;
      }
      // `i++` / `i--`: a mutation, not an expression.
      //
      // The compiler has no assignment expression, so a postfix increment can
      // only be consumed by a *statement* slot (a statement, or a for-loop
      // init/update clause). It is lowered to `i = i + 1` and handed back through
      // `_pendingIncDec`; the caller commits it. Accepting it in expression
      // position and emitting a bare `i + 1` would silently discard the update,
      // leaving the loop variable unchanged - every `for` loop then spins until a
      // budget is exhausted, which is exactly how this first showed up.
      if (_cur.kind == Tok.plusPlus || _cur.kind == Tok.minusMinus) {
        final opTok = _cur;
        if (!_postfixIncDecAllowed) {
          _fail('${opTok.text} is only allowed as a statement or as the update '
              'clause of a for loop; elsewhere write `x = x + 1`', opTok);
        }
        _p++;
        if (e is! Ident && e is! Index) {
          _fail('${opTok.text} requires a variable or index target', opTok);
        }
        _pendingIncDec = AssignStmt(
            e,
            Binary(
                opTok.kind == Tok.plusPlus ? Tok.plus : Tok.minus,
                e,
                IntLit(1, opTok.line, opTok.col),
                opTok.line,
                opTok.col),
            opTok.line,
            opTok.col);
        return e;
      }
      return e;
    }
  }

  List<Expr> _parseArgs() {
    _expect(Tok.lparen, "'('");
    final args = <Expr>[];
    if (_accept(Tok.rparen)) return args;
    while (true) {
      args.add(_parseExpr());
      if (_accept(Tok.comma)) continue;
      _expect(Tok.rparen, "')' or ','");
      return args;
    }
  }

  Expr _parsePrimary() {
    final t = _cur;
    switch (t.kind) {
      case Tok.intLit:
        _p++;
        return IntLit(t.intValue!, t.line, t.col);
      case Tok.strLit:
        _p++;
        return StrLit(t.strValue!, t.line, t.col);
      case Tok.true_:
        _p++;
        return BoolLit(true, t.line, t.col);
      case Tok.false_:
        _p++;
        return BoolLit(false, t.line, t.col);
      case Tok.null_:
        _p++;
        return NullLit(t.line, t.col);
      case Tok.ident:
        _p++;
        return Ident(t.text, t.line, t.col);
      case Tok.lparen: {
        _p++;
        final e = _parseExpr();
        _expect(Tok.rparen, "')'");
        return e;
      }
      case Tok.lbracket: {
        _p++;
        final items = <Expr>[];
        if (!_accept(Tok.rbracket)) {
          while (true) {
            items.add(_parseExpr());
            if (_accept(Tok.comma)) continue;
            _expect(Tok.rbracket, "']' or ','");
            break;
          }
        }
        return ListLit(items, t.line, t.col);
      }
      case Tok.lbrace: {
        _p++;
        final entries = <(Expr, Expr)>[];
        if (!_accept(Tok.rbrace)) {
          while (true) {
            final k = _parseExpr();
            _expect(Tok.colon, "':'");
            final v = _parseExpr();
            entries.add((k, v));
            if (_accept(Tok.comma)) continue;
            _expect(Tok.rbrace, "'}' or ','");
            break;
          }
        }
        return MapLit(entries, t.line, t.col);
      }
      default:
        _fail('expected an expression but found ${_describe(t)}');
    }
  }
}
