/// Token definitions for the DartVMP restricted-Dart front end.
///
/// The front end deliberately accepts only a *subset* of Dart (see
/// `lib/src/lang_limits.dart`). Everything it accepts has a direct, cheap
/// lowering into the private instruction set defined in
/// `packages/dartvmp/src/dvmp_wire.h`.
library;

enum Tok {
  eof,
  ident,
  intLit,
  strLit,
  // keywords
  fn_,
  int_,
  string_,
  bool_,
  void_,
  list_,
  map_,
  var_,
  if_,
  else_,
  while_,
  for_,
  return_,
  break_,
  continue_,
  in_,
  const_,
  true_,
  false_,
  null_,
  // punctuation
  lparen,
  rparen,
  lbrace,
  rbrace,
  lbracket,
  rbracket,
  comma,
  semi,
  arrow,
  assign,
  // operators
  plus,
  minus,
  plusPlus,
  minusMinus,
  plusEq,
  minusEq,
  starEq,
  slashEq,
  percentEq,
  ampEq,
  pipeEq,
  caretEq,
  shlEq,
  shrEq,
  star,
  slash,
  percent,
  amp,
  pipe,
  caret,
  tilde,
  shl,
  shr,
  lt,
  le,
  gt,
  ge,
  eq,
  ne,
  andAnd,
  orOr,
  bang,
  question,
  colon,
  dot,
  // annotations
  at,
}

/// A lexed token. [line] is 1-based and used for diagnostics.
class Token {
  final Tok kind;
  final String text;
  final int? intValue;
  final String? strValue;
  final int line;
  final int col;

  const Token(this.kind, this.text, this.line, this.col,
      {this.intValue, this.strValue});

  @override
  String toString() =>
      '${kind.name}(${text.isEmpty ? '' : text})@$line:$col';
}

class LexError implements Exception {
  final String message;
  final int line;
  final int col;
  final String sourceName;
  LexError(this.message, this.line, this.col, this.sourceName);

  @override
  String toString() => '$sourceName:$line:$col: lex error: $message';
}

const Map<String, Tok> kKeywords = {
  'fn': Tok.fn_,
  'int': Tok.int_,
  'String': Tok.string_,
  'string': Tok.string_,
  'bool': Tok.bool_,
  'void': Tok.void_,
  'List': Tok.list_,
  'Map': Tok.map_,
  'var': Tok.var_,
  'if': Tok.if_,
  'else': Tok.else_,
  'while': Tok.while_,
  'for': Tok.for_,
  'in': Tok.in_,
  'const': Tok.const_,
  'return': Tok.return_,
  'break': Tok.break_,
  'continue': Tok.continue_,
  'true': Tok.true_,
  'false': Tok.false_,
  'null': Tok.null_,
};

/// Hand-written lexer for the protected-source subset.
///
/// It is intentionally strict: anything it does not understand becomes a
/// [LexError] rather than being silently skipped, because silently skipping
/// syntax in a *protection* compiler would mean shipping a stub whose real
/// body never made it into the bytecode.
class Lexer {
  final String src;
  final String sourceName;
  int _i = 0;
  int _line = 1;
  int _lineStart = 0;

  Lexer(this.src, {this.sourceName = '<source>'});

  int get _col => _i - _lineStart + 1;

  Never _fail(String msg) => throw LexError(msg, _line, _col, sourceName);

  List<Token> tokenize() {
    final out = <Token>[];
    while (true) {
      _skipTrivia();
      if (_i >= src.length) {
        out.add(Token(Tok.eof, '', _line, _col));
        return out;
      }
      out.add(_next());
    }
  }

  void _skipTrivia() {
    while (_i < src.length) {
      final c = src.codeUnitAt(_i);
      if (c == 0x0A) {
        _i++;
        _line++;
        _lineStart = _i;
      } else if (c == 0x20 || c == 0x09 || c == 0x0D) {
        _i++;
      } else if (c == 0x2F && _i + 1 < src.length &&
          src.codeUnitAt(_i + 1) == 0x2F) {
        // line comment
        while (_i < src.length && src.codeUnitAt(_i) != 0x0A) {
          _i++;
        }
      } else if (c == 0x2F && _i + 1 < src.length &&
          src.codeUnitAt(_i + 1) == 0x2A) {
        final startLine = _line;
        _i += 2;
        while (true) {
          if (_i + 1 >= src.length) {
            _fail('unterminated block comment starting on line $startLine');
          }
          final d = src.codeUnitAt(_i);
          if (d == 0x0A) {
            _line++;
            _lineStart = _i + 1;
          }
          if (d == 0x2A && src.codeUnitAt(_i + 1) == 0x2F) {
            _i += 2;
            break;
          }
          _i++;
        }
      } else {
        return;
      }
    }
  }

  static bool _isIdentStart(int c) =>
      (c >= 0x41 && c <= 0x5A) ||
      (c >= 0x61 && c <= 0x7A) ||
      c == 0x5F ||
      c == 0x24 ||
      c > 0x7F;
  static bool _isIdentPart(int c) => _isIdentStart(c) || (c >= 0x30 && c <= 0x39);
  static bool _isDigit(int c) => c >= 0x30 && c <= 0x39;

  Token _next() {
    final line = _line;
    final col = _col;
    final c = src.codeUnitAt(_i);

    if (_isIdentStart(c)) {
      final start = _i;
      while (_i < src.length && _isIdentPart(src.codeUnitAt(_i))) {
        _i++;
      }
      final text = src.substring(start, _i);
      final kw = kKeywords[text];
      if (kw != null) {
        return Token(kw, text, line, col);
      }
      return Token(Tok.ident, text, line, col);
    }

    if (_isDigit(c)) {
      final start = _i;
      int radix = 10;
      if (c == 0x30 && _i + 1 < src.length) {
        final n = src.codeUnitAt(_i + 1);
        if (n == 0x78 || n == 0x58) {
          radix = 16;
          _i += 2;
        } else if (n == 0x62 || n == 0x42) {
          radix = 2;
          _i += 2;
        }
      }
      final digitsStart = _i;
      while (_i < src.length) {
        final d = src.codeUnitAt(_i);
        final ok = radix == 16
            ? (_isDigit(d) || (d >= 0x61 && d <= 0x66) || (d >= 0x41 && d <= 0x46))
            : radix == 2
                ? (d == 0x30 || d == 0x31)
                : _isDigit(d);
        if (!ok) break;
        _i++;
      }
      final digits = src.substring(digitsStart, _i);
      if (digits.isEmpty) _fail('malformed numeric literal');
      final v = int.tryParse(digits, radix: radix);
      if (v == null) _fail('integer literal out of range: $digits');
      return Token(Tok.intLit, src.substring(start, _i), line, col,
          intValue: v);
    }

    if (c == 0x27 || c == 0x22) {
      return _string(c, line, col);
    }

    // Multi-character operators first.
    Token two(Tok k, String s) {
      _i += 2;
      return Token(k, s, line, col);
    }

    if (_i + 1 < src.length) {
      final c2 = src.codeUnitAt(_i + 1);
      if (c == 0x3D && c2 == 0x3D) return two(Tok.eq, '==');
      if (c == 0x21 && c2 == 0x3D) return two(Tok.ne, '!=');
      if (c == 0x3C && c2 == 0x3D) return two(Tok.le, '<=');
      if (c == 0x3E && c2 == 0x3D) return two(Tok.ge, '>=');
      if (c == 0x26 && c2 == 0x26) return two(Tok.andAnd, '&&');
      if (c == 0x7C && c2 == 0x7C) return two(Tok.orOr, '||');
      if (c == 0x3C && c2 == 0x3C) {
        if (_i + 2 < src.length && src.codeUnitAt(_i + 2) == 0x3D) {
          _i += 3;
          return Token(Tok.shlEq, '<<=', line, col);
        }
        return two(Tok.shl, '<<');
      }
      if (c == 0x3E && c2 == 0x3E) {
        if (_i + 2 < src.length && src.codeUnitAt(_i + 2) == 0x3D) {
          _i += 3;
          return Token(Tok.shrEq, '>>=', line, col);
        }
        return two(Tok.shr, '>>');
      }
      if (c == 0x2D && c2 == 0x3E) return two(Tok.arrow, '->');
      // Increment / decrement, and the compound assignments. The compiler
      // lowers all of them, so recognising them as single tokens keeps the
      // parser unambiguous (a bare `+` followed by `=` would otherwise parse
      // as a binary plus and then choke).
      if (c == 0x2B && c2 == 0x2B) return two(Tok.plusPlus, '++');
      if (c == 0x2D && c2 == 0x2D) return two(Tok.minusMinus, '--');
      if (_i + 2 < src.length && src.codeUnitAt(_i + 2) == 0x3D) {
        final three = switch (c) {
          0x2B => Tok.plusEq,
          0x2D => Tok.minusEq,
          0x2A => Tok.starEq,
          0x2F => Tok.slashEq,
          0x25 => Tok.percentEq,
          0x26 => Tok.ampEq,
          0x7C => Tok.pipeEq,
          0x5E => Tok.caretEq,
          _ => null,
        };
        if (three != null) {
          _i += 3;
          return Token(three, src.substring(_i - 3, _i), line, col);
        }
      }
    }

    _i++;
    switch (c) {
      case 0x28:
        return Token(Tok.lparen, '(', line, col);
      case 0x29:
        return Token(Tok.rparen, ')', line, col);
      case 0x7B:
        return Token(Tok.lbrace, '{', line, col);
      case 0x7D:
        return Token(Tok.rbrace, '}', line, col);
      case 0x5B:
        return Token(Tok.lbracket, '[', line, col);
      case 0x5D:
        return Token(Tok.rbracket, ']', line, col);
      case 0x2C:
        return Token(Tok.comma, ',', line, col);
      case 0x3B:
        return Token(Tok.semi, ';', line, col);
      case 0x2B:
        return Token(Tok.plus, '+', line, col);
      case 0x2D:
        return Token(Tok.minus, '-', line, col);
      case 0x2A:
        return Token(Tok.star, '*', line, col);
      case 0x2F:
        return Token(Tok.slash, '/', line, col);
      case 0x25:
        return Token(Tok.percent, '%', line, col);
      case 0x26:
        return Token(Tok.amp, '&', line, col);
      case 0x7C:
        return Token(Tok.pipe, '|', line, col);
      case 0x5E:
        return Token(Tok.caret, '^', line, col);
      case 0x7E:
        return Token(Tok.tilde, '~', line, col);
      case 0x3C:
        return Token(Tok.lt, '<', line, col);
      case 0x3E:
        return Token(Tok.gt, '>', line, col);
      case 0x3D:
        return Token(Tok.assign, '=', line, col);
      case 0x21:
        return Token(Tok.bang, '!', line, col);
      case 0x3F:
        return Token(Tok.question, '?', line, col);
      case 0x3A:
        return Token(Tok.colon, ':', line, col);
      case 0x2E:
        return Token(Tok.dot, '.', line, col);
      case 0x40:
        return Token(Tok.at, '@', line, col);
    }
    _fail('unexpected character U+${c.toRadixString(16).toUpperCase().padLeft(4, '0')}');
  }

  Token _string(int quote, int line, int col) {
    _i++; // opening quote
    final sb = StringBuffer();
    while (true) {
      if (_i >= src.length) _fail('unterminated string literal');
      final c = src.codeUnitAt(_i);
      if (c == quote) {
        _i++;
        return Token(Tok.strLit, sb.toString(), line, col, strValue: sb.toString());
      }
      if (c == 0x0A) _fail('unterminated string literal (newline in literal)');
      if (c == 0x5C) {
        _i++;
        if (_i >= src.length) _fail('unterminated escape sequence');
        final e = src.codeUnitAt(_i);
        _i++;
        switch (e) {
          case 0x6E:
            sb.write('\n');
            break;
          case 0x74:
            sb.write('\t');
            break;
          case 0x72:
            sb.write('\r');
            break;
          case 0x30:
            sb.write('\x00');
            break;
          case 0x5C:
            sb.write('\\');
            break;
          case 0x27:
            sb.write("'");
            break;
          case 0x22:
            sb.write('"');
            break;
          case 0x24:
            sb.write(r'$');
            break;
          case 0x78: {
            // \xHH
            if (_i + 2 > src.length) _fail('truncated \\x escape');
            final hex = src.substring(_i, _i + 2);
            final v = int.tryParse(hex, radix: 16);
            if (v == null) _fail('invalid \\x escape: $hex');
            sb.writeCharCode(v);
            _i += 2;
            break;
          }
          default:
            _fail('unsupported escape sequence: \\${String.fromCharCode(e)}');
        }
        continue;
      }
      if (c == 0x24) {
        _fail('string interpolation (\$) is not supported in protected '
            'functions; build the value with explicit concatenation');
      }
      sb.writeCharCode(c);
      _i++;
    }
  }
}
