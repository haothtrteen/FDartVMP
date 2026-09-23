#!/usr/bin/env python3
"""Local single-page UI for declaring DartVMP protection on Dart sources.

Run it from anywhere; it always operates on the repository root it lives in:

    python tool/ui/serve.py                 # http://127.0.0.1:8777
    python tool/ui/serve.py --port 9000
    python tool/ui/serve.py --no-browser

The page is one self-contained HTML document (no CDN, no external asset, works
offline) and talks to a small JSON API served by this file:

    GET  /                          the page
    GET  /api/status                manifest summary + generated artifact state
    GET  /api/files                 *.dart under protected/, recursively
    GET  /api/functions?file=PATH   parsed top-level functions + marker state
    GET  /api/manifest              raw vmp_manifest.json
    POST /api/plan                  dry run of a marker edit (diff + self-check)
    POST /api/apply                 the same edit, written atomically
    POST /api/build                 dart run tool/build.dart with the given sources
    POST /api/verify                vmpc check / verify_descriptors.py / walk_bytecode.py

The only thing this file is allowed to change in a source tree is the set of
``// @vmp`` marker lines that sit above top-level function declarations. See
``plan_edits`` for the proof obligation it enforces before any byte is written.

Standard library only.
"""

from __future__ import annotations

import argparse
import difflib
import hashlib
import json
import locale
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import traceback
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

# ---------------------------------------------------------------------------
# repository layout
# ---------------------------------------------------------------------------

ROOT = Path(__file__).resolve().parents[2]
MANIFEST_REL = "app/test/generated/vmp_manifest.json"
DEFAULT_SOURCES = ["protected/licensing.dart", "protected/keys.dart"]

# Files `dart run tool/build.dart` rewrites. Hashed before/after a build so the
# UI can show *what* a build changed instead of just "done".
ARTIFACT_RELS = [
    "app/lib/generated/protected_stubs.dart",
    "app/test/generated/protected_oracle.dart",
    "app/test/generated/vm_builtins.dart",
    "app/test/generated/vmp_manifest.json",
    "packages/dartvmp/generated/vmp_module.inc",
]
ARTIFACT_GLOBS = ["app/test/generated/*.dart", "build/evicted/*.dart"]

VERIFY_TOOLS = [
    {
        "id": "check",
        "label": "vmpc check",
        "cmd": ["dart", "run", "tool/vmpc/bin/vmpc.dart", "check"],
        "required": True,
        "note": "asserts every // @vmp marker became a compiled function",
    },
    {
        "id": "descriptors",
        "label": "verify_descriptors.py",
        "cmd": ["python", "tool/verify_descriptors.py"],
        "required": True,
        "note": "decodes the container independently and checks the call policy fields",
    },
    {
        "id": "walk",
        "label": "walk_bytecode.py",
        "cmd": ["python", "tool/walk_bytecode.py"],
        "required": True,
        "note": "walks the shipped bytecode exactly as the runtime does",
    },
    {
        "id": "crypto",
        "label": "verify_crypto.ps1",
        "cmd": ["powershell", "-ExecutionPolicy", "Bypass", "-File", "tool/verify_crypto.ps1"],
        "required": False,
        "note": "optional: needs the built native library / APK on disk",
    },
]
VERIFY_BY_ID = {t["id"]: t for t in VERIFY_TOOLS}

MAX_BODY = 1 << 20  # 1 MiB is far above anything this page posts

# ---------------------------------------------------------------------------
# errors
# ---------------------------------------------------------------------------


class ApiError(Exception):
    def __init__(self, status: int, message: str, **extra):
        super().__init__(message)
        self.status = status
        self.message = message
        self.extra = extra


# ---------------------------------------------------------------------------
# text helpers
# ---------------------------------------------------------------------------


def split_lines(text: str) -> list[str]:
    """Split keeping line endings, so ''.join(split_lines(t)) == t exactly."""
    if text == "":
        return [""]
    return re.split(r"(?<=\n)", text)


def blank_noncode(text: str) -> str:
    """Blank out comments and string literals, preserving every newline.

    The result has the same line count and the same brace/paren structure as
    real code, which is what makes the declaration scan below able to count
    braces and match parentheses without being confused by `{` inside a string
    or `// }` inside a comment.
    """
    out = list(text)
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if c == "/" and i + 1 < n and text[i + 1] == "/":
            while i < n and text[i] != "\n":
                out[i] = " "
                i += 1
            continue
        if c == "/" and i + 1 < n and text[i + 1] == "*":
            depth = 0
            while i < n:
                if text[i] == "/" and i + 1 < n and text[i + 1] == "*":
                    depth += 1
                    out[i] = out[i + 1] = " "
                    i += 2
                    continue
                if text[i] == "*" and i + 1 < n and text[i + 1] == "/":
                    depth -= 1
                    out[i] = out[i + 1] = " "
                    i += 2
                    if depth == 0:
                        break
                    continue
                if text[i] != "\n":
                    out[i] = " "
                i += 1
            continue
        if c in "'\"":
            quote = c
            out[i] = " "
            i += 1
            while i < n:
                if text[i] == "\\":
                    if text[i] != "\n":
                        out[i] = " "
                    i += 1
                    if i < n and text[i] != "\n":
                        out[i] = " "
                    i += 1
                    continue
                if text[i] == quote:
                    out[i] = " "
                    i += 1
                    break
                if text[i] != "\n":
                    out[i] = " "
                i += 1
            continue
        i += 1
    return "".join(out)


# ---------------------------------------------------------------------------
# marker syntax - mirrors tool/vmpc/lib/src/dart_source.dart injectMarkers()
# ---------------------------------------------------------------------------

GUARD_RE = re.compile(r"^(once|rate=\d+/\d+)$")


def marker_line_info(raw_line: str):
    """Classify one raw source line as a marker comment.

    Returns None when the line is not a marker, else a dict with:
      kind   - "marker" or "invalid"
      guard  - the guard spec ("once" / "rate=N/MS") or None
      error  - human readable reason when kind == "invalid"
    """
    s = raw_line.strip()
    if not s.startswith("//"):
        return None
    body = s[2:].strip()
    if body in ("@vmp", "@protect"):
        return {"kind": "marker", "guard": None, "error": None}
    # The Dart side tests the literal prefixes "@vmp " / "@protect " (a space),
    # so a tab after the directive makes the line an ordinary comment there too.
    if not (body.startswith("@vmp ") or body.startswith("@protect ")):
        return None
    rest = re.sub(r"^@(vmp|protect)\s*", "", body).strip()
    if not rest:
        return {"kind": "marker", "guard": None, "error": None}
    if not rest.startswith("guard:"):
        return {
            "kind": "invalid",
            "guard": None,
            "error": 'unrecognised marker option "%s" - the only supported form '
            'is "// @vmp guard:rate=N/MS" or "// @vmp guard:once"' % rest,
        }
    spec = rest[len("guard:"):].strip()
    if spec.split("=")[0].strip() not in ("once", "rate"):
        return {"kind": "invalid", "guard": None,
                "error": 'unknown guard "%s"; expected "once" or "rate=N/MS"' % spec}
    if not GUARD_RE.match(spec):
        return {"kind": "invalid", "guard": None,
                "error": 'malformed guard "%s"; expected "once" or "rate=N/MS" '
                'with integers' % spec}
    return {"kind": "marker", "guard": spec, "error": None}


def is_marker_comment(raw_line: str) -> bool:
    """True for any line that is (or claims to be) a `// @vmp` marker line.

    This predicate is the definition of "a line this UI is allowed to touch"
    and is used by the write self-check, so it deliberately returns True for
    malformed markers as well - the check compares the file with *all* marker
    lines removed, in both the old and the new text.
    """
    return marker_line_info(raw_line) is not None


def render_marker(guard: str | None, eol: str) -> str:
    return "// @vmp" + (" guard:" + guard if guard else "") + eol


# ---------------------------------------------------------------------------
# source parsing
# ---------------------------------------------------------------------------

RESERVED_NAMES = {
    "if", "for", "while", "switch", "catch", "return", "assert", "case", "do",
    "else", "new", "in", "is", "as", "throw", "await", "yield", "when", "try",
}

DECL_RE = re.compile(
    r"^(?:(?:external|static|final|const|late)\s+)*"
    r"(?P<ret>[A-Za-z_][A-Za-z0-9_<>,\.\?\[\]>\s]*?)\s+"
    r"(?P<name>[A-Za-z_]\w*)\s*\("
)


def _match_paren(text: str, open_idx: int) -> int:
    depth = 0
    for i in range(open_idx, len(text)):
        c = text[i]
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return i
    return -1


def _split_top(text: str) -> list[str]:
    parts, depth, cur = [], 0, ""
    for c in text:
        if c in "([{<":
            depth += 1
        elif c in ")]}>":
            depth -= 1
        if c == "," and depth <= 0:
            parts.append(cur.strip())
            cur = ""
        else:
            cur += c
    if cur.strip():
        parts.append(cur.strip())
    return parts


def _accumulate(clines: list[str], i: int):
    acc = ""
    j = i
    limit = len(clines)
    while j < limit and j - i < 60:
        seg = clines[j].strip()
        if seg:
            acc = (acc + " " + seg).strip() if acc else seg
            if re.search(r"(\{|;|=>)\s*$", acc):
                return acc, j
            if ";" in seg and "(" not in acc:
                return acc, j
        j += 1
    return acc, j


def _match_decl(acc: str):
    m = DECL_RE.match(acc)
    if not m:
        return None
    name = m.group("name")
    if name in RESERVED_NAMES:
        return None
    open_idx = acc.find("(", m.end("name") - 1)
    if open_idx < 0:
        return None
    close_idx = _match_paren(acc, open_idx)
    if close_idx < 0:
        return None
    tail = acc[close_idx + 1:].strip()
    if not (tail.startswith("{") or tail.startswith("=>") or
            tail.startswith(";") or tail.startswith("async")):
        return None
    if tail.startswith(";"):
        # external / abstract declaration: no body, not something the VMP
        # compiler can lower and not something a marker can protect.
        return None
    return {
        "name": name,
        "returnType": m.group("ret").strip(),
        "params": _split_top(acc[open_idx + 1:close_idx]),
        "signature": re.sub(r"\s+", " ", acc[:close_idx + 1]).strip(),
    }


def detect_eol(text: str) -> str:
    crlf = text.count("\r\n")
    lf = text.count("\n") - crlf
    return "\r\n" if crlf > lf else "\n"


def analyze_source(text: str) -> dict:
    """Parse a Dart source file into top-level functions plus marker state.

    Two passes, matching the two passes the real toolchain performs:

      1. A line pass that mirrors ``injectMarkers`` - which marker lines are
         pending, which guard a marker carries, and which declaration they land
         on. Anything Dart would reject is reported in ``problems`` instead of
         being silently treated as protection.
      2. A declaration pass over comment/string-blanked text that finds
         top-level function declarations (including multi-line signatures) and
         returns their names, signatures and line ranges.
    """
    lines = split_lines(text)
    clines = split_lines(blank_noncode(text))
    if len(clines) < len(lines):
        clines += [""] * (len(lines) - len(clines))
    n = len(lines)

    start_depth, d = [], 0
    for cl in clines:
        start_depth.append(d)
        d += (cl.count("{") - cl.count("}"))
        if d < 0:
            d = 0

    problems: list[dict] = []
    pending: list[tuple[int, str]] = []  # (line idx, "comment" | "annotation")
    pending_guard: str | None = None
    pending_at: dict[int, dict] = {}

    for i in range(n):
        stripped = lines[i].strip()
        if stripped.startswith("//"):
            info = marker_line_info(lines[i])
            if info is not None:
                if start_depth[i] > 0:
                    problems.append({
                        "line": i + 1, "text": stripped,
                        "message": 'a "// @vmp" marker appears inside a function '
                                   'body; it must sit immediately before a '
                                   'top-level function declaration',
                    })
                elif info["kind"] == "invalid":
                    problems.append({"line": i + 1, "text": stripped,
                                     "message": info["error"]})
                else:
                    pending.append((i, "comment"))
                    if info["guard"]:
                        pending_guard = info["guard"]
            continue
        if not stripped:
            continue
        cstripped = clines[i].strip()
        if cstripped.startswith("@"):
            m = re.match(r"^@(vmp|protect)\b(.*)$", cstripped)
            if m:
                extra = m.group(2).strip()
                if start_depth[i] > 0:
                    problems.append({
                        "line": i + 1, "text": stripped,
                        "message": "an @vmp annotation appears inside a "
                                   "function body",
                    })
                elif extra:
                    problems.append({
                        "line": i + 1, "text": stripped,
                        "message": "parameterised annotations are not supported",
                    })
                else:
                    pending.append((i, "annotation"))
                continue
        # First non-blank, non-comment line: whatever was pending lands here.
        if pending:
            pending_at[i] = {"markers": list(pending), "guard": pending_guard}
            pending = []
            pending_guard = None

    if pending:
        problems.append({
            "line": pending[0][0] + 1, "text": lines[pending[0][0]].strip(),
            "message": "a // @vmp marker is not followed by a function "
                       "declaration",
        })

    functions = []
    i = 0
    seen: dict[str, int] = {}
    while i < n:
        stripped = lines[i].strip()
        if (not stripped or stripped.startswith("//")
                or stripped.startswith("/*") or stripped.startswith("*")
                or clines[i].strip().startswith("@")):
            i += 1
            continue
        if start_depth[i] != 0:
            i += 1
            continue
        acc, _j = _accumulate(clines, i)
        decl = _match_decl(acc)
        if decl is None:
            i += 1
            continue
        pend = pending_at.get(i, {"markers": [], "guard": None})
        styles = {style for _idx, style in pend["markers"]}
        style = "annotation" if "annotation" in styles else (
            "comment" if "comment" in styles else None)
        toggleable = True
        blocker = None
        if style == "annotation":
            toggleable = False
            blocker = ("protected by a bare @vmp annotation; remove it by hand "
                       "- this UI only manages // @vmp marker lines")
        if decl["name"] in seen:
            toggleable = False
            blocker = 'duplicate top-level function name "%s"' % decl["name"]
        seen[decl["name"]] = i
        functions.append({
            "name": decl["name"],
            "signature": decl["signature"],
            "returnType": decl["returnType"],
            "params": decl["params"],
            "arity": len(decl["params"]),
            "line": i + 1,
            "lineIndex": i,
            "protect": bool(pend["markers"]),
            "guard": pend["guard"],
            "markerStyle": style,
            "markerLines": [idx + 1 for idx, _s in pend["markers"]],
            "markerLineIndexes": [idx for idx, _s in pend["markers"]],
            "toggleable": toggleable,
            "blocker": blocker,
            "inDefaultSources": False,
        })
        i += 1

    # Marker lines that landed on something other than a top-level function.
    fn_lines = {f["lineIndex"] for f in functions}
    for idx, info in pending_at.items():
        if idx not in fn_lines and info["markers"]:
            problems.append({
                "line": info["markers"][0][0] + 1,
                "text": lines[info["markers"][0][0]].strip(),
                "message": "a // @vmp marker is not followed by a top-level "
                           "function declaration",
            })

    comment_markers = sum(
        1 for ln in lines if (marker_line_info(ln) or {}).get("kind") == "marker"
        and ln.strip().startswith("//"))
    return {
        "functions": functions,
        "problems": problems,
        "markerCount": comment_markers,
        "unprotected": [f["name"] for f in functions if not f["protect"]],
        "toggleable": all(f["toggleable"] for f in functions) if functions else True,
    }


def insert_anchor(lines: list[str], decl_index: int) -> int:
    """Where a new marker line goes: top of the comment block above the decl.

    Walks up over contiguous comment / annotation lines and stops at the first
    blank line or code line. That keeps an existing doc comment attached below
    the marker (the style the repository already uses) and, because it stops at
    blank lines, it can never wander into the previous function's marker block.
    """
    k = decl_index - 1
    while k >= 0:
        s = lines[k].lstrip()
        if s.startswith("//") or s.startswith("/*") or s.startswith("*") or s.startswith("@"):
            k -= 1
            continue
        break
    return k + 1


# ---------------------------------------------------------------------------
# the edit planner - the only code path that writes to a source file
# ---------------------------------------------------------------------------


def normalize_guard(value) -> str | None:
    if value is None:
        return None
    v = str(value).strip()
    if v in ("", "none", "null"):
        return None
    if v == "once":
        return "once"
    if GUARD_RE.match(v):
        if not v.startswith("rate="):
            return v
        budget, window = v[len("rate="):].split("/")
        if int(budget) == 0:
            raise ApiError(400, "rate budget must be greater than zero")
        if int(window) == 0:
            raise ApiError(400, "rate window must be greater than zero")
        return v
    raise ApiError(
        400,
        'invalid guard "%s"; use none, once, or rate=BUDGET/WINDOW_MS with '
        "positive integers" % v,
    )


def plan_edits(text: str, analysis: dict, changes: list[dict]):
    """Compute the new file text for a set of per-function marker changes.

    Returns (new_text, edits). Raises ApiError when the request is not
    representable as marker-line edits.
    """
    lines = split_lines(text)
    eol = detect_eol(text)
    by_name = {f["name"]: f for f in analysis["functions"]}

    removals: set[int] = set()
    inserts: dict[int, list[str]] = {}
    edits = []

    for ch in changes:
        name = ch.get("name")
        fn = by_name.get(name)
        if fn is None:
            raise ApiError(404, 'no top-level function named "%s" in this file'
                           % name)
        if not fn["toggleable"]:
            raise ApiError(409, '"%s" cannot be edited: %s'
                           % (name, fn["blocker"] or "not toggleable"))
        protect = bool(ch.get("protect"))
        guard = normalize_guard(ch.get("guard"))
        if not protect and guard:
            raise ApiError(400, 'cannot set a guard on "%s" without protecting '
                                "it" % name)
        existing = list(fn["markerLineIndexes"])
        if not protect:
            if not existing:
                edits.append({"name": name, "action": "noop",
                              "detail": "already unprotected"})
                continue
            removals |= set(existing)
            edits.append({
                "name": name, "action": "unprotect",
                "detail": "remove %d marker line(s)" % len(existing),
                "removedLines": [{"line": i + 1, "text": lines[i].rstrip("\r\n")}
                                 for i in existing],
                "addedLines": [],
                "guard": None,
                "anchorLine": min(existing) + 1,
            })
            continue
        if existing and fn["guard"] == guard:
            edits.append({"name": name, "action": "noop",
                          "detail": "already protected"
                                    + (" (guard %s)" % guard if guard else "")})
            continue
        canonical = render_marker(guard, eol)
        pos = min(existing) if existing else insert_anchor(lines, fn["lineIndex"])
        removals |= set(existing)
        inserts.setdefault(pos, []).append(canonical)
        action = "protect" if not existing else (
            "set-guard" if fn["guard"] != guard else "canonicalise")
        edits.append({
            "name": name, "action": action,
            "detail": ("add marker at line %d" % (pos + 1)) if not existing
                      else ("replace %d marker line(s) with %s"
                            % (len(existing), canonical.strip())),
            "removedLines": [{"line": i + 1, "text": lines[i].rstrip("\r\n")}
                             for i in existing],
            "addedLines": [{"line": pos + 1, "text": canonical.rstrip("\r\n")}],
            "guard": guard,
            "anchorLine": pos + 1,
        })

    out: list[str] = []
    for i, line in enumerate(lines):
        if i in inserts:
            out.extend(inserts[i])
        if i in removals:
            continue
        out.append(line)
    for pos in sorted(k for k in inserts if k >= len(lines)):
        out.extend(inserts[pos])

    new_text = "".join(out)
    if not edits or all(e["action"] == "noop" for e in edits):
        return text, edits, []
    return new_text, edits, diff_lines(text, new_text)


def diff_lines(old: str, new: str) -> list[str]:
    a = [l.rstrip("\r\n") for l in split_lines(old)]
    b = [l.rstrip("\r\n") for l in split_lines(new)]
    return list(difflib.unified_diff(a, b, fromfile="a", tofile="b", lineterm="",
                                     n=3))


def self_check(old_text: str, new_text: str):
    """The write precondition.

    Removing every marker line from the original must produce byte-identical
    text to removing every marker line from the new version. That is what makes
    "only marker lines changed, nothing reformatted, nothing re-wrapped" a
    checkable property rather than a promise.
    """
    old_base = "".join(l for l in split_lines(old_text) if not is_marker_comment(l))
    new_base = "".join(l for l in split_lines(new_text) if not is_marker_comment(l))
    if old_base == new_base:
        return True, "ok"
    old_lines = split_lines(old_base)
    new_lines = split_lines(new_base)
    detail = []
    for line in difflib.unified_diff(
            [l.rstrip("\r\n") for l in old_lines],
            [l.rstrip("\r\n") for l in new_lines],
            fromfile="original-without-markers", tofile="rewritten-without-markers",
            lineterm="", n=2):
        detail.append(line)
    return False, "\n".join(detail) or "non-marker text differs"


def post_check(new_text: str, changes: list[dict], analysis: dict) -> list[str]:
    """Every requested state must actually hold in the rewritten text."""
    before = {f["name"]: (f["protect"], f["guard"]) for f in analysis["functions"]}
    after_analysis = analyze_source(new_text)
    after = {f["name"]: (f["protect"], f["guard"]) for f in after_analysis["functions"]}
    problems = []
    if set(after) != set(before):
        problems.append("the set of top-level functions changed: %s"
                        % sorted(set(after) ^ set(before)))
    for ch in changes:
        name = ch.get("name")
        want_protect = bool(ch.get("protect"))
        want_guard = normalize_guard(ch.get("guard")) if want_protect else None
        got = after.get(name)
        if got is None:
            problems.append('"%s" disappeared from the file' % name)
        elif got != (want_protect, want_guard):
            problems.append('"%s" ended up %s, expected %s'
                            % (name, got, (want_protect, want_guard)))
    for name, state in before.items():
        if any(ch.get("name") == name for ch in changes):
            continue
        if after.get(name) != state:
            problems.append('untouched function "%s" changed from %s to %s'
                            % (name, state, after.get(name)))
    for p in after_analysis["problems"]:
        problems.append("line %d: %s" % (p["line"], p["message"]))
    return problems


# ---------------------------------------------------------------------------
# backups + atomic write
# ---------------------------------------------------------------------------

_backup_lock = threading.Lock()
_backups: dict[str, str] = {}


def ensure_backup(path: Path) -> str:
    """First modification this session copies the file aside; never clobbers."""
    key = str(path)
    with _backup_lock:
        if key in _backups:
            return _backups[key]
        cand = Path(str(path) + ".bak")
        n = 1
        while cand.exists():
            cand = Path("%s.bak.%d" % (path, n))
            n += 1
        shutil.copy2(path, cand)
        _backups[key] = str(cand)
        return str(cand)


def atomic_write(path: Path, text: str) -> dict:
    data = text.encode("utf-8")
    before = path.read_bytes()
    backup = ensure_backup(path)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix="." + path.name + ".",
                               suffix=".vmpui.tmp")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, str(path))
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    return {
        "backup": backup,
        "bytesBefore": len(before),
        "bytesAfter": len(data),
        "sha256Before": hashlib.sha256(before).hexdigest(),
        "sha256After": hashlib.sha256(data).hexdigest(),
    }


def sha256_file(path: Path) -> str | None:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return None


# ---------------------------------------------------------------------------
# paths
# ---------------------------------------------------------------------------


def repo_path(rel: str, *, must_exist: bool = True) -> Path:
    if not rel or not str(rel).strip():
        raise ApiError(400, "missing 'file' (a path relative to the repository root)")
    rel = str(rel).strip().replace("\\", "/")
    if rel.startswith("/") or re.match(r"^[A-Za-z]:", rel):
        raise ApiError(400, "path must be relative to the repository root")
    p = (ROOT / rel).resolve()
    try:
        p.relative_to(ROOT.resolve())
    except ValueError:
        raise ApiError(400, "path escapes the repository root")
    if must_exist and not p.is_file():
        raise ApiError(404, "no such file in the repository: %s" % rel)
    if p.suffix.lower() != ".dart":
        raise ApiError(400, "only .dart sources can be edited here")
    return p


def rel_of(p: Path) -> str:
    try:
        return p.resolve().relative_to(ROOT.resolve()).as_posix()
    except ValueError:
        return p.as_posix()


def file_report(rel: str) -> dict:
    p = repo_path(rel)
    raw = p.read_bytes()
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as e:
        raise ApiError(415, "file is not valid UTF-8: %s" % e)
    analysis = analyze_source(text)
    rel = rel_of(p)
    in_default = rel in DEFAULT_SOURCES
    for f in analysis["functions"]:
        f["inDefaultSources"] = in_default
    blockers = []
    if not analysis["toggleable"]:
        for f in analysis["functions"]:
            if not f["toggleable"]:
                blockers.append('%s: %s' % (f["name"], f["blocker"]))
    return {
        "file": rel,
        "abs": str(p),
        "bytes": len(raw),
        "lines": text.count("\n") + (0 if text.endswith("\n") else 1),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "eol": "CRLF" if detect_eol(text) == "\r\n" else "LF",
        "inDefaultSources": in_default,
        "markerCount": analysis["markerCount"],
        "problems": analysis["problems"],
        "functions": analysis["functions"],
        "unprotected": analysis["unprotected"],
        "writeBlockers": blockers,
        "backupsThisSession": [b for k, b in _backups.items() if k == str(p)],
    }


def list_sources() -> list[dict]:
    base = ROOT / "protected"
    out = []
    if base.is_dir():
        for p in sorted(base.rglob("*.dart")):
            if not p.is_file():
                continue
            try:
                text = p.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                continue
            a = analyze_source(text)
            rel = rel_of(p)
            out.append({
                "path": rel,
                "bytes": p.stat().st_size,
                "functions": len(a["functions"]),
                "protected": sum(1 for f in a["functions"] if f["protect"]),
                "unprotected": a["unprotected"],
                "problems": len(a["problems"]),
                "inDefaultSources": rel in DEFAULT_SOURCES,
            })
    return out


def artifact_state() -> list[dict]:
    rels = list(ARTIFACT_RELS)
    for pattern in ARTIFACT_GLOBS:
        for p in sorted(ROOT.glob(pattern)):
            rel = rel_of(p)
            if rel not in rels:
                rels.append(rel)
    out = []
    for rel in rels:
        p = ROOT / rel
        if p.is_file():
            st = p.stat()
            out.append({"path": rel, "exists": True, "bytes": st.st_size,
                        "mtime": st.st_mtime, "sha256": sha256_file(p)})
        else:
            out.append({"path": rel, "exists": False, "bytes": None,
                        "mtime": None, "sha256": None})
    return out


def manifest_summary() -> dict:
    p = ROOT / MANIFEST_REL
    if not p.is_file():
        return {"present": False, "path": MANIFEST_REL}
    try:
        m = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        return {"present": False, "path": MANIFEST_REL, "error": str(e)}
    c = m.get("container", {})
    src = [s.strip() for s in str(m.get("source", "")).split(",") if s.strip()]
    return {
        "present": True,
        "path": MANIFEST_REL,
        "mtime": p.stat().st_mtime,
        "buildId": m.get("buildId"),
        "source": src or None,
        "functionCount": len(m.get("functions") or []),
        "containerBytes": c.get("bytes"),
        "bodyBytes": c.get("plaintextBodyBytes"),
        "seed": c.get("seed"),
        "bodyCrc32": c.get("bodyCrc32"),
        "authTag": c.get("authTag"),
        "stringTable": m.get("stringTable"),
        "functions": [
            {"id": f.get("id"), "name": f.get("name"), "arity": f.get("arity"),
             "returnType": f.get("returnType"), "guard": f.get("guard"),
             "params": f.get("params")}
            for f in (m.get("functions") or [])
        ],
    }


# ---------------------------------------------------------------------------
# child processes
# ---------------------------------------------------------------------------


def decode_output(raw: bytes) -> str:
    if not raw:
        return ""
    candidates = ["utf-8", locale.getpreferredencoding(False) or "", "cp1252", "cp437"]
    for enc in candidates:
        if not enc:
            continue
        try:
            return raw.decode(enc)
        except (UnicodeDecodeError, LookupError):
            continue
    return raw.decode("utf-8", "replace")


def resolve_exe(name: str) -> str:
    """Full path for a command name.

    `dart` on Windows is `dart.bat`, and CreateProcess (what subprocess uses
    with a list argv) only appends `.exe`, so an unresolved `dart` fails with
    WinError 2 even though it works in a shell. Resolve through PATH once here.
    """
    if os.path.isabs(name) or os.sep in name or (os.altsep and os.altsep in name):
        return name
    return shutil.which(name) or name


def run_command(cmd: list[str], timeout: float) -> dict:
    started = time.time()
    argv = [resolve_exe(cmd[0])] + list(cmd[1:])
    display = " ".join(cmd)
    try:
        proc = subprocess.run(argv, cwd=str(ROOT), stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, timeout=timeout)
        code, out, err, timed_out = proc.returncode, proc.stdout, proc.stderr, False
    except subprocess.TimeoutExpired as e:
        code, timed_out = None, True
        out = e.stdout or b""
        err = e.stderr or b""
    except FileNotFoundError as e:
        return {"command": display, "resolved": " ".join(argv),
                "exitCode": None, "ok": False, "stdout": "",
                "stderr": "executable not found: %s" % e,
                "durationMs": int((time.time() - started) * 1000),
                "timedOut": False, "error": "executable not found: %s" % e}
    duration = int((time.time() - started) * 1000)
    so, se = decode_output(out), decode_output(err)
    if timed_out:
        se += "\n[ui] timed out after %.0fs; the process was killed\n" % timeout
    return {
        "command": display,
        "resolved": " ".join(argv),
        "exitCode": code,
        "ok": (code == 0),
        "stdout": so,
        "stderr": se,
        "durationMs": duration,
        "timedOut": timed_out,
    }


# ---------------------------------------------------------------------------
# HTTP handler
# ---------------------------------------------------------------------------


class Handler(BaseHTTPRequestHandler):
    server_version = "dartvmp-ui"
    protocol_version = "HTTP/1.1"

    # -- plumbing ----------------------------------------------------------
    def log_message(self, fmt, *args):
        sys.stderr.write("[ui %s] %s\n" % (time.strftime("%H:%M:%S"), fmt % args))

    def _send(self, body: bytes, status: int, ctype: str):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _json(self, obj, status: int = 200):
        self._send(json.dumps(obj, ensure_ascii=False, indent=1).encode("utf-8"),
                   status, "application/json; charset=utf-8")

    def _error(self, status: int, message: str, **extra):
        payload = {"error": message, "status": status}
        payload.update(extra)
        self._json(payload, status)

    def _body(self) -> dict:
        try:
            n = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            raise ApiError(400, "bad Content-Length")
        if n > MAX_BODY:
            raise ApiError(413, "request body too large")
        raw = self.rfile.read(n) if n else b""
        if not raw:
            return {}
        try:
            data = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as e:
            raise ApiError(400, "request body is not JSON: %s" % e)
        if not isinstance(data, dict):
            raise ApiError(400, "request body must be a JSON object")
        return data

    # -- routes ------------------------------------------------------------
    def do_GET(self):  # noqa: N802
        u = urlparse(self.path)
        q = parse_qs(u.query)
        try:
            if u.path in ("/", "/index.html"):
                return self._send(PAGE.replace("__DEFAULT_PORT__", str(PORT)).encode("utf-8"),
                                  200, "text/html; charset=utf-8")
            if u.path == "/favicon.ico":
                return self._send(b"", 204, "image/x-icon")
            if u.path == "/api/status":
                return self._json({
                    "root": str(ROOT),
                    "manifestPath": MANIFEST_REL,
                    "manifest": manifest_summary(),
                    "artifacts": artifact_state(),
                    "defaultSources": DEFAULT_SOURCES,
                    "protectedSources": list_sources(),
                    "verifyTools": [{"id": t["id"], "label": t["label"],
                                     "command": " ".join(t["cmd"]),
                                     "required": t["required"], "note": t["note"]}
                                    for t in VERIFY_TOOLS],
                    "python": sys.executable,
                    "backupsThisSession": dict(_backups),
                })
            if u.path == "/api/files":
                return self._json({"files": list_sources(),
                                   "defaultSources": DEFAULT_SOURCES})
            if u.path == "/api/functions":
                rel = (q.get("file") or [""])[0]
                return self._json(file_report(rel))
            if u.path == "/api/manifest":
                p = ROOT / MANIFEST_REL
                if not p.is_file():
                    raise ApiError(404, "%s does not exist yet" % MANIFEST_REL)
                return self._json(json.loads(p.read_text(encoding="utf-8")))
            raise ApiError(404, "no such endpoint: %s" % u.path)
        except ApiError as e:
            return self._error(e.status, e.message, **e.extra)
        except Exception as e:  # pragma: no cover - surface everything
            return self._error(500, "%s: %s" % (type(e).__name__, e),
                               traceback=traceback.format_exc())

    def do_POST(self):  # noqa: N802
        u = urlparse(self.path)
        try:
            if u.path == "/api/plan":
                return self._json(self.handle_plan(self._body()))
            if u.path == "/api/apply":
                return self._json(self.handle_apply(self._body()))
            if u.path == "/api/build":
                return self._json(self.handle_build(self._body()))
            if u.path == "/api/verify":
                return self._json(self.handle_verify(self._body()))
            raise ApiError(404, "no such endpoint: %s" % u.path)
        except ApiError as e:
            return self._error(e.status, e.message, **e.extra)
        except Exception as e:  # pragma: no cover
            return self._error(500, "%s: %s" % (type(e).__name__, e),
                               traceback=traceback.format_exc())

    # -- endpoint bodies ---------------------------------------------------
    @staticmethod
    def _validate_changes(data: dict):
        changes = data.get("changes")
        if not isinstance(changes, list) or not changes:
            raise ApiError(400, "provide a non-empty 'changes' list")
        seen = set()
        for ch in changes:
            if not isinstance(ch, dict) or not ch.get("name"):
                raise ApiError(400, "every change needs a 'name'")
            if ch["name"] in seen:
                raise ApiError(400, 'duplicate change for "%s"' % ch["name"])
            seen.add(ch["name"])
        return changes

    @staticmethod
    def _prepare(data: dict):
        rel = data.get("file")
        p = repo_path(rel)
        raw = p.read_bytes()
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as e:
            raise ApiError(415, "file is not valid UTF-8: %s" % e)
        analysis = analyze_source(text)
        changes = Handler._validate_changes(data)
        expect = data.get("expectSha256")
        if expect:
            actual = hashlib.sha256(raw).hexdigest()
            if actual != expect:
                raise ApiError(409, "the file changed on disk since the page "
                                    "loaded it (sha256 mismatch); reload the "
                                    "file and re-apply", actual=actual,
                               expected=expect)
        new_text, edits, diff = plan_edits(text, analysis, changes)
        changed = new_text != text
        ok, detail = (True, "ok")
        if changed:
            ok, detail = self_check(text, new_text)
        post = post_check(new_text, changes, analysis) if changed else []
        return {
            "file": rel_of(p), "path": p, "text": text, "newText": new_text,
            "analysis": analysis, "changes": changes, "edits": edits,
            "diff": diff, "changed": changed,
            "selfCheck": ok, "selfCheckDetail": detail,
            "postCheck": post,
        }

    def handle_plan(self, data: dict):
        prep = self._prepare(data)
        return {
            "mode": "plan", "file": prep["file"], "changed": prep["changed"],
            "selfCheck": prep["selfCheck"], "selfCheckDetail": prep["selfCheckDetail"],
            "postCheck": prep["postCheck"],
            "edits": prep["edits"], "diff": prep["diff"],
            "sha256": hashlib.sha256(prep["text"].encode("utf-8")).hexdigest(),
            "writable": prep["changed"] and prep["selfCheck"] and not prep["postCheck"],
        }

    def handle_apply(self, data: dict):
        prep = self._prepare(data)
        if not prep["changed"]:
            return {"mode": "apply", "file": prep["file"], "changed": False,
                    "written": False, "message": "nothing to do: the requested "
                                                 "state already holds",
                    "edits": prep["edits"]}
        if not prep["selfCheck"]:
            raise ApiError(
                409,
                "refusing to write: removing every marker line from the "
                "rewritten file does not reproduce the original (the edit "
                "would touch something other than marker lines)",
                detail=prep["selfCheckDetail"])
        if prep["postCheck"]:
            raise ApiError(409, "refusing to write: the rewritten text does not "
                                "parse back to the requested state",
                           detail=prep["postCheck"])
        info = atomic_write(prep["path"], prep["newText"])
        return {
            "mode": "apply", "file": prep["file"], "changed": True, "written": True,
            "edits": prep["edits"], "diff": prep["diff"],
            "selfCheck": True, "postCheck": [],
            **info,
        }

    def handle_build(self, data: dict):
        sources = data.get("sources")
        if sources is None:
            sources = DEFAULT_SOURCES
        if isinstance(sources, str):
            sources = [s.strip() for s in sources.split(",") if s.strip()]
        if not isinstance(sources, list) or not sources:
            raise ApiError(400, "provide at least one source path")
        for s in sources:
            repo_path(s)
        seed = (data.get("seed") or "").strip()
        seed = seed or None
        if seed and not re.match(r"^(0[xX][0-9a-fA-F]+|\d+)$", seed):
            raise ApiError(400, "--seed must be a decimal or 0x-prefixed integer")
        timeout = float(data.get("timeoutSeconds") or BUILD_TIMEOUT)
        timeout = max(5.0, min(timeout, 3600.0))

        cmd = ["dart", "run", "tool/build.dart", "--source", ",".join(sources)]
        if seed:
            cmd += ["--seed", seed]
        before = {a["path"]: a["sha256"] for a in artifact_state()}
        res = run_command(cmd, timeout)
        after = artifact_state()
        changes = []
        for a in after:
            old = before.get(a["path"])
            if old == a["sha256"]:
                continue
            if old is None:
                kind = "created"
            elif a["sha256"] is None:
                kind = "removed"
            else:
                kind = "changed"
            changes.append({"path": a["path"], "kind": kind})
        for path, old in before.items():
            if path not in {a["path"] for a in after}:
                changes.append({"path": path, "kind": "removed"})
        res.update({
            "sources": sources, "seed": seed,
            "artifactChanges": changes,
            "artifacts": after,
            "manifest": manifest_summary(),
        })
        return res

    def handle_verify(self, data: dict):
        ids = data.get("tools")
        if not ids:
            ids = [t["id"] for t in VERIFY_TOOLS if t["required"]]
        if isinstance(ids, str):
            ids = [ids]
        timeout = float(data.get("timeoutSeconds") or VERIFY_TIMEOUT)
        timeout = max(5.0, min(timeout, 3600.0))
        results = []
        for tid in ids:
            tool = VERIFY_BY_ID.get(tid)
            if tool is None:
                raise ApiError(400, "unknown verify tool %r" % tid)
            r = run_command(list(tool["cmd"]), timeout)
            r.update({"id": tid, "label": tool["label"], "note": tool["note"],
                      "required": tool["required"]})
            results.append(r)
        return {"results": results,
                "allOk": all(r["ok"] for r in results if r["required"])}


# ---------------------------------------------------------------------------
# page
# ---------------------------------------------------------------------------

PAGE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>DartVMP protection UI</title>
<style>
  :root {
    --bg:#0f1216; --panel:#161b22; --panel2:#1c232c; --line:#2a3440;
    --fg:#e6edf3; --dim:#93a1b1; --accent:#4ea1ff; --ok:#3fb950; --bad:#f85149;
    --warn:#d29922; --mono:ui-monospace,SFMono-Regular,Consolas,"Liberation Mono",monospace;
  }
  * { box-sizing:border-box; }
  body { margin:0; background:var(--bg); color:var(--fg);
         font:14px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif; }
  header { display:flex; align-items:center; gap:12px; padding:14px 20px;
           border-bottom:1px solid var(--line); background:var(--panel);
           position:sticky; top:0; z-index:5; }
  header h1 { font-size:16px; margin:0; font-weight:600; }
  header .sub { color:var(--dim); font-size:12px; }
  main { max-width:1240px; margin:0 auto; padding:18px 20px 60px;
         display:flex; flex-direction:column; gap:16px; }
  section.panel { background:var(--panel); border:1px solid var(--line);
                  border-radius:8px; overflow:hidden; }
  section.panel > h2 { margin:0; padding:10px 14px; font-size:13px;
        text-transform:uppercase; letter-spacing:.08em; color:var(--dim);
        border-bottom:1px solid var(--line); background:var(--panel2);
        display:flex; align-items:center; gap:10px; }
  section.panel > h2 .grow { flex:1; }
  .body { padding:14px; }
  .row { display:flex; gap:10px; align-items:center; flex-wrap:wrap; }
  .grid2 { display:grid; grid-template-columns:260px 1fr; gap:14px; }
  @media (max-width:820px) { .grid2 { grid-template-columns:1fr; } }
  button { background:#21262d; color:var(--fg); border:1px solid var(--line);
           border-radius:6px; padding:6px 11px; cursor:pointer; font-size:13px; }
  button:hover { border-color:var(--accent); }
  button:disabled { opacity:.5; cursor:not-allowed; }
  button.primary { background:#1f6feb; border-color:#1f6feb; color:#fff; }
  button.danger { background:#3d1d1d; border-color:#6e2b2b; }
  input,select { background:#0d1117; color:var(--fg); border:1px solid var(--line);
           border-radius:6px; padding:5px 8px; font-size:13px; font-family:inherit; }
  input[type=number] { width:88px; }
  input.mono,code,pre { font-family:var(--mono); }
  .filelist { max-height:330px; overflow:auto; border:1px solid var(--line);
              border-radius:6px; }
  .filelist button { display:block; width:100%; text-align:left; border:0;
        border-radius:0; border-bottom:1px solid var(--line); padding:7px 10px;
        background:transparent; font-family:var(--mono); font-size:12px; }
  .filelist button.active { background:#1f2a37; border-left:3px solid var(--accent); }
  .filelist .meta { color:var(--dim); font-family:inherit; font-size:11px; }
  table { border-collapse:collapse; width:100%; font-size:13px; }
  th,td { text-align:left; padding:6px 8px; border-bottom:1px solid var(--line);
          vertical-align:top; }
  th { color:var(--dim); font-weight:500; font-size:11px; text-transform:uppercase;
       letter-spacing:.06em; }
  tr.changed { background:#16232e; }
  .badge { display:inline-block; padding:1px 7px; border-radius:10px; font-size:11px;
           border:1px solid var(--line); color:var(--dim); white-space:nowrap; }
  .badge.ok { color:var(--ok); border-color:#23543a; background:#0f2417; }
  .badge.bad { color:var(--bad); border-color:#5c2124; background:#2a1113; }
  .badge.warn { color:var(--warn); border-color:#5a4413; background:#2a2110; }
  pre { background:#0b0e13; border:1px solid var(--line); border-radius:6px;
        padding:10px; overflow:auto; max-height:420px; margin:6px 0 0;
        font-size:12px; white-space:pre; }
  pre.diff ins { background:#12351c; text-decoration:none; }
  .dim { color:var(--dim); }
  .muted { color:var(--dim); font-size:12px; }
  .err { color:var(--bad); white-space:pre-wrap; }
  .ok { color:var(--ok); }
  .kv { display:grid; grid-template-columns:auto 1fr; gap:2px 14px; font-size:13px; }
  .kv div:nth-child(odd) { color:var(--dim); }
  #report:empty { display:none; }
  .modal { position:fixed; inset:0; background:rgba(0,0,0,.6); display:none;
           align-items:center; justify-content:center; z-index:50; padding:20px; }
  .modal.open { display:flex; }
  .modal .box { background:var(--panel); border:1px solid var(--line);
        border-radius:10px; max-width:960px; width:100%; max-height:88vh;
        display:flex; flex-direction:column; }
  .modal h3 { margin:0; padding:12px 16px; border-bottom:1px solid var(--line);
              font-size:14px; }
  .modal .content { padding:14px 16px; overflow:auto; }
  .modal .foot { padding:12px 16px; border-top:1px solid var(--line);
                 display:flex; gap:10px; justify-content:flex-end; }
  .spin { display:inline-block; width:12px; height:12px; border:2px solid var(--dim);
          border-top-color:transparent; border-radius:50%;
          animation:sp .8s linear infinite; vertical-align:-2px; }
  @keyframes sp { to { transform:rotate(360deg); } }
  .tag { font-family:var(--mono); font-size:11px; color:var(--dim); }
  ul.tight { margin:6px 0; padding-left:20px; }
  ul.tight li { margin:2px 0; }
</style>
</head>
<body>
<header>
  <h1>DartVMP protection UI</h1>
  <span class="sub" id="rootLabel">loading&hellip;</span>
  <span class="grow" style="flex:1"></span>
  <span class="badge" id="manifestPill">manifest ?</span>
  <button onclick="refreshAll()">Reload all</button>
</header>

<main>
  <div id="fatal" class="err"></div>
  <div id="report"></div>

  <section class="panel">
    <h2>1 &middot; Sources <span class="grow"></span>
      <span class="muted">a function is protected iff a <code>// @vmp</code> marker sits above it</span>
    </h2>
    <div class="body grid2">
      <div>
        <div class="muted" style="margin-bottom:6px">under <code>protected/</code></div>
        <div class="filelist" id="filelist"></div>
        <div class="row" style="margin-top:10px">
          <input id="otherPath" class="mono" style="flex:1"
                 placeholder="any path relative to the repo root, e.g. lib/foo.dart">
          <button onclick="openOther()">Open</button>
        </div>
      </div>
      <div>
        <div id="editorHead" class="muted">Pick a file to list its top-level functions.</div>
        <div id="editor"></div>
      </div>
    </div>
  </section>

  <section class="panel">
    <h2>2 &middot; Build <span class="grow"></span>
      <span class="muted">runs <code>dart run tool/build.dart</code> from the repo root</span>
    </h2>
    <div class="body">
      <div class="row">
        <label class="muted">sources</label>
        <input id="buildSources" class="mono" style="flex:1; min-width:320px">
        <label class="muted">seed</label>
        <input id="buildSeed" class="mono" style="width:180px" placeholder="optional, 0x...">
        <button class="primary" id="buildBtn" onclick="runBuild()">Run build</button>
      </div>
      <div class="muted" style="margin-top:6px">
        Comma-separated, in module-id order. A build rewrites the generated
        artifacts; the list below shows exactly which ones changed.
      </div>
      <div id="buildResult"></div>
    </div>
  </section>

  <section class="panel">
    <h2>3 &middot; Verify <span class="grow"></span>
      <span class="muted">independent checks, repo root as working directory</span>
    </h2>
    <div class="body">
      <div class="row">
        <button class="primary" onclick="runVerify(null)">Verify all (3 required)</button>
        <span id="verifyButtons"></span>
      </div>
      <div id="verifyResult"></div>
    </div>
  </section>

  <section class="panel">
    <h2>4 &middot; Module status <span class="grow"></span>
      <button onclick="loadStatus()">Refresh</button>
    </h2>
    <div class="body" id="statusBody">loading&hellip;</div>
  </section>
</main>

<div class="modal" id="modal">
  <div class="box">
    <h3 id="modalTitle">Review changes</h3>
    <div class="content" id="modalBody"></div>
    <div class="foot" id="modalFoot"></div>
  </div>
</div>

<script>
"use strict";
const DEFAULT_PORT = __DEFAULT_PORT__;
let state = { status:null, file:null, data:null, pending:new Map(), busy:false };

function esc(s){ return String(s===null||s===undefined?"":s)
  .replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c])); }
function fmtBytes(n){ return n===null||n===undefined ? "-" : n.toLocaleString()+" B"; }
function fmtTime(t){ return t ? new Date(t*1000).toLocaleString() : "-"; }

async function api(path, opts){
  const r = await fetch(path, opts);
  const text = await r.text();
  let j = null;
  try { j = JSON.parse(text); } catch(e) {}
  if (!r.ok) {
    const msg = (j && (j.error || j.message)) || text || ("HTTP "+r.status);
    const err = new Error(msg);
    err.payload = j;
    throw err;
  }
  return j;
}
function post(path, body){
  return api(path, {method:"POST", headers:{"Content-Type":"application/json"},
                    body: JSON.stringify(body)});
}
function showReport(html, cls){
  const el = document.getElementById("report");
  el.innerHTML = '<section class="panel"><h2>Result</h2><div class="body '+
                 (cls||"")+'">'+html+'</div></section>';
}
function fatal(msg){ document.getElementById("fatal").innerHTML =
  '<section class="panel"><div class="body err">'+esc(msg)+'</div></section>'; }

/* ---------------- status ---------------- */
async function loadStatus(){
  const s = await api("/api/status");
  state.status = s;
  document.getElementById("rootLabel").textContent = s.root;
  const pill = document.getElementById("manifestPill");
  const m = s.manifest;
  if (m.present){
    pill.textContent = "build "+m.buildId+" \u00b7 "+m.functionCount+" fn";
    pill.className = "badge ok";
  } else {
    pill.textContent = "no manifest";
    pill.className = "badge warn";
  }
  renderStatus();
  // prefill build sources from the manifest that produced the current artifacts
  const bs = document.getElementById("buildSources");
  if (!bs.value) bs.value = (m.source && m.source.length ? m.source
                             : s.defaultSources).join(",");
  document.getElementById("verifyButtons").innerHTML = s.verifyTools
    .filter(t => !t.required)
    .map(t => '<button onclick="runVerify([\''+t.id+'\'])">'+esc(t.label)+'</button>')
    .join(" ");
}
function renderStatus(){
  const s = state.status; if (!s) return;
  const m = s.manifest;
  let h = "";
  if (m.present){
    h += '<div class="kv">'
      + '<div>build id</div><div class="mono">'+esc(m.buildId)+'</div>'
      + '<div>sources</div><div class="mono">'+esc((m.source||[]).join(", "))+'</div>'
      + '<div>functions</div><div>'+m.functionCount+' protected</div>'
      + '<div>container</div><div>'+fmtBytes(m.containerBytes)+' ('+fmtBytes(m.bodyBytes)+' bytecode)</div>'
      + '<div>seed</div><div class="mono">'+esc(m.seed)+'</div>'
      + '<div>body crc32</div><div class="mono">'+esc(m.bodyCrc32)+'</div>'
      + '<div>auth tag</div><div class="mono">'+esc(m.authTag)+'</div>'
      + '<div>manifest</div><div class="mono">'+esc(m.path)+' (mtime '+fmtTime(m.mtime)+')</div>'
      + '</div>';
    h += '<table style="margin-top:12px"><thead><tr><th>id</th><th>name</th>'
       + '<th>arity</th><th>returns</th><th>guard</th></tr></thead><tbody>';
    for (const f of m.functions){
      h += '<tr><td class="mono">'+f.id+'</td><td class="mono">'+esc(f.name)+'</td>'
         + '<td>'+f.arity+'</td><td class="mono">'+esc(f.returnType)+'</td>'
         + '<td>'+(f.guard ? '<span class="badge warn">'+esc(f.guard)+'</span>'
                           : '<span class="dim">none</span>')+'</td></tr>';
    }
    h += '</tbody></table>';
  } else {
    h += '<div class="warn">No <code>'+esc(m.path)+'</code>'
       + (m.error ? ' (unreadable: '+esc(m.error)+')' : '')
       + '. Run a build to generate it.</div>';
  }
  h += '<h3 style="font-size:12px;color:var(--dim);margin:16px 0 6px">GENERATED ARTIFACTS</h3>';
  h += '<table><thead><tr><th>file</th><th>state</th><th>bytes</th><th>modified</th></tr></thead><tbody>';
  for (const a of s.artifacts){
    h += '<tr><td class="mono">'+esc(a.path)+'</td>'
      + '<td>'+(a.exists ? '<span class="badge ok">present</span>'
                         : '<span class="badge bad">missing</span>')+'</td>'
      + '<td>'+(a.exists? a.bytes.toLocaleString() : "-")+'</td>'
      + '<td class="muted">'+fmtTime(a.mtime)+'</td></tr>';
  }
  h += '</tbody></table>';
  const bk = Object.entries(s.backupsThisSession||{});
  if (bk.length){
    h += '<h3 style="font-size:12px;color:var(--dim);margin:16px 0 6px">BACKUPS WRITTEN THIS SESSION</h3><ul class="tight">';
    for (const [k,v] of bk) h += '<li class="mono">'+esc(k)+' &rarr; '+esc(v)+'</li>';
    h += '</ul>';
  }
  document.getElementById("statusBody").innerHTML = h;
}

/* ---------------- sources ---------------- */
async function loadFiles(){
  const data = await api("/api/files");
  const el = document.getElementById("filelist");
  el.innerHTML = data.files.map(f =>
    '<button data-path="'+esc(f.path)+'" onclick="openFile(\''+esc(f.path)+'\')">'
    + esc(f.path)
    + '<div class="meta">'+f.protected+'/'+f.functions+' protected'
    + (f.unprotected.length ? ' \u00b7 <span style="color:var(--warn)">'+f.unprotected.length+' unprotected</span>' : '')
    + (f.problems ? ' \u00b7 <span style="color:var(--bad)">'+f.problems+' problem(s)</span>' : '')
    + (f.inDefaultSources ? ' \u00b7 default source' : '')
    + '</div></button>').join("")
    || '<div class="body muted">No .dart files under protected/.</div>';
}
function openOther(){
  const p = document.getElementById("otherPath").value.trim();
  if (p) openFile(p);
}

/* ---------------- per-file editor ---------------- */
function guardOf(fn, pend){
  if (pend) return pend.guard;
  return fn.guard;
}
function protectOf(fn, pend){ return pend ? pend.protect : fn.protect; }
function pendingFor(name){
  if (!state.pending.has(name)) state.pending.set(name, {});
  return state.pending.get(name);
}
function currentState(fn){
  const p = state.pending.get(fn.name);
  const protect = p && p.protect !== undefined ? p.protect : fn.protect;
  const guard = p && p.guard !== undefined ? p.guard : fn.guard;
  return {protect, guard: protect ? guard : null};
}
function isDirty(fn){
  const c = currentState(fn);
  return c.protect !== fn.protect || (c.protect && c.guard !== fn.guard);
}
function dirtyCount(){ return state.data ? state.data.functions.filter(isDirty).length : 0; }

async function openFile(path){
  const data = await api("/api/functions?file="+encodeURIComponent(path));
  state.file = data.file; state.data = data; state.pending = new Map();
  renderEditor();
  document.querySelectorAll("#filelist button").forEach(b => {
    b.classList.toggle("active", b.dataset.path === data.file);
  });
}
function renderEditor(){
  const d = state.data;
  if (!d){ return; }
  const head = document.getElementById("editorHead");
  const ed = document.getElementById("editor");
  let h = '<div class="row" style="justify-content:space-between">'
    + '<div><span class="mono">'+esc(d.file)+'</span> '
    + '<span class="muted">'+d.lines+' lines \u00b7 '+fmtBytes(d.bytes)+' \u00b7 '
    + d.eol+' \u00b7 sha256 '+esc(d.sha256.slice(0,12))+'</span></div>'
    + '<div>'+(d.inDefaultSources ? '<span class="badge ok">default source</span>'
                                  : '<span class="badge">not in default sources</span>')
    + ' <span class="badge '+(d.unprotected.length? 'warn':'ok')+'">'
    + (d.functions.length - d.unprotected.length)+'/'+d.functions.length
    + ' protected</span></div></div>';

  if (d.problems.length){
    h += '<div class="err" style="margin-top:10px"><b>The VMP compiler will reject this file:</b><ul class="tight">'
      + d.problems.map(p => '<li>line '+p.line+': '+esc(p.message)
          +' <span class="tag">'+esc(p.text)+'</span></li>').join("")
      + '</ul></div>';
  }
  if (!d.functions.length){
    h += '<div class="muted" style="margin-top:10px">No top-level function declarations found.</div>';
    ed.innerHTML = h; return;
  }

  h += '<table style="margin-top:10px"><thead><tr>'
    + '<th>protect</th><th>function</th><th>line</th><th>now</th>'
    + '<th>guard policy</th><th>pending</th></tr></thead><tbody>';
  for (const fn of d.functions){
    const cur = currentState(fn);
    const dirty = isDirty(fn);
    h += '<tr class="'+(dirty?'changed':'')+'">';
    h += '<td><input type="checkbox" '+(cur.protect?'checked':'')
       + (fn.toggleable?'':' disabled')
       + ' onchange="setProtect(\''+esc(fn.name)+'\', this.checked)"></td>';
    h += '<td class="mono">'+esc(fn.signature)
       + (fn.toggleable?'':'<div class="muted">'+esc(fn.blocker||'not editable')+'</div>')
       + '</td>';
    h += '<td class="mono">'+fn.line+'</td>';
    h += '<td>'+(fn.protect
            ? '<span class="badge ok">'+(fn.markerStyle==='annotation'?'@vmp annotation':'// @vmp')
              +' line '+fn.markerLines.join(",")+'</span>'
            : '<span class="badge bad">unprotected</span>')
       + (fn.guard ? ' <span class="badge warn">'+esc(fn.guard)+'</span>' : '')+'</td>';
    h += '<td>'+guardControls(fn, cur)+'</td>';
    h += '<td>'+(dirty ? '<span class="badge warn">'+esc(pendingLabel(fn))+'</span>'
                       : '<span class="dim">no change</span>')+'</td>';
    h += '</tr>';
  }
  h += '</tbody></table>';
  h += '<div class="row" style="margin-top:12px">'
    + '<button class="primary" id="applyBtn" onclick="reviewChanges()" '
    + (dirtyCount()? '' : 'disabled')+'>Review &amp; apply '+dirtyCount()+' change(s)</button>'
    + '<button onclick="openFile(state.file)">Discard pending</button>'
    + '<span class="muted">Only the <code>// @vmp</code> marker lines above the selected '
    + 'declarations are written. The file is rewritten atomically after a '
    + 'self-check, and the first write makes a <code>.bak</code>.</span></div>';
  ed.innerHTML = h;
}
function guardControls(fn, cur){
  if (!cur.protect) return '<span class="dim">n/a</span>';
  const g = cur.guard || "";
  const kind = !g ? "none" : (g === "once" ? "once" : "rate");
  const m = /^rate=(\d+)\/(\d+)$/.exec(g);
  let h = '<select onchange="setGuardKind(\''+esc(fn.name)+'\', this.value)">'
    + ['none','once','rate'].map(k => '<option value="'+k+'"'+(k===kind?' selected':'')+'>'+k+'</option>').join("")
    + '</select>';
  if (kind === 'rate'){
    h += ' <input type="number" min="1" value="'+(m?m[1]:4096)+'" '
       + 'onchange="setGuardRate(\''+esc(fn.name)+'\')" id="gb-'+esc(fn.name)+'" title="budget (calls)">'
       + ' <span class="dim">calls /</span> '
       + ' <input type="number" min="1" value="'+(m?m[2]:1000)+'" '
       + 'onchange="setGuardRate(\''+esc(fn.name)+'\')" id="gw-'+esc(fn.name)+'" title="window (ms)"> ms';
  }
  return h;
}
function pendingLabel(fn){
  const cur = currentState(fn);
  if (!cur.protect) return "marker will be removed";
  if (!fn.protect) return "marker will be added" + (cur.guard? " ("+cur.guard+")":"");
  return "guard \u2192 " + (cur.guard || "none");
}
function setProtect(name, val){
  const p = pendingFor(name); p.protect = val;
  if (val && p.guard === undefined){
    const fn = state.data.functions.find(f=>f.name===name);
    p.guard = fn.guard;
  }
  renderEditor();
}
function setGuardKind(name, kind){
  const p = pendingFor(name);
  if (kind === 'none') p.guard = null;
  else if (kind === 'once') p.guard = 'once';
  else p.guard = 'rate='+(document.getElementById('gb-'+name).value||4096)
                       +'/'+(document.getElementById('gw-'+name).value||1000);
  renderEditor();
}
function setGuardRate(name){
  const b = document.getElementById('gb-'+name).value || 4096;
  const w = document.getElementById('gw-'+name).value || 1000;
  pendingFor(name).guard = 'rate='+b+'/'+w;
  renderEditor();
}
function collectChanges(){
  return state.data.functions.filter(isDirty).map(fn => {
    const c = currentState(fn);
    return {name: fn.name, protect: c.protect, guard: c.guard};
  });
}

/* ---------------- review + apply ---------------- */
function closeModal(){ document.getElementById("modal").classList.remove("open"); }
function openModal(title, html, buttons){
  document.getElementById("modalTitle").textContent = title;
  document.getElementById("modalBody").innerHTML = html;
  const foot = document.getElementById("modalFoot");
  foot.innerHTML = "";
  for (const b of buttons){
    const el = document.createElement("button");
    el.textContent = b.label;
    if (b.cls) el.className = b.cls;
    el.onclick = b.onClick;
    foot.appendChild(el);
  }
  document.getElementById("modal").classList.add("open");
}
function diffHtml(diff){
  if (!diff || !diff.length) return '<div class="muted">no line changes</div>';
  return '<pre class="diff">' + diff.map(l => {
    const c = l.startsWith('+') && !l.startsWith('+++') ? 'ok'
            : l.startsWith('-') && !l.startsWith('---') ? 'err' : 'dim';
    return '<span class="'+c+'">'+esc(l)+'</span>';
  }).join("\n") + '</pre>';
}
function planHtml(p){
  let h = '<div class="kv"><div>file</div><div class="mono">'+esc(p.file)+'</div>'
    + '<div>self-check</div><div>'+(p.selfCheck
        ? '<span class="badge ok">removing marker lines reproduces the original byte-for-byte</span>'
        : '<span class="badge bad">FAILED</span>')+'</div>'
    + '<div>post-parse</div><div>'+(p.postCheck.length
        ? '<span class="badge bad">'+esc(p.postCheck.join("; "))+'</span>'
        : '<span class="badge ok">rewritten text parses to the requested state</span>')+'</div></div>';
  h += '<h4 style="margin:14px 0 4px;font-size:13px">Per-function edits</h4><ul class="tight">';
  for (const e of p.edits){
    h += '<li><span class="mono">'+esc(e.name)+'</span> \u2014 '+esc(e.action)
       + ': '+esc(e.detail) + (e.removedLines.length
          ? ' <span class="err">'+(e.removedLines.map(r=>'&minus;'+r.line).join(' '))+'</span>' : '')
       + (e.addedLines.length
          ? ' <span class="ok">'+(e.addedLines.map(r=>'+'+r.line).join(' '))+'</span>' : '')
       + '</li>';
  }
  h += '</ul>';
  if (!p.selfCheck) h += '<pre class="err">'+esc(p.selfCheckDetail)+'</pre>';
  h += '<h4 style="margin:14px 0 4px;font-size:13px">Unified diff (yellow = new file content)</h4>' + diffHtml(p.diff);
  return h;
}
async function reviewChanges(){
  const changes = collectChanges();
  if (!changes.length) return;
  openModal("Planning\u2026", '<div class="muted">computing the minimal marker-line edit\u2026</div>',
            [{label:"Cancel", onClick:closeModal}]);
  let p;
  try {
    p = await post("/api/plan", {file: state.file, changes,
                                 expectSha256: state.data.sha256});
  } catch (e) {
    openModal("Plan failed", '<div class="err">'+esc(e.message)+'</div>',
              [{label:"Close", onClick:closeModal}]);
    return;
  }
  const buttons = [{label:"Cancel", onClick:closeModal}];
  if (p.writable){
    buttons.push({label:"Write to "+p.file, cls:"primary", onClick:async () => {
      closeModal();
      await applyChanges(changes);
    }});
  } else {
    buttons.push({label:"Nothing to write", cls:"primary", onClick:closeModal});
  }
  openModal("Review: "+changes.length+" change(s) in "+p.file, planHtml(p), buttons);
}
async function applyChanges(changes){
  showReport('<span class="spin"></span> writing\u2026');
  let r;
  try {
    r = await post("/api/apply", {file: state.file, changes,
                                  expectSha256: state.data.sha256});
  } catch (e) {
    showReport('<b>Write refused.</b><div class="err">'+esc(e.message)+'</div>'
      + (e.payload && e.payload.detail
          ? '<pre class="err">'+esc(JSON.stringify(e.payload.detail,null,1))+'</pre>' : ''));
    return;
  }
  let h = '';
  if (!r.written){
    h = '<b>Nothing written.</b> <span class="muted">'+esc(r.message)+'</span>';
  } else {
    h = '<b>Wrote '+esc(r.file)+'</b><ul class="tight">'
      + '<li>backup: <span class="mono">'+esc(r.backup)+'</span></li>'
      + '<li>bytes: '+r.bytesBefore+' &rarr; '+r.bytesAfter+'</li>'
      + '<li>sha256: <span class="mono">'+esc(r.sha256Before.slice(0,16))+'</span> &rarr; '
      + '<span class="mono">'+esc(r.sha256After.slice(0,16))+'</span></li>'
      + '<li>self-check: <span class="ok">removing marker lines reproduces the original</span></li>'
      + '<li>post-parse: <span class="ok">all requested states hold, nothing else moved</span></li>'
      + '</ul><h4 style="margin:14px 0 4px;font-size:13px">What changed</h4>'
      + diffHtml(r.diff);
  }
  showReport(h);
  await openFile(state.file);
  await loadFiles();
  await loadStatus();
}

/* ---------------- build ---------------- */
async function runBuild(){
  const btn = document.getElementById("buildBtn");
  const sources = document.getElementById("buildSources").value
                    .split(",").map(s=>s.trim()).filter(Boolean);
  const seed = document.getElementById("buildSeed").value.trim();
  btn.disabled = true; btn.textContent = "Building\u2026";
  document.getElementById("buildResult").innerHTML =
    '<div class="muted" style="margin-top:10px"><span class="spin"></span> '
    + 'dart run tool/build.dart \u2014 this takes a while\u2026</div>';
  try {
    const r = await post("/api/build", {sources, seed: seed || null});
    renderBuild(r);
  } catch (e) {
    document.getElementById("buildResult").innerHTML =
      '<div class="err" style="margin-top:10px">'+esc(e.message)+'</div>';
  } finally {
    btn.disabled = false; btn.textContent = "Run build";
    await loadStatus();
  }
}
function renderBuild(r){
  const okBadge = r.ok ? '<span class="badge ok">exit 0</span>'
                       : '<span class="badge bad">exit '+esc(r.exitCode)+'</span>';
  let h = '<div class="row" style="margin-top:10px">'+okBadge
    + '<span class="muted">'+esc((r.durationMs/1000).toFixed(1))+'s</span>'
    + '<span class="tag">'+esc(r.command)+'</span></div>';
  if (r.artifactChanges && r.artifactChanges.length){
    h += '<h4 style="margin:12px 0 4px;font-size:13px">Artifacts rewritten</h4><ul class="tight">';
    for (const c of r.artifactChanges)
      h += '<li><span class="badge '+(c.kind==='removed'?'bad':'warn')+'">'+esc(c.kind)+'</span>'
         + ' <span class="mono">'+esc(c.path)+'</span></li>';
    h += '</ul>';
  } else {
    h += '<div class="muted" style="margin-top:8px">No generated artifact changed content.</div>';
  }
  const m = r.manifest;
  if (m && m.present){
    h += '<h4 style="margin:12px 0 4px;font-size:13px">vmp_manifest.json</h4>'
      + '<div class="kv"><div>build id</div><div class="mono">'+esc(m.buildId)+'</div>'
      + '<div>functions</div><div>'+m.functionCount+'</div>'
      + '<div>container</div><div>'+fmtBytes(m.containerBytes)+' (bytecode '+fmtBytes(m.bodyBytes)+')</div>'
      + '<div>seed</div><div class="mono">'+esc(m.seed)+'</div></div>'
      + '<table style="margin-top:8px"><thead><tr><th>id</th><th>name</th><th>arity</th>'
      + '<th>returns</th><th>guard</th></tr></thead><tbody>'
      + m.functions.map(f=>'<tr><td class="mono">'+f.id+'</td><td class="mono">'+esc(f.name)
          +'</td><td>'+f.arity+'</td><td class="mono">'+esc(f.returnType)+'</td><td>'
          +(f.guard?'<span class="badge warn">'+esc(f.guard)+'</span>':'<span class="dim">none</span>')
          +'</td></tr>').join("")
      + '</tbody></table>';
  } else if (m && m.error){
    h += '<div class="err" style="margin-top:10px">manifest unreadable: '+esc(m.error)+'</div>';
  }
  if (r.stdout) h += '<h4 style="margin:12px 0 4px;font-size:13px">stdout</h4><pre>'+esc(r.stdout)+'</pre>';
  if (r.stderr) h += '<h4 style="margin:12px 0 4px;font-size:13px">stderr</h4><pre class="err">'+esc(r.stderr)+'</pre>';
  h += '<div class="muted" style="margin-top:8px">exit code '
     + esc(r.exitCode) + (r.timedOut ? ' (timed out, killed)' : '') + '</div>';
  document.getElementById("buildResult").innerHTML = h;
}

/* ---------------- verify ---------------- */
async function runVerify(ids){
  const target = ids && ids.length ? ids : null;
  document.getElementById("verifyResult").innerHTML =
    '<div class="muted" style="margin-top:10px"><span class="spin"></span> running\u2026</div>';
  try {
    const r = await post("/api/verify", {tools: target});
    let h = '<div class="row" style="margin-top:10px">'
      + (r.allOk ? '<span class="badge ok">all required checks pass</span>'
                 : '<span class="badge bad">at least one required check failed</span>')
      + '</div>';
    for (const t of r.results){
      h += '<div style="margin-top:12px"><div class="row">'
        + (t.ok ? '<span class="badge ok">PASS</span>' : '<span class="badge bad">FAIL</span>')
        + '<b>'+esc(t.label)+'</b>'
        + '<span class="muted">exit '+esc(t.exitCode)+' \u00b7 '+esc((t.durationMs/1000).toFixed(1))+'s</span>'
        + '<span class="tag">'+esc(t.command)+'</span></div>'
        + '<div class="muted">'+esc(t.note)+'</div>';
      if (t.stdout) h += '<pre>'+esc(t.stdout)+'</pre>';
      if (t.stderr) h += '<pre class="err">'+esc(t.stderr)+'</pre>';
      h += '</div>';
    }
    document.getElementById("verifyResult").innerHTML = h;
  } catch (e) {
    document.getElementById("verifyResult").innerHTML =
      '<div class="err" style="margin-top:10px">'+esc(e.message)+'</div>';
  }
}

/* ---------------- boot ---------------- */
async function refreshAll(){
  try {
    await loadStatus();
    await loadFiles();
    if (state.file) await openFile(state.file);
  } catch (e) { fatal(e.message); }
}
document.addEventListener("keydown", e => { if (e.key === "Escape") closeModal(); });
refreshAll();
</script>
</body>
</html>
"""


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

PORT = 8777
BUILD_TIMEOUT = 600.0
VERIFY_TIMEOUT = 300.0


def main(argv=None) -> int:
    global PORT, BUILD_TIMEOUT, VERIFY_TIMEOUT
    ap = argparse.ArgumentParser(
        description="Local DartVMP protection UI (stdlib only).")
    ap.add_argument("--port", type=int, default=8777,
                    help="TCP port on 127.0.0.1 (default 8777)")
    ap.add_argument("--no-browser", action="store_true",
                    help="do not open the page in the default browser")
    ap.add_argument("--build-timeout", type=float, default=600.0,
                    help="seconds before a build is killed (default 600)")
    ap.add_argument("--verify-timeout", type=float, default=300.0,
                    help="seconds before a verify command is killed (default 300)")
    args = ap.parse_args(argv)

    PORT = args.port
    BUILD_TIMEOUT = args.build_timeout
    VERIFY_TIMEOUT = args.verify_timeout

    if not (ROOT / "tool" / "build.dart").is_file():
        sys.stderr.write("serve.py: %s does not look like the repository root "
                         "(tool/build.dart is missing)\n" % ROOT)
        return 2

    httpd = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    httpd.daemon_threads = True
    url = "http://127.0.0.1:%d/" % PORT
    print("DartVMP protection UI")
    print("  repo root : %s" % ROOT)
    print("  listening : %s (localhost only)" % url)
    print("  stop with : Ctrl+C")
    sys.stdout.flush()
    if not args.no_browser:
        threading.Timer(0.4, lambda: webbrowser.open(url)).start()
    try:
        httpd.serve_forever(poll_interval=0.25)
    except KeyboardInterrupt:
        print("\nstopping...")
    finally:
        httpd.shutdown()
        httpd.server_close()
        print("server stopped; no socket left open")
    return 0


if __name__ == "__main__":
    sys.exit(main())
