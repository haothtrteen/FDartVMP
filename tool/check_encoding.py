#!/usr/bin/env python3
"""Every text file in the repository must be valid UTF-8.

WHY THIS EXISTS, AS A SPECIFIC INCIDENT
---------------------------------------
README.md spent part of this session as an invalid-UTF-8 file. The cause was a shell idiom,
not a bad edit: `Get-Content -Raw` followed by `Set-Content -Encoding utf8` on a CP936
console decodes the file's UTF-8 bytes as CP936 and writes the result back, so every
non-ASCII character becomes a `?`-terminated remnant (`e2 80 3f` where an em dash was) and
the byte after it is consumed. It ran twice, so the damage compounded.

What made it expensive rather than merely annoying:

  * the transformation is **lossy** - the trailing byte is gone, so it cannot be inverted;
    the original characters had to be re-derived from context (see the recovery notes in
    build/, and the README's own account of it);
  * nothing failed. The build was green, the tests passed, and `read` on the file simply
    said "invalid UTF-8" - so the first symptom was a confusing tool error, not a broken
    document;
  * it happened while *editing documentation*, i.e. in the one place with no test.

So this is a check, not a note. It walks the repository's text files, requires each to
decode as UTF-8, and reports the offending byte offset. Run by `tool/test.ps1`, so the
class of mistake cannot be silent again.
"""
import pathlib
import sys

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except (AttributeError, OSError):
    pass

ROOT = pathlib.Path(__file__).resolve().parent.parent
SKIP_DIRS = {".git", "build", ".dart_tool", "node_modules", "ephemeral", "windows",
             "linux", "macos", "ios", "blutter", "__pycache__"}
TEXTUAL = {".md", ".dart", ".c", ".h", ".txt", ".ps1", ".py", ".yaml", ".yml", ".gradle",
           ".properties", ".json", ".kts", ".inc", ".in", ".map", ".sh", ".cmake", ".md.in"}

bad = []
checked = 0
for path in sorted(ROOT.rglob("*")):
    if not path.is_file():
        continue
    if any(part in SKIP_DIRS for part in path.relative_to(ROOT).parts):
        continue
    if path.suffix not in TEXTUAL:
        continue
    checked += 1
    raw = path.read_bytes()
    try:
        raw.decode("utf-8")
    except UnicodeDecodeError as e:
        bad.append((path.relative_to(ROOT), e.start))

print(f"encoding check: {checked} text files scanned")
if bad:
    for path, at in bad:
        print(f"  PROBLEM {path}: not valid UTF-8 (first bad byte at offset {at})")
    print("  These files were probably rewritten by a shell round-trip "
          "(Get-Content/Set-Content on a CP936 console). Repair the bytes before "
          "editing further: a UTF-8 file read as CP936 loses the trailing byte of every "
          "non-ASCII character.")
    sys.exit(1)
print("  ok    every text file is valid UTF-8")
sys.exit(0)
