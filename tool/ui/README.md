# Local protection UI for DartVMP

A single-page web UI for the one part of this project that is otherwise a
hand-editing job: deciding **which Dart functions become `// @vmp` protected**,
and with what call policy.

It is a stdlib-only Python HTTP server (`serve.py`) plus one self-contained HTML
page (inline CSS/JS, no CDN, no external asset, works offline). It talks to the
same CLI entry points the repository already uses; it does not reimplement the
compiler, and nothing outside this directory depends on it.

## Run it

```powershell
# from anywhere; the server always operates on the repo root it lives in
python tool\ui\serve.py                    # http://127.0.0.1:8777, opens a browser
python tool\ui\serve.py --port 9000        # different port
python tool\ui\serve.py --no-browser       # don't launch a browser
python tool\ui\serve.py --build-timeout 1800 --verify-timeout 600

# or the launcher
powershell -ExecutionPolicy Bypass -File tool\ui\serve.ps1 -Port 8777 -NoBrowser
```

Binds `127.0.0.1` only. `Ctrl+C` stops it and closes the socket.

## What it does

1. **Source browser** — lists `*.dart` under `protected/` recursively (with a
   protected/unprotected count per file) and can open any `.dart` path typed
   relative to the repository root.
2. **Per-file function view** — for every *top-level* function declaration it
   shows the name, the signature, the line number, whether a `// @vmp` marker
   currently sits above it, and the guard policy that marker carries.
   Unmarked functions are listed too, so unprotected code is visible rather
   than implied. The parse is done in Python (comment/string-blanked text, brace
   depth for top-level-ness, multi-line signatures, `@vmp` annotations); the
   Dart tooling is not imported and no code is executed to inspect a file.
3. **Toggle protection** — a checkbox per function plus a guard control
   (`none` / `once` / `rate=BUDGET/WINDOW_MS`), matching exactly what
   `tool/vmpc/lib/src/dart_source.dart` `injectMarkers()` accepts. A malformed
   marker or guard already present in a file is reported as a build-blocking
   problem instead of being silently ignored.
4. **Review before write** — "Review & apply" first POSTs a dry run that returns
   the per-function actions, the marker lines to remove/add, the result of the
   write self-check, and a unified diff. Nothing is written until the second
   explicit confirmation in that dialog.
5. **Build** — runs `dart run tool/build.dart --source a,b [--seed 0x...]` from
   the repository root and shows the exit code, combined stdout/stderr, the
   duration, **which generated artifacts changed**, and a rendered
   `vmp_manifest.json` summary (build id, function ids/names/arities/guards,
   container and bytecode sizes, seed).
6. **Verify** — one button (or one per tool) for
   `dart run tool/vmpc/bin/vmpc.dart check`,
   `python tool/verify_descriptors.py`, `python tool/walk_bytecode.py`, plus an
   optional `powershell -ExecutionPolicy Bypass -File tool/verify_crypto.ps1`.
   Each shows PASS/FAIL, the exit code, the duration and the full output.
   Commands run with the repo root as the working directory.
7. **Status panel on load** — the current manifest (or a clear "not built yet"),
   plus present/missing state, size and mtime of every generated stub/oracle/
   header/evicted file, and the `.bak` copies written during the session.

The full `tool/test.ps1` suite is deliberately **not** wired to any button: it
is slow, and the UI is an addition to that flow, not a replacement for it.

## The write path (why it is safe to click)

Only one code path in `serve.py` writes to a source file, and it can only touch
lines that are (or claim to be) `// @vmp` marker comments:

* The change is computed as a set of *line deletions* and *line insertions* at
  the marker block of the selected declarations. A new marker goes at the top of
  the contiguous comment block directly above the declaration; a removal deletes
  the existing marker lines; a guard change replaces the marker block with one
  canonical `// @vmp guard:...` line.
* **Self-check before writing**: the file with every marker line removed must be
  byte-identical to the new file with every marker line removed. If that fails,
  the server refuses to write and shows the differing lines. This makes "no
  reformatting, no re-wrapping, no touching anything else, no newline style
  change" a checked property rather than a promise.
* **Post-parse check**: the rewritten text is re-parsed and every requested
  state must hold, while every function that was not part of the request must be
  unchanged. A failure also refuses the write.
* **Stale-hash check**: the page sends the `sha256` it loaded; if the file
  changed on disk meanwhile the write is rejected with 409.
* **Backup**: the first time a file is modified in a session it is copied to
  `<file>.bak` (`<file>.bak.1`, `.bak.2`, … if a backup already exists — an
  existing backup is never overwritten). The exact path is reported in the UI.
* **Atomic write**: bytes are written to a temp file in the same directory,
  fsynced and `os.replace`d over the original.
* Paths are restricted to `.dart` files inside the repository root; `..`
  escapes and absolute paths are rejected.

## JSON API

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/` | the page |
| GET | `/api/status` | manifest summary, artifact state, config |
| GET | `/api/files` | `*.dart` under `protected/` + per-file counts |
| GET | `/api/functions?file=PATH` | parsed top-level functions + marker/guard state, `sha256`, problems |
| GET | `/api/manifest` | raw `app/test/generated/vmp_manifest.json` |
| POST | `/api/plan` | dry run: `{file, changes:[{name,protect,guard}], expectSha256?}` |
| POST | `/api/apply` | same body, writes atomically after the checks pass |
| POST | `/api/build` | `{sources:[...], seed?, timeoutSeconds?}` |
| POST | `/api/verify` | `{tools:["check","descriptors","walk","crypto"], timeoutSeconds?}` |

Failures are non-200 JSON objects `{"error": ..., "status": ...}`; command
failures always include the real exit code and stderr.

## Limits

* Localhost tool, no authentication. Anything that can reach `127.0.0.1:8777`
  can edit marker lines under the repository root; do not put it behind a
  proxy or bind it to a public interface.
* It understands **top-level function declarations** only — the same surface
  `vmpc` protects. Class members, closures, getters and generics are not
  offered for toggling (class members are ignored by the top-level scan).
* Functions protected by a bare `@vmp` *annotation* (rather than a `// @vmp`
  comment) are shown as protected but are not editable from the UI; the server
  returns 409 and says so.
* The declaration scan is a careful Python parse, not the Dart analyzer: exotic
  formatting (e.g. function types as return types, `=>` bodies split across
  many lines) may be reported as "no top-level function declarations found".
  Use `vmpc build` as the authority.
* A build without `--seed` uses a fresh random seed, so the generated artifacts
  (all gitignored) change on every build. The UI lists exactly which ones.
* `verify_crypto.ps1` needs the built native library / APK on disk and is
  therefore optional and not part of "Verify all".
* This does not run `tool/test.ps1` and does not build the native library. After
  changing the protection surface, run the normal flow yourself:
  `powershell -ExecutionPolicy Bypass -File tool/test.ps1`.
