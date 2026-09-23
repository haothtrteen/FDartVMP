#!/usr/bin/env python3
"""Rebuild an APK with one or more entries replaced, preserving how each entry is stored.

WHY THIS IS PYTHON AND NOT .NET's ZipArchive
--------------------------------------------
Android maps native libraries straight out of the APK when the app is built with
`android:extractNativeLibs="false"` (Flutter's release default), which requires those
entries to be **stored** (compression method 0) and page-aligned. Nothing in the APK
says so, the build succeeds, and the failure arrives at `adb install` as

    INSTALL_FAILED_INVALID_APK: Failed to extract native libraries, res=-2

which names neither the entry nor compression.

The first version of tool/repack_apk.ps1 rebuilt the archive with
`ZipArchive.CreateEntry(name)`, and that overload defaults to *Deflate* - so every entry
it rewrote came back compressed, including `libflutter.so`, `libapp.so` and the
`libdartvmp.so` it was replacing. The original archived had them stored, the repacked one
did not, and the APK stopped installing (measured: `method=0` before, `method=8` after).
`.NET`'s API exposes no way to read or set an entry's compression method directly, which
is why guessing went wrong in the first place; Python's `zipfile` has `ZipInfo
.compress_type` and copies it verbatim.

The check that this stays true is in the caller: after repacking, every `lib/**/*.so`
must be stored, and zipalign must still report the shared objects as page-aligned.
"""
import argparse
import pathlib
import shutil
import sys
import zipfile

# Entries that must be stored: the loader mmaps these directly. Matched by prefix and
# suffix rather than by exact name, so adding an ABI or a second library cannot quietly
# reintroduce the bug.
LIB_PREFIX = "lib/"
LIB_SUFFIX = ".so"


def must_be_stored(name: str) -> bool:
    """True for entries Android maps out of the APK rather than extracting."""
    return name.startswith(LIB_PREFIX) and name.endswith(LIB_SUFFIX)


def check(apk: str) -> int:
    """Report the storage of every native library in `apk`.

    Exit code is the gate: non-zero means at least one library that Android will try to
    mmap is compressed, which is the `INSTALL_FAILED_INVALID_APK: Failed to extract
    native libraries` failure this whole file exists for.
    """
    with zipfile.ZipFile(apk) as z:
        libs = [i for i in z.infolist() if must_be_stored(i.filename)]
        if not libs:
            print(f"{apk}: no native libraries found - the repack replaced nothing?")
            return 1
        bad = [i for i in libs if i.compress_type != zipfile.ZIP_STORED]
        for i in libs:
            how = "stored" if i.compress_type == zipfile.ZIP_STORED else f"COMPRESSED (method {i.compress_type})"
            print(f"  {i.filename}: {how}, {i.file_size} bytes")
    if bad:
        print(f"{apk}: {len(bad)} native library/libraries are compressed and will not load")
        return 1
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--apk", required=True)
    ap.add_argument("--out")
    ap.add_argument(
        "--check-only",
        action="store_true",
        help="report how every native library is stored in --apk and exit",
    )
    ap.add_argument(
        "--replace",
        action="append",
        default=[],
        metavar="ENTRY=PATH",
        help="replace ENTRY with the contents of PATH (repeatable)",
    )
    args = ap.parse_args()

    if args.check_only:
        return check(args.apk)
    if not args.out:
        raise SystemExit("--out is required unless --check-only is given")

    # `ENTRY=PATH` with a split on the first '=' only: a Windows path contains no '=',
    # but an entry name might in principle, and splitting from the right would break
    # paths that do.
    replacements = {}
    for spec in args.replace:
        if "=" not in spec:
            raise SystemExit(f"bad --replace spec {spec!r}; expected ENTRY=PATH")
        entry, path = spec.split("=", 1)
        src = pathlib.Path(path)
        if not src.is_file():
            raise SystemExit(f"replacement source not found: {path}")
        replacements[entry] = src
        print(f"  {entry}  <-  {path} ({src.stat().st_size} bytes)")

    apk = pathlib.Path(args.apk)
    out = pathlib.Path(args.out)
    if not apk.is_file():
        raise SystemExit(f"input APK not found: {apk}")
    out.parent.mkdir(parents=True, exist_ok=True)
    tmp = out.with_suffix(out.suffix + ".tmp")
    tmp.unlink(missing_ok=True)

    replaced = 0
    stored_libs = 0
    with zipfile.ZipFile(apk) as zin, zipfile.ZipFile(tmp, "w") as zout:
        for info in zin.infolist():
            name = info.filename
            # Drop the existing signature: a re-signed APK must not carry the old
            # META-INF, and leaving it in produces "invalid signature" rather than
            # "unsigned".
            if name.startswith("META-INF/"):
                continue

            data = replacements[name].read_bytes() if name in replacements else zin.read(name)
            if name in replacements:
                replaced += 1

            new = zipfile.ZipInfo(name, date_time=info.date_time)
            new.compress_type = info.compress_type
            new.external_attr = info.external_attr
            new.internal_attr = info.internal_attr
            new.create_system = info.create_system
            # Belt and braces: a native library is stored whatever the input said, so a
            # correctly-stored input and a future caller that hands over an APK built
            # with extractNativeLibs=true both come out loadable.
            if must_be_stored(name):
                new.compress_type = zipfile.ZIP_STORED
                stored_libs += 1
            zout.writestr(new, data)

    missing = [e for e in replacements if e not in zipfile.ZipFile(apk).namelist()]
    if missing:
        tmp.unlink(missing_ok=True)
        raise SystemExit(f"these -Replace entries are not in {apk}: {missing}")
    if replaced != len(replacements):
        tmp.unlink(missing_ok=True)
        raise SystemExit(f"replaced {replaced} of {len(replacements)} entries; an entry name is wrong")

    # Report the storage of every native library in the *output*, not just the replaced
    # one: the failure mode this file exists for was a neighbouring entry (libflutter.so)
    # silently losing its storage.
    with zipfile.ZipFile(tmp) as z:
        bad = [
            i.filename
            for i in z.infolist()
            if must_be_stored(i.filename) and i.compress_type != zipfile.ZIP_STORED
        ]
    if bad:
        tmp.unlink(missing_ok=True)
        raise SystemExit("these native libraries would not be loadable (compressed): " + ", ".join(bad))

    shutil.move(str(tmp), str(out))
    print(f"rebuilt with {replaced} replacement(s); {stored_libs} native libraries stored uncompressed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
