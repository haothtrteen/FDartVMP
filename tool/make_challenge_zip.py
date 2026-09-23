#!/usr/bin/env python3
"""Rebuilds the challenge zip from the current protected APK.

Kept as a script rather than a shell one-liner because it has to do three things that a
zip command cannot: carry the previous README.txt forward, restamp the two lines that
describe the artifact (size and SHA-256), and prove the APK it packed is the one that
contains the virtualized library.

    python tool/make_challenge_zip.py
"""
from __future__ import annotations

import hashlib
import pathlib
import re
import sys
import zipfile

REPO = pathlib.Path(__file__).resolve().parent.parent
APK = REPO / "build" / "app-vmpprotected.apk"
OUT_ZIP = REPO / "build" / "FDartVMP-challenge.zip"
STAGE = REPO / "build" / "zipstage-challenge" / "FDartVMP-challenge"
README_SRC = REPO / "build" / "FDartVMP-challenge.zip"


def main() -> int:
    if not APK.exists():
        raise SystemExit(f"FAIL: {APK} not found - run tool/test.ps1 -Release first")
    data = APK.read_bytes()
    sha = hashlib.sha256(data).hexdigest()

    if not README_SRC.exists():
        raise SystemExit(
            f"FAIL: {README_SRC} not found, so there is no README.txt to carry forward. "
            f"Write build/zipstage-challenge/FDartVMP-challenge/README.txt by hand."
        )
    readme = zipfile.ZipFile(README_SRC).read("FDartVMP-challenge/README.txt").decode("utf-8")
    readme = re.sub(
        r"Target  : .*",
        f"Target  : FDartVMP-challenge.apk  ({len(data) / 1048576:.1f} MB, arm64-v8a, Android 8.0+)",
        readme,
        count=1,
    )
    readme = re.sub(r"SHA-256 : .*", f"SHA-256 : {sha}", readme, count=1)

    # The APK has to be the one with the virtualized runtime in it, not a plain build.
    with zipfile.ZipFile(APK) as z:
        lib = z.read("lib/arm64-v8a/libdartvmp.so")
    lib_sha = hashlib.sha256(lib).hexdigest()[:16]
    protected = hashlib.sha256((REPO / "build" / "libdartvmp.vmpprotected.so").read_bytes()).hexdigest()[:16]
    if lib_sha != protected:
        raise SystemExit(
            f"FAIL: the APK's libdartvmp.so ({lib_sha}) is not the VMPacker output "
            f"({protected}) - this would ship a challenge whose C layer is not virtualized."
        )
    if len(lib) < 60000:
        raise SystemExit(f"FAIL: libdartvmp.so in the APK is only {len(lib)} bytes")

    STAGE.mkdir(parents=True, exist_ok=True)
    (STAGE / "FDartVMP-challenge.apk").write_bytes(data)
    (STAGE / "CHALLENGE.md").write_bytes((REPO / "docs" / "CHALLENGE.md").read_bytes())
    (STAGE / "README.txt").write_text(readme, encoding="utf-8", newline="\r\n")

    OUT_ZIP.unlink(missing_ok=True)
    with zipfile.ZipFile(OUT_ZIP, "w", zipfile.ZIP_DEFLATED) as z:
        for f in sorted(STAGE.iterdir()):
            z.write(f, f"FDartVMP-challenge/{f.name}")

    print(f"apk            : {APK.name} ({len(data)} bytes)")
    print(f"apk sha256     : {sha}")
    print(f"libdartvmp.so  : {len(lib)} bytes, sha256[:16]={lib_sha} (matches the VMPacker output)")
    print(f"written        : {OUT_ZIP.relative_to(REPO)} ({OUT_ZIP.stat().st_size} bytes)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
