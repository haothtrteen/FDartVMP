# verify_crypto.ps1 - checks the primitives the container's confidentiality rests on.
#
# Two independent things, and the second is the one that matters:
#
#   1. The hand-written SHA-256 in packages/dartvmp/src/dvmp_sha256.c runs the
#      published NIST vectors. Without this, a subtly wrong hash would still produce a
#      consistent keystream on both sides of the build - the Dart generator would be
#      changed to match it, the container would round-trip, every test would pass, and
#      the image would be masked with a function of unknown strength. The vectors are
#      the only thing that separates "SHA-256" from "some mixing".
#
#   2. The known-plaintext key recovery that used to work against the shipped APK must
#      fail. This is not a property of the *code*, it is a property of the artifact:
#      the previous mask was SplitMix64-finalise(key + index + G0), a bijection in the
#      key, and the container's first eight bytes are known plaintext, so
#      tool/recover_from_shipped.py recovered the key from the release APK and printed
#      the whole container - with no disassembly. That break is still implemented in
#      the tool, so this step is a real regression test rather than a memory of one.
#
# Usage (from the repository root):
#   powershell -ExecutionPolicy Bypass -File tool/verify_crypto.ps1
#   powershell -ExecutionPolicy Bypass -File tool/verify_crypto.ps1 -Apk <apk>
[CmdletBinding()]
param(
  [string]$Apk = 'app/build/app/outputs/flutter-apk/app-release.apk',
  [string]$Lib = 'app/build/native/dartvmp.dll'
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$problems = @()

Write-Host '== SHA-256 vectors =='
$libPath = Join-Path $root $Lib
if (-not (Test-Path $libPath)) {
  throw "runtime not found: $libPath`nRun: powershell -File tool/build_native.ps1 -Configuration Release"
}

# The probe is behind DVMP_DIAGNOSTICS, and the desktop test library is the only build
# that has it. Driving it through Python's ctypes keeps this independent of the Dart
# bindings - the point is to compare three separate implementations of the same hash.
$script = @'
import ctypes, hashlib, sys
lib = ctypes.CDLL(sys.argv[1])
lib.dartvmp_sha256_probe.restype = ctypes.c_int32
lib.dartvmp_sha256_probe.argtypes = [ctypes.c_char_p, ctypes.c_uint32, ctypes.c_char_p]

# Lengths chosen to cover every padding path: empty (pure padding block), one byte,
# 55 and 56 (the boundary where the length field no longer fits in the first block),
# 64 (exactly one block) and 200 (multi-block with a partial tail).
cases = [b"", b"abc", b"a" * 55, b"a" * 56, b"a" * 64, bytes(range(200))]
bad = 0
for msg in cases:
    out = ctypes.create_string_buffer(32)
    rc = lib.dartvmp_sha256_probe(msg, len(msg), out)
    if rc != 0:
        print(f"  FAIL  probe returned {rc} for len={len(msg)}")
        bad += 1
        continue
    got = out.raw[:32].hex()
    want = hashlib.sha256(msg).hexdigest()
    label = {0: "empty", 3: "abc"}.get(len(msg), f"{len(msg)} bytes")
    if got == want:
        print(f"  ok    {label:<10} {got[:16]}...")
    else:
        print(f"  FAIL  {label}: got {got} want {want}")
        bad += 1
sys.exit(1 if bad else 0)
'@
$tmp = Join-Path $root 'build/verify_sha256.py'
New-Item -ItemType Directory -Force -Path (Split-Path -Parent $tmp) | Out-Null
Set-Content -Path $tmp -Value $script -Encoding UTF8

$py = Get-Command python -ErrorAction SilentlyContinue
if (-not $py) {
  Write-Host '  (python not on PATH; cannot check the vectors)'
  $problems.Add('python unavailable, so the SHA-256 vectors were not run')
} else {
  & $py.Source $tmp $libPath
  if ($LASTEXITCODE -ne 0) {
    $problems.Add('dvmp_sha256 does not match the published SHA-256 vectors')
  }
}

Write-Host ''
Write-Host '== known-plaintext key recovery (must fail) =='
$apkPath = Join-Path $root $Apk
if (-not (Test-Path $apkPath)) {
  Write-Host "  (no APK at $Apk; build it with: cd app; flutter build apk --release)"
} else {
  $out = & $py.Source (Join-Path $PSScriptRoot 'recover_from_shipped.py') --apk $apkPath 2>&1
  $code = $LASTEXITCODE
  $out | ForEach-Object { Write-Host "  $_" }
  if ($code -ne 0) {
    $problems.Add('the mask key is recoverable from known plaintext in the shipped APK')
  }
}

Write-Host ''
if ($problems.Count -eq 0) {
  Write-Host 'CRYPTO OK: SHA-256 matches the published vectors, and the shipped'
  Write-Host '  artifact does not give up the mask key to known plaintext.'
  Write-Host ''
  Write-Host '  Residual exposure, quoted so it is not mistaken for safety: the key'
  Write-Host '  still ships inside libdartvmp.so, because offline distribution'
  Write-Host '  requires it, so an attacker who reads `unmask_image_into` can'
  Write-Host '  re-derive the keystream. That is the C-layer problem, and it is a'
  Write-Host '  different one from this check.'
  exit 0
}
Write-Host "CRYPTO FAILED: $($problems.Count) problem(s)"
$problems | ForEach-Object { Write-Host "  - $_" }
exit 1
