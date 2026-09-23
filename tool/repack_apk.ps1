# repack_apk.ps1 - replace a native library inside a built APK and re-sign it.
#
# This is the integration point for the C-layer virtualization on Android: VMPacker
# rewrites an ELF, so the protected `libdartvmp.so` has to end up inside the APK, and
# the APK has to be re-aligned and re-signed afterwards. Gradle cannot do this itself
# because the protected library is produced *after* the native build and *before*
# packaging - hence a step here, mirroring what VMPacker's own Android test does
# (test/android/scripts/protect_and_repack.sh).
#
# The entry is added with no compression and then page-aligned, because Android maps
# native libraries straight out of the APK when they are stored uncompressed. This step
# originally rebuilt the archive with .NET's `ZipArchive.CreateEntry`, which defaults to
# Deflate for every entry it rewrites - so the repacked APK had a *compressed*
# libflutter.so and stopped installing entirely:
#
#   INSTALL_FAILED_INVALID_APK: Failed to extract native libraries, res=-2
#
# The rebuild now lives in tool/repack_apk.py, where `ZipInfo.compress_type` can be read
# and copied instead of guessed, and where every `lib/**/*.so` is forced to STORED and
# checked afterwards. Measured before/after: `method=0` in the Flutter APK, `method=8`
# in the first repack, `method=0` again now.
#
# Usage (from the repository root):
#   powershell -ExecutionPolicy Bypass -File tool/repack_apk.ps1 `
#       -Apk <built.apk> -Replace "lib/arm64-v8a/libdartvmp.so=<protected.so>" -Out <out.apk>
[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)][string]$Apk,
  [Parameter(Mandatory = $true)][string[]]$Replace,
  [Parameter(Mandatory = $true)][string]$Out,
  [string]$Keystore = "$env:USERPROFILE\.android\debug.keystore",
  [string]$StorePass = 'android',
  [string]$KeyAlias = 'androiddebugkey'
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
# Absolute or repo-relative, both accepted. `Join-Path` on an already-absolute path
# produces `<root>\D:\...`, which fails as "Cannot find path ... does not exist" - and
# that is exactly how tool/test.ps1's device step, which naturally has absolute paths,
# broke this script.
function Resolve-UnderRoot([string]$p) {
  if ([System.IO.Path]::IsPathRooted($p)) { return (Resolve-Path $p).Path }
  return (Resolve-Path (Join-Path $root $p)).Path
}
$apkPath = Resolve-UnderRoot $Apk
$outPath = if ([System.IO.Path]::IsPathRooted($Out)) { $Out } else { Join-Path $root $Out }

$py = Get-Command python -ErrorAction SilentlyContinue
if (-not $py) {
  throw 'python is required for the zip rebuild (see the note at the top of this file)'
}

# $outPath, not $Out: joining the root onto an already-absolute path is the same bug
# twice, and the second time it surfaced inside the Python helper as
# `OSError: [WinError 123] ... 'D:\...\D:\...\build'`.
$rebuilt = "$outPath.rebuilt"
$argv = @((Join-Path $PSScriptRoot 'repack_apk.py'), '--apk', $apkPath, '--out', $rebuilt)
foreach ($r in $Replace) { $argv += @('--replace', $r) }
& python @argv
if ($LASTEXITCODE -ne 0) { throw "the zip rebuild failed ($LASTEXITCODE)" }

# apksigner is a wrapper around a jar and needs a JDK; the Android Studio JDK is not on
# PATH, and without JAVA_HOME it fails with that message and no mention of signing.
# gradle.properties already names the JDK this project builds with, so read it there
# rather than hard-coding a second copy of the path.
if (-not $env:JAVA_HOME) {
  $gp = Join-Path $root 'app/android/gradle.properties'
  if (Test-Path $gp) {
    $m = Select-String -Path $gp -Pattern '^\s*org\.gradle\.java\.home\s*=\s*(.+)$'
    if ($m) {
      $candidate = $m.Matches[0].Groups[1].Value.Trim().Replace('\\', '\')
      if (Test-Path $candidate) {
        $env:JAVA_HOME = $candidate
        Write-Host "JAVA_HOME=$candidate (from app/android/gradle.properties)"
      }
    }
  }
}
if (-not $env:JAVA_HOME) { throw 'apksigner needs JAVA_HOME; set it or add org.gradle.java.home to app/android/gradle.properties' }

$bt = Get-ChildItem (Join-Path $env:LOCALAPPDATA 'Android\Sdk\build-tools') -Directory |
  Sort-Object Name -Descending | Select-Object -First 1
$zipalign = Join-Path $bt.FullName 'zipalign.exe'
$apksigner = Join-Path $bt.FullName 'apksigner.bat'
if (-not (Test-Path $zipalign)) { throw "zipalign not found under $($bt.FullName)" }
if (-not (Test-Path $apksigner)) { throw "apksigner not found under $($bt.FullName)" }

& $zipalign -f -p 4 $rebuilt $outPath
if ($LASTEXITCODE -ne 0) { throw "zipalign failed ($LASTEXITCODE)" }
& $apksigner sign --ks $Keystore --ks-pass "pass:$StorePass" --ks-key-alias $KeyAlias $outPath
if ($LASTEXITCODE -ne 0) { throw "apksigner failed ($LASTEXITCODE)" }
Remove-Item -Force $rebuilt -ErrorAction SilentlyContinue
Remove-Item -Force "$Out.tmp" -ErrorAction SilentlyContinue

# Verify rather than assume: an unsigned or misaligned APK installs differently on
# different Android versions, and "it installed" is not the same as "it is valid".
& $apksigner verify --print-certs $outPath 2>&1 | Select-Object -First 2
& $zipalign -c -p 4 $outPath
if ($LASTEXITCODE -ne 0) { throw "the repacked APK is not 4-byte aligned on shared objects" }

# And re-check the storage of every native library *after* signing, from the shipped
# file rather than from the intermediate. This is the check whose absence let a
# compressed libflutter.so through: zipalign passed, apksigner passed, the APK was
# otherwise valid, and `adb install` refused it with a message about native libraries
# that never mentioned compression.
$storage = & python (Join-Path $PSScriptRoot 'repack_apk.py') --check-only --apk $outPath
if ($LASTEXITCODE -ne 0) { throw "the repacked APK is not loadable: $storage" }
Write-Host $storage
Write-Host "OK: $Out ($((Get-Item $outPath).Length) bytes)"
