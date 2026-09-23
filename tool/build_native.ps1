# build_native.ps1 - builds the dartvmp runtime as a standalone shared library
# for the host platform, so the differential test suite can load it under
# `flutter test`.
#
# WHY THIS EXISTS
# ---------------
# Flutter *statically* links FFI plugin code into the desktop runner, so on
# Windows and Linux the runtime only exists inside dartvmp_demo.exe and the
# `flutter test` host cannot dlopen it. This script builds the same sources into
# a loadable library (via tool/hostlib/CMakeLists.txt, which imports the plugin's
# own source list) and copies it where the test host will find it.
#
# On Android there is nothing to do: the runtime ships as libdartvmp.so inside
# the APK, and the app itself is the test.
#
# Usage (from the repository root):
#   powershell -ExecutionPolicy Bypass -File tool/build_native.ps1
#   powershell -ExecutionPolicy Bypass -File tool/build_native.ps1 -Configuration Release -Antidebug
#
# The test library always builds WITH the diagnostic probes: they are the only
# way `flutter test` can inspect the interpreter's decoded bytecode, and this
# artifact is never shipped. The shipped library is built by the Android plugin
# with -DDVMP_DIAGNOSTICS=OFF (see packages/dartvmp/android/build.gradle).

[CmdletBinding()]
param(
  [string]$Configuration = 'Release',
  [switch]$Antidebug,
  [string]$OutDir = 'app/build/native'
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$gen = Join-Path $root 'packages/dartvmp/generated/vmp_module.inc'

if (-not (Test-Path $gen)) {
  throw "vmp_module.inc not found at $gen. Run: dart run tool/build.dart"
}

# ---- locate cmake ----------------------------------------------------------

function Find-CMake {
  $cmd = Get-Command cmake.exe -ErrorAction SilentlyContinue
  if ($cmd) { return $cmd.Source }
  # Visual Studio ships its own CMake, which is what Flutter uses.
  $vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
  if (Test-Path $vswhere) {
    $vs = & $vswhere -latest -products * -property installationPath 2>$null
    if ($vs) {
      $candidates = Get-ChildItem (Join-Path $vs.Trim() 'Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin') `
                      -Filter cmake.exe -ErrorAction SilentlyContinue
      if ($candidates) { return $candidates[0].FullName }
    }
  }
  return $null
}

$cmake = Find-CMake
if (-not $cmake) {
  throw 'cmake.exe not found. Install CMake, or Visual Studio with the C++ workload.'
}

$buildDir = Join-Path $root 'build/hostlib'
$srcDir = Join-Path $root 'tool/hostlib'
$antidebugFlag = 'OFF'
if ($Antidebug) { $antidebugFlag = 'ON' }

Write-Host "configuring $srcDir"
# Both options are passed explicitly. The core project added by hostlib/CMakeLists
# also declares DVMP_DIAGNOSTICS, and once its value lands in the CMake *cache* a
# bare re-run of this script would inherit it instead of using hostlib's own
# default - which is how the probe symbols silently went missing before.
& $cmake -S $srcDir -B $buildDir -DCMAKE_BUILD_TYPE=$Configuration `
    "-DDVMP_HOSTLIB_ANTIDEBUG=$antidebugFlag" `
    "-DDVMP_HOSTLIB_DIAGNOSTICS=ON" | Out-Null
if ($LASTEXITCODE -ne 0) { throw "cmake configure failed ($LASTEXITCODE)" }

Write-Host "building ($Configuration)"
& $cmake --build $buildDir --config $Configuration
if ($LASTEXITCODE -ne 0) { throw "cmake build failed ($LASTEXITCODE)" }

# ---- locate the artifact ---------------------------------------------------

$names = @('dartvmp.dll', 'libdartvmp.so', 'libdartvmp.dylib')
$found = $null
foreach ($n in $names) {
  $hit = Get-ChildItem $buildDir -Recurse -Filter $n -ErrorAction SilentlyContinue |
         Select-Object -First 1
  if ($hit) { $found = $hit; break }
}
if (-not $found) {
  throw "no shared library produced under $buildDir"
}

$out = Join-Path $root $OutDir
New-Item -ItemType Directory -Force -Path $out | Out-Null
# A copy onto a file that is still mapped fails with an IOException, and
# PowerShell's Copy-Item would then leave the OLD library in place. That is the
# worst possible outcome for this script: every test and leak probe keeps passing
# while running against a library that no longer matches the generated header.
# Seen in practice when a `flutter test` process was left holding the DLL.
$deployed = Join-Path $out $found.Name
try {
  Copy-Item $found.FullName $deployed -Force -ErrorAction Stop
} catch {
  throw ("could not replace $deployed - a process is probably still holding it " +
         "(a stale 'dart' or 'flutter test' process). Close it and retry. " +
         "Underlying error: $_")
}
if ((Get-Item $deployed).Length -ne $found.Length) {
  throw "copy to $out produced a $( (Get-Item $deployed).Length )-byte file " +
        "from a $($found.Length)-byte source"
}
# Compare content, not just size: a same-size stale library is exactly the case
# that would go unnoticed.
$srcHash = (Get-FileHash $found.FullName -Algorithm SHA256).Hash
$dstHash = (Get-FileHash $deployed -Algorithm SHA256).Hash
if ($srcHash -ne $dstHash) {
  throw "deployed $deployed does not match the built library (hash mismatch)"
}
Write-Host "built $($found.Name) ($($found.Length) bytes)"

# Deploy for the desktop test host.
#
# Deliberately NOT copied into the package root (`app/`): the Flutter tool
# truncates files it treats as build output there, which produced a 0-byte
# `app/dartvmp.dll` and made every native test silently *skip* rather than fail.
# The test suite loads from `app/build/native` explicitly, via
# DARTVMP_LIBRARY_PATH (see the README).
#
# ALSO DELIBERATELY NOT COPIED INTO THE DESKTOP RUNNER DIRECTORY. It used to be,
# and that is a hole rather than a convenience: this library is built with the
# diagnostic probes ON, and on Windows the Dart loader resolves
# `DynamicLibrary.open('dartvmp.dll')` from the application directory. A desktop
# *release* built from `app/` would therefore bind the probe build, which exports
# `dartvmp_code_probe` (decoded bytecode on demand) and `dartvmp_session_probe`
# (the session key). The probes are compiled out of the shipped Android library
# and out of any release embedding; keeping the diagnostics build out of the
# runner directory is the same rule applied to the desktop path. Use
# `flutter run --release` with the plugin's own CMake build (which links the
# runtime statically and is what actually ships) rather than this test artifact.
$targets = New-Object System.Collections.Generic.List[string]
$targets.Add((Join-Path $root 'app/build/native'))

foreach ($d in $targets) {
  New-Item -ItemType Directory -Force -Path $d | Out-Null
  $target = Join-Path $d $found.Name
  try {
    Copy-Item $found.FullName $target -Force -ErrorAction Stop
  } catch {
    throw ("could not replace $target - a process is probably still holding it. " +
           "Underlying error: $_")
  }
  $size = (Get-Item $target).Length
  if ($size -ne $found.Length) {
    throw "copy to $d is $size bytes, expected $($found.Length)"
  }
  # Hash, not just size: a same-size stale library is the silent case.
  if ((Get-FileHash $target -Algorithm SHA256).Hash -ne $srcHash) {
    throw "copy to $d does not match the built library (hash mismatch)"
  }
  Write-Host "  copied to $d ($size bytes)"
}
