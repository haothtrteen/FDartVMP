# verify_concurrency.ps1 - proves the runtime survives concurrent calls.
#
# WHY A NATIVE HARNESS RATHER THAN A DART TEST
# --------------------------------------------
# The audit that found this bug used 4 Dart isolates. The same probe cannot run
# under `flutter test`: spawning an isolate that dlopens the runtime hangs in this
# harness even with the runtime's lock disabled, so an isolate-based test would be
# measuring the test environment rather than the runtime. A C harness drives the
# same public ABI from several OS threads directly, which is what the lock actually
# has to survive.
#
# Usage: powershell -ExecutionPolicy Bypass -File tool/verify_concurrency.ps1
[CmdletBinding()]
param(
  [int]$Threads = 8,
  [int]$Rounds = 400
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$work = Join-Path $root 'build/concurrency'
$gen = Join-Path $root 'packages/dartvmp/generated/vmp_module.inc'
$lib = Join-Path $root 'app/build/native/dartvmp.dll'

if (-not (Test-Path $gen)) { throw "run `dart run tool/build.dart` first" }
if (-not (Test-Path $lib)) { throw "run `tool/build_native.ps1` first" }

New-Item -ItemType Directory -Force -Path $work | Out-Null

$src = Join-Path $root 'tool/concurrency_harness.c'
if (-not (Test-Path $src)) { throw "harness missing: $src" }

function Find-Cl {
  $cmd = Get-Command cl.exe -ErrorAction SilentlyContinue
  if ($cmd) { return $cmd.Source }
  $vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
  if (Test-Path $vswhere) {
    $vs = & $vswhere -latest -products * -property installationPath 2>$null
    if ($vs) {
      $vc = Join-Path $vs.Trim() 'VC/Auxiliary/Build/vcvars64.bat'
      if (Test-Path $vc) { return $vc }
    }
  }
  return $null
}

$cl = Find-Cl
if (-not $cl) { throw 'no C compiler found (need MSVC)' }

$exe = Join-Path $work 'concurrency.exe'
$inc = Join-Path $root 'packages/dartvmp/src'
# Link against the import library, not the DLL - and copy the DLL next to the
# harness so it resolves at run time without touching PATH.
$implib = Join-Path $root 'build/hostlib/Release/dartvmp.lib'
if (-not (Test-Path $implib)) { throw "import library missing: $implib" }
Copy-Item $lib (Join-Path $work 'dartvmp.dll') -Force

Write-Host "building the harness"
# Run inside the VS developer environment so the compiler and linker are on PATH.
#
# `/Fo` is not optional. Without it `cl` writes the intermediate object next to the
# *process* working directory rather than next to the source, and this batch file is run
# from the repository root - so the build left `concurrency_harness.obj` sitting in the
# source tree, which is the first thing `git status` shows in a freshly initialised
# repository. The executable was always placed correctly because `/Fe` takes an absolute
# path; only the object escaped.
$bat = Join-Path $work 'build.bat'
@"
@echo off
call "$cl" >nul 2>&1
cl /nologo /W3 /O2 /I"$inc" /Fo:"$work\\" /Fe:"$exe" "$src" /link "$implib"
"@ | Set-Content -Path $bat -Encoding ASCII

& cmd.exe /c $bat 2>&1 | ForEach-Object { Write-Host "  $_" }
if (-not (Test-Path $exe)) { throw "harness build failed" }

Write-Host "running: $Threads threads x $Rounds calls"
& $exe $Threads $Rounds
$rc = $LASTEXITCODE
Write-Host ''
if ($rc -eq 0) {
  Write-Host 'CONCURRENCY OK: every thread agreed with the serial result and no'
  Write-Host '  call returned an error code.'
  exit 0
}
Write-Host "CONCURRENCY FAILED (exit $rc)"
exit 1
