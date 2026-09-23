# Empirically verifies that the anti-debug escape hatch is compiled out of a
# release build. The claim is not "the string is hard to find" - it is that the
# release build does not reference the environment variable at all, so there is
# nothing to set.
#
# Two builds of the same sources differing only in DVMP_DIAGNOSTICS:
#   diagnostics ON  (the test library) -> the name is present, by design
#   diagnostics OFF (the shipped library) -> the name must be ABSENT
#
# Usage: powershell -ExecutionPolicy Bypass -File tool/verify_antidebug_gate.ps1
[CmdletBinding()]
param(
  [string]$OutRoot = 'build/gatecheck'
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$work = Join-Path $root $OutRoot
$src = Join-Path $root 'tool/hostlib'

function Find-CMake {
  $cmd = Get-Command cmake.exe -ErrorAction SilentlyContinue
  if ($cmd) { return $cmd.Source }
  $vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
  if (Test-Path $vswhere) {
    $vs = & $vswhere -latest -products * -property installationPath 2>$null
    if ($vs) {
      $c = Get-ChildItem (Join-Path $vs.Trim() 'Common7/IDE/CommonExtensions/Microsoft/CMake/CMake/bin') `
             -Filter cmake.exe -ErrorAction SilentlyContinue
      if ($c) { return $c[0].FullName }
    }
  }
  return $null
}

$cmake = Find-CMake
if (-not $cmake) { throw 'cmake.exe not found' }

# The escape hatch is only compiled in when the anti-debug layer itself is, so
# both builds must enable it - otherwise the check would pass for the wrong
# reason.
function Build-And-Scan([string]$label, [string]$diagnostics) {
  $dir = Join-Path $work $label
  Remove-Item -Recurse -Force $dir -ErrorAction SilentlyContinue
  & $cmake -S $src -B $dir -DCMAKE_BUILD_TYPE=Release `
      '-DDVMP_HOSTLIB_ANTIDEBUG=ON' "-DDVMP_HOSTLIB_DIAGNOSTICS=$diagnostics" | Out-Null
  if ($LASTEXITCODE -ne 0) { throw "configure failed for $label" }
  & $cmake --build $dir --config Release | Out-Null
  if ($LASTEXITCODE -ne 0) { throw "build failed for $label" }
  $lib = Get-ChildItem $dir -Recurse -Filter 'dartvmp.dll' -ErrorAction SilentlyContinue |
         Select-Object -First 1
  if (-not $lib) { throw "no library produced for $label" }
  $text = [System.Text.Encoding]::ASCII.GetString(
      [System.IO.File]::ReadAllBytes($lib.FullName))
  $found = $text.Contains('DARTVMP_NO_ANTIDEBUG')
  Write-Host ("  {0,-22} diagnostics={1,-3} {2,8} bytes  name present: {3}" -f `
      $label, $diagnostics, $lib.Length, $found)
  return $found
}

Write-Host '== anti-debug escape hatch =='
$withDiagnostics = Build-And-Scan 'diag' 'ON'
$withoutDiagnostics = Build-And-Scan 'release' 'OFF'

$problems = New-Object System.Collections.Generic.List[string]
if (-not $withDiagnostics) {
  $problems.Add('the test library does not contain the escape-hatch name, so ' +
    'this check cannot tell a fixed build from an unfixed one')
}
if ($withoutDiagnostics) {
  $problems.Add('a release build still references DARTVMP_NO_ANTIDEBUG, so the ' +
    'whole anti-debug layer is disableable with one environment variable')
}

Write-Host ''
if ($problems.Count -eq 0) {
  Write-Host 'GATE OK: the escape hatch exists where it is useful (diagnostic'
  Write-Host '  builds) and is absent where it is a hole (release builds).'
  exit 0
}
Write-Host "GATE FAILED: $($problems.Count) problem(s)"
$problems | ForEach-Object { Write-Host "  - $_" }
exit 1
