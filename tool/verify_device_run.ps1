# verify_device_run.ps1 - install a built APK and prove the protected runtime starts.
#
# WHY THIS EXISTS
# ---------------
# Every other check in this repository looks at the artifact. This one runs it, and it
# is here because the artifact checks were all green while **five of the seven
# virtualized functions killed the application on launch**:
#
#   * tool/apply_vmpacker.ps1 reported "all 5/5 targets replaced by VM trampolines"
#     and read the bytes back to prove it;
#   * the suite was ALL GREEN;
#   * and the APK died with SIGSEGV in the VMPacker payload before the first frame.
#
# That is the whole argument for a device gate: a mistranslated instruction is not a
# build error and not a structural difference, it is a crash (or worse, a wrong answer)
# that only a run can find. README's "What only a real run could find" says the same
# thing about the Windows runner.
#
# WHAT IT PROVES, AND WHAT IT DOES NOT
# ------------------------------------
# Proves: the process survives startup with the protected library, and no crash record
# was written while it did. That is exactly the gate that caught the five bad targets.
# Does not prove the *answers* are right - a wrong answer keeps the process alive. The
# value check is the demo screen's own output: it prints the result of every protected
# function plus all nine dispatch entries, and those must equal the reference
# implementations. This script leaves the app running so that can be looked at (or
# screenshot with `adb shell screencap`), and prints the expected values.
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File tool/verify_device_run.ps1 -Apk build/apk_safe.apk
[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)][string]$Apk,
  [string]$Package = 'com.dartvmp.dartvmp_demo',
  [string]$Activity = '.MainActivity',
  [int]$SettleSeconds = 10,
  [switch]$KeepInstalled
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot

function Find-Adb {
  $cmd = Get-Command adb -ErrorAction SilentlyContinue
  if ($cmd) { return $cmd.Source }
  $sdk = $env:ANDROID_HOME
  if (-not $sdk) { $sdk = Join-Path $env:LOCALAPPDATA 'Android\Sdk' }
  $exe = Join-Path $sdk 'platform-tools\adb.exe'
  if (Test-Path $exe) { return $exe }
  throw 'adb not found; put platform-tools on PATH or set ANDROID_HOME'
}

# Native stderr is not an error here (adb writes its daemon banner there), and
# $ErrorActionPreference='Stop' would turn it into a terminating error before any check
# can run. Same reason as Invoke-NativeLines in apply_vmpacker.ps1.
function Invoke-Adb([string[]]$argv) {
  $prev = $ErrorActionPreference
  $ErrorActionPreference = 'Continue'
  try { return @(& $script:adb @argv 2>$null) } finally { $ErrorActionPreference = $prev }
}

$script:adb = Find-Adb
# Absolute or repo-relative, both accepted - the caller is usually test.ps1, which
# builds absolute paths. `Join-Path` on an absolute path yields `<root>\<drive>:\...`,
# which is a confusing "Cannot find path" rather than a bad argument.
$apkPath = if ([System.IO.Path]::IsPathRooted($Apk)) {
  (Resolve-Path $Apk).Path
} else {
  (Resolve-Path (Join-Path $root $Apk)).Path
}

$devices = @(Invoke-Adb @('devices') | Where-Object { $_ -match '\sdevice$' })
if ($devices.Count -eq 0) {
  throw @"
no device attached, so the run cannot be verified.

  adb devices  ->  $((Invoke-Adb @('devices')) -join ' ')

This is reported rather than skipped on purpose: "the device was not there" and "the
protected library works" must not look the same in a log. Everything else in
tool/test.ps1 -Release can run without a device; this step cannot, and saying so is the
point.
"@
}
Write-Host "device: $($devices[0].Trim())"

Write-Host "installing $Apk"
$out = Invoke-Adb @('install', '-r', '-t', $apkPath)
# Joined before matching on purpose: `-notmatch` on an *array* filters it and returns
# the non-matching elements, which is truthy whenever there is more than one line - so
# `if ($out -notmatch 'Success')` threw "install failed: ... Success" on a successful
# install. (Same family as the `-and`/`-or` precedence trap in apply_vmpacker.ps1.)
$outText = $out -join "`n"
if ($outText -notmatch 'Success') { throw "install failed: $outText" }
Write-Host "  $($out[-1])"

# Clear the crash buffer first: otherwise a crash from an earlier run of a *different*
# build is indistinguishable from this one, which is exactly the mistake that would
# make this script report a false failure (or a false pass).
Invoke-Adb @('logcat', '-c') | Out-Null
Invoke-Adb @('shell', 'am', 'force-stop', $Package) | Out-Null
Invoke-Adb @('shell', 'am', 'start', '-n', "$Package/$Activity") | Out-Null
Start-Sleep -Seconds $SettleSeconds

$pidText = (Invoke-Adb @('shell', 'pidof', $Package)) -join ''
$alive = $pidText.Trim() -ne ''
$crash = @(Invoke-Adb @('logcat', '-d', '-b', 'crash') |
  Where-Object { $_ -match 'Fatal signal|signal \d+ \(SIG' })

if (-not $alive) {
  $detail = if ($crash.Count -gt 0) { $crash -join "`n  " } else { '(no crash record)' }
  throw @"
the protected runtime did not survive startup: $Package is not running.

  $detail

A SIGSEGV inside the appended payload is what a VMPacker mistranslation looks like, and
the fault address is diagnostic: it equals the *call target* when the VM branches to an
unbiased link-time address (`bl 0x6d60` -> fault addr 0x6d60), and it is 0x28 when the
VM fails the TLS stack-canary read. See tool/vmpacker_targets.txt.
"@
}

if ($crash.Count -gt 0) {
  throw "the process is alive but a crash record appeared during startup:`n  $($crash -join "`n  ")"
}

Write-Host ''
Write-Host "OK: $Package is running (pid $($pidText.Trim())) and wrote no crash record."
Write-Host 'A live process is not a correct answer - check the demo screen prints:'
Write-Host '  add(20,22) = 42    makeLicenseKey("demo-seed", 7) = ZVEXKFVVCDH93W6R'
Write-Host '  verifyLicense(key) = true    verifyLicense(1 char changed) = false'
Write-Host '  deviceToken("pixel-7", 1700000000) = -5031510683369134119'
Write-Host '  selfTest() = true    and dispatch [0]..[8] all ticked'
if (-not $KeepInstalled) {
  Write-Host ''
  Write-Host '(the app is left installed and running so the screen can be inspected)'
}
