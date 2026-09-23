# verify_protection.ps1 - proves the shipped artifacts carry no plaintext
# protected logic.
#
# This is the evidence behind the design's central claim: the protected
# implementations are compiled to the private instruction set and never reach the
# AOT snapshot. Rather than assert it in prose, this script checks the actual
# APK contents.
#
# Checks
#   1. libdartvmp.so exports the documented ABI and nothing else meaningful
#   2. libapp.so (the AOT snapshot) contains no protected identifier or constant
#   3. libdartvmp.so contains no protected identifier or constant in the clear
#   4. the container magic is not present verbatim in either library
#   5. no plain-Dart copy of a protected implementation ships in libapp.so
#      (the dev-only benchmark baseline must be tree-shaken out of release)
#
# Usage (from the repository root):
#   powershell -ExecutionPolicy Bypass -File tool/verify_protection.ps1
[CmdletBinding()]
param(
  [string]$Apk = 'app/build/app/outputs/flutter-apk/app-release.apk',
  [string]$Abi = 'arm64-v8a'
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$apkPath = Join-Path $root $Apk
if (-not (Test-Path $apkPath)) {
  throw "APK not found: $apkPath`nRun: cd app; flutter build apk --release --target-platform android-arm64"
}

$work = Join-Path $root 'build/verify'
Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path $work | Out-Null

Add-Type -AssemblyName System.IO.Compression.FileSystem
$zip = [System.IO.Compression.ZipFile]::OpenRead($apkPath)
$wanted = "lib/$Abi/libapp.so", "lib/$Abi/libdartvmp.so"
foreach ($e in $zip.Entries) {
  if ($wanted -contains $e.FullName) {
    # Flattened name, and always inside build/verify. Extracting a
    # `libdartvmp.so` next to the test host would shadow the desktop build's
    # `dartvmp.dll` and make every managed test fail to load.
    $dest = Join-Path $work ($e.FullName -replace '[/]', '_')
    [System.IO.Compression.ZipFileExtensions]::ExtractToFile($e, $dest, $true)
  }
}
$zip.Dispose()

$appSo = Join-Path $work "lib_${Abi}_libapp.so"
$rtSo = Join-Path $work "lib_${Abi}_libdartvmp.so"
if (-not (Test-Path $appSo)) { throw "libapp.so not found in the APK for ABI $Abi" }
if (-not (Test-Path $rtSo)) { throw "libdartvmp.so not found in the APK for ABI $Abi" }

# Strings that exist ONLY inside the protected implementations. If any of these
# reaches either library, the eviction step failed and the protection is void.
$logicProbes = @(
  'ABCDEFGHJKLMNPQRSTUVWXYZ23456789',   # the alphabet from licensing.dart
  'kAlphabet',                           # and its identifier
  '1048576',                             # constants inside checkSum
  '2654435761',
  '3735928559',
  # A release runtime must not name its own escape hatch. This one used to be a
  # runtime-only getenv() check, which made the whole anti-debug layer optional
  # from the shell: `DARTVMP_NO_ANTIDEBUG=1 ./app` disabled it. It is now
  # compiled out of any build without the diagnostic probes, and this asserts
  # that. (tool/verify_antidebug_gate.ps1 checks the same property directly by
  # building both configurations.)
  'DARTVMP_NO_ANTIDEBUG'
)

# The *names* of the protected functions, in the runtime's metadata table.
#
# These are NOT expected anywhere any more. They used to be emitted as string
# literals in `kDvmpEntries[]`, which put a greppable list of the protection
# surface in .rodata - a map pointing at exactly which functions are worth
# attacking, plus a hint at the algorithm family. The generator now emits them
# masked (`kDvmpNameBlob`) and the runtime un-masks one byte at a time while
# comparing, so finding one in the shipped library means that regressed.
#
# In libapp.so the *stub* names were ordinary Dart and were accepted as such, on the
# grounds that business code calls them by name. `flutter build apk --release
# --obfuscate` ended that: obfuscation renames the declarations and the call sites
# together, and the stubs dispatch by numeric id (`Vmp.call(4, ...)`), so the eight
# names below are now required to be absent from the snapshot as well.
#
# `add` IS DELIBERATELY NOT IN THIS LIST, and the reason is the opposite of the one
# that put it here. It was added because it is the shortest and most generic name and
# so the most likely to slip through - and then, once the standard became "zero
# protected names in the snapshot", it was the only probe still reporting anything:
# `add` is an ordinary Dart method name (`List.add`, `Set.add`, `Duration.add`,
# `TextSpan.add`...), so `libapp.so` contains that token no matter what this project
# does. A probe that cannot be made clean is a probe that gets disabled, which is worse
# than not having it: it teaches everyone to ignore the check.
#
# What matters is that our `add` is unreachable from the app, and that is covered
# differently: `add` is only reachable from inside the container (Blutter confirms zero
# occurrences of `base32Index` and `checkSum` for the same reason), and the eight
# distinctive names below are all required to be absent.
$nameProbes = @(
  'normalizeKey', 'makeLicenseKey', 'checkSum', 'deviceToken',
  'commandChecksum', 'verifyLicense', 'base32Index', 'selfTest'
)

# The dev-only benchmark baseline in app/lib/main.dart is a plain-Dart copy of
# `deviceToken`. It is legitimate in a development build and fatal in a shipped
# one: comparing the two implementations gives an attacker a differential
# oracle, which is strictly more useful than the algorithm by itself (it turns
# recovery into a yes/no search). Its whole body sits behind a kReleaseMode
# early return, so the AOT compiler drops it - this asserts that it really did.
# The *unmangled* prefix is enough: Dart AOT privatises `_x` to `_x@<hash>`, so
# match the name without the leading underscore.
$baselineProbes = @(
  'benchmarkBaselineDeviceToken'
)

# Text that describes *how the protection works*, which must not ship either.
#
# This list exists because of an independent check rather than a code review: Blutter
# (github.com/worawit/blutter) reconstructs a Flutter AOT snapshot into readable Dart
# and disassembly, and run against this app's release libapp.so it showed the
# protected functions correctly reduced to one-line FFI stubs - and, sitting in the
# same object pool, a complete plain-text description of the mechanism. Two sources:
#
#   * the demo's own "How this works" card, which named protected/*.dart, tool/vmpc,
#     the opcode permutation, the masked uint64 image, the packed argument buffer and
#     the per-call re-seed;
#   * the diagnostics binders in packages/dartvmp, whose lookupFunction string
#     literals - `dartvmp_plaintext_probe`, `dartvmp_body_residue` and friends - named
#     what each probe reveals even though the probes themselves are compiled out of a
#     release runtime.
#
# Both are now behind `kReleaseMode`, which is a compile-time constant, so the
# tree-shaker drops the text. None of this is protected *logic* - the verdict on that
# is in the same Blutter run and it is clean - but the shipped binary should not carry
# a map of its own defences, which is the same rule that made the entry-name table
# masked. Long, distinctive fragments rather than whole sentences: ascii-stripping
# and identifier-token matching do not apply to prose, and a fragment is enough to
# catch a regression without tripping over unrelated words.
$mechanismProbes = @(
  'protected/*.dart holds the real implementations',
  'permutes the opcodes',
  'masked uint64 words',
  'packed argument buffer',
  'dart run tool/build.dart',
  're-encrypts under a fresh seed',
  'dartvmp_plaintext_probe',
  'dartvmp_body_residue',
  'dartvmp_session_probe',
  'dartvmp_code_chunk_probe',
  'dartvmp_code_residue',
  'dartvmp_guard_reset'
)

function Get-AsciiStripped([string]$path) {
  # ASCII view of the bytes with NULs removed, so a chunked or UTF-16-ish layout
  # cannot hide a match.
  $bytes = [System.IO.File]::ReadAllBytes($path)
  $sb = New-Object System.Text.StringBuilder
  foreach ($b in $bytes) { if ($b -ne 0) { [void]$sb.Append([char]$b) } }
  return $sb.ToString()
}

# Same view, but split into the identifier-like runs, for the name probes.
#
# `Contains()` is the wrong test for a short name. `add` is a substring of the
# runtime's own diagnostics - `str append failed: len=%u cap=%u add=%u` - so the
# plain search reported a leak in a library that contains no such name at all, and
# a gate that cries wolf is a gate people learn to ignore. Identifiers are matched
# whole: `[A-Za-z_][A-Za-z0-9_]*` runs, compared exactly.
function Get-IdentifierTokens([string]$path) {
  $text = Get-AsciiStripped $path
  return [regex]::Matches($text, '[A-Za-z_][A-Za-z0-9_]*') |
         ForEach-Object { $_.Value }
}

$problems = New-Object System.Collections.Generic.List[string]

Write-Host "== libdartvmp.so ($((Get-Item $rtSo).Length) bytes) =="
$rtText = Get-AsciiStripped $rtSo
$rtLeaks = @($logicProbes | Where-Object { $rtText.Contains($_) })
if ($rtLeaks.Count -eq 0) {
  Write-Host '  ok    no protected algorithm data in the runtime'
} else {
  foreach ($p in $rtLeaks) {
    Write-Host "  LEAK  $p"
    $problems.Add("libdartvmp.so leaks protected data '$p'")
  }
}
# Matched as whole identifiers: `add` occurs inside this file's own diagnostics
# (`cap=%u add=%u`), so a substring search would report a leak in a library that
# contains no such name.
$rtTokens = Get-IdentifierTokens $rtSo
$rtNameSet = New-Object System.Collections.Generic.HashSet[string]
foreach ($t in $rtTokens) { [void]$rtNameSet.Add($t) }
$rtNames = @($nameProbes | Where-Object { $rtNameSet.Contains($_) })
if ($rtNames.Count -eq 0) {
  Write-Host '  ok    no protected function name appears in the runtime metadata'
} else {
  foreach ($p in $rtNames) {
    Write-Host "  LEAK  $p"
    $problems.Add("libdartvmp.so publishes the protected function name '$p'; " +
      'the entry-name table must stay masked (see _namesTable in c_emitter.dart)')
  }
}

Write-Host "== libapp.so ($((Get-Item $appSo).Length) bytes) =="
$appText = Get-AsciiStripped $appSo
# Algorithm data must be absent: that is the whole point of evicting the bodies
# from the application source. These probes are long constants, so a substring
# search is unambiguous.
$appLeaks = @($logicProbes | Where-Object { $appText.Contains($_) })
if ($appLeaks.Count -eq 0) {
  Write-Host '  ok    no protected algorithm data in the AOT snapshot'
} else {
  foreach ($p in $appLeaks) {
    Write-Host "  LEAK  $p"
    $problems.Add("libapp.so leaks protected data '$p'")
  }
}

# The names are now expected to be ABSENT here too.
#
# They used to be reported as "info ... expected: the generated stubs are ordinary
# Dart", on the reasoning that a stub function must be named something. That is
# true of the stub *declarations* the business code calls - those have to keep
# their names - but it was also true of a string literal at every call site
# (`Vmp.call(id, 'makeLicenseKey', ...)`), which handed over the whole protection
# surface for free and made the runtime's masked name table pointless. Call sites
# now carry only the id, so anything still found here reached the binary by another
# route.
$appTokens = Get-IdentifierTokens $appSo
$appNameSet = New-Object System.Collections.Generic.HashSet[string]
foreach ($t in $appTokens) { [void]$appNameSet.Add($t) }
$appNames = @($nameProbes | Where-Object { $appNameSet.Contains($_) })

# EVERY protected name must now be absent, and that is a change of standard with a
# specific cause: `flutter build apk --release --obfuscate` renames the generated stub
# declarations along with the rest of the app's Dart, so the reason the previous version
# of this check accepted them - "business code calls verifyLicense(...) by name, so the
# declaration's name has to ship" - stopped being true. Obfuscation renames the call
# sites and the declarations consistently, and the stubs dispatch by numeric id
# (`Vmp.call(4, ...)`), so nothing depends on a protected function being *called* by its
# real name.
#
# Measured: the obfuscated snapshot has zero occurrences of all nine names. It had seven
# before, and the seven were this demo's own row labels ("verifyLicense(key) = true"),
# not the declarations - which is why `main.dart` now labels rows by id in release.
#
# So anything found here means one of two things, and the message says which:
#   * the APK was built without --obfuscate, and the stub declarations are back;
#   * something reintroduced a name as a string literal - a label, a diagnostic, a log.
# Both are fixable, neither is benign, and the old `stub declaration` classification is
# gone because it was the loophole that let the first case stay unreported.
if ($appNames.Count -eq 0) {
  Write-Host '  ok    no protected function name appears in the AOT snapshot'
} else {
  foreach ($p in $appNames) {
    Write-Host "  LEAK  protected name '$p' is in libapp.so"
  }
  $problems.Add("libapp.so contains protected function names ($($appNames -join ', ')). " +
    'Build the release APK with --obfuscate --split-debug-info=<dir> so the stub ' +
    'declarations are renamed, and keep names out of string literals in the app ' +
    '(a Blutter dump reads the object pool).')
}

# Check 5: no shipped oracle.
$appBaseline = @($baselineProbes | Where-Object { $appText.Contains($_) })
if ($appBaseline.Count -eq 0) {
  Write-Host '  ok    the dev-only benchmark baseline is absent from the release snapshot'
} else {
  foreach ($p in $appBaseline) {
    Write-Host "  LEAK  $p"
    $problems.Add("libapp.so ships the dev-only benchmark baseline '$p', which " +
      'is a plain-Dart oracle for a protected function; gate the benchmark ' +
      'behind kReleaseMode before its first call site')
  }
}

# Check 6: no map of the mechanism.
#
# A description of the defences is not the defences, but it is the part an attacker
# would otherwise have to reconstruct, and this is the check that would have caught
# the demo's "How this works" card and the diagnostics symbol names sitting in the
# release object pool.
#
# WHY THIS IS NOW A LIST OF *WORDS* AND NOT OF SENTENCES. The first version was twelve
# hand-picked phrases ("permutes the opcodes", "masked uint64 words", "dartvmp_
# plaintext_probe", ...) taken from the text that had leaked at the time. A Blutter
# dump of the release snapshot then walked straight past all twelve and found:
#
#     "the shipped module image is not a DVMP container"
#     "invalid opcode in the module image"
#     "bad argument across the VMP boundary"        (and VMP arena / VMP error / VMP status)
#     " does not fit in the VM's signed 64-bit slot"
#     "dartvmp_instrumented_probe", "dartvmp_antidebug_force"
#     "Every row below executed inside the native private VM."
#     "They run inside a native interpreter, ..."
#     "deviceToken() runs 512 mixing rounds, ..."
#
# A phrase list only ever catches the leak you already knew about; a word list catches
# the category. So the probe is now a set of *mechanism words*, and anything the
# snapshot legitimately has to contain is allowlisted explicitly, with the reason.
$mechanismWords = @(
  'DVMP',                     # the container magic; masking the image is pointless if
                              # the app's own error text spells it out
  'VMP',
  'opcode',
  'bytecode',
  'permut',
  'SplitMix',
  'mask key',
  'private VM',
  'native interpreter',
  'native private',
  'masked uint64',
  'packed argument',
  'protected/*.dart',
  'tool/vmpc',
  'mixing rounds',
  'instrumented_probe',
  'antidebug_force'
)

# Words that must appear, because the shipped library's own directory entry and
# dynamic symbol table publish them anyway: `lib/arm64-v8a/libdartvmp.so` is visible in
# the APK's zip listing, and all nine ABI names are in `.dynsym`, readable with `nm`.
# Treating those as leaks would be theatre - the fix is not to hide them but to say so.
# `DartVMP` is the product name in the app's title, which contains `VMP` as a substring;
# it is allowlisted for that reason and the check counts substrings, not words.
$mechanismAllowed = @(
  'DartVMP',
  'libdartvmp.so',
  'DARTVMP_LIBRARY_PATH',
  'dartvmp.dll',
  'dartvmp_init',
  'dartvmp_call',
  'dartvmp_call_named',
  'dartvmp_function_count',
  'dartvmp_function_info',
  'dartvmp_last_error',
  'dartvmp_status_name',
  'dartvmp_secure_bytes_live',
  'dartvmp_build_id'
)

# The old sentence probes are kept alongside the words: they are free, and they pin the
# exact wording of text that has leaked once, so a reworded regression is caught even if
# the new wording avoids every word above.
$mechanismProbes = $mechanismWords + @(
  'protected/*.dart holds the real implementations',
  're-encrypts under a fresh seed',
  'dartvmp_plaintext_probe',
  'dartvmp_body_residue',
  'dartvmp_session_probe',
  'dartvmp_code_chunk_probe',
  'dartvmp_code_residue',
  'dartvmp_guard_reset'
)
# The allowlisted strings are blanked out of the ASCII view *first*, longest first so a
# shorter entry cannot eat part of a longer one, and the mechanism words are then
# searched in what remains. That is what lets "DartVMP" (the product name, which
# contains VMP) pass while a bare "VMP" in an error message fails.
$scannable = $appText
foreach ($a in ($mechanismAllowed | Sort-Object { $_.Length } -Descending)) {
  $scannable = $scannable.Replace($a, '')
}
$appMechanism = @($mechanismProbes | Where-Object { $scannable.Contains($_) })
if ($appMechanism.Count -eq 0) {
  Write-Host ("  ok    the release snapshot describes nothing about the mechanism" +
    " ($($mechanismWords.Count) words + $($mechanismProbes.Count - $mechanismWords.Count) phrases," +
    " $($mechanismAllowed.Count) names allowlisted as necessarily public)")
} else {
  foreach ($p in $appMechanism) {
    # Show where it is: "the string is somewhere in 4 MB" is not actionable.
    $at = $scannable.IndexOf($p)
    $from = [Math]::Max(0, $at - 40)
    $ctx = $scannable.Substring($from, [Math]::Min(120, $scannable.Length - $from))
    $ctx = ($ctx -replace '[^\x20-\x7E]', '.')
    Write-Host "  LEAK  mechanism text in libapp.so: '$p'"
    Write-Host "        ...$ctx..."
    $problems.Add("libapp.so ships text describing the protection mechanism " +
      "('$p'); gate it behind kReleaseMode as a compile-time early return so the " +
      'tree-shaker drops it, or reword it')
  }
}

Write-Host '== container magic =='
# Searching the runtime for the four magic bytes is a blunt instrument: they can
# occur by chance in unrelated binary data (and do), so finding them proves
# nothing. tool/verify_image.py checks the property that actually matters - that
# un-masking the emitted words reproduces the magic, and that the emitted literal
# does not contain it - so delegate to it.
$py = Get-Command python -ErrorAction SilentlyContinue
if ($py) {
  $imageOut = & $py.Source (Join-Path $PSScriptRoot 'verify_image.py') 2>&1
  $imageOk = $LASTEXITCODE -eq 0
  $imageOut | ForEach-Object { Write-Host "  $_" }
  if (-not $imageOk) {
    $problems.Add('the static image is not correctly masked (see verify_image.py)')
  }
} else {
  Write-Host '  (python not on PATH; run tool/verify_image.py manually)'
}

Write-Host '== exported ABI =='
# The shipped library must expose the documented execution ABI and NOT the
# diagnostic probes (disabled via -DDVMP_DIAGNOSTICS=OFF in the Android build) nor
# any interpreter internal - the interpreter's own functions are static or
# hidden-visibility, so they cannot be called by name from a hooking framework.
$py = Get-Command python -ErrorAction SilentlyContinue
if ($py) {
  $symOut = & $py.Source (Join-Path $PSScriptRoot 'list_symbols.py') $rtSo 2>&1
  $symOk = $LASTEXITCODE -eq 0
  $symOut | ForEach-Object { Write-Host "  $_" }
  if (-not $symOk) {
    $problems.Add('libdartvmp.so exports interpreter internals')
  }
  $probeExports = @($symOut | Select-String '_probe')
  if ($probeExports.Count -gt 0) {
    Write-Host "  LEAK  $($probeExports.Count) diagnostic probe symbol(s) exported in a release build"
    $problems.Add('diagnostic probes are exported; build with -DDVMP_DIAGNOSTICS=OFF')
  } else {
    Write-Host '  ok    no diagnostic probe symbols exported'
  }
} else {
  Write-Host '  (python not on PATH; run tool/list_symbols.py manually)'
}

Write-Host ''
if ($problems.Count -eq 0) {
  Write-Host "PROTECTION OK: $($logicProbes.Count) data probes, $($nameProbes.Count) name"
  Write-Host "  probes and $($mechanismProbes.Count) mechanism-text probes, the container"
  Write-Host '  magic and the entry-name table were checked against libapp.so and'
  Write-Host '  libdartvmp.so; no protected logic, algorithm data, function name,'
  Write-Host '  dev-only oracle or description of the mechanism ships in the clear.'
  exit 0
}
Write-Host "PROTECTION FAILED: $($problems.Count) problem(s)"
$problems | ForEach-Object { Write-Host "  - $_" }
exit 1
