# apply_vmpacker.ps1 - hands the C layer to VMPacker and proves it was virtualized.
#
# WHY THIS SCRIPT IS MOSTLY CHECKS
# --------------------------------
# VMPacker selects the functions to virtualize **by symbol name** and rewrites an
# ELF in place:
#
#     vmpacker -func "name1,name2" -v -o out.so in.so
#
# (No source annotation: that is how VMPacker's own Android test,
# test/android/scripts/protect_and_repack.sh, drives it against a .so pulled out of
# an APK.)
#
# A name-based selection has a failure mode that is worse than failing: if the tool
# finds no matching symbol it has nothing to do, and "nothing to do" is
# indistinguishable from success. The artifact is bit-identical, the build goes
# green, and the library ships unprotected while everyone believes otherwise.
#
# So the value of this script is not the invocation - that is one line - it is the
# three checks around it:
#
#   pre-flight   every declared target must be present in the *input* symbol table,
#                and the input must still have one at all. This is what catches the
#                two real mistakes: running against the stripped release .so (no
#                symbols whatsoever), and declaring a target that -O2 inlined away
#                so it never existed as a function.
#   post-flight  every declared target must be *absent* from the output symbol
#                table, or at least its body replaced, which is the only observable
#                that proves work happened rather than a file being written.
#   ABI check    the nine exported entry points must be unchanged and no
#                interpreter internal may become exported, because a virtualized
#                function is still an interpreter internal.
#
# Every check was reverse-verified: see the notes on each below.
#
# USAGE
#   powershell -ExecutionPolicy Bypass -File tool/apply_vmpacker.ps1 `
#       -InputSo app/build/dartvmp/intermediates/cxx/Release/<hash>/obj/arm64-v8a/libdartvmp.so
#
#   -AllowMissing   do not fail when VMPacker is absent; report NOT APPLIED instead
#                   (used by tool/test.ps1 -Release so the rest of the suite still
#                   runs on a machine without the tool)
[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)][string]$InputSo,
  [string]$OutputSo = '',
  [string]$TargetsFile = '',
  [string]$Vmpacker = '',
  [switch]$AllowMissing,
  [switch]$KeepIntermediate,
  [switch]$PcRel
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
if (-not $TargetsFile) { $TargetsFile = Join-Path $PSScriptRoot 'vmpacker_targets.txt' }
if (-not $OutputSo) { $OutputSo = $InputSo }

function Find-Tool([string]$name) {
  # Not just `Get-Command $name`: an empty name is a *parameter validation* error,
  # not a miss, so the caller has to be able to ask without knowing.
  if ([string]::IsNullOrWhiteSpace($name)) { return $null }
  $cmd = Get-Command $name -ErrorAction SilentlyContinue
  if ($cmd) { return $cmd.Source }
  return $null
}

# llvm-nm/llvm-readelf from the NDK: the host has no binutils, and the NDK copies
# are the same ones the linker used, so they cannot disagree with it about the
# artifact under test.
function Find-NdkTool([string]$name) {
  $found = Find-Tool $name
  if ($found) { return $found }
  $sdk = $env:ANDROID_HOME
  if (-not $sdk) { $sdk = Join-Path $env:LOCALAPPDATA 'Android\Sdk' }
  $ndkRoot = Join-Path $sdk 'ndk'
  if (-not (Test-Path $ndkRoot)) { return $null }
  $exe = Get-ChildItem $ndkRoot -Recurse -Filter "$name.exe" -ErrorAction SilentlyContinue |
    Select-Object -First 1 -ExpandProperty FullName
  return $exe
}

function Invoke-NativeLines([string]$exe, [string[]]$argv) {
  # Native tools write to stderr for things that are not failures - `llvm-nm` says
  # "no symbols" there for a stripped file, which is a *finding* here, not an
  # error. With $ErrorActionPreference = 'Stop' at the top of this script,
  # `& $exe ... 2>&1` turns that into a terminating error before any of the checks
  # below can look at it, so the whole script dies with a raw NativeCommandError
  # instead of the message it was written to produce. The preference is relaxed
  # for the duration of the call and stderr is dropped; the exit code and stdout
  # are what the checks actually use.
  $prev = $ErrorActionPreference
  $ErrorActionPreference = 'Continue'
  try {
    $out = & $exe @argv 2>$null
  } finally {
    $ErrorActionPreference = $prev
  }
  return @($out)
}

function Get-Symbols([string]$so, [string]$nm) {
  # Only defined symbols. Both the binding and the *address* are kept: the binding is
  # what the pre-flight reports (so a target that is local rather than global is
  # visible), and the address is what lets the post-flight read the function's bytes.
  $map = @{}
  foreach ($line in (Invoke-NativeLines $nm @('--defined-only', $so))) {
    if ($line -match '^([0-9a-fA-F]+)\s+([A-Za-z])\s+(\S+)$') {
      $map[$Matches[3]] = [pscustomobject]@{
        Address = [Convert]::ToInt32($Matches[1], 16)
        Binding = $Matches[2]
      }
    }
  }
  return $map
}

function Get-Exports([string]$so, [string]$readelf) {
  if (-not $readelf) { return @() }
  $names = @()
  foreach ($line in (Invoke-NativeLines $readelf @('--dyn-syms', $so))) {
    if ($line -match 'FUNC\s+GLOBAL\s+DEFAULT\s+\d+\s+(\S+)$' -and
        $Matches[1] -like 'dartvmp_*') {
      $names += $Matches[1]
    }
  }
  return @($names | Sort-Object)
}

# ---- targets -------------------------------------------------------------
# `name`  - a function to virtualize; it must exist in the input symbol table.
# `!name` - a helper that must NOT exist as its own function. See the check below.
# `#+wide` / `#+hot` open optional sections, selected by -Wide / -Hot.
$sections = @{ '' = @(); 'pcrel' = @() }
$section = ''
foreach ($line in (Get-Content $TargetsFile)) {
  $raw = $line.Trim()
  if ($raw -match '^#\+(\w+)\s*$') {
    $section = $Matches[1].ToLower()
    if (-not $sections.ContainsKey($section)) {
      throw "unknown section '#+$section' in ${TargetsFile}"
    }
    continue
  }
  $t = ($raw -split '#')[0].Trim()
  if ($t -eq '') { continue }
  $sections[$section] += $t
}

$selected = @($sections[''])
if ($PcRel) { $selected += $sections['pcrel'] }
if ($selected.Count -eq 0) { throw "no targets in $TargetsFile" }

$targets = @($selected | Where-Object { -not $_.StartsWith('!') })
$mustVanish = @($selected | Where-Object { $_.StartsWith('!') } |
  ForEach-Object { $_.Substring(1).Trim() })
if ($targets.Count -eq 0) { throw "no targets in $TargetsFile" }
Write-Host "targets ($(if ($PcRel) { 'including the pc-relative section' } else { 'default' })): $($targets -join ', ')"
if ($mustVanish.Count -gt 0) {
  Write-Host "must be inlined away: $($mustVanish -join ', ')"
}

if (-not (Test-Path $InputSo)) { throw "input not found: $InputSo" }
$InputSo = (Resolve-Path $InputSo).Path

# ---- the tool ------------------------------------------------------------
# Resolve in order: -Vmpacker, $env:VMPACKER, PATH.
#
# Written as separate statements rather than one boolean expression on purpose:
# PowerShell gives `-and` and `-or` equal precedence and evaluates them strictly
# left to right, so `A -or B -and C` is `(A -or B) -and C`. The first version of
# this file folded the three lookups into one condition and, with no tool present,
# called the PATH lookup with an empty name - which PowerShell rejects as a
# parameter binding error rather than returning "not found". The symptom was a
# confusing validation exception instead of the message below.
$toolPath = $null
if ($Vmpacker) { $toolPath = $Vmpacker }
if (-not $toolPath -and $env:VMPACKER) { $toolPath = $env:VMPACKER }
if ($toolPath -and -not (Test-Path $toolPath)) {
  $onPath = Find-Tool $toolPath
  if ($onPath) { $toolPath = $onPath } else { $toolPath = $null }
}
if (-not $toolPath) { $toolPath = Find-Tool 'vmpacker' }
# Then the binary tool/build_vmpacker.ps1 produces. Looking here matters because that
# script is the documented way to obtain the tool, so a machine that has just run it has
# a working packer and no reason to also set an environment variable - and the failure
# mode of not looking is a silent "NOT APPLIED" printed next to a binary sitting right
# there, which is exactly what happened on the first end-to-end run.
if (-not $toolPath) {
  foreach ($cand in @('build/vmpacker.exe', 'build/vmpacker')) {
    $full = Join-Path $root $cand
    if (Test-Path $full) {
      $toolPath = $full
      Write-Host "using the locally built packer: $full"
      break
    }
  }
}
# Hand the resolved path back to the parameter the invocation below uses. Missing this
# is silent until the moment of use: `& $Vmpacker` with an empty name fails with "The
# expression after '&' in a pipeline element produced an object that was not valid",
# which says nothing about the resolution having succeeded. The refactor to $toolPath
# introduced it and an explicit -Vmpacker on the command line hid it.
$Vmpacker = $toolPath

if (-not $toolPath) {
  $msg = @"
VMPacker was not found, so the C layer is NOT virtualized.

  looked for: -Vmpacker <path>, then `$env:VMPACKER, then 'vmpacker' on PATH
  target file: $InputSo

This is reported rather than skipped on purpose: an unvirtualized library and a
virtualized one are indistinguishable once built, so 'we could not run the tool'
has to be a fact someone can see, not an absence of output.

VMPacker builds from source with Go (github.com/bivex/VMPacker):

  git clone https://github.com/bivex/VMPacker
  cd VMPacker && make
  `$env:VMPACKER = "<repo>\vmpacker.exe"      # or put it on PATH

The build must be run against the UNSTRIPPED library. Gradle strips
libdartvmp.so of its symbol table (`llvm-nm` on the packaged copy says "no
symbols"), and a name-based tool has nothing to select from at that point - which
is why this script exists as a build step rather than a post-processing step on
the APK.
"@
  if ($AllowMissing) { Write-Host $msg; Write-Host 'RESULT: NOT APPLIED'; exit 0 }
  throw $msg
}

$nm = Find-NdkTool 'llvm-nm'
$readelf = Find-NdkTool 'llvm-readelf'
if (-not $nm) { throw 'llvm-nm not found (Android NDK platform-tools); cannot verify the hand-off' }

# ---- machine check --------------------------------------------------------
# The input must be AArch64. Gradle builds this library once per ABI, and the x86_64
# one has the same symbol names, the same export surface and a plausible size - so
# pointing the hand-off at it produces a library that is *not virtualized* for the
# device that ships it, and the only symptom is VMPacker's own "ARM64 only, got:
# EM_X86_64". That happened here: the CMake post-build copy used one filename for
# every ABI, the x86_64 build won the race, and the path that said "arm64" held
# x86_64. Cheap to check, and the message below says which file to use instead.
if ($readelf) {
  $machine = $null
  foreach ($line in (Invoke-NativeLines $readelf @('-h', $InputSo))) {
    if ($line -match 'Machine:\s*(.+?)\s*$') { $machine = $Matches[1] }
  }
  if ($machine -and $machine -notmatch 'AArch64') {
    throw @"
$InputSo is a $machine library, and VMPacker rewrites AArch64 only.

Gradle builds this CMake project once per ABI (arm64-v8a and x86_64, see abiFilters in
packages/dartvmp/android/build.gradle). The x86_64 build has the same symbols, so the
pre-flight checks below would all pass and the tool would then refuse it - or, with a
tool that did not check, produce nothing useful.

Use the arm64-v8a library. The build keeps an unstripped copy of each ABI at:
  build/unstripped/libdartvmp.unstripped.arm64-v8a.so
"@
  }
}

# ---- pre-flight ----------------------------------------------------------
# The two mistakes this catches, both of which produce a green build around an
# unprotected library:
#   * the input is the *stripped* artifact, so it has no symbol table at all;
#   * a target was declared but the compiler inlined it away, so it never existed
#     as a function and there is nothing for the tool to find.
$before = Get-Symbols $InputSo $nm
if ($before.Count -eq 0) {
  throw @"
$InputSo has no symbol table, so VMPacker cannot find any function in it.

That is what a stripped library looks like, and it is exactly the artifact Gradle
packages. Run this on the CMake output instead, before stripReleaseDebugSymbols -
see the note at the top of this file.
"@
}
Write-Host "symbols in input: $($before.Count)"

$missing = @($targets | Where-Object { -not $before.ContainsKey($_) })
if ($missing.Count -gt 0) {
  throw @"
these targets are not symbols in ${InputSo}: $($missing -join ', ')

Either the name in $TargetsFile is wrong, or the function was inlined away - which
is the common case, because at -O2 the small helpers (keystream_seed, mask_word,
permute_code) have no separate existence unless the build marks them noinline.

Fix: build with -DDVMP_VMPACKER=ON (dvmp_vmpacker.h adds noinline+used to exactly
the declared targets). `flutter build apk --release` with DVMP_VMPACKER=ON in the
environment does that.
"@
}
$bindings = $targets | ForEach-Object { "$_=$($before[$_].Binding)" }
Write-Host "all targets present: $($bindings -join ' ')"

# ---- the helper check ----------------------------------------------------
# A helper called from a virtualized target must not have a body of its own. If it
# does, the trampoline is decoration: the attacker disassembles around it, finds the
# call, reads the helper in plain AArch64, and never runs VMPacker's VM at all.
#
# This is not hypothetical, and the check exists because it happened. The first build
# with the keyed opcode permutation shipped `unpermute_code` and `permute_code` as
# trampolines with a *shared* `op_tables` helper beside them, and VMPacker's own
# verbose disassembly says so:
#
#     [*] Processing: unpermute_code
#     0x0040: BL           raw=0x97FFFF0C        <- into op_tables
#
# `llvm-nm libdartvmp.so` listed `t op_tables` in the same output. The fix was
# DVMP_ALWAYS_INLINE on the helper (dvmp_vmpacker.h); this is the check that makes the
# fix a fact about the artifact rather than a claim about the source. Reverse-verified
# by adding `!apply_keystream` to the target file - an obvious survivor - and watching
# this throw.
$survivors = @($mustVanish | Where-Object { $before.ContainsKey($_) })
if ($survivors.Count -gt 0) {
  throw @"
these helpers exist as separate functions in ${InputSo}: $($survivors -join ', ')

Each one is called by a virtualized target, so its body is a plain-AArch64 copy of
what that target's trampoline is supposed to hide - and it is reachable without ever
entering VMPacker's VM. Virtualizing the caller while leaving the helper out of line
protects nothing.

Fix: mark the helper DVMP_ALWAYS_INLINE (see dvmp_vmpacker.h). At -O2 a `static`
helper called from two sites gets an out-of-line copy of its own; `inline` plus
always_inline is what removes it, and `llvm-nm` is how you check.
"@
}

# ---- instruction-coverage check -----------------------------------------
#
# THE CHECK THAT MATTERS MOST HERE, because it is the only one that can be made
# before shipping rather than after crashing. VMPacker 1.3's VM does not reproduce
# two things, and a target containing either is *translated successfully* and then
# kills the process on the device:
#
#   * `BL` / `BLR` - a call. VMPacker only remaps branches *inside* the translated
#     function, so an external call keeps its link-time address and the VM branches
#     there without adding the library's load bias. Measured (rooted Xiaomi 12,
#     Android 13, arm64-v8a), the fault address is exactly the call target:
#         dvmp_body_tag   has `bl 0x6d60 <dvmp_fnv1a64>`   -> SIGSEGV at 0x6d60
#         unpermute_code  has `bl 0x6dcc <dvmp_vm_set_error>` -> SIGSEGV at 0x6dcc
#   * `ADRP`/`ADR`/`LDR ..pc` - PC-relative address materialisation, which every read
#     of a global or a .rodata table needs. `permute_code` reads `kWidth[]` and no
#     longer has any call at all, and it still dies (fault addr 0x0); the two targets
#     that work on the device, `apply_keystream` and `keystream_seed`, are precisely
#     the two whose instructions are all immediates, register moves and branches.
#
# So: refuse a target that contains either, and say which instruction and where. This
# is what turns "applied and structurally verified" into "safe to ship", and it is
# why the default target list is two functions rather than seven.
$objdump = Find-NdkTool 'llvm-objdump'
if ($objdump) {
  $current = ''
  $offenders = @{}
  foreach ($line in (Invoke-NativeLines $objdump @('-d', '--no-show-raw-insn', $InputSo))) {
    if ($line -match '^[0-9a-f]+ <([^>]+)>:') { $current = $Matches[1]; continue }
    if ($current -eq '' -or $targets -notcontains $current) { continue }
    if ($line -match '^\s*([0-9a-f]+):\s+(.+)$') {
      $at = $Matches[1]
      $ins = $Matches[2].Trim()
      # `bl`/`blr` and the PC-relative address forms. `b`/`b.cond` are fine: those are
      # the internal branches VMPacker remaps (and the post-flight verifies).
      if ($ins -match '^(bl|blr|adrp|adr)\b' -or $ins -match '\[pc,') {
        if (-not $offenders.ContainsKey($current)) { $offenders[$current] = @() }
        $op = ($ins -split '\s+')[0]
        $offenders[$current] += "+0x$at  $op  $($ins.Substring($op.Length).Trim())"
      }
    }
  }
  if ($offenders.Count -gt 0) {
    $detail = foreach ($t in ($offenders.Keys | Sort-Object)) {
      "  $t`n" + (($offenders[$t] | ForEach-Object { "      $_" }) -join "`n")
    }
    throw @"
vmpacker would translate these targets, but its VM cannot execute them:

$($detail -join "`n")

`bl`/`blr` keep their link-time address inside the VM, so the process jumps to that
absolute address and dies (measured: the SIGSEGV fault address equals the call target).
`adrp`/`adr`/`pc`-relative loads are how a function reaches a global or a constant
table, and the VM gets those wrong too.

This is VMPacker 1.3's instruction coverage, not a mistake in the build. Remove the
target, or inline what it calls and replace its global reads with immediates - the
targets that work today (apply_keystream, keystream_seed) have no calls and no
PC-relative data access. See item 1 in the README's "What was strengthened".
"@
  }
  Write-Host "instruction coverage: no calls and no PC-relative addressing in any target"
}

# Report the binding, because it is the one thing this hand-off cannot control.
# On this toolchain a symbol is global only if it is exported, and exporting
# unpermute_code would hand an attacker the private opcode mapping - see
# dvmp_vmpacker.h. So the targets are local ('t') by design, and if VMPacker turns
# out to filter on global binding, the post-flight below is what says so.
$localOnly = @($targets | Where-Object { $before[$_].Binding -cmatch '[a-z]' })
if ($localOnly.Count -eq $targets.Count) {
  Write-Host "note: all targets are local symbols (expected; see dvmp_vmpacker.h)"
}

$exportsBefore = @()
if ($readelf) {
  $exportsBefore = Get-Exports $InputSo $readelf
  Write-Host "exported dartvmp_* before: $($exportsBefore.Count)"
}

# ---- run -----------------------------------------------------------------
$tmpOut = "$InputSo.vmpprotected"
if (Test-Path $tmpOut) { Remove-Item -Force $tmpOut }
# Create the output directory before the final move, or a run that did all the work
# fails on its last line with "Could not find a part of the path" - which reads like the
# tool failed rather than like the caller named a directory that does not exist yet.
if ($OutputSo -ne $InputSo) {
  $outDir = Split-Path -Parent $OutputSo
  if ($outDir -and -not (Test-Path $outDir)) {
    New-Item -ItemType Directory -Force -Path $outDir | Out-Null
  }
}
$funcArg = ($targets -join ',')
# `-strip=false` on purpose: the tool's default strips the output symbol table, which
# makes "the target names are gone from the output" true whether or not anything was
# virtualized. The symbol table is needed for the byte-level check below; the shipped
# artifact is stripped afterwards, which is all the default was really doing.
Write-Host "running: $Vmpacker -func `"$funcArg`" -strip=false -v -o $tmpOut $InputSo"
# Captured rather than streamed so the translation counts can be checked below; the
# preference is relaxed for the duration because native tools write their progress to
# stderr and `2>&1` under 'Stop' turns that into a terminating error (see
# Invoke-NativeLines). The merged output is printed, so nothing is hidden by this.
$prevEap = $ErrorActionPreference
$ErrorActionPreference = 'Continue'
try {
  $vmpOut = & $Vmpacker -func $funcArg -strip=false -v -o $tmpOut $InputSo 2>&1
  $rc = $LASTEXITCODE
} finally {
  $ErrorActionPreference = $prevEap
}
foreach ($line in $vmpOut) { Write-Host ([string]$line) }
if ($rc -ne 0) { throw "vmpacker exited $rc" }
if (-not (Test-Path $tmpOut)) { throw "vmpacker reported success but wrote no output" }

# ---- full-translation check ----------------------------------------------
# The byte-level post-flight below proves a target's entry point was rewritten into a
# trampoline. It cannot see *partial* translation: VMPacker emits a trampoline for the
# instructions it did translate, so "the bytes changed and there is a branch" passes
# while the rest of the function sits in plain AArch64 next to it. With `-v` the tool
# reports "Translated: N/M" per target, so this reads that instead of trusting it.
#
# Reverse-verified against the vectorized library: `-Wide` there reports
# `dvmp_mask_keystream  64/70` (NEON, no SIMD translation in VMPacker 1.3) and this
# throws, which is exactly how item 2's remaining NEON targets were found.
$translated = @{}
$current = ''
foreach ($line in $vmpOut) {
  $s = [string]$line
  if ($s -match 'Processing:\s*(\S+)\s*$') { $current = $Matches[1] }
  elseif ($s -match 'Translated:\s*(\d+)/(\d+)') {
    if ($current) {
      $translated[$current] = [pscustomobject]@{
        Done = [int]$Matches[1]; Total = [int]$Matches[2]
      }
    }
  }
}
$notSeen = @($targets | Where-Object { -not $translated.ContainsKey($_) })
if ($notSeen.Count -gt 0) {
  throw @"
vmpacker did not report a translation for: $($notSeen -join ', ')

It exited 0 and wrote an output file, so this is the silent case: the target was not
translated (or the tool's output format changed and this check can no longer see it).
Refusing to ship a library whose targets are only believed to be virtualized.
"@
}
$partial = @($translated.Keys | Where-Object { $translated[$_].Done -ne $translated[$_].Total })
foreach ($t in ($translated.Keys | Sort-Object)) {
  Write-Host "  translated $t : $($translated[$t].Done)/$($translated[$t].Total)"
}
if ($partial.Count -gt 0) {
  $detail = @($partial | ForEach-Object { "$_ $($translated[$_].Done)/$($translated[$_].Total)" })
  throw @"
vmpacker translated these targets only partially: $($detail -join ', ')

A partial translation is not a protected function. The untranslated instructions are
still plain AArch64 at their original offsets, reachable with a debugger, and the
trampoline only hides the part the tool understood.

The usual cause is SIMD the compiler generated (VMPacker 1.3 has no SIMD translation,
so a byte-copy loop becomes LDR q / ORR vector and the decode stops). Build with
-DVMP_VMPACKER_NO_VECTORIZE=ON, or drop the target from the list.
"@
}

$sizeBefore = (Get-Item $InputSo).Length
$sizeAfter = (Get-Item $tmpOut).Length
Write-Host "size: $sizeBefore -> $sizeAfter bytes"

# ---- post-flight ---------------------------------------------------------
#
# The check that makes this script worth having, and the first version of it did not
# have teeth. It asked whether the target *names* were absent from the output symbol
# table - which VMPacker's default `-strip` made true regardless of whether it had
# virtualized anything. A run that translated nothing would have passed.
#
# What proves virtualization is the *code*: each target's entry point must still exist
# at the same address (the output is rewritten in place) and must no longer contain the
# original instructions. VMPacker replaces a translated function with a short
# trampoline - `mov w16, #imm` / `movk w16, ...` / `b <vm>` - so the test is that the
# bytes changed and that a branch appears within the first few instructions.
$before = Get-Symbols $InputSo $nm
$after = Get-Symbols $tmpOut $nm
$inBytes = [System.IO.File]::ReadAllBytes($InputSo)
$outBytes = [System.IO.File]::ReadAllBytes($tmpOut)

function Test-Trampoline([byte[]]$buf, [int]$off) {
  # Scan the first three 4-byte instructions for an unconditional branch (B: 0x14 top
  # byte) or a branch register (BR: 0xD61F0000 mask). Either means control left for the
  # VM; the original function had neither at its entry unless it was also a thunk.
  for ($i = 0; $i -lt 3; $i++) {
    $at = $off + $i * 4
    if ($at + 4 -gt $buf.Length) { return $false }
    $w = [BitConverter]::ToUInt32($buf, $at)
    if (($w -band 0xFC000000) -eq 0x14000000) { return $true }   # B
    if (($w -band 0xFFFFFC1F) -eq 0xD61F0000) { return $true }   # BR
  }
  return $false
}

$changed = 0
$problems = @()
foreach ($t in $targets) {
  if (-not $before.ContainsKey($t)) {
    $problems += "$t was not a symbol in the input"
    continue
  }
  $addr = $before[$t].address
  if ($addr + 16 -gt $inBytes.Length -or $addr + 16 -gt $outBytes.Length) {
    $problems += "$t at 0x$($addr.ToString('x')) is outside the file"
    continue
  }
  $same = $true
  for ($i = 0; $i -lt 16; $i++) {
    if ($inBytes[$addr + $i] -ne $outBytes[$addr + $i]) { $same = $false; break }
  }
  if ($same) {
    $problems += "$t still has its original instructions at 0x$($addr.ToString('x'))"
    continue
  }
  if (-not (Test-Trampoline $outBytes $addr)) {
    $problems += "$t changed at 0x$($addr.ToString('x')) but has no branch: the bytes " +
                 "differ for some other reason"
    continue
  }
  $changed++
}

if ($problems.Count -gt 0) {
  throw @"
vmpacker exited 0 but the output does not show the targets virtualized:
  $($problems -join "`n  ")

The likely cause is that the tool could not resolve the names. On this toolchain the
targets are LOCAL symbols in .symtab (see dvmp_vmpacker.h for why they cannot be made
global without also exporting them), and a tool that only considers global/dynamic
symbols would find none of them and exit successfully with nothing translated.
"@
}
Write-Host "all $changed/$($targets.Count) targets replaced by VM trampolines"

# Strip the symbol table for the artifact that ships. VMPacker's own default does this,
# and doing it here instead is what lets the check above look at the symbols.
$strip = Find-NdkTool 'llvm-strip'
if ($strip) {
  & $strip --strip-all $tmpOut
  if ($LASTEXITCODE -ne 0) { throw "llvm-strip failed ($LASTEXITCODE)" }
  Write-Host "stripped for shipping: $((Get-Item $tmpOut).Length) bytes"
} else {
  Write-Host "note: llvm-strip not found, leaving the symbol table in place"
}

if ($readelf) {
  $exportsAfter = Get-Exports $tmpOut $readelf
  $lost = @($exportsBefore | Where-Object { $exportsAfter -notcontains $_ })
  $gained = @($exportsAfter | Where-Object { $exportsBefore -notcontains $_ })
  if ($lost.Count -gt 0) { throw "the ABI lost exports: $($lost -join ', ')" }
  Write-Host "exported dartvmp_* after: $($exportsAfter.Count) (+$(($gained | Measure-Object).Count) new)"
  if ($gained.Count -gt 0) {
    # Not fatal - the tool's own VM entry points legitimately appear - but it has to
    # be visible, and tool/verify_protection.ps1 decides whether any of them is an
    # interpreter internal that should not be callable.
    Write-Host "  new exports: $($gained -join ', ')"
  }
}

Move-Item -Force $tmpOut $OutputSo
Write-Host "written: $OutputSo"
if (-not $KeepIntermediate) { Remove-Item -Force "$OutputSo.vmpprotected" -ErrorAction SilentlyContinue }
Write-Host 'RESULT: APPLIED'
