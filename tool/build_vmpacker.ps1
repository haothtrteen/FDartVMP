# build_vmpacker.ps1 - builds the VMPacker toolchain from source.
#
# Two halves, and they need different things:
#
#   1. the VM interpreter stub (C, AArch64). The upstream Makefile builds it with an
#      `aarch64-linux-gnu-` cross toolchain, which this machine does not have - but
#      the Android NDK ships clang/ld.lld/llvm-objcopy/llvm-nm for exactly that
#      target, and they build the stub unchanged (the only complaint is a nested
#      comment in a header). This script does that with the NDK and assembles
#      `cmd/vmpacker/vm_interp.bin` the way the Makefile does: link the object with
#      the provided linker script, objcopy it to a raw blob, and prepend the three
#      symbol offsets the packer needs (vm_entry, vm_entry_token, _token_table_va)
#      as little-endian u64s.
#
#   2. the packer itself (Go, ~180 KB: AArch64 decoder, translator, ELF rewriter,
#      trampolines). This needs a Go toolchain and there is no substitute - the
#      binary embeds the blob from step 1 via go:embed, so the stub has to exist
#      first. go.mod has no dependencies, so it is a plain `go build`.
#
# Usage (from the repository root):
#   powershell -ExecutionPolicy Bypass -File tool/build_vmpacker.ps1
[CmdletBinding()]
param(
  [string]$Source = '',
  [string]$Out = ''
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot

# ---- locate the source ---------------------------------------------------
if (-not $Source) { $Source = $env:VMPACKER_SRC }
if (-not $Source) {
  $candidate = Get-ChildItem (Join-Path $root 'build') -Directory -ErrorAction SilentlyContinue |
    ForEach-Object { Join-Path $_.FullName 'VMPacker-1.3' } |
    Where-Object { Test-Path (Join-Path $_ 'Makefile') } |
    Select-Object -First 1
  if ($candidate) { $Source = $candidate }
}
if (-not $Source -or -not (Test-Path (Join-Path $Source 'Makefile'))) {
  throw @"
VMPacker source not found.

  looked for: -Source <dir>, then `$env:VMPACKER_SRC, then build/*/VMPacker-1.3

Unpack the release next to the build directory, or point VMPACKER_SRC at it:
  `$env:VMPACKER_SRC = 'D:\path\to\VMPacker-1.3'
"@
}
$Source = (Resolve-Path $Source).Path
if (-not $Out) { $Out = Join-Path $root 'build/vmpacker.exe' }
Write-Host "source: $Source"

# ---- NDK toolchain -------------------------------------------------------
function Find-NdkBin {
  $sdk = $env:ANDROID_HOME
  if (-not $sdk) { $sdk = Join-Path $env:LOCALAPPDATA 'Android\Sdk' }
  $bin = Get-ChildItem (Join-Path $sdk 'ndk') -Directory -ErrorAction SilentlyContinue |
    Sort-Object Name -Descending |
    ForEach-Object { Join-Path $_.FullName 'toolchains/llvm/prebuilt/windows-x86_64/bin' } |
    Where-Object { Test-Path (Join-Path $_ 'clang.exe') } |
    Select-Object -First 1
  if (-not $bin) { throw 'no NDK clang found; set ANDROID_HOME' }
  return $bin
}
$bin = Find-NdkBin
Write-Host "ndk:    $bin"

# Native tools write to stderr for things that are not failures - clang warns about a
# nested comment in the stub's headers, ld.lld warns that a bare blob has no _start -
# and with $ErrorActionPreference = 'Stop' at the top of this script each warning
# becomes a terminating error before the exit code can be checked. The preference is
# relaxed for the duration of a native call; the exit code is what decides.
function Invoke-Native([string]$exe, [string[]]$argv, [switch]$Quiet) {
  $prev = $ErrorActionPreference
  $ErrorActionPreference = 'Continue'
  try {
    if ($Quiet) { $out = & $exe @argv 2>$null } else { $out = & $exe @argv 2>&1 }
  } finally {
    $ErrorActionPreference = $prev
  }
  return @($out)
}

$stubDir = Join-Path $Source 'stub/linux/arm64'
$work = Join-Path $root 'build/vmpstub'
New-Item -ItemType Directory -Force -Path $work | Out-Null

# The flags are the Makefile's STUB_CFLAGS, unchanged. -mcmodel=tiny and
# -fno-builtin matter: the blob is executed at an arbitrary address inside the
# target process, so it must be position-independent-ish and must not reach for
# libc. -nostdlib is not decorative either; there is no libc where it runs.
$cflags = @(
  '--target=aarch64-none-elf', '-c', '-Os', '-mcmodel=tiny',
  '-fno-stack-protector', '-fno-builtin', '-nostdlib', '-march=armv8-a',
  '-DVM_INDIRECT_DISPATCH', '-DVM_FUNC_SPLIT', '-DVM_TOKEN_ENTRY'
)

# ---- 1. stub -------------------------------------------------------------
Write-Host '[1/3] building the VM interpreter stub'
Invoke-Native (Join-Path $bin 'clang.exe') (@() + $cflags + @(
  (Join-Path $stubDir 'vm_interp.c'), '-o', (Join-Path $work 'vm_interp.o'))) -Quiet | Out-Null
if ($LASTEXITCODE -ne 0) { throw "clang failed ($LASTEXITCODE)" }

# ld.lld warns "cannot find entry symbol _start" - expected for a bare blob whose
# entry points are found by symbol, not by ELF entry.
Invoke-Native (Join-Path $bin 'ld.lld.exe') @(
  '-T', (Join-Path $stubDir 'vm_interp.lds'),
  '-o', (Join-Path $work 'vm_interp.elf'),
  (Join-Path $work 'vm_interp.o')) -Quiet | Out-Null
if ($LASTEXITCODE -ne 0) { throw "ld.lld failed ($LASTEXITCODE)" }

Invoke-Native (Join-Path $bin 'llvm-objcopy.exe') @(
  '-O', 'binary', (Join-Path $work 'vm_interp.elf'),
  (Join-Path $work 'vm_interp_raw.bin')) -Quiet | Out-Null
if ($LASTEXITCODE -ne 0) { throw "objcopy failed ($LASTEXITCODE)" }

$nmOut = Invoke-Native (Join-Path $bin 'llvm-nm.exe') @((Join-Path $work 'vm_interp.elf')) -Quiet
function Get-SymOffset([string]$name) {
  $m = $nmOut | Select-String -Pattern "\b$name`$" | Select-Object -First 1
  if (-not $m) { throw "the stub has no '$name' symbol; the packer cannot patch it" }
  return [Convert]::ToUInt64(($m.ToString().Trim() -split '\s+')[0], 16)
}
$o1 = Get-SymOffset 'vm_entry'
$o2 = Get-SymOffset 'vm_entry_token'
$o3 = Get-SymOffset '_token_table_va'
$raw = [IO.File]::ReadAllBytes((Join-Path $work 'vm_interp_raw.bin'))
$blob = [BitConverter]::GetBytes([UInt64]$o1) +
        [BitConverter]::GetBytes([UInt64]$o2) +
        [BitConverter]::GetBytes([UInt64]$o3) + $raw

# The header order is the Makefile's and the Go side reads it in that order:
# vm_entry, vm_entry_token, _token_table_va. Getting it wrong produces a blob that
# still embeds and still links, and then jumps to the wrong place at runtime.
$blobPath = Join-Path $Source 'cmd/vmpacker/vm_interp.bin'
[IO.File]::WriteAllBytes($blobPath, $blob)
Write-Host ("      vm_interp.bin: {0} bytes (24 header + {1} raw); vm_entry=0x{2:X} vm_entry_token=0x{3:X} _token_table_va=0x{4:X}" -f `
  $blob.Length, $raw.Length, $o1, $o2, $o3)

# ---- 2. packer -----------------------------------------------------------
Write-Host '[2/3] building the packer (Go)'
$go = Get-Command go -ErrorAction SilentlyContinue
if (-not $go) {
  throw @"
The VM interpreter stub built successfully, but the packer needs a Go toolchain and
there is none on this machine.

  go.mod requires go 1.21 and has no dependencies, so this is a plain build:
    cd "$Source"
    go build -o "$Out" ./cmd/vmpacker/

Install Go (winget install GoLang.Go, or a portable zip from go.dev/dl), or point
`$env:VMPACKER at a prebuilt packer binary and skip this half entirely - the stub
above is only needed to *build* it, not to run it.
"@
}
Push-Location $Source
try {
  & $go.Source build -o $Out ./cmd/vmpacker/
  if ($LASTEXITCODE -ne 0) { throw "go build failed ($LASTEXITCODE)" }
} finally { Pop-Location }

# ---- 3. verify -----------------------------------------------------------
Write-Host '[3/3] verifying the packer runs'
& $Out -info (Join-Path $work 'vm_interp.elf') 2>&1 | Select-Object -First 4
if ($LASTEXITCODE -ne 0) { throw "the packer was built but exited $LASTEXITCODE" }
Write-Host "OK: $Out"
