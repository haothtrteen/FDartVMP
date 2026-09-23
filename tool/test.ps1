# test.ps1 - builds everything and runs the whole test suite.
#
# The native differential tests need the runtime as a *loadable* library, which
# the desktop build does not produce (Flutter links plugin code into the runner).
# This deploys it and points DARTVMP_LIBRARY_PATH at the deployed copy, so the
# native groups actually run instead of reporting "skipped".
#
# Usage (from the repository root):
#   powershell -ExecutionPolicy Bypass -File tool/test.ps1
#   powershell -ExecutionPolicy Bypass -File tool/test.ps1 -SkipBuild
[CmdletBinding()]
param(
  [switch]$SkipBuild,
  [switch]$Release
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Push-Location $root
$failed = New-Object System.Collections.Generic.List[string]

function Step([string]$name, [scriptblock]$body) {
  Write-Host ''
  Write-Host "== $name ==" -ForegroundColor Cyan
  try {
    & $body
    if ($LASTEXITCODE -ne 0 -and $null -ne $LASTEXITCODE) {
      throw "exit code $LASTEXITCODE"
    }
  } catch {
    Write-Host "FAILED: $_" -ForegroundColor Red
    $failed.Add($name)
  }
}

try {
  if (-not $SkipBuild) {
    Step 'compile protected sources' {
      dart run tool/build.dart
    }
  }

  Step 'compiler tests (tool/vmpc)' {
    Push-Location tool/vmpc
    try {
      dart analyze
      dart test
    } finally { Pop-Location }
  }

  Step 'artifact self-check' {
    dart run tool/vmpc/bin/vmpc.dart check
  }

  Step 'text files are valid UTF-8' {
    # Cheap, and it exists because a documentation edit in this repository silently
    # turned README.md into an invalid-UTF-8 file: `Get-Content -Raw` plus
    # `Set-Content -Encoding utf8` on a CP936 console decodes UTF-8 as CP936 and writes
    # it back, replacing the trailing byte of every non-ASCII character with `?`. The
    # build stayed green and the tests passed, so nothing noticed until a tool refused to
    # open the file - and the transformation is lossy, so the repair was a manual
    # reconstruction. See tool/check_encoding.py.
    & python (Join-Path $PSScriptRoot 'check_encoding.py')
    if ($LASTEXITCODE -ne 0) { throw 'a text file in the repository is not valid UTF-8' }
  }

  Step 'describe the generated module' {
    # No pipeline: piping a native command's output makes PowerShell treat its
    # stderr as a terminating error under $ErrorActionPreference='Stop'.
    dart run tool/vmpc/bin/vmpc.dart disasm --seed 1 > $null
  }

  Step 'deploy the desktop runtime' {
    # build_native.ps1 runs cl.exe through cmd.exe, and cl writes its banner to
    # stderr. With $ErrorActionPreference='Stop' inherited, PowerShell would treat
    # that banner as a failure, so run it in a child process where the preference
    # does not leak in.
    $script = Join-Path $PSScriptRoot 'build_native.ps1'
    & powershell -NoProfile -ExecutionPolicy Bypass -File $script -Configuration Release
    if ($LASTEXITCODE -ne 0) { throw "build_native.ps1 exited $LASTEXITCODE" }
  }

  Step 'operand widths match the assembler' {
    # The runtime's `op_width()` and the assembler's `kOperandBytes` drive the same
    # sequential walk from opposite ends, and a disagreement does not fail the walk -
    # it desynchronises it. Compared through the runtime's own probe, for all 256 byte
    # values, so the check covers the size of the opcode set as well as the widths.
    # Reverse-verified: see tool/verify_wire_widths.py --negative-test and the note in
    # tool/vmpacker_targets.txt.
    & python (Join-Path $PSScriptRoot 'verify_wire_widths.py')
    if ($LASTEXITCODE -ne 0) { throw 'the decoder and the assembler disagree about operand widths' }
  }

  Step 'concurrency (native harness)' {
    # The runtime is one module and one interpreter shared by every thread in the
    # process. `flutter test` cannot drive that: spawning an isolate that dlopens
    # the runtime hangs in this harness even with the runtime's lock removed, so an
    # isolate-based test would measure the test environment. A C harness drives the
    # same public ABI from several OS threads, which is what the lock must survive.
    & (Join-Path $PSScriptRoot 'verify_concurrency.ps1')
  }

  Step 'app tests (differential + protection)' {
    Push-Location app
    try {
      $lib = if ($IsWindows -or $env:OS -eq 'Windows_NT') {
        (Resolve-Path 'build/native/dartvmp.dll').Path
      } else {
        (Resolve-Path 'build/native/libdartvmp.so').Path
      }
      $env:DARTVMP_LIBRARY_PATH = $lib
      Write-Host "  DARTVMP_LIBRARY_PATH=$lib"
      flutter test
    } finally {
      Remove-Item Env:\DARTVMP_LIBRARY_PATH -ErrorAction SilentlyContinue
      Pop-Location
    }
  }

  if ($Release) {
    Step 'release APK' {
      # `--obfuscate --split-debug-info` is not cosmetic here, and not optional either:
      # `verify_protection.ps1` requires that **zero** protected function names appear in
      # libapp.so. That is only achievable with obfuscation, because a non-obfuscated
      # snapshot keeps the generated stub declarations under their real names (the
      # reverse test for this check is exactly the build without the flag: it reports
      # six of the eight). The stubs dispatch by numeric id, so renaming costs nothing.
      #
      # The symbols directory is what maps a crash stack back to real names, so it has
      # to be archived with the release rather than deleted - a shipped build whose
      # crashes cannot be symbolised is a real cost, and it is the price of this step.
      Push-Location app
      try {
        flutter build apk --release --target-platform android-arm64 `
          --obfuscate --split-debug-info=build/symbols
      } finally { Pop-Location }
    }
    Step 'release desktop runner' {
      # The Windows runner is the only artifact that links the runtime statically,
      # and it is the only one `flutter test` cannot see: the test host loads a
      # separately built DLL through DARTVMP_LIBRARY_PATH. A release build of the
      # runner is what the desktop real-run step below inspects.
      Push-Location app
      try { flutter build windows --release }
      finally { Pop-Location }
    }
    Step 'desktop runtime is in the runner' {
      # A link check, not a launch: it needs no desktop session, so CI can run it.
      # This is the check that was missing when the plugin's CMake linked the
      # static core library and the MSVC linker discarded it (nothing in the
      # runner references dartvmp_* by name, so a plain target_link_libraries is a
      # no-op): the runner came out at 90 KB, `flutter build` succeeded, every test
      # passed, and the shipped application's first screen said "The protected
      # runtime is unavailable". Run tool/capture_desktop_run.ps1 to launch it and
      # capture the window instead.
      & (Join-Path $PSScriptRoot 'capture_desktop_run.ps1') -CheckOnly
    }
    Step 'protection verification' {
      & (Join-Path $PSScriptRoot 'verify_protection.ps1')
    }
    Step 'cryptographic primitives' {
      # Two things, and the second is a property of the shipped artifact rather than of
      # the source: the SHA-256 the keystream is built on must match the published
      # vectors, and the known-plaintext key recovery that used to work against the
      # release APK must fail. The attack is still implemented in
      # tool/recover_from_shipped.py, and it caught the genuinely vulnerable build
      # before the mask was replaced - so this is a regression test, not a claim.
      & (Join-Path $PSScriptRoot 'verify_crypto.ps1')
    }
    Step 'opcode map recovery (reverse test)' {
      # Item 1's reverse test, and it is the only check that can tell whether the
      # private instruction set got weaker: the container's stream cipher is keyed by
      # the seed in its own header, so an attacker strips it offline and is left with
      # just the opcode permutation. The old mapping was affine with a public salt, so
      # 128 candidates plus the stored CRC recovered it - tool/recover_opcodes.py does
      # exactly that and must now fail. --selftest re-packs the same body with the old
      # affine mapping and must still recover it, because a detector that can only ever
      # say "nothing found" is a print statement: its first version zeroed operand
      # bytes, so its CRC oracle never matched and it reported "not affine" for every
      # input, including the legacy container it was supposed to crack.
      $py = Get-Command python -ErrorAction SilentlyContinue
      if (-not $py) {
        throw 'python unavailable, so the opcode-map reverse test was not run'
      }
      & python (Join-Path $root 'tool/recover_opcodes.py')
      if ($LASTEXITCODE -ne 0) {
        throw 'the affine brute force recovered the shipped opcode map (item 1 regressed)'
      }
      & python (Join-Path $root 'tool/recover_opcodes.py') --selftest
      if ($LASTEXITCODE -ne 0) {
        throw 'the reverse test cannot recover even a legacy container, so it proves nothing'
      }
    }
    Step 'C-layer virtualization (VMPacker)' {
      # Reports the state of the C layer rather than assuming it. Two facts have to
      # be visible here, because neither is observable from the artifact:
      #   * whether VMPacker is present at all - a machine without it must say
      #     "NOT APPLIED" out loud, not stay silent, since an unvirtualized library
      #     and a virtualized one look the same once built;
      #   * whether the hand-off would actually find its targets, which the script
      #     proves by running the tool rather than trusting the target list.
      # -AllowMissing keeps this informational when the tool is absent; when it is
      # present, any failure is a real failure and fails the step.
      #
      # The target list is whatever tool/vmpacker_targets.txt says, which is two
      # functions: the five that would need VMPacker to resolve a call or an `adrp`
      # are listed in a section that the instruction-coverage check refuses, because
      # on a real device they crash the application (see that file's table).
      #
      # The unstripped copy the CMake build keeps (see the post-build note in
      # packages/dartvmp/src/CMakeLists.txt), not the library inside Gradle's own
      # intermediates tree. AGP strips that one in place depending on which task ran
      # last, so reading it is a race - and when it loses, the hand-off finds no symbol
      # table and reports NOT APPLIED for a library that was actually built correctly.
      # (Observed twice: 3g6s6f4x had no symbols while 316f1687 next to it had 83.)
      # The fallback keeps this informative for a tree built before that copy existed.
      #
      # The comment also has to sit outside the pipeline: a # between | elements ends
      # the statement and produces "The expression after '&' ... was not valid".
      $so = Join-Path $root 'build/unstripped/libdartvmp.unstripped.arm64-v8a.so'
      if (-not (Test-Path $so)) {
        $newest = Get-ChildItem -Path (Join-Path $root 'app/build/dartvmp/intermediates/cxx') `
          -Recurse -Filter 'libdartvmp.so' -ErrorAction SilentlyContinue |
          Where-Object { $_.FullName -match 'arm64-v8a' } |
          Sort-Object LastWriteTime -Descending | Select-Object -First 1
        if ($newest) { $so = $newest.FullName }
      }
      if (-not (Test-Path $so)) {
        Write-Host '  (no libdartvmp.so found; build the APK first)'
      } else {
        Write-Host "  unstripped library: $so"
        & (Join-Path $PSScriptRoot 'apply_vmpacker.ps1') -InputSo $so `
          -OutputSo (Join-Path $root 'build/libdartvmp.vmpprotected.so') -AllowMissing
      }
    }
    Step 'device run (virtualized library)' {
      # THE ONLY CHECK THAT RUNS THE PROTECTED ARTIFACT. It exists because every
      # structural check was green while five of the seven virtualized functions
      # killed the application on launch: VMPacker reported "5/5 targets replaced by
      # VM trampolines", the APK was valid and signed, and the process SIGSEGV'd before
      # its first frame. Nothing that inspects bytes can see that.
      #
      # Requires a device, and says so rather than skipping silently - "no device" and
      # "the protected runtime works" must not look the same in a log.
      $adbPath = $null
      $adbCmd = Get-Command adb -ErrorAction SilentlyContinue
      if ($adbCmd) { $adbPath = $adbCmd.Source }
      if (-not $adbPath) {
        $cand = Join-Path $env:LOCALAPPDATA 'Android\Sdk\platform-tools\adb.exe'
        if (Test-Path $cand) { $adbPath = $cand }
      }
      $attached = $false
      if ($adbPath) {
        $prevEap = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        try { $attached = @(& $adbPath devices 2>$null | Where-Object { $_ -match '\sdevice$' }).Count -gt 0 }
        finally { $ErrorActionPreference = $prevEap }
      }
      $protectedSo = Join-Path $root 'build/libdartvmp.vmpprotected.so'
      $releaseApk = Join-Path $root 'app/build/app/outputs/flutter-apk/app-release.apk'
      $protectedApk = Join-Path $root 'build/app-vmpprotected.apk'
      if (-not $attached) {
        Write-Host '  NO DEVICE ATTACHED: the protected library was NOT run.' -ForegroundColor Yellow
        Write-Host '  Everything else in this suite looks at the artifact; nothing here has'
        Write-Host '  proved it works. Attach a device and re-run to close that gap.'
      } elseif (-not (Test-Path $protectedSo) -or -not (Test-Path $releaseApk)) {
        Write-Host '  (no virtualized library or no release APK; nothing to run)' -ForegroundColor Yellow
      } else {
        # Built here rather than read from a previous run: the step has to exercise the
        # documented pipeline end to end, and a stale APK from an earlier session is
        # exactly the kind of thing that makes a device gate report the wrong build.
        & (Join-Path $PSScriptRoot 'repack_apk.ps1') -Apk $releaseApk `
          -Replace "lib/arm64-v8a/libdartvmp.so=$protectedSo" -Out $protectedApk
        & (Join-Path $PSScriptRoot 'verify_device_run.ps1') -Apk $protectedApk
      }
    }
    Step 'anti-debug gate' {
      # Compiles the runtime twice (with and without the diagnostic probes) and
      # asserts the DARTVMP_NO_ANTIDEBUG escape hatch is absent from the second.
      # A runtime-only escape hatch made the whole anti-debug layer optional from
      # the shell, which is worth a regression check rather than a comment.
      & (Join-Path $PSScriptRoot 'verify_antidebug_gate.ps1')
    }
  }
} finally {
  Pop-Location
}

Write-Host ''
if ($failed.Count -eq 0) {
  Write-Host 'ALL GREEN' -ForegroundColor Green
  exit 0
}
Write-Host "FAILED: $($failed.Count) step(s)" -ForegroundColor Red
$failed | ForEach-Object { Write-Host "  - $_" }
exit 1
