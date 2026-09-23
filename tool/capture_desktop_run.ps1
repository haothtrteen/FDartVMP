# capture_desktop_run.ps1 - launches the Windows release runner, waits for the
# first frame to settle, captures the window, and reports whether the process
# survived.
#
# This is the desktop half of the real-device check. `flutter test` drives the
# runtime through a *loadable* library; the shipped runner links it statically, so
# a run of the actual executable is the only thing that exercises that path - plus
# it is the only check that looks at what the user actually sees.
#
# Usage (from the repository root):
#   powershell -ExecutionPolicy Bypass -File tool/capture_desktop_run.ps1
[CmdletBinding()]
param(
  [string]$Exe = 'app/build/windows/x64/runner/Release/dartvmp_demo.exe',
  [string]$Out = 'build/desktop-run.png',
  [int]$SettleSeconds = 8,
  # Resize the window before capturing. The demo's list of protected calls is
  # longer than the default 1280x720 window, and resizing is a far more reliable
  # way to see all of it than synthesising wheel events: a wheel event goes to
  # whatever window is under the pointer, needs the target to be genuinely
  # foreground, and when it silently fails the screenshot still shows a plausible
  # page - which is how the first three attempts at this "verified" the top of the
  # list. 0 leaves the window as it is.
  [int]$Width = 0,
  [int]$Height = 0,
  # Wheel notches to scroll down before capturing, if resizing is not enough.
  [int]$ScrollNotches = 0,
  # Stop after the link check, without launching anything. `tool/test.ps1` uses
  # this: the symbol scan is the part that catches the bug this script was written
  # for, and it needs no desktop session, so CI can run it. The capture itself
  # needs a real display.
  [switch]$CheckOnly
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$exePath = Join-Path $root $Exe
if (-not (Test-Path $exePath)) {
  throw "runner not found: $exePath`nRun: cd app; flutter build windows --release"
}
$outPath = Join-Path $root $Out
New-Item -ItemType Directory -Force -Path (Split-Path -Parent $outPath) | Out-Null

# The runtime has to actually be in the executable before launching it.
#
# This check exists because the plugin's CMake once linked the static core library
# without /WHOLEARCHIVE and the MSVC linker discarded it entirely: the runner came
# out at 90 KB with no dartvmp_* symbols, the app launched normally, and its first
# screen read "The protected runtime is unavailable". Every test in the suite
# passed, because `flutter test` loads a separately built DLL through
# DARTVMP_LIBRARY_PATH and never touches the runner. Checking the export table
# takes milliseconds and turns a screenshot inspection into a build-time fact.
$exeBytes = [System.IO.File]::ReadAllBytes($exePath)
$exeText = [System.Text.Encoding]::ASCII.GetString($exeBytes)
$required = @('dartvmp_init', 'dartvmp_call', 'dartvmp_function_info')
$missing = @($required | Where-Object { -not $exeText.Contains($_) })
if ($missing.Count -gt 0) {
  throw @"
the runner does not contain the runtime: $($missing -join ', ') absent from
  $exePath ($($exeBytes.Length) bytes)
The plugin must link the static core with /WHOLEARCHIVE - see
  packages/dartvmp/windows/CMakeLists.txt
A plain target_link_libraries() succeeds and is then discarded by the linker,
because nothing in the runner references the symbols by name.
"@
}
Write-Host "runtime present in the runner ($($exeBytes.Length) bytes in the executable)"

if ($CheckOnly) {
  Write-Host 'link check only; not launching the application'
  exit 0
}

Add-Type -AssemblyName System.Drawing
Add-Type @"
using System;
using System.Runtime.InteropServices;
public class Win32Cap {
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h, out RECT r);
  [DllImport("user32.dll")] public static extern bool SetCursorPos(int x, int y);
  [DllImport("user32.dll")] public static extern void mouse_event(uint f, uint dx, uint dy, int d, IntPtr e);
  [DllImport("user32.dll")] public static extern bool SetWindowPos(IntPtr h, IntPtr after, int x, int y, int cx, int cy, uint flags);
  [DllImport("user32.dll")] public static extern IntPtr WindowFromPoint(POINT p);
  [DllImport("user32.dll")] public static extern IntPtr GetAncestor(IntPtr h, uint flags);
  [StructLayout(LayoutKind.Sequential)]
  public struct RECT { public int Left, Top, Right, Bottom; }
  [StructLayout(LayoutKind.Sequential)]
  public struct POINT { public int X, Y; }
}
"@

$proc = Start-Process -FilePath $exePath -PassThru
Write-Host "launched pid $($proc.Id)"

# A first-run Flutter desktop window takes a moment to appear and then a moment
# more to finish the post-frame callback that runs the protected calls.
$deadline = (Get-Date).AddSeconds(30)
$handle = [IntPtr]::Zero
while ((Get-Date) -lt $deadline) {
  Start-Sleep -Milliseconds 500
  if ($proc.HasExited) { throw "the runner exited during startup with code $($proc.ExitCode)" }
  $proc.Refresh()
  if ($proc.MainWindowHandle -ne [IntPtr]::Zero) { $handle = $proc.MainWindowHandle; break }
}
if ($handle -eq [IntPtr]::Zero) { throw 'no main window appeared within 30s' }
Write-Host "main window handle $handle"

Start-Sleep -Seconds $SettleSeconds
if ($proc.HasExited) { throw "the runner exited after the window appeared, code $($proc.ExitCode)" }

[void][Win32Cap]::SetForegroundWindow($handle)
Start-Sleep -Milliseconds 700

if ($Width -gt 0 -and $Height -gt 0) {
  # SWP_NOZORDER | SWP_SHOWWINDOW. NOT SWP_NOSIZE: adding it is the obvious-looking
  # mistake and it makes SetWindowPos return success while leaving the window at
  # its old size, so the capture silently comes back at 1280x720.
  if (-not [Win32Cap]::SetWindowPos($handle, [IntPtr]::Zero, 0, 0,
                                    $Width, $Height, 0x0044)) {
    throw "could not resize the runner to ${Width}x${Height}"
  }
  Write-Host "resized to ${Width}x${Height}"
  Start-Sleep -Seconds 2
  if ($proc.HasExited) { throw "the runner exited after the resize, code $($proc.ExitCode)" }
}

# Geometry first: the scroll block needs a point inside the window.
$rect = New-Object Win32Cap+RECT
if (-not [Win32Cap]::GetWindowRect($handle, [ref]$rect)) { throw 'GetWindowRect failed' }
$w = $rect.Right - $rect.Left
$h = $rect.Bottom - $rect.Top
Write-Host "window ${w}x${h} at $($rect.Left),$($rect.Top)"

if ($ScrollNotches -ne 0) {
  # Raise the window above everything else first. `SetForegroundWindow` alone is
  # not enough on a live desktop: Windows refuses it for a process that is not
  # already foreground, and the wheel then goes to whatever window *is* - which is
  # how an earlier version of this script captured the top of the list four times
  # in a row while reporting success.
  [void][Win32Cap]::SetWindowPos($handle, [IntPtr]::new(-1), 0, 0, 0, 0, 0x0043)  # HWND_TOPMOST, NOSIZE|NOMOVE|SHOWWINDOW
  [void][Win32Cap]::SetForegroundWindow($handle)
  Start-Sleep -Milliseconds 500

  # Park the cursor inside the window before scrolling, or the wheel goes to
  # whatever the pointer happens to be over. It deliberately does not use the
  # window's centre: the capture runs on a live desktop where another window can
  # be covering that point, and the wheel would then scroll *that* window while
  # the screenshot still looked plausible.
  $px = $rect.Left + 120
  $py = $rect.Top + 520
  [void][Win32Cap]::SetCursorPos($px, $py)
  Start-Sleep -Milliseconds 200
  # And confirm the point really is ours before scrolling into it.
  $pt = New-Object Win32Cap+POINT
  $pt.X = $px; $pt.Y = $py
  $top = [Win32Cap]::GetAncestor([Win32Cap]::WindowFromPoint($pt), 2)  # GA_ROOT
  if ($top -ne $handle) {
    throw "the scroll point ($px,$py) belongs to another window ($top, not $handle); close whatever is covering the runner and retry"
  }
  for ($i = 0; $i -lt $ScrollNotches; $i++) {
    # Positive delta scrolls down: the wheel convention is that a positive value
    # is "away from the user", and getting the sign wrong silently captures the
    # top of the list instead of the bottom - which still looks like a pass.
    [Win32Cap]::mouse_event(0x0800, 0, 0, 120, [IntPtr]::Zero)  # MOUSEEVENTF_WHEEL
    Start-Sleep -Milliseconds 80
  }
  Start-Sleep -Milliseconds 600
  [void][Win32Cap]::SetWindowPos($handle, [IntPtr]::new(-2), 0, 0, 0, 0, 0x0043)  # HWND_NOTOPMOST
}

$bmp = New-Object System.Drawing.Bitmap $w, $h
$g = [System.Drawing.Graphics]::FromImage($bmp)
$g.CopyFromScreen($rect.Left, $rect.Top, 0, 0, $bmp.Size)
$bmp.Save($outPath, [System.Drawing.Imaging.ImageFormat]::Png)
$g.Dispose(); $bmp.Dispose()
Write-Host "captured $outPath ($((Get-Item $outPath).Length) bytes)"

# The exit code matters: a Flutter desktop app that hits an unhandled Dart
# exception in the post-frame callback still shows a window, so "it stayed open"
# is not by itself evidence. A clean CloseMainWindow() returning 0 is.
[void]$proc.CloseMainWindow()
if (-not $proc.WaitForExit(10000)) { $proc.Kill(); Write-Host 'had to kill the runner' }
else { Write-Host "runner exit code $($proc.ExitCode)" }
