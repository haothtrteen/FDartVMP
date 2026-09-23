# serve.ps1 - launch the DartVMP protection UI against this repository.
# Usage: powershell -ExecutionPolicy Bypass -File tool/ui/serve.ps1 [-Port 8777] [-NoBrowser]
[CmdletBinding()] param([int]$Port = 8777, [switch]$NoBrowser)
$args2 = @((Join-Path $PSScriptRoot 'serve.py'), '--port', $Port); if ($NoBrowser) { $args2 += '--no-browser' }
& python @args2; exit $LASTEXITCODE
