$ErrorActionPreference = "Stop"

Set-Location $PSScriptRoot

py -m pip install -r requirements.txt
py -m pip install -r requirements-build.txt

py -m PyInstaller --noconfirm --clean --onefile --windowed `
    --name WISE `
    --collect-submodules pywifi `
    app.py

$exePath = Join-Path $PSScriptRoot "dist\WISE.exe"
if (-not (Test-Path -LiteralPath $exePath)) {
    throw "Build did not create $exePath"
}

Write-Host "Build complete: $exePath"
