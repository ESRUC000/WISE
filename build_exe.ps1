$ErrorActionPreference = "Stop"

Set-Location $PSScriptRoot

if (-not (Test-Path -LiteralPath (Join-Path $PSScriptRoot "data\wise_scans.db"))) {
    throw "The empty SQLite template is missing from data\wise_scans.db"
}

py -m pip install -r requirements.txt
if ($LASTEXITCODE -ne 0) { throw "Installing app dependencies failed." }

py -m pip install -r requirements-build.txt
if ($LASTEXITCODE -ne 0) { throw "Installing build dependencies failed." }

py -m PyInstaller --noconfirm --clean --onefile --windowed `
    --name WISE `
    --add-data "data\wise_scans.db;data" `
    --collect-submodules pywifi `
    app.py
if ($LASTEXITCODE -ne 0) { throw "PyInstaller failed to build WISE.exe." }

py -m PyInstaller --noconfirm --onefile --console `
    --name WISE-Debug `
    --add-data "data\wise_scans.db;data" `
    --collect-submodules pywifi `
    app.py
if ($LASTEXITCODE -ne 0) { throw "PyInstaller failed to build WISE-Debug.exe." }

foreach ($name in @("WISE.exe", "WISE-Debug.exe")) {
    $exePath = Join-Path $PSScriptRoot "dist\$name"
    if (-not (Test-Path -LiteralPath $exePath)) {
        throw "Build did not create $exePath"
    }
}

Write-Host "Build complete: dist\WISE.exe and dist\WISE-Debug.exe"
