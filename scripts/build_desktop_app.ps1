<#
.SYNOPSIS
    Build the standalone Windows desktop app: one folder, one .exe, nothing
    else required on the target machine (no Python, no Node, no pip/npm).

.DESCRIPTION
    Produces `dist_desktop\BinaryGraphAnalyzer\`:
        BinaryGraphAnalyzer.exe   <- native launcher (PyInstaller, ~9 MB)
        python_embed\             <- portable Python + angr and every other
                                     backend dependency, already pip-installed
        backend\                  <- this repo's app/ source + desktop_launcher.py
        frontend_dist\            <- built frontend static files

    Copy that whole folder to any Windows 10/11 x64 machine and double-click
    the .exe - it opens a native window (WebView2, which every current
    Windows ships with) showing the same UI as the web deployment, backed by
    a FastAPI server running entirely inside the bundled Python. No install
    step, no admin rights, no internet access needed at run time.

    Why an *embeddable* Python instead of freezing everything with PyInstaller:
    angr's plugin/SimProcedure system relies on a lot of dynamic,
    introspection-based importing that PyInstaller's static import analysis
    does not reliably discover - a well-known source of "works from source,
    breaks when frozen" bugs for angr-based tools. This script keeps angr on
    a real, unfrozen interpreter (verified: capstone and claripy/z3 - the two
    heaviest compiled dependencies - both work correctly there) and only
    PyInstaller-freezes the ~30-line native launcher stub, which has none of
    that dynamic-import risk.

.PARAMETER PythonVersion
    Embeddable CPython version to bundle. Must be one Windows amd64 embeddable
    builds exist for. Defaults to the version this project is developed with.

.PARAMETER OutputDir
    Where to write the final app folder. Defaults to `dist_desktop` at the
    repo root.

.PARAMETER SkipDownload
    Reuse a previously-downloaded embeddable Python zip / get-pip.py from the
    local cache instead of re-fetching them.

.PARAMETER Zip
    Also produce `dist_desktop\BinaryGraphAnalyzer-win-x64.zip` for easy
    handoff.

.EXAMPLE
    .\build_desktop_app.ps1
    .\build_desktop_app.ps1 -Zip
    .\build_desktop_app.ps1 -SkipDownload -OutputDir C:\builds\bga
#>

[CmdletBinding()]
param(
    [string]$PythonVersion = "3.14.4",
    [string]$OutputDir = "",
    [switch]$SkipDownload,
    [switch]$Zip
)

$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $PSScriptRoot
$backendDir = Join-Path $root "backend"
$frontendDir = Join-Path $root "frontend"
$desktopDir = Join-Path $root "desktop"
$cacheDir = Join-Path $desktopDir ".cache"
if (-not $OutputDir) { $OutputDir = Join-Path $root "dist_desktop" }
$appDir = Join-Path $OutputDir "BinaryGraphAnalyzer"

function Write-Step($message) {
    Write-Host "[build] $message" -ForegroundColor Cyan
}

New-Item -ItemType Directory -Force -Path $cacheDir | Out-Null

# --- Preflight ------------------------------------------------------------

foreach ($cmd in @("npm", "curl")) {
    if (-not (Get-Command $cmd -ErrorAction SilentlyContinue)) {
        throw "Khong tim thay '$cmd' trong PATH."
    }
}

$devPython = Join-Path $backendDir ".venv\Scripts\python.exe"
if (-not (Test-Path $devPython)) {
    throw "Khong tim thay $devPython. Chay scripts\run_backend.bat mot lan de tao venv truoc."
}

$pyinstaller = Join-Path $backendDir ".venv\Scripts\pyinstaller.exe"
if (-not (Test-Path $pyinstaller)) {
    Write-Step "Cai pyinstaller vao backend .venv (chi can cho buoc build nay)..."
    & $devPython -m pip install pyinstaller --quiet
}

# --- 1. Build frontend ------------------------------------------------------

Write-Step "npm run build..."
Push-Location $frontendDir
try {
    if (-not (Test-Path (Join-Path $frontendDir "node_modules"))) {
        npm install
        if ($LASTEXITCODE -ne 0) { throw "npm install that bai." }
    }
    npm run build
    if ($LASTEXITCODE -ne 0) { throw "npm run build that bai." }
} finally {
    Pop-Location
}

# --- 2. Fetch embeddable Python --------------------------------------------

$embedZipName = "python-$PythonVersion-embed-amd64.zip"
$embedZipPath = Join-Path $cacheDir $embedZipName
if (-not $SkipDownload -or -not (Test-Path $embedZipPath)) {
    Write-Step "Tai Python embeddable $PythonVersion..."
    $embedUrl = "https://www.python.org/ftp/python/$PythonVersion/$embedZipName"
    curl.exe -sL -o $embedZipPath $embedUrl
    if (-not (Test-Path $embedZipPath) -or (Get-Item $embedZipPath).Length -lt 1MB) {
        throw "Tai Python embeddable that bai: $embedUrl"
    }
}

$getPipPath = Join-Path $cacheDir "get-pip.py"
if (-not $SkipDownload -or -not (Test-Path $getPipPath)) {
    Write-Step "Tai get-pip.py..."
    curl.exe -sL -o $getPipPath "https://bootstrap.pypa.io/get-pip.py"
}

# --- 3. Assemble python_embed with every backend dependency ----------------

if (Test-Path $OutputDir) {
    Write-Step "Xoa build cu $OutputDir..."
    Remove-Item -Recurse -Force $OutputDir
}
New-Item -ItemType Directory -Force -Path $appDir | Out-Null

$pyEmbedDir = Join-Path $appDir "python_embed"
Write-Step "Giai nen Python embeddable..."
Expand-Archive -Path $embedZipPath -DestinationPath $pyEmbedDir -Force

# The embeddable distribution ships with site-packages disabled by default
# (a `._pth` file fully controls sys.path) - enable it so `pip install` and
# our own imports work normally. Edited in place with a targeted replace
# rather than rebuilt from scratch: the existing lines (the bundled stdlib
# zip, ".") must survive untouched, or the interpreter cannot even import
# `encodings` and fails before running a single line of our code.
$pthCandidates = Get-ChildItem $pyEmbedDir -Filter "python*._pth"
if ($pthCandidates.Count -ne 1) {
    throw "Khong tim thay dung 1 file ._pth trong $pyEmbedDir (tim thay $($pthCandidates.Count))"
}
$pthFile = $pthCandidates[0].FullName
$pthContent = (Get-Content $pthFile -Raw) -replace '#\s*import site', 'import site'
$pthContent = $pthContent.TrimEnd() + "`r`nLib\site-packages`r`n"
# NOT `Set-Content -Encoding utf8`: on Windows PowerShell 5.1 that writes a
# UTF-8 BOM, which Python's `._pth` parser does not strip - the BOM glues
# onto the first line ("python314.zip" becomes "﻿python314.zip"), the
# interpreter can no longer find its own bundled stdlib zip, and it fails
# before running a single line of code ("Failed to import encodings module").
# `._pth` content is plain ASCII, so ASCII encoding (never a BOM) is exact.
[System.IO.File]::WriteAllText($pthFile, $pthContent, [System.Text.Encoding]::ASCII)

$embedPython = Join-Path $pyEmbedDir "python.exe"

Write-Step "Cai pip vao Python embeddable..."
& $embedPython $getPipPath --no-warn-script-location --quiet
if ($LASTEXITCODE -ne 0) { throw "Cai pip that bai." }

Write-Step "Cai dependencies (angr va cac thu vien khac - co the mat vai phut)..."
& $embedPython -m pip install -r (Join-Path $desktopDir "requirements.txt") --no-warn-script-location
if ($LASTEXITCODE -ne 0) { throw "pip install that bai." }

# --- 4. Copy backend source + built frontend --------------------------------

Write-Step "Sao chep backend app/ va desktop_launcher.py..."
$appBackendDir = Join-Path $appDir "backend"
New-Item -ItemType Directory -Force -Path $appBackendDir | Out-Null
Copy-Item (Join-Path $backendDir "app") (Join-Path $appBackendDir "app") -Recurse
Copy-Item (Join-Path $backendDir "desktop_launcher.py") $appBackendDir

Write-Step "Sao chep frontend da build..."
Copy-Item (Join-Path $frontendDir "dist") (Join-Path $appDir "frontend_dist") -Recurse

# --- 5. Build the native launcher .exe (PyInstaller freezes ONLY this) -----

Write-Step "Build BinaryGraphAnalyzer.exe (launcher, khong dong goi angr)..."
$pyiBuildDir = Join-Path $desktopDir "build"
$pyiDistDir = Join-Path $desktopDir "dist"
if (Test-Path $pyiBuildDir) { Remove-Item -Recurse -Force $pyiBuildDir }
if (Test-Path $pyiDistDir) { Remove-Item -Recurse -Force $pyiDistDir }

Push-Location $desktopDir
try {
    & $pyinstaller --onefile --console --name BinaryGraphAnalyzer `
        --workpath $pyiBuildDir --distpath $pyiDistDir --specpath $desktopDir `
        launcher_stub.py
    if ($LASTEXITCODE -ne 0) { throw "PyInstaller build that bai." }
} finally {
    Pop-Location
}

Copy-Item (Join-Path $pyiDistDir "BinaryGraphAnalyzer.exe") $appDir

# --- 6. Report ---------------------------------------------------------------

$sizeBytes = (Get-ChildItem $appDir -Recurse -File | Measure-Object -Property Length -Sum).Sum
$sizeMb = [Math]::Round($sizeBytes / 1MB, 1)

Write-Step "Xong: $appDir ($sizeMb MB)"

if ($Zip) {
    # Most of this tree is already-compressed binaries (angr's wheels, DLLs),
    # so zipping buys little space but - with PowerShell's Compress-Archive,
    # which has real per-item overhead - can take a very long time over
    # thousands of small files. .NET's ZipFile API directly, at the lowest
    # compression level, is markedly faster for a tree shaped like this one.
    $zipPath = Join-Path $OutputDir "BinaryGraphAnalyzer-win-x64.zip"
    Write-Step "Nen thanh $zipPath (co the mat vai phut, cay nhieu file nho)..."
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    if (Test-Path $zipPath) { Remove-Item -Force $zipPath }
    [System.IO.Compression.ZipFile]::CreateFromDirectory(
        $appDir, $zipPath,
        [System.IO.Compression.CompressionLevel]::Fastest,
        $true  # include the BinaryGraphAnalyzer\ folder itself at the zip root
    )
    $zipSizeMb = [Math]::Round((Get-Item $zipPath).Length / 1MB, 1)
    Write-Step "Zip xong: $zipPath ($zipSizeMb MB)"
}

Write-Host ""
Write-Host "Chay thu: $appDir\BinaryGraphAnalyzer.exe" -ForegroundColor Green
Write-Host "Phan phoi: copy ca thu muc BinaryGraphAnalyzer\ (khuyen nghi - nhanh hon zip" -ForegroundColor DarkGray
Write-Host "voi cay nhieu file nho nhu the nay) sang may khac va chay - khong can cai gi them." -ForegroundColor DarkGray
