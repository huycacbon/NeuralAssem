<#
.SYNOPSIS
    Start the Binary Graph Analyzer backend and frontend together.

.DESCRIPTION
    Provisions the Python venv and npm packages on first run, then launches both
    servers in separate windows. Both bind to 127.0.0.1 only - this tool analyses
    untrusted samples and must not be reachable from the network.

    The backend never executes an uploaded binary; it only reads and disassembles.

.PARAMETER SkipInstall
    Skip dependency provisioning (faster when everything is already installed).

.PARAMETER NoBrowser
    Do not open the browser once the frontend is up.

.EXAMPLE
    .\run_all.ps1
    .\run_all.ps1 -SkipInstall
#>

[CmdletBinding()]
param(
    [switch]$SkipInstall,
    [switch]$NoBrowser
)

$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSScriptRoot
$backend = Join-Path $root 'backend'
$frontend = Join-Path $root 'frontend'
$venvPython = Join-Path $backend '.venv\Scripts\python.exe'

function Write-Step($message) {
    Write-Host "[bga] $message" -ForegroundColor Cyan
}

# --- Preflight -----------------------------------------------------------

if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
    throw 'Khong tim thay python trong PATH. Can Python 3.11 tro len.'
}
if (-not (Get-Command npm -ErrorAction SilentlyContinue)) {
    throw 'Khong tim thay npm trong PATH. Can Node.js 18 tro len.'
}

# --- Backend setup -------------------------------------------------------

if (-not $SkipInstall) {
    if (-not (Test-Path $venvPython)) {
        Write-Step 'Tao virtualenv cho backend...'
        python -m venv (Join-Path $backend '.venv')
    }

    Write-Step 'Cai dependencies backend (angr co the mat vai phut)...'
    & $venvPython -m pip install --upgrade pip --quiet
    & $venvPython -m pip install -r (Join-Path $backend 'requirements.txt') --quiet
    if ($LASTEXITCODE -ne 0) { throw 'pip install that bai.' }

    if (-not (Test-Path (Join-Path $frontend 'node_modules'))) {
        Write-Step 'Cai dependencies frontend...'
        Push-Location $frontend
        try {
            npm install
            if ($LASTEXITCODE -ne 0) { throw 'npm install that bai.' }
        } finally {
            Pop-Location
        }
    }
}

if (-not (Test-Path $venvPython)) {
    throw "Khong tim thay $venvPython. Chay lai khong kem -SkipInstall."
}

$envFile = Join-Path $frontend '.env'
$envExample = Join-Path $frontend '.env.example'
if ((-not (Test-Path $envFile)) -and (Test-Path $envExample)) {
    Copy-Item $envExample $envFile
}

# --- Launch --------------------------------------------------------------

Write-Step 'Khoi dong backend tren http://127.0.0.1:8000 ...'
Start-Process -FilePath $venvPython `
    -ArgumentList '-m', 'uvicorn', 'app.main:app', '--host', '127.0.0.1', '--port', '8000' `
    -WorkingDirectory $backend

# Wait for the health endpoint rather than sleeping a fixed amount.
$backendReady = $false
foreach ($attempt in 1..60) {
    try {
        $health = Invoke-RestMethod 'http://127.0.0.1:8000/api/health' -TimeoutSec 2
        if ($health.status) {
            $backendReady = $true
            Write-Step "Backend san sang (angr: $($health.angrAvailable))."
            break
        }
    } catch {
        Start-Sleep -Milliseconds 800
    }
}
if (-not $backendReady) {
    Write-Warning 'Backend chua phan hoi /api/health. Kiem tra cua so backend de xem loi.'
}

Write-Step 'Khoi dong frontend tren http://127.0.0.1:5173 ...'
Start-Process -FilePath 'cmd.exe' `
    -ArgumentList '/c', 'npm run dev' `
    -WorkingDirectory $frontend

if (-not $NoBrowser) {
    foreach ($attempt in 1..40) {
        try {
            Invoke-WebRequest 'http://127.0.0.1:5173' -TimeoutSec 2 -UseBasicParsing | Out-Null
            Start-Process 'http://127.0.0.1:5173'
            break
        } catch {
            Start-Sleep -Milliseconds 800
        }
    }
}

Write-Host ''
Write-Step 'Dang chay:'
Write-Host '  Backend : http://127.0.0.1:8000  (API docs: http://127.0.0.1:8000/docs)'
Write-Host '  Frontend: http://127.0.0.1:5173'
Write-Host ''
Write-Host 'Dong hai cua so vua mo de dung server.' -ForegroundColor DarkGray
Write-Host 'Luu y: cong cu chi phan tich TINH. File mau khong bao gio duoc thuc thi.' -ForegroundColor Yellow
