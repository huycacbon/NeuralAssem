@echo off
REM Start the Binary Graph Analyzer backend on loopback.
REM Creates the venv and installs dependencies on first run.

setlocal
cd /d "%~dp0\..\backend" || exit /b 1

if not exist ".venv\Scripts\python.exe" (
    echo [setup] Tao virtualenv...
    python -m venv .venv || (echo Khong tao duoc venv. Can Python 3.11+ trong PATH. & exit /b 1)
    echo [setup] Cai dependencies ^(angr co the mat vai phut^)...
    ".venv\Scripts\python.exe" -m pip install --upgrade pip
    ".venv\Scripts\python.exe" -m pip install -r requirements.txt || (echo Cai dat that bai. & exit /b 1)
)

echo [run] Backend: http://127.0.0.1:8000  ^(docs: /docs^)
".venv\Scripts\python.exe" -m uvicorn app.main:app --host 127.0.0.1 --port 8000

endlocal
