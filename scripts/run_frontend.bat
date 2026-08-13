@echo off
REM Start the Binary Graph Analyzer frontend dev server.

setlocal
cd /d "%~dp0\..\frontend" || exit /b 1

if not exist "node_modules" (
    echo [setup] Cai npm dependencies...
    call npm install || (echo npm install that bai. & exit /b 1)
)

if not exist ".env" (
    if exist ".env.example" copy /y ".env.example" ".env" >nul
)

echo [run] Frontend: http://127.0.0.1:5173
call npm run dev

endlocal
