@echo off
REM Build the benign PE test fixtures with MSVC (cl.exe).
REM Run from any prompt: it locates and calls vcvars64 itself.
REM
REM All fixtures are inert. See samples\README.md and each src\*.c header.

setlocal enabledelayedexpansion
cd /d "%~dp0"

REM --- Locate a Visual Studio C/C++ toolchain -----------------------------
set "VCVARS="
for %%P in (
    "C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat"
    "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
    "C:\Program Files\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
) do (
    if exist %%P set "VCVARS=%%~P"
)

if not defined VCVARS (
    echo [error] Khong tim thay vcvars64.bat. Can Visual Studio voi C++ workload.
    exit /b 1
)

echo [setup] Dung toolchain: "%VCVARS%"
call "%VCVARS%" >nul || (echo [error] vcvars64 that bai. & exit /b 1)

if not exist build mkdir build

REM cl flags:
REM   /nologo  yen lang       /W3 canh bao      /MT static CRT
REM   /Od debug (khong toi uu) + /Zi symbol     /O2 release (toi uu)
set "COMMON=/nologo /W3 /MT"
set "DBG=%COMMON% /Od /Zi /DDEBUG"
set "REL=%COMMON% /O2 /DNDEBUG"

echo [build] 01_simple_debug.exe
cl %DBG% src\simple.c /Fo:build\ /Fd:build\01.pdb /Fe:01_simple_debug.exe /link /INCREMENTAL:NO /NOLOGO || goto :fail

echo [build] 02_simple_release.exe
cl %REL% src\simple.c /Fo:build\ /Fe:02_simple_release.exe /link /INCREMENTAL:NO /NOLOGO || goto :fail

echo [build] 03_branch_loop.exe
cl %REL% src\branch_loop.c /Fo:build\ /Fe:03_branch_loop.exe /link /INCREMENTAL:NO /NOLOGO || goto :fail

echo [build] 04_imports.exe
cl %REL% src\imports.c /Fo:build\ /Fe:04_imports.exe /link /INCREMENTAL:NO /NOLOGO || goto :fail

echo [build] 05_multithread.exe
cl %REL% src\multithread.c /Fo:build\ /Fe:05_multithread.exe /link /INCREMENTAL:NO /NOLOGO || goto :fail

echo [build] 07_strings_sysinternals.exe
cl %REL% src\strings_fixture.c /Fo:build\ /Fe:07_strings_sysinternals.exe /link /INCREMENTAL:NO /NOLOGO || goto :fail

REM --- 06 is a real, benign system binary (no source to compile) ----------
echo [copy ] 06_whoami.exe  (from System32)
copy /y "%SystemRoot%\System32\whoami.exe" "06_whoami.exe" >nul || (echo [warn] khong copy duoc whoami.exe)

REM --- tidy intermediates -------------------------------------------------
del /q *.obj 2>nul
del /q *.pdb 2>nul
del /q *.ilk 2>nul
rmdir /s /q build 2>nul

echo.
echo [done] Fixtures da tao trong: %CD%
dir /b *.exe
exit /b 0

:fail
echo [error] Bien dich that bai.
exit /b 1
