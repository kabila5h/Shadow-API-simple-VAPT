@echo off
REM ─────────────────────────────────────────────────────────────
REM Shadow API Scanner — Windows Build & Run Script
REM ─────────────────────────────────────────────────────────────
setlocal enabledelayedexpansion

set "SCRIPT_DIR=%~dp0"
set "VENV_DIR=%SCRIPT_DIR%.venv"
set "DIST_DIR=%SCRIPT_DIR%dist"

echo.
echo   ____  _               _                  _    ____ ___
echo  / ___^|^| ^|__   __ _  __^| ^| _____      __  / \  ^|  _ \_ _^|
echo  \___ \^| '_ \ / _` ^|/ _` ^|/ _ \ \ /\ / / / _ \ ^| ^|_) ^| ^|
echo   ___) ^| ^| ^| ^| (_^| ^| (_^| ^| (_) \ V  V / / ___ \^|  __/^| ^|
echo  ^|____/^|_^| ^|_^|\__,_^|\__,_^|\___/ \_/\_/ /_/   \_\_^|  ^|___^|
echo          Scanner v1.0.0 -- Windows Build ^& Run
echo.

if "%~1"=="" goto usage
if "%~1"=="setup" goto setup
if "%~1"=="build" goto build
if "%~1"=="run" goto run

REM Check if first arg is a URL
echo %~1 | findstr /i "http" >nul
if %errorlevel%==0 goto run_direct

goto usage

:setup
echo [+] Setting up virtual environment...
python -m venv "%VENV_DIR%"
call "%VENV_DIR%\Scripts\activate.bat"

echo [+] Installing dependencies...
pip install --upgrade pip setuptools wheel >nul 2>&1
pip install -r "%SCRIPT_DIR%requirements.txt" >nul 2>&1

echo [+] Installing Playwright browsers...
python -m playwright install chromium 2>nul || echo [!] Playwright browser install failed (optional)

echo [+] Setup complete.
goto end

:build
echo [+] Building standalone Windows executable...
if not exist "%VENV_DIR%\Scripts\activate.bat" goto setup
call "%VENV_DIR%\Scripts\activate.bat"
pip install pyinstaller >nul 2>&1

pyinstaller ^
    --onefile ^
    --name shadow-scan ^
    --hidden-import shadow_api_scanner ^
    --hidden-import shadow_api_scanner.phase1 ^
    --hidden-import shadow_api_scanner.phase2 ^
    --hidden-import shadow_api_scanner.phase3 ^
    --hidden-import shadow_api_scanner.phase4 ^
    --hidden-import shadow_api_scanner.utils ^
    --hidden-import shadow_api_scanner.core ^
    --collect-all shadow_api_scanner ^
    "%SCRIPT_DIR%shadow_api_scanner\__main__.py"

echo [+] Executable built: %DIST_DIR%\shadow-scan.exe
echo     Usage: dist\shadow-scan.exe https://target-spa.com
goto end

:run
shift
:run_direct
if not exist "%VENV_DIR%\Scripts\activate.bat" (
    echo [!] Virtual environment not found. Running setup first...
    call :setup
)
call "%VENV_DIR%\Scripts\activate.bat"
python -m shadow_api_scanner %*
goto end

:usage
echo Usage: %~nx0 {setup^|build^|run} [options]
echo.
echo Commands:
echo   setup   Install dependencies and Playwright
echo   build   Create standalone .exe with PyInstaller
echo   run     Run the scanner
echo.
echo Examples:
echo   %~nx0 setup
echo   %~nx0 run https://example.com
echo   %~nx0 run https://example.com --verbose --no-browser
echo   %~nx0 build
echo.

:end
endlocal
