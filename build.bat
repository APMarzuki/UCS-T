@echo off
title UCS-T Builder
echo ================================
echo    UCS-T Build System
echo ================================
echo.

:: Check if required files exist
if not exist "app.py" (
    echo ❌ ERROR: app.py not found!
    echo Please run this script from the project root directory.
    pause
    exit /b 1
)

if not exist "requirements.txt" (
    echo ❌ ERROR: requirements.txt not found!
    pause
    exit /b 1
)

:: Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo ❌ ERROR: Python is not installed or not in PATH!
    echo Please install Python 3.8+ from python.org
    pause
    exit /b 1
)

:: Check if PyInstaller is installed
pip list | findstr PyInstaller >nul 2>&1
if errorlevel 1 (
    echo 📦 Installing PyInstaller...
    pip install pyinstaller
)

echo.
echo 🔨 Building UCS-T executable...
echo.

:: Create build command
set BUILD_CMD=pyinstaller --windowed --onefile --name "UCS-T" --clean --noconfirm

:: Add icon if exists
if exist "assets\logo.ico" (
    set BUILD_CMD=%BUILD_CMD% --icon=assets\logo.ico
) else (
    echo ⚠️  No logo.ico found in assets folder
)

:: Complete the command
set BUILD_CMD=%BUILD_CMD% app.py

echo Executing: %BUILD_CMD%
echo.

%BUILD_CMD%

if %errorlevel% == 0 (
    echo.
    echo ================================
    echo ✅ BUILD SUCCESSFUL!
    echo ================================
    echo.
    echo 📁 Your executable is here:
    echo    dist\UCS-T.exe
    echo.
    echo 🚀 You can now distribute UCS-T.exe
    echo.
) else (
    echo.
    echo ❌ BUILD FAILED!
    echo Check the errors above.
)

pause