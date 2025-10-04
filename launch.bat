@echo off
REM Secure File Encryption Tool Launcher
REM This script launches the GUI application

echo.
echo ========================================
echo  Secure File Encryption Tool
echo ========================================
echo.

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python is not installed or not in PATH
    echo Please install Python 3.8 or higher from python.org
    echo.
    pause
    exit /b 1
)

REM Check if cryptography is installed
python -c "import cryptography" >nul 2>&1
if errorlevel 1 (
    echo Installing required dependencies...
    pip install -r requirements.txt
    if errorlevel 1 (
        echo ERROR: Failed to install dependencies
        echo Please run: pip install -r requirements.txt
        echo.
        pause
        exit /b 1
    )
)

REM Launch the GUI
echo Starting application...
echo.
python gui_app.py

if errorlevel 1 (
    echo.
    echo Application closed with errors
    pause
)
