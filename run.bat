@echo off
title Emoji Cipher Pro Server

echo Starting local server for Emoji Cipher Pro...

:: Check for Python
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo.
    echo [ERROR] Python is not installed or not found in your system's PATH.
    echo Please install Python 3 to run this application correctly.
    echo Visit https://www.python.org/downloads/
    echo.
    pause
    exit /b
)

echo.
echo Server starting at: http://localhost:8000
echo Open this URL in your browser if it doesn't open automatically.
echo.
echo *** Press CTRL+C in this window to stop the server. ***
echo.

start "" http://localhost:8000
python -m http.server 8000
