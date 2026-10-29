@echo off
title ETIPOS Secure Relay & Tunnel
cd /d "%~dp0"

echo ===================================================
echo   ETIPOS SECURE RELAY - ZERO CONFIG LAUNCHER
echo ===================================================
echo.

python run.py

if %ERRORLEVEL% NEQ 0 (
    echo.
    echo [ERROR] ETIPOS terminated with error code %ERRORLEVEL%.
    pause
)

