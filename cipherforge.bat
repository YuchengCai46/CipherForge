@echo off
title CipherForge Interactive CLI
echo ==========================================
echo   CipherForge Interactive CLI
echo ==========================================
echo.
echo Starting interactive CLI...
echo Type help for available commands
echo.
"C:\Users\Administrator\AppData\Local\Programs\Python\Python313\python.exe" "%~dp0cipherforge_cli.py"
if errorlevel 1 (
    echo.
    echo Error: startup failed
    echo Make sure Python 3.12+ is installed.
    pause
)
