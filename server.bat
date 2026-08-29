@echo off
title CipherForge Web Server
echo ==========================================
echo   CipherForge Web Server
echo ==========================================
echo.
echo Please select startup mode:
echo.
echo   [1] Localhost  - only this machine (http://127.0.0.1:8000)
echo   [2] LAN        - other devices on same WiFi (http://<IP>:8000)
echo   [q] Quit
echo.
set /p MODE=Select (1/2/q): 
if /i "%MODE%"=="q" goto :eof
if /i "%MODE%"=="2" (
    echo.
    echo Starting LAN mode (0.0.0.0:8000)...
    echo Your IP:
    ipconfig | findstr "IPv4"
    echo.
    python "%~dp0server.py" --host 0.0.0.0
) else if /i "%MODE%"=="1" (
    echo.
    echo Starting localhost mode (127.0.0.1:8000)...
    python "%~dp0server.py"
) else (
    echo.
    echo Invalid option, using default localhost mode...
    python "%~dp0server.py"
)
if errorlevel 1 (
    echo.
    echo Error: startup failed
    echo Make sure fastapi and uvicorn are installed.
    pause
)
