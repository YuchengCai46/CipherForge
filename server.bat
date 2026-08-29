@echo off
title CipherForge Web Server
echo ==========================================
echo   CipherForge Web Server
echo ==========================================
echo.
echo Please select an option:
echo.
echo   [1] Start Localhost  (http://127.0.0.1:8000)
echo   [2] Start LAN        (will show your IP)
echo   [3] Stop server
echo   [q] Quit
echo.
set /p MODE=Select (1/2/3/q): 
if /i "%MODE%"=="q" goto :eof
if /i "%MODE%"=="3" (
    echo.
    echo Stopping CipherForge server...
    taskkill /f /im uvicorn.exe 2>nul
    taskkill /f /fi "WINDOWTITLE eq CipherForge*" /im python.exe 2>nul
    echo Server stopped.
    pause
    goto :eof
)
for %%p in (python python3 py) do (
    %%p -c "import fastapi" >nul 2>&1 && set PYTHON=%%p && goto :found
)
echo Error: Python with fastapi not found
echo Please install Python 3.12+ and run: pip install fastapi uvicorn
pause
goto :eof
:found
if /i "%MODE%"=="2" (
    echo.
    echo Starting LAN mode...
    "%%PYTHON%%" "%~dp0server.py" --host 0.0.0.0
) else if /i "%MODE%"=="1" (
    echo.
    echo Starting localhost mode...
    "%%PYTHON%%" "%~dp0server.py"
) else (
    echo.
    echo Invalid option.
)
if errorlevel 1 (
    echo.
    echo Error: startup failed
    pause
)
goto :eof
