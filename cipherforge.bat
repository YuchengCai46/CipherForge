@echo off
title CipherForge Interactive CLI
echo ==========================================
echo   CipherForge Interactive CLI
echo ==========================================
echo.
echo Starting interactive CLI...
echo Type help for available commands
echo.
for %%p in (python python3 py) do (
    %%p -c "import cipherforge" >nul 2>&1 && set PYTHON=%%p && goto :found
)
echo Error: Python with cipherforge not found
echo Please install Python 3.12+ and run: pip install -e .
pause
goto :eof
:found
"%%PYTHON%%" "%~dp0cipherforge_cli.py"
if errorlevel 1 (
    echo.
    echo Error: startup failed
    pause
)
