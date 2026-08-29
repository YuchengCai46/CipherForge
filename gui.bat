@echo off
title CipherForge GUI
echo Starting CipherForge GUI...
for %%p in (python python3 py) do (
    %%p -c "import tkinter" >nul 2>&1 && set PYTHON=%%p && goto :found
)
echo Error: Python with tkinter not found
echo Please install Python 3.12+ with tkinter support
pause
goto :eof
:found
"%%PYTHON%%" "%~dp0gui.py"
if errorlevel 1 (
    echo.
    echo Failed to start GUI.
    pause
)
