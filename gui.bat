@echo off
title CipherForge GUI
echo Starting CipherForge GUI...
python "%~dp0gui.py"
if errorlevel 1 (
    echo.
    echo Failed to start GUI.
    echo Make sure Python 3.12+ with tkinter is installed.
    pause
)
