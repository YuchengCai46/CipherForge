@echo off
title CipherForge GUI
echo Starting CipherForge GUI...
python "%~dp0gui.py"
if errorlevel 1 (
    echo.
    echo Failed to start GUI.
    echo Check if tkinter is installed.
    pause
)
