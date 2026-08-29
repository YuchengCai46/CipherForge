@echo off
title CipherForge GUI
echo Starting CipherForge GUI...
"C:\Users\Administrator\AppData\Local\Programs\Python\Python313\python.exe" "%~dp0gui.py"
if errorlevel 1 (
    echo.
    echo Failed to start GUI.
    echo Check if tkinter is installed.
    pause
)
