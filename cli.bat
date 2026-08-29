@echo off
title CipherForge CLI
"C:\Users\Administrator\AppData\Local\Programs\Python\Python313\python.exe" "%~dp0cli.py" passgen --length 16
echo.
echo Usage examples:
echo   python cli.py passgen --length 12
echo   python cli.py hash --algo SHA-256 --text hello
echo   python cli.py encrypt --algo AES-256-GCM --password xxx --in f.txt --out f.enc
echo.
echo Type python cli.py --help for full usage
echo ==========================================
pause
