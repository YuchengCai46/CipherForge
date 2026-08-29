@echo off
title CipherForge CLI
echo ==========================================
echo   CipherForge CLI
echo ==========================================
echo.
echo Generating a sample password...
for %%p in (python python3 py) do (
    %%p -c "import cipherforge" >nul 2>&1 && set PYTHON=%%p && goto :found
)
echo Error: Python with cipherforge not found
echo Please install Python 3.12+ and run: pip install -e .
pause
goto :eof
:found
"%%PYTHON%%" "%~dp0cli.py" passgen --length 16
echo.
echo Usage examples:
echo   python cli.py passgen --length 12
echo   python cli.py hash --algo SHA-256 --text hello
echo   python cli.py encrypt --algo AES-256-GCM --password xxx --in f.txt --out f.enc
echo.
echo Type python cli.py --help for full usage
echo ==========================================
pause
