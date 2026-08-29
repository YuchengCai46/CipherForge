@echo off
title CipherForge 交互式 CLI
echo ==========================================
echo   CipherForge 交互式命令行
echo ==========================================
echo.
echo 启动交互式 CLI...
echo 输入 'help' 查看可用命令
echo.
python "%~dp0cipherforge_cli.py"
if errorlevel 1 (
    echo.
    echo 错误：启动失败
    echo 请确保已安装 Python 3.12+
    pause
)
