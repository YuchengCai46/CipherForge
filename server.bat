@echo off
title CipherForge Web Server
echo ==========================================
echo   CipherForge Web 服务
echo ==========================================
echo.
echo 请选择启动模式：
echo.
echo   [1] 本地回环  - 仅本机访问 (http://127.0.0.1:8000)
echo   [2] 局域网   - 同一 WiFi 下其他设备可访问 (http://<本机IP>:8000)
echo   [q] 退出
echo.
set /p MODE="请输入选项 (1/2/q): "

if /i "%MODE%"=="q" goto :eof
if /i "%MODE%"=="2" (
    echo.
    echo 启动局域网模式 (0.0.0.0:8000)...
    echo 本机 IP:
    ipconfig | findstr "IPv4"
    echo.
    python "%~dp0server.py" --host 0.0.0.0
) else if /i "%MODE%"=="1" (
    echo.
    echo 启动本地回环模式 (127.0.0.1:8000)...
    python "%~dp0server.py"
) else (
    echo.
    echo 无效选项，使用默认本地回环模式...
    python "%~dp0server.py"
)

if errorlevel 1 (
    echo.
    echo 错误：启动失败
    echo 请确保已安装 fastapi uvicorn
    pause
)
