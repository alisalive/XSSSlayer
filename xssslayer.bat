@echo off
:: XSSSlayer global launcher for Windows
:: Place this file in a directory that is in your PATH
:: e.g. C:\Windows\System32\ or C:\Users\%USERNAME%\AppData\Local\Microsoft\WindowsApps\

set "XSSSLAYER_DIR=%~dp0"
:: Remove trailing backslash
if "%XSSSLAYER_DIR:~-1%"=="\" set "XSSSLAYER_DIR=%XSSSLAYER_DIR:~0,-1%"

"%XSSSLAYER_DIR%\venv\Scripts\python.exe" "%XSSSLAYER_DIR%\xss_slayer.py" %*
