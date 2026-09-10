@echo off
setlocal enabledelayedexpansion
title CCIT - Cyber Crime Investigation Tool
color 0A

echo.
echo  =========================================================
echo   CCIT - Cyber Crime Investigation Tool v1.0.0
echo   Starting application...
echo  =========================================================
echo.

:: Prefer the py launcher (matches install_requirements.bat, avoids
:: mismatches with the Microsoft Store python.exe stub)
where py >nul 2>&1
if errorlevel 1 (
    set PYCMD=python
) else (
    set PYCMD=py -3
)

:: Check Python
%PYCMD% --version >nul 2>&1
if errorlevel 1 (
    echo  [ERROR] Python not found in PATH.
    echo  Please run install_requirements.bat first.
    pause
    exit /b 1
)

:: Check PySide6 (using the SAME interpreter we'll launch with)
%PYCMD% -c "import PySide6" >nul 2>&1
if errorlevel 1 (
    echo  [WARNING] PySide6 not found for "%PYCMD%".
    if exist requirements_downloader.exe (
        echo  Running requirements downloader...
        call requirements_downloader.exe
    ) else if exist install_requirements.bat (
        echo  Running install_requirements.bat...
        call install_requirements.bat
    ) else (
        echo  [ERROR] No installer found ^(requirements_downloader.exe or
        echo  install_requirements.bat^) in this folder.
        pause
        exit /b 1
    )

    :: Re-check after install attempt so we fail fast with a clear message
    :: instead of launching main.py and hitting a Python traceback.
    %PYCMD% -c "import PySide6" >nul 2>&1
    if errorlevel 1 (
        echo.
        echo  [ERROR] PySide6 still not found for "%PYCMD%" after install.
        echo  Try running manually:
        echo    %PYCMD% -m pip install PySide6
        pause
        exit /b 1
    )
)

echo  Launching CCIT with "%PYCMD%"...
echo.
%PYCMD% ccit\main.py

if errorlevel 1 (
    echo.
    echo  [ERROR] CCIT exited with an error.
    echo  Check ccit\logs\ for crash logs.
    pause
)
