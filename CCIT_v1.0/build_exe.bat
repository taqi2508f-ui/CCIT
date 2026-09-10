@echo off
title CCIT - Build requirements_downloader.exe
color 0A

echo.
echo  =========================================================
echo   Building requirements_downloader.exe
echo   (one-time step - only needs to run once on this PC)
echo  =========================================================
echo.

where py >nul 2>&1
if errorlevel 1 (
    set PYCMD=python
) else (
    set PYCMD=py -3
)

%PYCMD% --version >nul 2>&1
if errorlevel 1 (
    echo  [ERROR] Python not found in PATH.
    echo  Install Python 3.10+ from https://www.python.org first.
    pause
    exit /b 1
)

echo  Installing PyInstaller...
%PYCMD% -m pip install --upgrade pyinstaller
if errorlevel 1 (
    echo  [ERROR] Could not install PyInstaller. Check your internet connection.
    pause
    exit /b 1
)

echo.
echo  Building requirements_downloader.exe ...
%PYCMD% -m PyInstaller --onefile --console --name requirements_downloader requirements_downloader.py
if errorlevel 1 (
    echo  [ERROR] Build failed. See output above.
    pause
    exit /b 1
)

echo.
echo  Moving requirements_downloader.exe next to this script...
move /Y dist\requirements_downloader.exe requirements_downloader.exe >nul
rmdir /S /Q build >nul 2>&1
rmdir /S /Q dist >nul 2>&1
del /Q requirements_downloader.spec >nul 2>&1

echo.
echo  =========================================================
echo   Done. requirements_downloader.exe is ready in this folder.
echo   You can delete build_exe.bat and requirements_downloader.py now
echo   if you want - only the .exe is needed from here on.
echo  =========================================================
echo.
pause
