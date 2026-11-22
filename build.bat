@echo off
setlocal EnableExtensions
rem NetWolf v2 - build script (x64, Release). Run from PowerShell: .\build.bat
cd /d "%~dp0"
set "VCVARS=C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
set "BUILD_DIR=build-x64"
if not exist "%VCVARS%" (echo [ERROR] vcvars64.bat was not found in the BuildTools folder. & goto :fail)
echo [1/4] Setting up the x64 compiler...
call "%VCVARS%" >nul
if /I not "%VSCMD_ARG_TGT_ARCH%"=="x64" (echo [ERROR] The compiler environment is not x64. & goto :fail)
taskkill /IM NetWolfV2Gui.exe /F >nul 2>&1
echo [2/4] Checking the build folder...
if exist "%BUILD_DIR%\CMakeCache.txt" findstr /C:"Hostx86/x86" "%BUILD_DIR%\CMakeCache.txt" >nul && (echo       Removing old 32-bit build folder... & rmdir /s /q "%BUILD_DIR%")
if exist "%BUILD_DIR%\CMakeCache.txt" findstr /C:"Hostx86/x86" "%BUILD_DIR%\CMakeCache.txt" >nul && (echo [ERROR] Could not delete the old build folder. Close Visual Studio and Explorer windows, then retry. & goto :fail)
echo [3/4] Configuring...
cmake -S . -B "%BUILD_DIR%" -G Ninja -DCMAKE_BUILD_TYPE=Release
if errorlevel 1 goto :fail
echo [4/4] Building...
cmake --build "%BUILD_DIR%"
if errorlevel 1 goto :fail
echo.
echo BUILD OK: %BUILD_DIR%\bin\NetWolfV2Gui.exe
exit /b 0
:fail
echo.
echo BUILD FAILED - copy everything above and send it.
exit /b 1
