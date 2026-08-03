@echo off
REM Run Flutter Windows builds with VS Community MSBuild / CMake shims.
set "ROOT=%~dp0.."
set "VS_COMMUNITY=C:\Program Files\Microsoft Visual Studio\18\Community"
set "PATH=%~dp0;%VS_COMMUNITY%\MSBuild\Current\Bin\arm64;%VS_COMMUNITY%\MSBuild\Current\Bin;%PATH%"
set "VSINSTALLDIR=%VS_COMMUNITY%\"
set "VCINSTALLDIR=%VS_COMMUNITY%\VC\"
call "%VS_COMMUNITY%\VC\Auxiliary\Build\vcvarsall.bat" arm64 >nul
cd /d "%ROOT%"
flutter %*
