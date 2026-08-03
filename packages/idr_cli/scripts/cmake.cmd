@echo off
REM Shim so CMake (invoked by Flutter) selects VS Community, not incomplete BuildTools.
setlocal
set "CMAKE_BIN=C:\Program Files\Microsoft Visual Studio\18\Community\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe"
if not exist "%CMAKE_BIN%" set "CMAKE_BIN=cmake"
"%CMAKE_BIN%" -DCMAKE_GENERATOR_INSTANCE=C:/Program Files/Microsoft Visual Studio/18/Community %*
