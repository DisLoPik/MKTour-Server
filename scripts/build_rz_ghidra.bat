@echo off
rem Build rz-ghidra (core_ghidra.dll + sleigh specs) with MSVC against an installed Windows rizin,
rem so `pdg` (Ghidra decompiler) works inside rizin. Output stays under tools/rz-ghidra.
rem
rem Paths are auto-discovered; override with env vars if needed:
rem   RIZIN_HOME  = rizin install root (contains bin\rizin.exe). Default: resolved from `where rizin`.
rem   VSINSTALL   = Visual Studio / Build Tools install root. Default: resolved via vswhere.
setlocal
set ROOT=%~dp0..
set SRC=%ROOT%\tools\src\rz-ghidra
set BUILD=%ROOT%\tools\src\rz-ghidra-build
set DEST=%ROOT%\tools\rz-ghidra

if not defined RIZIN_HOME (
  for /f "delims=" %%I in ('where rizin 2^>nul') do set RIZIN_EXE=%%I
  if not defined RIZIN_EXE echo ERROR: rizin not found on PATH. Set RIZIN_HOME. & exit /b 1
  rem strip "\bin\rizin.exe" -> install root
  for %%I in ("%RIZIN_EXE%") do set RIZIN_BIN=%%~dpI
  for %%I in ("%RIZIN_BIN%.") do set RIZIN_HOME=%%~dpI
)
if "%RIZIN_HOME:~-1%"=="\" set RIZIN_HOME=%RIZIN_HOME:~0,-1%

if not defined VSINSTALL (
  set VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe
  if not exist "%VSWHERE%" echo ERROR: vswhere not found. Set VSINSTALL. & exit /b 1
  for /f "usebackq delims=" %%I in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set VSINSTALL=%%I
)

echo Using RIZIN_HOME=%RIZIN_HOME%
echo Using VSINSTALL=%VSINSTALL%
call "%VSINSTALL%\VC\Auxiliary\Build\vcvars64.bat" || exit /b 1
set PATH=%VSINSTALL%\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin;%VSINSTALL%\Common7\IDE\CommonExtensions\Microsoft\CMake\Ninja;%PATH%

cmake -S "%SRC%" -B "%BUILD%" -G Ninja ^
  -DCMAKE_BUILD_TYPE=Release ^
  -DCMAKE_PREFIX_PATH="%RIZIN_HOME%" ^
  -DCMAKE_INSTALL_PREFIX="%DEST%" ^
  -DRIZIN_INSTALL_PLUGDIR="%DEST%/plugins" ^
  -DUSE_SYSTEM_ZLIB=OFF ^
  -DBUILD_SLEIGH_PLUGIN=OFF ^
  -DBUILD_CUTTER_PLUGIN=OFF || exit /b 1
cmake --build "%BUILD%" --parallel || exit /b 1
cmake --install "%BUILD%" || exit /b 1
echo BUILD OK
