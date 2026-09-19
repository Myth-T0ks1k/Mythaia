@echo off
rem ---------------------------------------------------------------------------
rem build.cmd - one-shot Release build of mythaia_native.dll for x64 Windows.
rem
rem   1. loads the MSVC x64 environment
rem   2. configures desktop/native with CMake + Ninja in Release
rem   3. builds
rem   4. copies the DLL to desktop/native/out/mythaia_native.dll
rem
rem Step 1 prefers vcvars64.bat. On a VS install where that script is broken
rem (vcvarsall.bat missing - the case on the machine this was written on,
rem whose MSVC 14.41 toolset has bin/ and lib/onecore/ but no include/), it
rem assembles PATH, INCLUDE and LIB by hand from:
rem   - cl/link/lib/dumpbin  : VC\Tools\MSVC\<MSVC_VER>\bin\Hostx64\x64
rem   - MSVC headers         : VC\Tools\MSVC\<MSVC_VER>\include if present,
rem                            else the copy VS ships in SDK\ScopeCppSDK\vc15
rem   - MSVC libs            : VC\Tools\MSVC\<MSVC_VER>\lib\x64 if present,
rem                            else lib\onecore\x64 (same CRT, OneCore imports)
rem   - UCRT + Win32 headers/libs, rc.exe, mt.exe : Windows SDK <WINSDK_VER>
rem
rem Overrides (environment variables):
rem   VSDIR              Visual Studio root      (default: VS 2022 Community)
rem   MSVC_VER           toolset folder name     (default: 14.41.34120)
rem   WINSDK_VER         Windows 10 SDK version  (default: 10.0.22621.0)
rem   JAVA_HOME          JDK with include/jni.h  (default: C:\Program Files\Java\jdk-21)
rem   MYTHAIA_WITH_LWIP  ON or OFF               (default: ON)
rem
rem Keep this file ASCII with CRLF line endings: cmd.exe misreads anything else.
rem ---------------------------------------------------------------------------
setlocal

set "HERE=%~dp0"
set "BUILD_DIR=%HERE%build"
set "OUT_DIR=%HERE%out"

if "%VSDIR%"=="" set "VSDIR=C:\Program Files\Microsoft Visual Studio\2022\Community"
if "%MSVC_VER%"=="" set "MSVC_VER=14.41.34120"
if "%WINSDK_VER%"=="" set "WINSDK_VER=10.0.22621.0"
if "%MYTHAIA_WITH_LWIP%"=="" set "MYTHAIA_WITH_LWIP=ON"

set "VCVARS=%VSDIR%\VC\Auxiliary\Build\vcvars64.bat"
set "VCVARSALL=%VSDIR%\VC\Auxiliary\Build\vcvarsall.bat"
set "CMAKE_EXE=%VSDIR%\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe"
set "NINJA_EXE=%VSDIR%\Common7\IDE\CommonExtensions\Microsoft\CMake\Ninja\ninja.exe"

if not exist "%CMAKE_EXE%" (
    echo build.cmd: cmake.exe not found at "%CMAKE_EXE%" - set VSDIR
    exit /b 1
)
if not exist "%NINJA_EXE%" (
    echo build.cmd: ninja.exe not found at "%NINJA_EXE%" - set VSDIR
    exit /b 1
)

echo === MSVC environment
if exist "%VCVARSALL%" goto :use_vcvars
goto :manual_env

:use_vcvars
echo     via vcvars64.bat
call "%VCVARS%" >nul
if errorlevel 1 (
    echo build.cmd: vcvars64.bat failed
    exit /b 1
)
goto :env_done

:manual_env
echo     vcvarsall.bat is missing - assembling the environment by hand
set "MSVC=%VSDIR%\VC\Tools\MSVC\%MSVC_VER%"
set "WINSDK=C:\Program Files (x86)\Windows Kits\10"

if not exist "%MSVC%\bin\Hostx64\x64\cl.exe" (
    echo build.cmd: cl.exe not found under "%MSVC%" - set MSVC_VER
    exit /b 1
)
if not exist "%WINSDK%\Include\%WINSDK_VER%\ucrt\stdio.h" (
    echo build.cmd: Windows SDK %WINSDK_VER% not found - set WINSDK_VER
    exit /b 1
)

if exist "%MSVC%\include\vcruntime.h" (
    set "MSVC_INC=%MSVC%\include"
) else (
    set "MSVC_INC=%VSDIR%\SDK\ScopeCppSDK\vc15\VC\include"
)
if not exist "%MSVC_INC%\vcruntime.h" (
    echo build.cmd: no MSVC headers - neither "%MSVC%\include" nor ScopeCppSDK
    exit /b 1
)

if exist "%MSVC%\lib\x64\libcmt.lib" (
    set "MSVC_LIB=%MSVC%\lib\x64"
) else (
    set "MSVC_LIB=%MSVC%\lib\onecore\x64"
)
if not exist "%MSVC_LIB%\libcmt.lib" (
    echo build.cmd: no MSVC libs - neither "%MSVC%\lib\x64" nor lib\onecore\x64
    exit /b 1
)

echo     cl:      %MSVC%\bin\Hostx64\x64
echo     headers: %MSVC_INC%
echo     libs:    %MSVC_LIB%
echo     sdk:     %WINSDK% %WINSDK_VER%

set "PATH=%MSVC%\bin\Hostx64\x64;%WINSDK%\bin\%WINSDK_VER%\x64;%PATH%"
set "INCLUDE=%MSVC_INC%;%WINSDK%\Include\%WINSDK_VER%\ucrt;%WINSDK%\Include\%WINSDK_VER%\um;%WINSDK%\Include\%WINSDK_VER%\shared"
set "LIB=%MSVC_LIB%;%WINSDK%\Lib\%WINSDK_VER%\ucrt\x64;%WINSDK%\Lib\%WINSDK_VER%\um\x64"

:env_done

echo === Configure
"%CMAKE_EXE%" -S "%HERE%." -B "%BUILD_DIR%" -G Ninja ^
    -DCMAKE_MAKE_PROGRAM="%NINJA_EXE%" ^
    -DCMAKE_BUILD_TYPE=Release ^
    -DMYTHAIA_WITH_LWIP=%MYTHAIA_WITH_LWIP%
if errorlevel 1 (
    echo build.cmd: configure failed
    exit /b 1
)

echo === Build
"%CMAKE_EXE%" --build "%BUILD_DIR%"
if errorlevel 1 (
    echo build.cmd: build failed
    exit /b 1
)

echo === Copy
if not exist "%OUT_DIR%" mkdir "%OUT_DIR%"
copy /y "%BUILD_DIR%\mythaia_native.dll" "%OUT_DIR%\mythaia_native.dll" >nul
if errorlevel 1 (
    echo build.cmd: copy failed
    exit /b 1
)

echo === Done: %OUT_DIR%\mythaia_native.dll
endlocal
exit /b 0
