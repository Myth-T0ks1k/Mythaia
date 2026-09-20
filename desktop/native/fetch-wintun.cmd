@echo off
rem ---------------------------------------------------------------------------
rem fetch-wintun.cmd - downloads the official Wintun driver package and puts
rem wintun.dll (x64) plus its licence next to mythaia_native.dll in
rem desktop\native\out, from where Gradle's prepareNative task copies both
rem into desktop\resources\windows-x64 (gitignored).
rem
rem   https://www.wintun.net/builds/wintun-0.14.1.zip
rem   sha256 07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51
rem
rem curl honours HTTPS_PROXY from the environment. Re-run whenever
rem WINTUN_VERSION changes.
rem
rem Keep this file ASCII with CRLF line endings: cmd.exe misreads anything else.
rem ---------------------------------------------------------------------------
setlocal

set "HERE=%~dp0"
set "OUT_DIR=%HERE%out"
set "WORK=%HERE%build\wintun"
if "%WINTUN_VERSION%"=="" set "WINTUN_VERSION=0.14.1"
set "ZIP=%WORK%\wintun-%WINTUN_VERSION%.zip"
set "URL=https://www.wintun.net/builds/wintun-%WINTUN_VERSION%.zip"

if not exist "%WORK%" mkdir "%WORK%"
if not exist "%OUT_DIR%" mkdir "%OUT_DIR%"

if exist "%ZIP%" goto :unzip
echo === Download %URL%
curl -sSL -o "%ZIP%" "%URL%"
if errorlevel 1 (
    echo fetch-wintun.cmd: download failed
    exit /b 1
)

:unzip
echo === Unzip
tar -xf "%ZIP%" -C "%WORK%"
if errorlevel 1 (
    echo fetch-wintun.cmd: unzip failed
    exit /b 1
)
if not exist "%WORK%\wintun\bin\amd64\wintun.dll" (
    echo fetch-wintun.cmd: wintun\bin\amd64\wintun.dll missing from the archive
    exit /b 1
)

echo === Copy
copy /y "%WORK%\wintun\bin\amd64\wintun.dll" "%OUT_DIR%\wintun.dll" >nul
copy /y "%WORK%\wintun\LICENSE.txt" "%OUT_DIR%\wintun-LICENSE.txt" >nul
if errorlevel 1 (
    echo fetch-wintun.cmd: copy failed
    exit /b 1
)

echo === Done: %OUT_DIR%\wintun.dll
endlocal
exit /b 0
