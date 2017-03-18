REM Build preparation script for wireshark for windows with Visual Studio 2015
REM See https://www.wireshark.org/docs/wsdg_html_chunked/ChSetupWin32.html
REM Call this script in the directory where you want to run the build - NOT in the source directory!
REM Modify this script to your needs and run it from the MSVC command prompt

set repo-root=%~dp0
rem // remove trailing slash
set repo-root=%repo-root:~0,-1%
echo Building from source in %repo-root% ...

set CYGWIN=nodosfilewarning
set WIRESHARK_BASE_DIR=%repo-root%\..
set WIRESHARK_TARGET_PLATFORM=win32
set QT5_BASE_DIR=C:\Qt\5.6\msvc2015
set WIRESHARK_CYGWIN_INSTALL_PATH=C:\cygwin64
set WIRESHARK_VERSION_EXTRA=-s7commplus
REM Ensure that cygwin bash is found before Windows10 Ubunutu bash:
set PATH=%WIRESHARK_CYGWIN_INSTALL_PATH%\bin;%PATH%

"C:\Program Files\CMake\bin\cmake" -DENABLE_CHM_GUIDES=on %repo-root%
if !ERRORLEVEL! == 0 exit /b !ERRORLEVEL!
pause
Rem build wireshark
msbuild /m /p:Configuration=RelWithDebInfo Wireshark.sln
if !ERRORLEVEL! == 0 exit /b !ERRORLEVEL!
pause
Rem build the installer
msbuild /m /p:Configuration=RelWithDebInfo nsis_package_prep.vcxproj
msbuild /m /p:Configuration=RelWithDebInfo nsis_package.vcxproj
