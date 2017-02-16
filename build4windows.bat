REM Build preparation script for wireshark for windows with Visual Studio 2015
REM See https://www.wireshark.org/docs/wsdg_html_chunked/ChSetupWin32.html
REM Modify this script to your needs and run it from the MSVC command prompt
set CYGWIN=nodosfilewarning
set WIRESHARK_BASE_DIR=C:\Programmierung
set WIRESHARK_TARGET_PLATFORM=win32
set QT5_BASE_DIR=C:\Qt\5.6\msvc2015
set WIRESHARK_CYGWIN_INSTALL_PATH=C:\cygwin64
set WIRESHARK_VERSION_EXTRA=-s7commplus
REM Ensure that cygwin bash is found before Windows10 Ubunutu bash:
set PATH=%WIRESHARK_CYGWIN_INSTALL_PATH%\bin;%PATH%

cd wireshark-cmake
"C:\Program Files\CMake\bin\cmake" -DENABLE_CHM_GUIDES=off ..\wireshark
pause
Rem build wireshark
msbuild /m /p:Configuration=RelWithDebInfo Wireshark.sln
pause
Rem build the installer
REM msbuild /m /p:Configuration=RelWithDebInfo nsis_package_prep.vcxproj
REM msbuild /m /p:Configuration=RelWithDebInfo nsis_package.vcxproj
