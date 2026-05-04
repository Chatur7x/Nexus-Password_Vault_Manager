@echo off
echo Compiling C Engine...

:: Check if GCC is available
where gcc >nul 2>nul
if %errorlevel%==0 (
    echo Found GCC!
    gcc -shared -o vault_engine.dll -fPIC vault_crypto.c aes.c -DAES256=1 -D_CRT_SECURE_NO_WARNINGS
    echo Successfully compiled vault_engine.dll using GCC.
    goto end
)

:: Check if MSVC (cl.exe) is available
where cl >nul 2>nul
if %errorlevel%==0 (
    echo Found MSVC!
    cl /LD /Fe:vault_engine.dll vault_crypto.c aes.c /DAES256=1 /D_CRT_SECURE_NO_WARNINGS
    echo Successfully compiled vault_engine.dll using MSVC.
    goto end
)

echo No supported C compiler found (GCC or MSVC).
echo Please install MinGW (GCC) or Visual Studio Build Tools to compile the C library.

:end
pause
