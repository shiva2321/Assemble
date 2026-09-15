@echo off
setlocal enabledelayedexpansion

echo [Assemble] Building 64-Bit Assembly Calculator...

REM Check for NASM in PATH or common install directories
where nasm >nul 2>nul
if %ERRORLEVEL% equ 0 (
    set "NASM=nasm"
) else if exist "%LOCALAPPDATA%\bin\NASM\nasm.exe" (
    set "NASM=%LOCALAPPDATA%\bin\NASM\nasm.exe"
) else if exist "C:\Program Files\NASM\nasm.exe" (
    set "NASM=C:\Program Files\NASM\nasm.exe"
) else (
    echo Error: NASM assembler not found. Please install NASM and add to PATH.
    exit /b 1
)

echo Using NASM: %NASM%

"%NASM%" -f win64 math.asm -o math.obj
if %ERRORLEVEL% neq 0 exit /b %ERRORLEVEL%

"%NASM%" -f win64 io.asm -o io.obj
if %ERRORLEVEL% neq 0 exit /b %ERRORLEVEL%

"%NASM%" -f win64 main.asm -o main.obj
if %ERRORLEVEL% neq 0 exit /b %ERRORLEVEL%

where link >nul 2>nul
if %ERRORLEVEL% equ 0 (
    link /subsystem:console /entry:main /defaultlib:kernel32.lib /out:calculator.exe main.obj math.obj io.obj
) else (
    echo MSVC link.exe not in current shell. Initializing vcvars64...
    if exist "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" (
        call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" >nul
        link /subsystem:console /entry:main /defaultlib:kernel32.lib /out:calculator.exe main.obj math.obj io.obj
    ) else (
        echo Error: MSVC link.exe not found. Run from 'x64 Native Tools Command Prompt'.
        exit /b 1
    )
)

if %ERRORLEVEL% equ 0 (
    echo [Assemble] calculator.exe successfully built!
)
