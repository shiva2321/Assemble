@echo off
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"

echo Running assemble lint...
..\target\release\assemble.exe lint editor.asm --abi windows

echo Running assemble fix...
..\target\release\assemble.exe fix editor.asm --abi windows --write

echo Assembling...
ml64 /c /W3 /Zd /Zi editor.asm

echo Linking...
link /subsystem:console /entry:main editor.obj ucrt.lib vcruntime.lib msvcrt.lib legacy_stdio_definitions.lib kernel32.lib user32.lib

echo Build finished.
