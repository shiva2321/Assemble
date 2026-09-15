# ==============================================================================
# Assemble Calculator Build Script (PowerShell)
# ==============================================================================
$ErrorActionPreference = "Stop"

Write-Host "[Assemble] Building 64-Bit Assembly Calculator..." -ForegroundColor Cyan

# Find NASM
$nasm = Get-Command nasm -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source
if (-not $nasm) {
    $candidates = @(
        "$env:LOCALAPPDATA\bin\NASM\nasm.exe",
        "C:\Program Files\NASM\nasm.exe"
    )
    foreach ($cand in $candidates) {
        if (Test-Path $cand) { $nasm = $cand; break }
    }
}

if (-not $nasm) {
    Write-Error "NASM assembler not found. Please ensure NASM is installed."
    exit 1
}

Write-Host "Using NASM: $nasm" -ForegroundColor Green

& $nasm -f win64 calculator\math.asm -o calculator\math.obj
& $nasm -f win64 calculator\io.asm -o calculator\io.obj
& $nasm -f win64 calculator\main.asm -o calculator\main.obj

# Find link.exe
$linker = Get-Command link.exe -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source
if (-not $linker) {
    $msvcLinkers = Get-ChildItem "C:\Program Files\Microsoft Visual Studio\*\Community\VC\Tools\MSVC\*\bin\Hostx64\x64\link.exe" -ErrorAction SilentlyContinue
    if ($msvcLinkers) {
        $linker = $msvcLinkers[0].FullName
    }
}

# Find kernel32.lib
$kernel32 = "kernel32.lib"
$sdkLibs = Get-ChildItem "C:\Program Files (x86)\Windows Kits\10\Lib\*\um\x64\kernel32.Lib" -ErrorAction SilentlyContinue
if ($sdkLibs) {
    $kernel32 = $sdkLibs[0].FullName
}

Write-Host "Using Linker: $linker" -ForegroundColor Green

& $linker /nologo /subsystem:console /entry:main "/defaultlib:$kernel32" /out:calculator\calculator.exe calculator\main.obj calculator\math.obj calculator\io.obj

Write-Host "[Assemble] calculator.exe successfully assembled and linked!" -ForegroundColor Green
