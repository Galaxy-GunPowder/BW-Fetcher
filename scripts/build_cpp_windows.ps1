# C++ BW-Fetcher — Windows build (MSVC + vcpkg).
# Output: builds/BW-Fetcher_windows_YYYYMMDD_HHMMSS_Release/BW-Fetcher-win64.exe
#
# Usage:
#   .\scripts\build_cpp_windows.ps1
#   .\scripts\build_cpp_windows.ps1 -Config Debug

param(
    [ValidateSet("Release", "Debug")]
    [string]$Config = "Release"
)

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent $PSScriptRoot
$Stamp = Get-Date -Format "yyyyMMdd_HHmmss"
$BuildDir = Join-Path (Join-Path $RepoRoot "builds") "BW-Fetcher_windows_${Stamp}_${Config}"

New-Item -ItemType Directory -Force -Path $BuildDir | Out-Null

$Vcvars = @(
    "${env:ProgramFiles}\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat",
    "${env:ProgramFiles}\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat",
    "D:\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat"
) | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $Vcvars) { throw "vcvars64.bat not found" }

$Cmake = if (Test-Path "D:\C++\cmake\bin\cmake.exe") { "D:\C++\cmake\bin\cmake.exe" } else { "cmake" }
$VcpkgToolchain = Join-Path $RepoRoot "vcpkg\scripts\buildsystems\vcpkg.cmake"
$ToolchainArg = ""
if (Test-Path $VcpkgToolchain) {
    $ToolchainArg = "-DCMAKE_TOOLCHAIN_FILE=`"$VcpkgToolchain`""
}

Write-Host "==> Platform:  Windows (C++)"
Write-Host "==> Build dir: $BuildDir"
Write-Host "==> Config:    $Config"

$configureCmd = "call `"$Vcvars`" && `"$Cmake`" -S `"$RepoRoot`" -B `"$BuildDir`" -G Ninja -DCMAKE_BUILD_TYPE=$Config $ToolchainArg"
cmd.exe /c $configureCmd
if ($LASTEXITCODE -ne 0) { throw "cmake configure failed ($LASTEXITCODE)" }

$buildCmd = "call `"$Vcvars`" && `"$Cmake`" --build `"$BuildDir`" --target BW_Fetcher"
cmd.exe /c $buildCmd
if ($LASTEXITCODE -ne 0) { throw "cmake build failed ($LASTEXITCODE)" }

$Exe = Join-Path $BuildDir "BW-Fetcher-win64.exe"
if (-not (Test-Path $Exe)) { throw "Expected $Exe after build" }

$LatestFile = Join-Path (Join-Path $RepoRoot "builds") "latest_windows.txt"
Set-Content -Path $LatestFile -Value $BuildDir -NoNewline

Write-Host ""
Write-Host "OK  $Exe"
Write-Host "    pointer -> builds/latest_windows.txt"
