# Builds, installs, and validates the CMake package against an independent
# consuming project that only uses find_package(nof) and installed headers.
param(
  [string]$BuildDir = "build",
  [string]$InstallDir = "build/stage",
  [string]$Config = "Release"
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot

Write-Host "==> configure and build"
cmake -S $root -B "$root/$BuildDir" -DCMAKE_BUILD_TYPE=$Config -DNOF_BUILD_TESTS=ON
if ($LASTEXITCODE -ne 0) { exit 1 }
cmake --build "$root/$BuildDir" --config $Config
if ($LASTEXITCODE -ne 0) { exit 1 }

Write-Host "==> install to $InstallDir"
cmake --install "$root/$BuildDir" --config $Config --prefix "$root/$InstallDir"
if ($LASTEXITCODE -ne 0) { exit 1 }

Write-Host "==> build the downstream consumer with find_package"
cmake -S "$root/examples/downstream" -B "$root/$BuildDir/downstream" `
  -DCMAKE_BUILD_TYPE=$Config -DCMAKE_PREFIX_PATH="$root/$InstallDir"
if ($LASTEXITCODE -ne 0) { exit 1 }
cmake --build "$root/$BuildDir/downstream" --config $Config
if ($LASTEXITCODE -ne 0) { exit 1 }

Write-Host "==> run the downstream consumer"
$consumer = Get-ChildItem -Path "$root/$BuildDir/downstream" -Filter nof_consumer.exe -Recurse |
  Select-Object -First 1
if (-not $consumer) { Write-Error "consumer binary not found"; exit 1 }
& $consumer.FullName
if ($LASTEXITCODE -ne 0) { exit 1 }

Write-Host "downstream package validation succeeded"
