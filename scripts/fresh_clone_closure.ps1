# Fresh-clone closure: from committed sources only, configure, build, test,
# install, and run the independent downstream consumer.
param(
  [string]$WorkDir = "",
  [string]$Config = "Release"
)

$ErrorActionPreference = "Stop"
$source = Split-Path -Parent $PSScriptRoot
if ([string]::IsNullOrEmpty($WorkDir)) {
  $WorkDir = Join-Path ([System.IO.Path]::GetTempPath()) ("nof-closure-" + [guid]::NewGuid().ToString("N"))
}

Write-Host "==> cloning committed sources to $WorkDir"
git clone --quiet "$source" "$WorkDir"
if ($LASTEXITCODE -ne 0) { exit 1 }
git -C "$WorkDir" log -1 --format="cloned commit %H"
git -C "$WorkDir" status --porcelain

Write-Host "==> configure, build, test"
cmake -S $WorkDir -B "$WorkDir/build" -DCMAKE_BUILD_TYPE=$Config
if ($LASTEXITCODE -ne 0) { exit 1 }
cmake --build "$WorkDir/build" --config $Config
if ($LASTEXITCODE -ne 0) { exit 1 }
$tester = Get-ChildItem -Path "$WorkDir/build/tests" -Filter nof_tests.exe -Recurse |
  Select-Object -First 1
if (-not $tester) { Write-Error "test binary not found"; exit 1 }
Push-Location $tester.DirectoryName
& $tester.FullName
$testExit = $LASTEXITCODE
Pop-Location
if ($testExit -ne 0) { exit 1 }

Write-Host "==> install and build the downstream consumer"
cmake --install "$WorkDir/build" --prefix "$WorkDir/stage"
if ($LASTEXITCODE -ne 0) { exit 1 }
cmake -S "$WorkDir/examples/downstream" -B "$WorkDir/downstream" `
  -DCMAKE_BUILD_TYPE=$Config -DCMAKE_PREFIX_PATH="$WorkDir/stage"
if ($LASTEXITCODE -ne 0) { exit 1 }
cmake --build "$WorkDir/downstream" --config $Config
if ($LASTEXITCODE -ne 0) { exit 1 }
$consumer = Get-ChildItem -Path "$WorkDir/downstream" -Filter nof_consumer.exe -Recurse |
  Select-Object -First 1
if (-not $consumer) { Write-Error "consumer binary not found"; exit 1 }
& $consumer.FullName
if ($LASTEXITCODE -ne 0) { exit 1 }

Write-Host "fresh-clone closure succeeded in $WorkDir"
