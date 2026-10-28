# Портативный zip: бинари + WinDivert + desync-шаблоны + пример конфига. Без секретов.
param([string]$Version = '')
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
if (-not $Version) { $Version = (Get-Content (Join-Path $root 'VERSION') -Raw).Trim() }
$stage = Join-Path $env:TEMP ("rupas-dist-" + [guid]::NewGuid().ToString('N').Substring(0,8))
New-Item -ItemType Directory -Path $stage | Out-Null
foreach ($f in 'rupasd.exe','rupasctl.exe','rupas-gui.exe') {
  Copy-Item (Join-Path $root "build\$f") $stage
}
foreach ($f in 'WinDivert.dll','WinDivert64.sys') {
  Copy-Item (Join-Path $root "build\$f") $stage
}
Copy-Item (Join-Path $root 'configs/rupas.example.yaml') $stage
Copy-Item (Join-Path $root 'README.md') $stage
if (Test-Path (Join-Path $root 'build/desync')) {
  Copy-Item (Join-Path $root 'build/desync') (Join-Path $stage 'desync') -Recurse
}
$zip = Join-Path $root "dist/Rupas-win64-$Version.zip"
New-Item -ItemType Directory -Force -Path (Split-Path $zip) | Out-Null
if (Test-Path $zip) { Remove-Item $zip -Force }
Compress-Archive -Path (Join-Path $stage '*') -DestinationPath $zip
Remove-Item $stage -Recurse -Force
Write-Output "dist OK: $zip"
