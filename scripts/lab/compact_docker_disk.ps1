# Give back the empty space inside Docker's virtual disk to Windows.
# Docker's disk file grows but never shrinks by itself; after cleaning images and cache, compact it.
# Run in an ADMINISTRATOR PowerShell:   powershell -ExecutionPolicy Bypass -File scripts\lab\compact_docker_disk.ps1
# It stops Docker Desktop and WSL for a few minutes (the lab is down meanwhile). No data is deleted.
$ErrorActionPreference = 'Stop'
$vhdx = "$env:LOCALAPPDATA\Docker\wsl\disk\docker_data.vhdx"
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  Write-Host "Run this in an Administrator PowerShell."; exit 1
}
if (-not (Test-Path $vhdx)) { Write-Host "Not found: $vhdx"; exit 1 }
$before = [math]::Round((Get-Item $vhdx).Length / 1GB, 1)
Write-Host "Docker disk before: $before GB"

Get-Process 'Docker Desktop' -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep -Seconds 5
wsl --shutdown
Start-Sleep -Seconds 8

$script = @"
select vdisk file="$vhdx"
attach vdisk readonly
compact vdisk
detach vdisk
exit
"@
$tmp = Join-Path $env:TEMP 'compact_docker.txt'
Set-Content -Path $tmp -Value $script -Encoding ASCII
diskpart /s $tmp
Remove-Item $tmp -ErrorAction SilentlyContinue

$after = [math]::Round((Get-Item $vhdx).Length / 1GB, 1)
Write-Host "Docker disk after: $after GB (freed $([math]::Round($before - $after, 1)) GB)"
Write-Host "Start Docker Desktop again when you need the lab."
