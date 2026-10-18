# Create the Ubuntu Server VM that will run the whole ORION lab on a standard Linux kernel
# (process auditing and connection capture work there, unlike under WSL2).
# Run in a normal PowerShell (not WSL) after VirtualBox is installed:
#   powershell -ExecutionPolicy Bypass -File scripts\lab\vm\create_vm.ps1
# The account password is asked at the prompt. It is not stored in any file.
param(
  [string]$Name   = "orion-lab",
  [string]$Iso    = "$env:USERPROFILE\Downloads\ubuntu-26.04-live-server-amd64.iso",
  [int]$MemoryMB  = 5120,
  [int]$Cpus      = 2,
  [int]$DiskGB    = 40
)
$ErrorActionPreference = 'Stop'
$vbox = "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe"
if (-not (Test-Path $vbox)) { Write-Host "VirtualBox is not installed. Run VirtualBox-7.2.14-174565-Win.exe from Downloads first."; exit 1 }
if (-not (Test-Path $Iso))  { Write-Host "ISO not found: $Iso"; exit 1 }
if ((& $vbox list vms) -match "`"$Name`"") { Write-Host "A VM named $Name already exists. Nothing done."; exit 0 }

$secure = Read-Host "Choose a password for the VM account 'soc'" -AsSecureString
$pw = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure))
if ($pw.Length -lt 8) { Write-Host "Use at least 8 characters."; exit 1 }

# Host-only adapter: lets the VM and Windows (and WSL) reach each other without exposing the lab to the network.
$hostonly = (& $vbox list hostonlyifs) | Select-String '^Name:\s+(.+)$' | ForEach-Object { $_.Matches[0].Groups[1].Value.Trim() } | Select-Object -First 1
if (-not $hostonly) { & $vbox hostonlyif create | Out-Null; $hostonly = (& $vbox list hostonlyifs) | Select-String '^Name:\s+(.+)$' | ForEach-Object { $_.Matches[0].Groups[1].Value.Trim() } | Select-Object -First 1 }
Write-Host "Host-only adapter: $hostonly"

& $vbox createvm --name $Name --ostype Ubuntu_64 --register | Out-Null
& $vbox modifyvm $Name --memory $MemoryMB --cpus $Cpus --ioapic on --audio-enabled off --graphicscontroller vmsvga --vram 16 `
    --nic1 nat --nic2 hostonly --hostonlyadapter2 "$hostonly"
$folder = Split-Path ((& $vbox showvminfo $Name --machinereadable | Select-String '^CfgFile="(.+)"$').Matches[0].Groups[1].Value)
$disk = Join-Path $folder "$Name.vdi"
& $vbox createmedium disk --filename $disk --size ($DiskGB * 1024) --variant Standard | Out-Null
& $vbox storagectl $Name --name SATA --add sata --controller IntelAhci
& $vbox storageattach $Name --storagectl SATA --port 0 --device 0 --type hdd --medium $disk

& $vbox unattended install $Name --iso="$Iso" --user=soc --full-user-name="SOC" --password="$pw" `
    --hostname=orion-lab.local --time-zone=Africa/Tunis --locale=en_US --install-additions=false --start-vm=gui
Write-Host ""
Write-Host "The VM is installing Ubuntu by itself (about 10 minutes). When the login prompt appears, log in as 'soc' and run:  ip -4 a"
Write-Host "Send the 192.168.56.x address back to continue with the setup."
