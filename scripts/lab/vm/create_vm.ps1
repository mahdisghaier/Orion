# Create the Ubuntu Server VM that will run the whole ORION lab on a standard Linux kernel
# (process auditing and connection capture work there, unlike under WSL2).
# Run in a normal PowerShell (not WSL) after VirtualBox is installed:
#   powershell -ExecutionPolicy Bypass -File scripts\lab\vm\create_vm.ps1
# The account password is asked at the prompt. It is not stored in any file.
param(
  [string]$Name   = "orion-lab",
  [string]$Iso    = "$env:USERPROFILE\Downloads\ubuntu-26.04-live-server-amd64.iso",
  [int]$MemoryMB  = 3072,
  [int]$Cpus      = 1,   # one CPU: with Hyper-V active (WSL2, Docker Desktop) more virtual CPUs make the guest kernel lock up
  [int]$DiskGB    = 40,
  [string]$Password = ""
)
$ErrorActionPreference = 'Stop'
$vbox = "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe"
if (-not (Test-Path $vbox)) { Write-Host "VirtualBox is not installed. Run VirtualBox-7.2.14-174565-Win.exe from Downloads first."; exit 1 }
if (-not (Test-Path $Iso))  { Write-Host "ISO not found: $Iso"; exit 1 }
if ((& $vbox list vms) -match "`"$Name`"") { Write-Host "A VM named $Name already exists. Nothing done."; exit 0 }

if ($Password) { $pw = $Password } else {
  $secure = Read-Host "Choose a password for the VM account 'soc'" -AsSecureString
  $pw = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure))
}
if ($pw.Length -lt 8) { Write-Host "Use at least 8 characters."; exit 1 }

# Public key of the operator's WSL account (created with: ssh-keygen -t ed25519 -f ~/.ssh/orion_vm). It is installed in the VM,
# so no password has to be shared to administer it. The pubkey is not a secret.
$pub = (wsl.exe -e bash -lc 'cat ~/.ssh/orion_vm.pub 2>/dev/null').Trim()

& $vbox createvm --name $Name --ostype Ubuntu_64 --register | Out-Null
& $vbox modifyvm $Name --memory $MemoryMB --cpus $Cpus --ioapic on --audio-enabled off --graphicscontroller vmsvga --vram 16 `
    --nic1 nat
# NAT only (no host-only driver needed): ssh is reached through 127.0.0.1:2222, the lab web interface through 5173 and 8000,
# and the VM reaches Windows services (for example Docker ports) at 10.0.2.2.
& $vbox modifyvm $Name --natpf1 "ssh,tcp,127.0.0.1,2222,,22" --natpf1 "ui,tcp,127.0.0.1,5173,,5173" --natpf1 "api,tcp,127.0.0.1,8000,,8000"
$folder = Split-Path ((& $vbox showvminfo $Name --machinereadable | Select-String '^CfgFile="(.+)"$').Matches[0].Groups[1].Value)
$disk = Join-Path $folder "$Name.vdi"
& $vbox createmedium disk --filename $disk --size ($DiskGB * 1024) --variant Standard | Out-Null
& $vbox storagectl $Name --name SATA --add sata --controller IntelAhci
& $vbox storageattach $Name --storagectl SATA --port 0 --device 0 --type hdd --medium $disk

& $vbox unattended install $Name --iso="$Iso" --user=soc --full-user-name="SOC" --user-password="$pw" `
    --hostname=orion-lab.local --time-zone=Africa/Tunis --locale=en_US --no-install-additions `
    --post-install-command="mkdir -p /home/soc/.ssh && echo '$pub' >> /home/soc/.ssh/authorized_keys && chown -R soc:soc /home/soc/.ssh && chmod 700 /home/soc/.ssh && chmod 600 /home/soc/.ssh/authorized_keys && (apt-get install -y openssh-server >/dev/null 2>&1; systemctl enable ssh)" `
    --start-vm=gui
Write-Host ""
Write-Host "The VM is installing Ubuntu by itself (about 10 minutes) and then reboots. Tell Claude when the login prompt appears: ssh is reachable at 127.0.0.1:2222 for user soc."
