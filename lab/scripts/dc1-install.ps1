# ============================================================
# DC1-INSTALL.PS1 - Install AD DS and promote to Domain Controller
# Forest: lab1.local | IP: 192.168.56.10
# ============================================================

$ErrorActionPreference = "Stop"

Write-Host "[*] ===== DC1: Installing Active Directory Domain Services =====" -ForegroundColor Cyan

# ── Set local Administrator password (required before DC promotion) ──
Write-Host "[*] Setting local Administrator password..."
net user Administrator "V@grant123!" /active:yes
Write-Host "[+] Administrator password set"

# ── Set static IP (ensure it persists after reboot) ──
$adapter = Get-NetAdapter | Where-Object { $_.Status -eq "Up" -and $_.Name -like "Ethernet*" } | Select-Object -Last 1
if ($adapter) {
    $existingIP = Get-NetIPAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 | Where-Object { $_.IPAddress -eq "192.168.56.10" }
    if (-not $existingIP) {
        Write-Host "[*] Configuring static IP 192.168.56.10"
        New-NetIPAddress -InterfaceIndex $adapter.ifIndex -IPAddress 192.168.56.10 -PrefixLength 24 -DefaultGateway 192.168.56.1 -ErrorAction SilentlyContinue
    }
    # DNS: point to self (will be DNS server) + DC2
    Set-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -ServerAddresses @("192.168.56.10", "192.168.56.11")
}

# ── Install AD DS role ──
if (-not (Get-WindowsFeature AD-Domain-Services).Installed) {
    Write-Host "[*] Installing AD-Domain-Services feature..."
    Install-WindowsFeature AD-Domain-Services -IncludeManagementTools -IncludeAllSubFeature
    Write-Host "[+] AD DS feature installed"
} else {
    Write-Host "[=] AD DS already installed"
}

# ── Promote to Domain Controller ──
$domainCheck = $null
try { $domainCheck = Get-ADDomain -ErrorAction SilentlyContinue } catch {}

if (-not $domainCheck) {
    Write-Host "[*] Promoting to Domain Controller for lab1.local..."

    $safeModePassword = ConvertTo-SecureString "P@ssw0rd123!" -AsPlainText -Force

    Install-ADDSForest `
        -DomainName "lab1.local" `
        -DomainNetbiosName "LAB1" `
        -ForestMode "WinThreshold" `
        -DomainMode "WinThreshold" `
        -InstallDns:$true `
        -SafeModeAdministratorPassword $safeModePassword `
        -NoRebootOnCompletion:$false `
        -Force:$true `
        -Confirm:$false

    Write-Host "[+] DC promotion initiated - rebooting..."
} else {
    Write-Host "[=] Already a DC for $($domainCheck.DNSRoot)"
}
