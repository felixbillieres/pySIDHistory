# ============================================================
# DC1-CONFIGURE.PS1 - Create users, groups, configure DNS & trust
# Forest: lab1.local | DC: DC1 | IP: 192.168.56.10
# ============================================================

$ErrorActionPreference = "SilentlyContinue"

Write-Host "[*] ===== DC1: Configuring Active Directory =====" -ForegroundColor Cyan

# Wait for AD DS to be fully operational
$maxRetries = 30
$retry = 0
while ($retry -lt $maxRetries) {
    try {
        Get-ADDomain | Out-Null
        break
    } catch {
        Write-Host "[.] Waiting for AD DS to start... ($retry/$maxRetries)"
        Start-Sleep -Seconds 10
        $retry++
    }
}

$domainDN = "DC=lab1,DC=local"
$password = ConvertTo-SecureString "Password123!" -AsPlainText -Force

# ── Firewall: Allow all from lab network ──
Write-Host "[*] Configuring firewall..."
New-NetFirewallRule -DisplayName "Allow Lab Network" -Direction Inbound -RemoteAddress 192.168.56.0/24 -Action Allow -ErrorAction SilentlyContinue
# Also allow LDAP, LDAPS, Kerberos, RPC explicitly
@(389, 636, 88, 464, 135, 445, 53) | ForEach-Object {
    New-NetFirewallRule -DisplayName "Allow Port $_" -Direction Inbound -LocalPort $_ -Protocol TCP -Action Allow -ErrorAction SilentlyContinue
}
# Allow RPC dynamic range
New-NetFirewallRule -DisplayName "Allow RPC Dynamic" -Direction Inbound -LocalPort 49152-65535 -Protocol TCP -Action Allow -ErrorAction SilentlyContinue

# ── Create OUs ──
Write-Host "[*] Creating OUs..."
New-ADOrganizationalUnit -Name "LabUsers" -Path $domainDN -ErrorAction SilentlyContinue
New-ADOrganizationalUnit -Name "LabGroups" -Path $domainDN -ErrorAction SilentlyContinue
New-ADOrganizationalUnit -Name "LabComputers" -Path $domainDN -ErrorAction SilentlyContinue

# ── Create Users ──
Write-Host "[*] Creating users..."

# Domain Admin (for testing)
$users = @(
    @{ Name = "da-admin";     Given = "DA";      Surname = "Admin";    Desc = "Domain Admin for testing";     Admin = $true  },
    @{ Name = "user1";        Given = "Alice";    Surname = "Target";   Desc = "Low-priv user (injection target)"; Admin = $false },
    @{ Name = "user2";        Given = "Bob";      Surname = "Normal";   Desc = "Low-priv user (second target)";    Admin = $false },
    @{ Name = "svc-backup";   Given = "Service";  Surname = "Backup";   Desc = "Service account for testing";      Admin = $false },
    @{ Name = "helpdesk";     Given = "Help";     Surname = "Desk";     Desc = "Helpdesk operator";                Admin = $false }
)

foreach ($u in $users) {
    $sam = $u.Name
    $exists = Get-ADUser -Filter "sAMAccountName -eq '$sam'" -ErrorAction SilentlyContinue
    if (-not $exists) {
        New-ADUser `
            -Name "$($u.Given) $($u.Surname)" `
            -SamAccountName $sam `
            -UserPrincipalName "$sam@lab1.local" `
            -GivenName $u.Given `
            -Surname $u.Surname `
            -Description $u.Desc `
            -Path "OU=LabUsers,$domainDN" `
            -AccountPassword $password `
            -Enabled $true `
            -PasswordNeverExpires $true `
            -CannotChangePassword $true

        if ($u.Admin) {
            Add-ADGroupMember -Identity "Domain Admins" -Members $sam
            Write-Host "[+] Created DA: $sam"
        } else {
            Write-Host "[+] Created user: $sam"
        }
    } else {
        Write-Host "[=] User $sam already exists"
    }
}

# ── Create custom groups (RID > 1000, for SID filtering tests) ──
Write-Host "[*] Creating custom groups..."
$groups = @(
    @{ Name = "IT-Admins";     Desc = "IT Administrators (custom group, RID>1000)" },
    @{ Name = "DB-Admins";     Desc = "Database Administrators" },
    @{ Name = "Server-Admins"; Desc = "Server Administrators" }
)

foreach ($g in $groups) {
    $exists = Get-ADGroup -Filter "Name -eq '$($g.Name)'" -ErrorAction SilentlyContinue
    if (-not $exists) {
        New-ADGroup -Name $g.Name -GroupScope Global -GroupCategory Security `
            -Path "OU=LabGroups,$domainDN" -Description $g.Desc
        Write-Host "[+] Created group: $($g.Name)"
    }
}

# Add some users to groups
Add-ADGroupMember -Identity "IT-Admins" -Members "svc-backup" -ErrorAction SilentlyContinue
Add-ADGroupMember -Identity "Server-Admins" -Members "helpdesk" -ErrorAction SilentlyContinue

# ── Configure DNS: Add conditional forwarder for lab2.local ──
Write-Host "[*] Configuring DNS conditional forwarder for lab2.local..."
try {
    Add-DnsServerConditionalForwarderZone -Name "lab2.local" -MasterServers 192.168.56.11 -ErrorAction Stop
    Write-Host "[+] DNS forwarder for lab2.local added"
} catch {
    Write-Host "[=] DNS forwarder may already exist: $_"
}

# ── Enable auditing (required for DRSAddSidHistory) ──
Write-Host "[*] Enabling audit policies..."
auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable
auditpol /set /subcategory:"Security Group Management" /success:enable /failure:enable
auditpol /set /subcategory:"Computer Account Management" /success:enable /failure:enable
Write-Host "[+] Audit policies configured"

# ── Configure TcpipClientSupport for DRSAddSidHistory ──
Write-Host "[*] Setting TcpipClientSupport registry key..."
$lsaPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
Set-ItemProperty -Path $lsaPath -Name "TcpipClientSupport" -Value 1 -Type DWord -ErrorAction SilentlyContinue
Write-Host "[+] TcpipClientSupport set to 1"

# ── Create the audit group for DRSAddSidHistory ──
# DsAddSidHistory requires a group named "<SrcDomainNetBIOS>$$$" on the source DC
Write-Host "[*] Creating SID History audit groups..."
$auditGroups = @("LAB1$$$", "LAB2$$$")
foreach ($grp in $auditGroups) {
    $exists = Get-ADGroup -Filter "Name -eq '$grp'" -ErrorAction SilentlyContinue
    if (-not $exists) {
        # Create as a local domain group (SAM group)
        try {
            net localgroup "$grp" /add 2>$null
            Write-Host "[+] Created audit group: $grp"
        } catch {
            Write-Host "[-] Failed to create audit group: $grp"
        }
    }
}

Write-Host ""
Write-Host "[*] ===== DC1 configuration complete =====" -ForegroundColor Green
Write-Host "[*] Domain : lab1.local"
Write-Host "[*] DC     : DC1 (192.168.56.10)"
Write-Host "[*] DA user: da-admin / Password123!"
Write-Host "[*] Users  : user1, user2, svc-backup, helpdesk / Password123!"
Write-Host ""
