# ============================================================
# DC2-CONFIGURE.PS1 - Create users, groups, configure DNS & trust
# Forest: lab2.local | DC: DC2 | IP: 192.168.56.11
# ============================================================

$ErrorActionPreference = "SilentlyContinue"

Write-Host "[*] ===== DC2: Configuring Active Directory =====" -ForegroundColor Cyan

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

$domainDN = "DC=lab2,DC=local"
$password = ConvertTo-SecureString "Password123!" -AsPlainText -Force

# ── Firewall: Allow all from lab network ──
Write-Host "[*] Configuring firewall..."
New-NetFirewallRule -DisplayName "Allow Lab Network" -Direction Inbound -RemoteAddress 192.168.56.0/24 -Action Allow -ErrorAction SilentlyContinue
@(389, 636, 88, 464, 135, 445, 53) | ForEach-Object {
    New-NetFirewallRule -DisplayName "Allow Port $_" -Direction Inbound -LocalPort $_ -Protocol TCP -Action Allow -ErrorAction SilentlyContinue
}
New-NetFirewallRule -DisplayName "Allow RPC Dynamic" -Direction Inbound -LocalPort 49152-65535 -Protocol TCP -Action Allow -ErrorAction SilentlyContinue

# ── Create OUs ──
Write-Host "[*] Creating OUs..."
New-ADOrganizationalUnit -Name "LabUsers" -Path $domainDN -ErrorAction SilentlyContinue
New-ADOrganizationalUnit -Name "LabGroups" -Path $domainDN -ErrorAction SilentlyContinue

# ── Create Users ──
Write-Host "[*] Creating users..."

$users = @(
    @{ Name = "da-admin2";    Given = "DA2";     Surname = "Admin";    Desc = "Domain Admin forest 2";          Admin = $true  },
    @{ Name = "target-user";  Given = "Target";  Surname = "User";     Desc = "Injection target in forest 2";   Admin = $false },
    @{ Name = "migrate-user"; Given = "Migrate"; Surname = "User";     Desc = "Simulated migration user";       Admin = $false },
    @{ Name = "svc-sql";      Given = "Service"; Surname = "SQL";      Desc = "SQL service account";            Admin = $false }
)

foreach ($u in $users) {
    $sam = $u.Name
    $exists = Get-ADUser -Filter "sAMAccountName -eq '$sam'" -ErrorAction SilentlyContinue
    if (-not $exists) {
        New-ADUser `
            -Name "$($u.Given) $($u.Surname)" `
            -SamAccountName $sam `
            -UserPrincipalName "$sam@lab2.local" `
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

# ── Create custom groups ──
Write-Host "[*] Creating custom groups..."
$groups = @(
    @{ Name = "App-Admins";    Desc = "Application Administrators (RID>1000)" },
    @{ Name = "Data-Analysts"; Desc = "Data Analysts group" }
)

foreach ($g in $groups) {
    $exists = Get-ADGroup -Filter "Name -eq '$($g.Name)'" -ErrorAction SilentlyContinue
    if (-not $exists) {
        New-ADGroup -Name $g.Name -GroupScope Global -GroupCategory Security `
            -Path "OU=LabGroups,$domainDN" -Description $g.Desc
        Write-Host "[+] Created group: $($g.Name)"
    }
}

Add-ADGroupMember -Identity "App-Admins" -Members "svc-sql" -ErrorAction SilentlyContinue

# ── Configure DNS: Add conditional forwarder for lab1.local ──
Write-Host "[*] Configuring DNS conditional forwarder for lab1.local..."
try {
    Add-DnsServerConditionalForwarderZone -Name "lab1.local" -MasterServers 192.168.56.10 -ErrorAction Stop
    Write-Host "[+] DNS forwarder for lab1.local added"
} catch {
    Write-Host "[=] DNS forwarder may already exist: $_"
}

# ── Enable auditing ──
Write-Host "[*] Enabling audit policies..."
auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable
auditpol /set /subcategory:"Security Group Management" /success:enable /failure:enable
auditpol /set /subcategory:"Computer Account Management" /success:enable /failure:enable
Write-Host "[+] Audit policies configured"

# ── TcpipClientSupport ──
Write-Host "[*] Setting TcpipClientSupport registry key..."
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "TcpipClientSupport" -Value 1 -Type DWord -ErrorAction SilentlyContinue
Write-Host "[+] TcpipClientSupport set to 1"

# ── Create SID History audit groups ──
Write-Host "[*] Creating SID History audit groups..."
foreach ($grp in @("LAB1$$$", "LAB2$$$")) {
    try {
        net localgroup "$grp" /add 2>$null
        Write-Host "[+] Created audit group: $grp"
    } catch {}
}

Write-Host ""
Write-Host "[*] ===== DC2 configuration complete =====" -ForegroundColor Green
Write-Host "[*] Domain : lab2.local"
Write-Host "[*] DC     : DC2 (192.168.56.11)"
Write-Host "[*] DA user: da-admin2 / Password123!"
Write-Host "[*] Users  : target-user, migrate-user, svc-sql / Password123!"
Write-Host ""
