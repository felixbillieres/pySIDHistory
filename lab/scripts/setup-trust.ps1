# ============================================================
# SETUP-TRUST.PS1 - Establish bidirectional forest trust
# Run on DC1 (lab1.local) AFTER both DCs are fully configured
#
# Usage from host:
#   vagrant winrm dc1 -c "powershell -File C:\vagrant\scripts\setup-trust.ps1"
# ============================================================

$ErrorActionPreference = "Stop"

Write-Host "[*] ===== Setting up Forest Trust: lab1.local <-> lab2.local =====" -ForegroundColor Cyan

# ── Verify DNS resolution ──
Write-Host "[*] Verifying DNS resolution..."
$dc2Resolved = $false
for ($i = 0; $i -lt 10; $i++) {
    try {
        $result = Resolve-DnsName -Name "lab2.local" -Type A -ErrorAction Stop
        Write-Host "[+] lab2.local resolves to: $($result.IPAddress)"
        $dc2Resolved = $true
        break
    } catch {
        Write-Host "[.] Waiting for DNS resolution of lab2.local... ($i/10)"
        Start-Sleep -Seconds 5
    }
}

if (-not $dc2Resolved) {
    Write-Host "[-] Cannot resolve lab2.local - check DNS conditional forwarder" -ForegroundColor Red
    Write-Host "[-] Run: Add-DnsServerConditionalForwarderZone -Name 'lab2.local' -MasterServers 192.168.56.11"
    exit 1
}

# ── Verify network connectivity ──
Write-Host "[*] Verifying network connectivity to DC2..."
$pingResult = Test-Connection -ComputerName 192.168.56.11 -Count 2 -Quiet
if (-not $pingResult) {
    Write-Host "[-] Cannot reach DC2 at 192.168.56.11" -ForegroundColor Red
    exit 1
}
Write-Host "[+] DC2 is reachable"

# ── Create the bidirectional forest trust ──
Write-Host "[*] Creating bidirectional forest trust..."

$trustPassword = "TrustP@ss123!"

# Check if trust already exists
$existingTrust = Get-ADTrust -Filter "Target -eq 'lab2.local'" -ErrorAction SilentlyContinue
if ($existingTrust) {
    Write-Host "[=] Trust to lab2.local already exists (Direction: $($existingTrust.Direction))"
} else {
    try {
        # Method 1: netdom (most reliable for cross-forest)
        Write-Host "[*] Using netdom to create forest trust..."
        $cmd = "netdom trust lab1.local /d:lab2.local /add /twoway " +
               "/UserD:administrator@lab2.local /PasswordD:V@grant123! " +
               "/UserO:administrator@lab1.local /PasswordO:V@grant123!"

        $result = cmd /c $cmd 2>&1
        Write-Host $result

        if ($LASTEXITCODE -eq 0 -or $LASTEXITCODE -eq 1379 -or $LASTEXITCODE -eq 183) {
            # 1379 = ERROR_ALIAS_EXISTS (local group already exists - harmless)
            # 183  = ERROR_ALREADY_EXISTS (trust already exists)
            Write-Host "[+] Forest trust created/exists successfully via netdom" -ForegroundColor Green
        } else {
            Write-Host "[!] netdom returned code $LASTEXITCODE, trying PowerShell method..." -ForegroundColor Yellow

            # Method 2: PowerShell AD cmdlets
            $lab1Context = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext(
                [System.DirectoryServices.ActiveDirectory.DirectoryContextType]::Forest,
                "lab1.local",
                "administrator",
                "V@grant123!"
            )
            $lab1Forest = [System.DirectoryServices.ActiveDirectory.Forest]::GetForest($lab1Context)

            $lab2Context = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext(
                [System.DirectoryServices.ActiveDirectory.DirectoryContextType]::Forest,
                "lab2.local",
                "administrator",
                "V@grant123!"
            )
            $lab2Forest = [System.DirectoryServices.ActiveDirectory.Forest]::GetForest($lab2Context)

            # Create bidirectional forest trust
            $lab1Forest.CreateTrustRelationship(
                $lab2Forest,
                [System.DirectoryServices.ActiveDirectory.TrustDirection]::Bidirectional
            )
            Write-Host "[+] Forest trust created via .NET API" -ForegroundColor Green
        }
    } catch {
        Write-Host "[-] Trust creation failed: $_" -ForegroundColor Red
        Write-Host "[*] You may need to create it manually via Server Manager"
        exit 1
    }
}

# ── Enable SID History on the trust (disable SID filtering) ──
Write-Host "[*] Enabling SID History on the forest trust..."
try {
    # This sets TREAT_AS_EXTERNAL flag, allowing SID History to flow
    netdom trust lab1.local /d:lab2.local /enablesidhistory:yes /UserD:administrator@lab2.local /PasswordD:V@grant123!
    Write-Host "[+] SID History enabled on trust (SID filtering relaxed)" -ForegroundColor Green
} catch {
    Write-Host "[!] Could not enable SID History automatically: $_" -ForegroundColor Yellow
    Write-Host "[*] Manual command: netdom trust lab1.local /d:lab2.local /enablesidhistory:yes"
}

# ── Verify the trust ──
Write-Host ""
Write-Host "[*] Verifying trust configuration..."
$trust = Get-ADTrust -Filter "Target -eq 'lab2.local'" -Properties * -ErrorAction SilentlyContinue
if ($trust) {
    Write-Host "[+] Trust verified:" -ForegroundColor Green
    Write-Host "    Target     : $($trust.Target)"
    Write-Host "    Direction  : $($trust.Direction)"
    Write-Host "    TrustType  : $($trust.TrustType)"
    Write-Host "    Transitive : $($trust.IsTreeParent -or $trust.ForestTransitive)"

    $attrs = $trust.TrustAttributes
    $sidHistEnabled = ($attrs -band 0x40) -ne 0  # TREAT_AS_EXTERNAL
    Write-Host "    Attributes : $attrs"
    Write-Host "    SIDHistory : $(if ($sidHistEnabled) { 'ENABLED' } else { 'Filtered' })"
} else {
    Write-Host "[-] Could not verify trust" -ForegroundColor Yellow
}

# ── Inject a test sIDHistory entry (for audit testing) ──
Write-Host ""
Write-Host "[*] Adding a test sIDHistory entry for audit testing..."
try {
    # Create a sacrificial user to simulate a migrated account
    $testSID = "S-1-5-21-999888777-666555444-333222111-1234"  # Fake foreign SID
    $sidBytes = @()

    # Build binary SID for S-1-5-21-999888777-666555444-333222111-1234
    # Revision=1, SubAuthCount=5, Authority=5(NT)
    $sidBytes = [byte[]]@(
        0x01, 0x05,                                     # Revision, SubAuthCount
        0x00, 0x00, 0x00, 0x00, 0x00, 0x05              # NT Authority (big-endian)
    )
    # SubAuth[0] = 21
    $sidBytes += [System.BitConverter]::GetBytes([uint32]21)
    # SubAuth[1] = 999888777
    $sidBytes += [System.BitConverter]::GetBytes([uint32]999888777)
    # SubAuth[2] = 666555444
    $sidBytes += [System.BitConverter]::GetBytes([uint32]666555444)
    # SubAuth[3] = 333222111
    $sidBytes += [System.BitConverter]::GetBytes([uint32]333222111)
    # SubAuth[4] = 1234
    $sidBytes += [System.BitConverter]::GetBytes([uint32]1234)

    # Use Set-ADUser to add the SID History (this works locally on the DC)
    $migrateUser = Get-ADUser -Filter "sAMAccountName -eq 'helpdesk'" -ErrorAction Stop
    if ($migrateUser) {
        Set-ADObject -Identity $migrateUser.DistinguishedName -Add @{sIDHistory = $sidBytes} -ErrorAction Stop
        Write-Host "[+] Added fake foreign SID to helpdesk's sIDHistory (for audit testing)" -ForegroundColor Green
        Write-Host "    SID: $testSID"
    }
} catch {
    Write-Host "[!] Could not set test sIDHistory (expected on some configs): $_" -ForegroundColor Yellow
    Write-Host "[*] This is OK - the audit test will still work with empty sIDHistory"
}

Write-Host ""
Write-Host "============================================================" -ForegroundColor Green
Write-Host " Lab setup complete!" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
Write-Host ""
Write-Host " Forest 1: lab1.local  (DC1: 192.168.56.10)"
Write-Host " Forest 2: lab2.local  (DC2: 192.168.56.11)"
Write-Host " Trust:    Bidirectional forest trust (SID History enabled)"
Write-Host ""
Write-Host " Credentials:"
Write-Host "   lab1.local\da-admin    / Password123!  (Domain Admin)"
Write-Host "   lab1.local\user1       / Password123!  (Target user)"
Write-Host "   lab1.local\user2       / Password123!  (Target user)"
Write-Host "   lab1.local\helpdesk    / Password123!  (Has test sIDHistory)"
Write-Host "   lab2.local\da-admin2   / Password123!  (Domain Admin)"
Write-Host "   lab2.local\target-user / Password123!  (Target user)"
Write-Host ""
Write-Host " Vagrant default: administrator / vagrant"
Write-Host "============================================================" -ForegroundColor Green
