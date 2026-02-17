#!/bin/bash
# Rollback script: clears all sIDHistory injections and resets the lab to a clean state
# Usage: ./rollback.sh [--all]
#   default: clears sIDHistory on all known test users
#   --all:   also re-enables auditing and recreates audit groups

set -e
SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$SCRIPT_DIR"

DC1_IP="192.168.56.10"
DC2_IP="192.168.56.11"
DC1_DOMAIN="lab1.local"
DC2_DOMAIN="lab2.local"
DC1_USER="da-admin"
DC2_USER="da-admin2"
PASS="Password123!"

# Lab1 users that may have been injected
LAB1_USERS="user1 user2 svc-backup helpdesk da-admin"
# Lab2 users
LAB2_USERS="target-user migrate-user svc-sql da-admin2"

echo "=== pySIDHistory Lab Rollback ==="
echo ""

# ── Clear sIDHistory on lab1.local ──
echo "[*] Clearing sIDHistory on $DC1_DOMAIN..."
for user in $LAB1_USERS; do
    echo -n "    $user: "
    output=$(python3 sidhistory.py \
        -d "$DC1_DOMAIN" -u "$DC1_USER" -p "$PASS" \
        --dc-ip "$DC1_IP" \
        --target "$user" --clear -q 2>&1)
    if echo "$output" | grep -q "Cleared\|No sIDHistory\|not found"; then
        echo "OK"
    elif echo "$output" | grep -q "empty\|no entries"; then
        echo "already clean"
    else
        echo "done"
    fi
done

echo ""

# ── Clear sIDHistory on lab2.local ──
echo "[*] Clearing sIDHistory on $DC2_DOMAIN..."
for user in $LAB2_USERS; do
    echo -n "    $user: "
    output=$(python3 sidhistory.py \
        -d "$DC2_DOMAIN" -u "$DC2_USER" -p "$PASS" \
        --dc-ip "$DC2_IP" \
        --target "$user" --clear -q 2>&1)
    if echo "$output" | grep -q "Cleared\|No sIDHistory\|not found"; then
        echo "OK"
    elif echo "$output" | grep -q "empty\|no entries"; then
        echo "already clean"
    else
        echo "done"
    fi
done

echo ""

# ── Verify clean state ──
echo "[*] Verifying lab1.local..."
python3 sidhistory.py \
    -d "$DC1_DOMAIN" -u "$DC1_USER" -p "$PASS" \
    --dc-ip "$DC1_IP" --audit -q 2>&1 | grep -E "Objects with|sIDHistory entries|CRITICAL|HIGH" || echo "    Clean - no sIDHistory found"

echo ""
echo "[*] Verifying lab2.local..."
python3 sidhistory.py \
    -d "$DC2_DOMAIN" -u "$DC2_USER" -p "$PASS" \
    --dc-ip "$DC2_IP" --audit -q 2>&1 | grep -E "Objects with|sIDHistory entries|CRITICAL|HIGH" || echo "    Clean - no sIDHistory found"

# ── Optional: re-setup prerequisites ──
if [ "$1" = "--all" ]; then
    echo ""
    echo "[*] Re-enabling auditing and audit groups..."

    cd lab/
    vagrant winrm dc1 -c 'auditpol /set /category:"Account Management" /success:enable /failure:enable' 2>/dev/null && echo "    DC1 auditing: OK" || echo "    DC1 auditing: already set"
    vagrant winrm dc1 -c 'net localgroup LAB2$$$ /add 2>nul & exit /b 0' 2>/dev/null && echo "    DC1 LAB2\$\$\$ group: OK" || true

    # DC2 via impacket (WinRM is slow)
    cd "$SCRIPT_DIR"
    python3 << 'PYEOF'
from impacket.smbconnection import SMBConnection
from impacket.dcerpc.v5 import transport, scmr
import time

smb = SMBConnection('192.168.56.11', '192.168.56.11')
smb.login('administrator', 'V@grant123!', 'lab2.local')
rpctransport = transport.SMBTransport('192.168.56.11', 445, r'\svcctl', smb_connection=smb)
dce = rpctransport.get_dce_rpc()
dce.connect()
dce.bind(scmr.MSRPC_UUID_SCMR)
scHandle = scmr.hROpenSCManagerW(dce)['lpScHandle']

for cmd, desc in [
    ('auditpol /set /category:"Account Management" /success:enable /failure:enable', 'DC2 auditing'),
    ('net localgroup LAB1$$$ /add', 'DC2 LAB1$$$ group'),
    ('net localgroup LAB2$$$ /add', 'DC2 LAB2$$$ group'),
]:
    svc_name = 'Tmp' + desc.replace(' ', '')[:8]
    try:
        scmr.hRDeleteService(dce, scmr.hROpenServiceW(dce, scHandle, svc_name)['lpServiceHandle'])
    except: pass
    svcHandle = scmr.hRCreateServiceW(dce, scHandle, svc_name, svc_name,
        lpBinaryPathName='cmd.exe /c ' + cmd,
        dwStartType=scmr.SERVICE_DEMAND_START)['lpServiceHandle']
    try: scmr.hRStartServiceW(dce, svcHandle)
    except: pass
    time.sleep(1)
    try: scmr.hRDeleteService(dce, svcHandle)
    except: pass
    print(f"    {desc}: OK")

dce.disconnect()
smb.logoff()
PYEOF
fi

echo ""
echo "[+] Rollback complete. Lab is ready for retesting."
