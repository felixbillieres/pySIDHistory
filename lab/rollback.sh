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

# ── Clear sIDHistory on both domains via LDAP MODIFY_DELETE ──
echo "[*] Clearing sIDHistory on both domains..."
python3 << PYEOF
import sys
sys.path.insert(0, '$SCRIPT_DIR')
from ldap3 import Server, Connection, NTLM, SUBTREE, MODIFY_DELETE

domains = [
    ('$DC1_IP', '$DC1_DOMAIN', '$DC1_USER', '$PASS', '$LAB1_USERS'.split()),
    ('$DC2_IP', '$DC2_DOMAIN', '$DC2_USER', '$PASS', '$LAB2_USERS'.split()),
]

for dc_ip, domain, user, password, users in domains:
    base_dn = ','.join(f'DC={p}' for p in domain.split('.'))
    server = Server(dc_ip, port=389, use_ssl=False)
    conn = Connection(server, user=f'{domain}\\\\{user}', password=password, authentication=NTLM, auto_bind=True)
    print(f'  [{domain}]')
    for u in users:
        conn.search(base_dn, f'(sAMAccountName={u})', SUBTREE, attributes=['sIDHistory'])
        if not conn.entries:
            print(f'    {u}: not found')
            continue
        entry = conn.entries[0]
        try:
            raw = entry.sIDHistory.raw_values
            if not raw:
                print(f'    {u}: clean')
                continue
        except:
            print(f'    {u}: clean')
            continue
        conn.modify(str(entry.entry_dn), {'sIDHistory': [(MODIFY_DELETE, list(raw))]})
        if conn.result['result'] == 0:
            print(f'    {u}: cleared {len(raw)} SID(s)')
        else:
            print(f'    {u}: failed ({conn.result["description"]})')
    conn.unbind()
PYEOF

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
