# pySIDHistory

Remote SID History injection & auditing from Linux — two injection methods, full audit toolkit, one command.

> *"There is currently no way to exploit this technique purely from a distant UNIX-like machine"* — [The Hacker Recipes](https://www.thehacker.recipes/ad/persistence/sid-history)

Challenge accepted.

## Installation

```bash
git clone https://github.com/felixbillieres/pySIDHistory.git
cd pySIDHistory
pip install -r requirements.txt
```

**Requirements**: Python 3.7+, `ldap3`, `impacket`

---

## Two injection methods

| | DSInternals (default) | DRSUAPI (stealth) |
|---|---|---|
| **What it does** | Stops NTDS, modifies ntds.dit offline via DSInternals, restarts NTDS | Calls `DRSAddSidHistory` (opnum 20) over RPC |
| **Privileged SIDs** (DA, EA, krbtgt) | Yes | No (SID-filtered at trust boundary) |
| **Same-domain injection** | Yes | No (error 8534 — same forest) |
| **Cross-forest injection** | Yes | Yes |
| **Requires** | Domain Admin on the DC | DA + auditing + audit groups + cross-forest trust |
| **NTDS downtime** | ~5-10 seconds | None |
| **Stealth** | Lower (stops NTDS, creates service, writes to disk) | Higher (pure RPC, no disk writes) |
| **Best for** | Privilege escalation (RID < 1000) | Stealth persistence (RID > 1000, cross-forest) |

**When to use which:**
- **Need Domain Admins / Enterprise Admins / krbtgt?** → DSInternals (only method that can inject RID < 1000)
- **Cross-forest, stealth matters, RID > 1000?** → DRSUAPI (pure RPC, no NTDS downtime, no disk artifacts)

---

## Injection — DSInternals (default)

```bash
# Same-domain: inject Domain Admins into user1
python3 sidhistory.py -d lab1.local -u da-admin -p 'Password123!' --dc-ip 192.168.56.10 \
    --target user1 --inject domain-admins --force

# Cross-domain: inject Domain Admins of lab2.local via trust resolution
python3 sidhistory.py -d lab1.local -u da-admin -p 'Password123!' --dc-ip 192.168.56.10 \
    --target user1 --inject domain-admins --inject-domain lab2.local --force

# Raw SID injection
python3 sidhistory.py -d lab1.local -u da-admin -p 'Password123!' --dc-ip 192.168.56.10 \
    --target user1 --inject S-1-5-21-3522073385-2671856591-2684624930-512 --force
```

### DSInternals risks

The DSInternals method stops the NTDS service to get exclusive access to `ntds.dit`. This is fundamentally different from tools like `secretsdump` (DCSync via `DRSGetNCChanges` — read-only, zero risk) or `ntdsutil` (VSS snapshot — read-only copy).

| Risk | Impact | Mitigation |
|---|---|---|
| **NTDS downtime** | DC stops processing auth for ~5-10s | Emergency restart built in, auto-retry on failure |
| **Failed restart** | DC stays down until manual `Start-Service ntds` | Script always attempts restart in catch block |
| **ntds.dit corruption** | Unlikely but possible if crash during write | ESE transactions, DSInternals uses safe APIs |
| **Disk artifacts** | Service `__pySIDHist`, script in `C:\Windows\Temp\` | Auto-cleanup after execution |

In a production environment with a single DC, the brief NTDS downtime is the main concern. In a multi-DC environment, other DCs continue serving authentication during the ~10s window.

## Injection — DRSUAPI (stealth)

```bash
# Cross-forest injection (pure RPC, no NTDS downtime)
python3 sidhistory.py -d lab1.local -u da-admin -p 'Password123!' --dc-ip 192.168.56.10 \
    --target user1 --method drsuapi --source-user da-admin2 --source-domain lab2.local \
    --src-username da-admin2 --src-password 'Password123!' --src-domain lab2.local
```

DRSUAPI is the stealth option — pure RPC, no disk writes, no service creation, no NTDS downtime. The limitation is that Windows SID filtering strips SIDs with RID < 1000 from the PAC at forest trust boundaries, so you can't inject Domain Admins (-512) this way. But for custom groups (RID > 1000), it's undetectable by standard monitoring.

### DRSUAPI prerequisites

| Requirement | Details |
|---|---|
| Cross-forest trust | Source and destination must be in different forests |
| Auditing on both DCs | `auditpol /set /category:"Account Management" /success:enable /failure:enable` |
| Audit groups | Local groups `$SRC_DOMAIN$$$` and `$DST_DOMAIN$$$` must exist on both DCs |
| Source domain credentials | `--src-username`, `--src-password`, `--src-domain` |
| Domain Admin on destination | The authenticated user must be DA in the target domain |

---

## Blue Team — Audit & Recon

### Query sIDHistory

```bash
python3 sidhistory.py -d CORP.LOCAL -u admin -p 'Pass123' --dc-ip 10.0.0.1 \
    --query user1
```

### Domain-wide audit

Scans every object for sIDHistory entries with risk assessment (CRITICAL/HIGH/MEDIUM/LOW). Same-domain SIDs are almost always attack artifacts.

```bash
python3 sidhistory.py -d CORP.LOCAL -u admin -p 'Pass123' --dc-ip 10.0.0.1 --audit

# JSON export for SIEM
python3 sidhistory.py -d CORP.LOCAL -u admin -p 'Pass123' --dc-ip 10.0.0.1 \
    --audit -o json --output-file audit.json
```

### Enumerate trusts

```bash
python3 sidhistory.py -d CORP.LOCAL -u admin -p 'Pass123' --dc-ip 10.0.0.1 --enum-trusts
```

### SID lookup & presets

```bash
python3 sidhistory.py -d CORP.LOCAL -u admin -p 'Pass123' --dc-ip 10.0.0.1 --lookup user1
python3 sidhistory.py -d CORP.LOCAL -u admin -p 'Pass123' --dc-ip 10.0.0.1 --list-presets
```

---

## Authentication

| Method | Flags |
|--------|-------|
| NTLM (password) | `-u USER -p 'PASSWORD'` |
| Pass-the-Hash | `-u USER --ntlm-hash NT_HASH` |
| Kerberos | `--kerberos --ccache ccache_file` |
| Certificate (PTC) | `--certificate --cert-file cert.pem --key-file key.pem` |
| SIMPLE bind | `--simple -u USER -p 'PASSWORD' --use-ssl` |

---

## Architecture

```
sidhistory.py              CLI entry point & argument handling
  └── core/
      ├── attack.py        Orchestrator (wires everything together)
      ├── auth.py          Authentication (5 methods, ldap3 + impacket)
      ├── ldap_operations.py  LDAP queries & domain enumeration
      ├── injection.py     DSInternals injection via SMB + SCMR
      ├── drsuapi.py       DRSAddSidHistory RPC (opnum 20)
      ├── scanner.py       Domain-wide auditing & risk assessment
      ├── sid_utils.py     SID binary conversion, presets, well-known SIDs
      └── output.py        Console/JSON/CSV formatting
```

## Detection

### DRSUAPI method

| Event ID | Description |
|----------|-------------|
| **4765** | SID History added to an account |
| **4766** | SID History add attempt failed |
| **4738** | User account changed (any attribute) |

### DSInternals method

| Indicator | What to look for |
|-----------|-----------------|
| **Event 7045** | New service `__pySIDHist` installed (System log) |
| **Event 7036** | NTDS service entered stopped/running state |
| **Event 4688** | `powershell.exe -ExecutionPolicy Bypass` as SYSTEM |
| **File artifacts** | `C:\Windows\Temp\__pysidhistory_*` |
| **SMB writes** | File upload to `\\DC\ADMIN$\Temp\` |

## Lab

**[sIDHistoryLab](https://github.com/felixbillieres/sIDHistoryLab)** — Two Windows Server 2019 DCs with cross-forest trust, fully automated with Vagrant.

## Verbose mode

Default output is clean and minimal. Use `-v` for full debug traces (LDAP, SMB, RPC, SCMR).

```bash
python3 sidhistory.py -d CORP.LOCAL -u admin -p 'Pass123' --dc-ip 10.0.0.1 --audit -v
```

## References

- [MS-DRSR: IDL_DRSAddSidHistory (Opnum 20)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/376230a5-d806-4ae5-970a-f6243ee193c8)
- [MS-SCMR: Service Control Manager Remote Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/)
- [DSInternals](https://github.com/MichaelGrafnetter/DSInternals)
- [The Hacker Recipes: SID History](https://www.thehacker.recipes/ad/persistence/sid-history)
- [Dirkjan Mollema: SID Filtering](https://dirkjanm.io/active-directory-forest-trusts-part-one-how-does-sid-filtering-work/)
- [impacket](https://github.com/fortra/impacket)
- [MITRE ATT&CK T1134.005](https://attack.mitre.org/techniques/T1134/005/)

## Author

[@felixbillieres](https://github.com/felixbillieres)
