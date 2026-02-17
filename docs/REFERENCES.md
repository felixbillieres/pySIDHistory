# pySIDHistory - References & Documentation Links

Complete reference collection for understanding, implementing, and extending pySIDHistory.

---

## Microsoft Protocol Specifications (MS-DRSR)

The backbone of the DRSUAPI implementation. These are the official Microsoft Open Specifications
for the Directory Replication Service Remote Protocol.

| Document | URL | Relevance |
|----------|-----|-----------|
| **MS-DRSR Full Specification** | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/ | Master reference for all DRS operations |
| **IDL_DRSAddSidHistory (Opnum 20)** | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/376230a5-d806-4ae5-970a-f6243ee193c8 | The RPC call we implement |
| **DRS_MSG_ADDSIDREQ_V1 Structure** | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/50b7cc92-608c-44ac-9d3e-48e2112c9bc0 | Request structure definition |
| **DRS_ADDSID_FLAGS** | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/76d50efe-d165-42ee-b8e4-5face33fe081 | CHK_SECURE and DEL_SRC_OBJ flags |
| **Server Behavior (Processing Rules)** | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/fbc94975-28ef-4334-bb47-35708a15d586 | How the DC processes the call (3 variants) |
| **DRSUAPI RPC Interface** | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/58f33216-d9f1-43bf-a183-87e3c899c410 | Interface UUID, opnum table |
| **DRS_EXTENSIONS_INT** | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/3ee529b1-23db-4996-948a-042f04998e91 | Capability negotiation (DRS_EXT_ADD_SID_HISTORY) |
| **Full IDL (Appendix A)** | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/3f5d9495-9563-44de-876a-ce6f880e3fb2 | Complete IDL definitions |
| **Calling with DEL_SRC_OBJ** | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/e7ffa674-98d3-43af-b699-8c158622c8f5 | Same-domain variant processing |

## Microsoft Active Directory Documentation

| Document | URL | Relevance |
|----------|-----|-----------|
| **Using DsAddSidHistory (Win32 API)** | https://learn.microsoft.com/en-us/windows/win32/ad/using-dsaddsidhistory | Prerequisites, auditing requirements, trust requirements |
| **sIDHistory Attribute Schema** | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-ada3/1c47c6a0-e614-49e5-bef3-f42f71f5eeb2 | Schema definition (systemOnly: FALSE but SAM-enforced) |
| **DsAddSidHistory Function (ntdsapi.h)** | https://learn.microsoft.com/en-us/windows/win32/api/ntdsapi/nf-ntdsapi-dsaddsidhistoryw | Win32 API wrapper documentation |
| **Well-Known SIDs** | https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-identifiers | Complete SID reference table |
| **Migrate-SID-History Extended Right** | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/1522b774-6c5a-4321-9b93-d9693334b2a2 | Control access right GUID |

## Impacket (Python RPC/LDAP Framework)

| Resource | URL | Relevance |
|----------|-----|-----------|
| **impacket GitHub** | https://github.com/fortra/impacket | Main repository |
| **drsuapi.py Source** | https://github.com/fortra/impacket/blob/master/impacket/dcerpc/v5/drsuapi.py | DRSUAPI implementation we extend |
| **secretsdump.py** | https://github.com/fortra/impacket/blob/master/impacket/examples/secretsdump.py | Reference for DRSBind + DRSGetNCChanges flow |
| **LDAP client (ldap.py)** | https://github.com/fortra/impacket/blob/master/impacket/ldap/ldap.py | impacket's native LDAP client |
| **LDAP ASN.1 types** | https://github.com/fortra/impacket/blob/master/impacket/ldap/ldapasn1.py | ASN.1 structures for LDAP |
| **NDR framework (ndr.py)** | https://github.com/fortra/impacket/blob/master/impacket/dcerpc/v5/ndr.py | How to define NDR structures |
| **raiseChild.py** | https://github.com/fortra/impacket/blob/master/impacket/examples/raiseChild.py | Child-to-parent escalation via ExtraSids |
| **ticketer.py** | https://github.com/fortra/impacket/blob/master/impacket/examples/ticketer.py | Golden Ticket with ExtraSids |
| **ldapattack.py (ntlmrelayx)** | https://github.com/fortra/impacket/blob/master/impacket/examples/ntlmrelayx/attacks/ldapattack.py | LDAP modify patterns |
| **Impacket Developer Guide (RPC Deep Dive)** | https://cicada-8.medium.com/impacket-developer-guide-part-1-rpc-4df4fe6d79d7 | How to extend impacket with custom RPC calls |

## Attack Technique References

| Resource | URL | Relevance |
|----------|-----|-----------|
| **The Hacker Recipes - SID History** | https://www.thehacker.recipes/ad/persistence/sid-history | Primary technique reference |
| **MITRE ATT&CK T1134.005** | https://attack.mitre.org/techniques/T1134/005/ | Official technique classification |
| **HackTricks - SID History Injection** | https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/sid-history-injection | Practical attack guide |
| **ADSecurity - Sneaky Persistence #14** | https://adsecurity.org/?p=1772 | Sean Metcalf's SID History persistence write-up |
| **ired.team - Child DA to EA** | https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain | Child-to-parent escalation via SID History |
| **SpecterOps - AD Forest Trusts** | https://specterops.io/blog/2025/06/25/good-fences-make-good-neighbors-new-ad-trusts-attack-paths-in-bloodhound/ | Trust attack paths |

## Existing Tools (SID History Related)

| Tool | URL | Notes |
|------|-----|-------|
| **mimikatz sid:: module** | https://github.com/gentilkiwi/mimikatz/blob/master/mimikatz/modules/kuhl_m_sid.c | In-memory patching + LDAP write |
| **mimikatz sid::add docs** | https://tools.thehacker.recipes/mimikatz/modules/sid/add | Usage documentation |
| **mimikatz sid::patch docs** | https://tools.thehacker.recipes/mimikatz/modules/sid/patch | Memory patching technique |
| **DSInternals** | https://github.com/MichaelGrafnetter/DSInternals | Offline ntds.dit modification (Add-ADDBSidHistory) |
| **DSInternals drsr.idl** | https://github.com/MichaelGrafnetter/DSInternals/blob/master/Src/DSInternals.Replication.Interop/drsr.idl | Full DRSR IDL with DRSAddSidHistory |
| **GreyCorbel SIDCloner** | https://github.com/GreyCorbel/SIDCloner | C++/CLI wrapper around DsAddSidHistory API |
| **BloodHound SpoofSIDHistory** | https://bloodhound.specterops.io/resources/edges/spoof-sid-history | Attack path modeling |

## SID Filtering & Trust Security

| Resource | URL | Relevance |
|----------|-----|-----------|
| **Dirkjan Mollema - SID Filtering** | https://dirkjanm.io/active-directory-forest-trusts-part-one-how-does-sid-filtering-work/ | Definitive guide to SID filtering internals |
| **Active Directory FAQ - SID Filtering** | https://activedirectoryfaq.com/2015/10/active-directory-sid-filtering/ | Practical SID filtering reference |
| **Microsoft - Trust Attributes** | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/e9a2d23c-c31e-4a6f-88a0-6646571e68a9 | TRUST_ATTRIBUTE flags (QUARANTINED_DOMAIN, TREAT_AS_EXTERNAL) |

## Blue Team / Detection

| Resource | URL | Relevance |
|----------|-----|-----------|
| **Event ID 4765** | https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4765 | SID History added successfully |
| **Event ID 4766** | https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4766 | SID History add failed |
| **Splunk - Same Domain SID Detection** | https://research.splunk.com/endpoint/5fde0b7c-df7a-40b1-9b3a-294c00f0289d/ | SIEM detection rule |
| **Semperis - Defend SID History** | https://www.semperis.com/blog/how-to-defend-against-sid-history-injection/ | Defense strategies |
| **SentinelOne - SID History Exposure** | https://www.sentinelone.com/blog/windows-sid-history-injection-exposure-blog/ | Exposure analysis |
| **Microsoft Defender for Identity** | https://learn.microsoft.com/en-us/defender-for-identity/security-assessment-unsecure-sid-history-attribute | MDI assessment for unsecure sIDHistory |
| **ManageEngine - Event 4765** | https://www.manageengine.com/products/active-directory-audit/account-management-events/event-id-4765.html | Event analysis guide |

## Python Libraries

| Library | URL | Usage in pySIDHistory |
|---------|-----|-----------------------|
| **ldap3** | https://ldap3.readthedocs.io/ | Primary LDAP client for queries, modifications |
| **ldap3 escape_filter_chars** | https://ldap3.readthedocs.io/en/latest/abstraction.html | LDAP injection prevention |
| **impacket** | https://github.com/fortra/impacket | DRSUAPI RPC, PTH authentication, LDAP fallback |

## Schema & Internals

| Resource | URL | Relevance |
|----------|-----|-----------|
| **SID Binary Format** | https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-sid | Binary SID structure (revision, authority, sub-authorities) |
| **ADSecurity - Well-Known SIDs** | https://adsecurity.org/?p=1001 | Comprehensive SID table |
| **MS-ADTS Trust Objects** | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/b645c112-7348-4397-8e2a-5f5dc5e5b77c | trustedDomain object schema |
| **PowerShell SID History Module** | https://learn.microsoft.com/en-us/archive/blogs/ashleymcglone/powershell-module-for-working-with-ad-sid-history | Ashley McGlone's PS module |
| **How to Remove SID History** | https://learn.microsoft.com/en-us/archive/blogs/ashleymcglone/how-to-remove-sid-history-with-powershell | PS removal techniques |
