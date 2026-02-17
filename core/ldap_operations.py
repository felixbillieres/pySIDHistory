"""
LDAP Operations
Handles LDAP queries and modifications for Active Directory.
Supports users, groups, and computer objects with paged searches.
"""

import logging
from typing import Optional, List, Dict, Any
from ldap3 import (
    Connection, SUBTREE,
    ALL_ATTRIBUTES
)
from ldap3.core.exceptions import LDAPException
from ldap3.utils.conv import escape_filter_chars
from ldap3.extend.microsoft.addMembersToGroups import ad_add_members_to_groups

from .sid_utils import SIDConverter


class LDAPOperations:
    """
    Performs LDAP operations on Active Directory.
    Supports users, groups, and computer objects.
    """

    # Object class filters
    FILTER_USER = "(&(objectCategory=person)(objectClass=user))"
    FILTER_GROUP = "(objectClass=group)"
    FILTER_COMPUTER = "(objectClass=computer)"
    FILTER_ANY = "(|(objectCategory=person)(objectClass=group)(objectClass=computer))"

    # Page size for paged searches
    PAGE_SIZE = 1000

    def __init__(self, connection: Connection, base_dn: str):
        self.connection = connection
        self.base_dn = base_dn
        self.sid_converter = SIDConverter()

    # ─── SID LOOKUPS ──────────────────────────────────────────────────────

    def get_object_sid(self, sam_account_name: str) -> Optional[str]:
        """Retrieve the SID of any object by sAMAccountName."""
        try:
            safe_name = escape_filter_chars(sam_account_name)
            search_filter = f"(sAMAccountName={safe_name})"
            self.connection.search(
                search_base=self.base_dn,
                search_filter=search_filter,
                search_scope=SUBTREE,
                attributes=['objectSid']
            )

            if not self.connection.entries:
                logging.error(f"Object '{sam_account_name}' not found")
                return None

            sid_bytes = self.connection.entries[0].objectSid.raw_values[0]
            sid = self.sid_converter.bytes_to_string(sid_bytes)
            logging.debug(f"SID for {sam_account_name}: {sid}")
            return sid

        except LDAPException as e:
            logging.error(f"Error retrieving SID for {sam_account_name}: {e}")
            return None

    # Keep backward compatibility
    def get_user_sid(self, sam_account_name: str) -> Optional[str]:
        return self.get_object_sid(sam_account_name)

    def get_object_dn(self, sam_account_name: str) -> Optional[str]:
        """Retrieve the DN of any object by sAMAccountName."""
        try:
            safe_name = escape_filter_chars(sam_account_name)
            search_filter = f"(sAMAccountName={safe_name})"
            self.connection.search(
                search_base=self.base_dn,
                search_filter=search_filter,
                search_scope=SUBTREE,
                attributes=['distinguishedName']
            )

            if not self.connection.entries:
                logging.error(f"Object '{sam_account_name}' not found")
                return None

            dn = str(self.connection.entries[0].distinguishedName)
            logging.debug(f"DN for {sam_account_name}: {dn}")
            return dn

        except LDAPException as e:
            logging.error(f"Error retrieving DN for {sam_account_name}: {e}")
            return None

    # Keep backward compatibility
    def get_user_dn(self, sam_account_name: str) -> Optional[str]:
        return self.get_object_dn(sam_account_name)

    def get_object_info(self, sam_account_name: str) -> Optional[Dict[str, Any]]:
        """Get comprehensive info about an object."""
        try:
            safe_name = escape_filter_chars(sam_account_name)
            search_filter = f"(sAMAccountName={safe_name})"
            self.connection.search(
                search_base=self.base_dn,
                search_filter=search_filter,
                search_scope=SUBTREE,
                attributes=['objectSid', 'sIDHistory', 'distinguishedName',
                           'objectClass', 'sAMAccountName', 'memberOf',
                           'userAccountControl', 'description']
            )

            if not self.connection.entries:
                return None

            entry = self.connection.entries[0]
            info = {
                'dn': str(entry.distinguishedName),
                'sam': str(entry.sAMAccountName),
                'objectClass': list(entry.objectClass.values) if entry.objectClass else [],
            }

            # SID
            try:
                sid_bytes = entry.objectSid.raw_values[0]
                info['sid'] = self.sid_converter.bytes_to_string(sid_bytes)
            except Exception:
                info['sid'] = None

            # SID History
            info['sidHistory'] = self._extract_sid_history(entry)

            # Description
            try:
                info['description'] = str(entry.description) if entry.description else ''
            except Exception:
                info['description'] = ''

            return info

        except LDAPException as e:
            logging.error(f"Error getting object info: {e}")
            return None

    # ─── SID HISTORY OPERATIONS ───────────────────────────────────────────

    def get_sid_history(self, sam_account_name: str) -> List[str]:
        """Retrieve the current SID History of an object."""
        try:
            safe_name = escape_filter_chars(sam_account_name)
            search_filter = f"(sAMAccountName={safe_name})"
            self.connection.search(
                search_base=self.base_dn,
                search_filter=search_filter,
                search_scope=SUBTREE,
                attributes=['sIDHistory']
            )

            if not self.connection.entries:
                logging.error(f"Object '{sam_account_name}' not found")
                return []

            return self._extract_sid_history(self.connection.entries[0])

        except LDAPException as e:
            logging.error(f"Error retrieving SID History: {e}")
            return []

    def _extract_sid_history(self, entry) -> List[str]:
        """Extract SID History from an LDAP entry."""
        try:
            raw_values = entry.sIDHistory.raw_values
            if not raw_values:
                return []
            return [self.sid_converter.bytes_to_string(b) for b in raw_values]
        except Exception:
            return []

    # ─── DOMAIN-WIDE SEARCHES ────────────────────────────────────────────

    def find_all_with_sid_history(self) -> List[Dict[str, Any]]:
        """
        Find ALL objects in the domain that have non-empty sIDHistory.
        Uses paged search for large domains.
        """
        results = []
        search_filter = "(&(sIDHistory=*)(|(objectCategory=person)(objectClass=group)(objectClass=computer)))"

        try:
            self.connection.search(
                search_base=self.base_dn,
                search_filter=search_filter,
                search_scope=SUBTREE,
                attributes=['sAMAccountName', 'objectSid', 'sIDHistory',
                           'objectClass', 'distinguishedName', 'description'],
                paged_size=self.PAGE_SIZE
            )

            while True:
                for entry in self.connection.entries:
                    obj = self._parse_entry(entry)
                    if obj:
                        results.append(obj)

                # Check for more pages
                cookie = self.connection.result.get('controls', {}).get(
                    '1.2.840.113556.1.4.319', {}
                ).get('value', {}).get('cookie')

                if cookie:
                    self.connection.search(
                        search_base=self.base_dn,
                        search_filter=search_filter,
                        search_scope=SUBTREE,
                        attributes=['sAMAccountName', 'objectSid', 'sIDHistory',
                                   'objectClass', 'distinguishedName', 'description'],
                        paged_size=self.PAGE_SIZE,
                        paged_cookie=cookie
                    )
                else:
                    break

        except LDAPException as e:
            logging.error(f"Error scanning domain: {e}")

        return results

    def get_domain_sid(self) -> Optional[str]:
        """Get the domain SID from the domain object."""
        try:
            self.connection.search(
                search_base=self.base_dn,
                search_filter="(objectClass=domain)",
                search_scope=SUBTREE,
                attributes=['objectSid']
            )

            if self.connection.entries:
                sid_bytes = self.connection.entries[0].objectSid.raw_values[0]
                return self.sid_converter.bytes_to_string(sid_bytes)

            # Fallback: get domain SID from any domain user
            self.connection.search(
                search_base=self.base_dn,
                search_filter="(&(objectCategory=person)(objectClass=user))",
                search_scope=SUBTREE,
                attributes=['objectSid'],
                size_limit=1
            )

            if self.connection.entries:
                user_sid = self.sid_converter.bytes_to_string(
                    self.connection.entries[0].objectSid.raw_values[0]
                )
                return self.sid_converter.extract_domain_sid(user_sid)

            return None

        except LDAPException as e:
            logging.error(f"Error getting domain SID: {e}")
            return None

    def get_name_by_sid(self, sid_string: str) -> Optional[str]:
        """Resolve a SID string to a sAMAccountName via LDAP."""
        try:
            sid_bytes = self.sid_converter.string_to_bytes(sid_string)
            escaped = ''.join(f'\\{b:02x}' for b in sid_bytes)
            search_filter = f"(objectSid={escaped})"

            self.connection.search(
                search_base=self.base_dn,
                search_filter=search_filter,
                search_scope=SUBTREE,
                attributes=['sAMAccountName'],
                size_limit=1
            )

            if self.connection.entries:
                return str(self.connection.entries[0].sAMAccountName)

            return None

        except Exception as e:
            logging.debug(f"SID lookup failed for {sid_string}: {e}")
            return None

    def enumerate_trusts(self) -> List[Dict[str, Any]]:
        """Enumerate domain trusts via LDAP."""
        trusts = []
        try:
            self.connection.search(
                search_base=f"CN=System,{self.base_dn}",
                search_filter="(objectClass=trustedDomain)",
                search_scope=SUBTREE,
                attributes=['trustPartner', 'trustDirection', 'trustType',
                           'trustAttributes', 'flatName', 'securityIdentifier']
            )

            for entry in self.connection.entries:
                trust = {
                    'partner': str(entry.trustPartner) if entry.trustPartner else '',
                    'flatName': str(entry.flatName) if entry.flatName else '',
                    'direction': self._parse_trust_direction(entry),
                    'type': self._parse_trust_type(entry),
                    'attributes': self._parse_trust_attributes(entry),
                }

                # Trust SID
                try:
                    sid_bytes = entry.securityIdentifier.raw_values[0]
                    trust['sid'] = self.sid_converter.bytes_to_string(sid_bytes)
                except Exception:
                    trust['sid'] = 'Unknown'

                # SID filtering status
                attrs = int(str(entry.trustAttributes)) if entry.trustAttributes else 0
                trust['sidFilteringEnabled'] = not bool(attrs & 0x00000040)  # TRUST_ATTRIBUTE_TREAT_AS_EXTERNAL
                trust['sidHistoryEnabled'] = bool(attrs & 0x00000040)

                trusts.append(trust)

        except LDAPException as e:
            logging.error(f"Error enumerating trusts: {e}")

        return trusts

    def search_by_sid(self, sid: str) -> Optional[str]:
        """Search for an object by SID, return sAMAccountName."""
        try:
            sid_bytes = self.sid_converter.string_to_bytes(sid)
            if not sid_bytes:
                return None

            sid_hex = ''.join([f'\\{b:02x}' for b in sid_bytes])
            search_filter = f"(objectSid={sid_hex})"

            self.connection.search(
                search_base=self.base_dn,
                search_filter=search_filter,
                search_scope=SUBTREE,
                attributes=['sAMAccountName', 'objectClass']
            )

            if not self.connection.entries:
                return None

            return str(self.connection.entries[0].sAMAccountName)

        except LDAPException as e:
            logging.error(f"Error searching by SID: {e}")
            return None

    def check_sid_history_acl(self, sam_account_name: str) -> Optional[Dict]:
        """
        Check the security descriptor on an object to see who can write sIDHistory.
        Returns basic ACL info (requires nTSecurityDescriptor read access).
        """
        try:
            safe_name = escape_filter_chars(sam_account_name)
            search_filter = f"(sAMAccountName={safe_name})"

            # Request SD with LDAP_SERVER_SD_FLAGS_OID control
            # 0x04 = DACL_SECURITY_INFORMATION
            from ldap3 import SEQUENCE_TYPES
            self.connection.search(
                search_base=self.base_dn,
                search_filter=search_filter,
                search_scope=SUBTREE,
                attributes=['nTSecurityDescriptor', 'distinguishedName'],
                controls=[('1.2.840.113556.1.4.801', True, b'\x30\x03\x02\x01\x04')]
            )

            if not self.connection.entries:
                return None

            return {
                'dn': str(self.connection.entries[0].distinguishedName),
                'hasSD': bool(self.connection.entries[0].nTSecurityDescriptor),
                'note': 'Full ACL parsing requires additional tooling (e.g., BloodHound, dacledit)'
            }

        except Exception as e:
            logging.debug(f"ACL check failed (may need elevated privileges): {e}")
            return None

    # ─── HELPER METHODS ──────────────────────────────────────────────────

    def _parse_entry(self, entry) -> Optional[Dict[str, Any]]:
        """Parse an LDAP entry into a dict."""
        try:
            obj = {
                'dn': str(entry.distinguishedName),
                'sam': str(entry.sAMAccountName),
                'objectClass': list(entry.objectClass.values) if entry.objectClass else [],
            }

            try:
                sid_bytes = entry.objectSid.raw_values[0]
                obj['sid'] = self.sid_converter.bytes_to_string(sid_bytes)
            except Exception:
                obj['sid'] = None

            obj['sidHistory'] = self._extract_sid_history(entry)

            try:
                obj['description'] = str(entry.description) if entry.description else ''
            except Exception:
                obj['description'] = ''

            return obj
        except Exception as e:
            logging.debug(f"Error parsing entry: {e}")
            return None

    @staticmethod
    def _parse_trust_direction(entry) -> str:
        """Parse trust direction flags."""
        try:
            direction = int(str(entry.trustDirection))
            mapping = {0: "Disabled", 1: "Inbound", 2: "Outbound", 3: "Bidirectional"}
            return mapping.get(direction, f"Unknown ({direction})")
        except Exception:
            return "Unknown"

    @staticmethod
    def _parse_trust_type(entry) -> str:
        """Parse trust type flags."""
        try:
            trust_type = int(str(entry.trustType))
            mapping = {1: "Windows NT", 2: "Active Directory", 3: "MIT Kerberos"}
            return mapping.get(trust_type, f"Unknown ({trust_type})")
        except Exception:
            return "Unknown"

    @staticmethod
    def _parse_trust_attributes(entry) -> List[str]:
        """Parse trust attribute flags into readable list."""
        try:
            attrs = int(str(entry.trustAttributes))
        except Exception:
            return []

        flags = []
        attr_map = {
            0x00000001: "NON_TRANSITIVE",
            0x00000002: "UPLEVEL_ONLY",
            0x00000004: "QUARANTINED_DOMAIN",
            0x00000008: "FOREST_TRANSITIVE",
            0x00000010: "CROSS_ORGANIZATION",
            0x00000020: "WITHIN_FOREST",
            0x00000040: "TREAT_AS_EXTERNAL",
            0x00000080: "USES_RC4_ENCRYPTION",
            0x00000200: "CROSS_ORGANIZATION_NO_TGT_DELEGATION",
            0x00000400: "PIM_TRUST",
        }

        for flag_val, flag_name in attr_map.items():
            if attrs & flag_val:
                flags.append(flag_name)

        return flags

