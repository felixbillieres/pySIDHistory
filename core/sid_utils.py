"""
SID Conversion Utilities
Handles conversion between binary and string SID representations,
well-known SID constants, presets, and SID analysis.
"""

import struct
import logging
from typing import Optional, Dict, List, Tuple


# Well-known domain-relative RIDs
WELL_KNOWN_RIDS: Dict[int, str] = {
    500: "Administrator",
    501: "Guest",
    502: "krbtgt",
    512: "Domain Admins",
    513: "Domain Users",
    514: "Domain Guests",
    515: "Domain Computers",
    516: "Domain Controllers",
    517: "Cert Publishers",
    518: "Schema Admins",
    519: "Enterprise Admins",
    520: "Group Policy Creator Owners",
    521: "Read-only Domain Controllers",
    522: "Cloneable Domain Controllers",
    525: "Protected Users",
    526: "Key Admins",
    527: "Enterprise Key Admins",
    498: "Enterprise Read-Only Domain Controllers",
    553: "RAS and IAS Servers",
    571: "Allowed RODC Password Replication Group",
    572: "Denied RODC Password Replication Group",
}

# Well-known builtin SIDs (not domain-relative)
WELL_KNOWN_SIDS: Dict[str, str] = {
    "S-1-0-0": "Nobody",
    "S-1-1-0": "Everyone",
    "S-1-2-0": "Local",
    "S-1-3-0": "Creator Owner",
    "S-1-3-1": "Creator Group",
    "S-1-5-1": "Dialup",
    "S-1-5-2": "Network",
    "S-1-5-3": "Batch",
    "S-1-5-4": "Interactive",
    "S-1-5-6": "Service",
    "S-1-5-7": "Anonymous",
    "S-1-5-9": "Enterprise Domain Controllers",
    "S-1-5-10": "Self",
    "S-1-5-11": "Authenticated Users",
    "S-1-5-13": "Terminal Server Users",
    "S-1-5-14": "Remote Interactive Logon",
    "S-1-5-17": "IUSR",
    "S-1-5-18": "Local System",
    "S-1-5-19": "NT Authority\\Local Service",
    "S-1-5-20": "NT Authority\\Network Service",
    "S-1-5-32-544": "BUILTIN\\Administrators",
    "S-1-5-32-545": "BUILTIN\\Users",
    "S-1-5-32-546": "BUILTIN\\Guests",
    "S-1-5-32-547": "BUILTIN\\Power Users",
    "S-1-5-32-548": "BUILTIN\\Account Operators",
    "S-1-5-32-549": "BUILTIN\\Server Operators",
    "S-1-5-32-550": "BUILTIN\\Print Operators",
    "S-1-5-32-551": "BUILTIN\\Backup Operators",
    "S-1-5-32-552": "BUILTIN\\Replicator",
    "S-1-5-32-554": "BUILTIN\\Pre-Windows 2000 Compatible Access",
    "S-1-5-32-555": "BUILTIN\\Remote Desktop Users",
    "S-1-5-32-556": "BUILTIN\\Network Configuration Operators",
    "S-1-5-32-557": "BUILTIN\\Incoming Forest Trust Builders",
    "S-1-5-32-558": "BUILTIN\\Performance Monitor Users",
    "S-1-5-32-559": "BUILTIN\\Performance Log Users",
    "S-1-5-32-560": "BUILTIN\\Windows Authorization Access Group",
    "S-1-5-32-562": "BUILTIN\\Distributed COM Users",
    "S-1-5-32-568": "BUILTIN\\IIS_IUSRS",
    "S-1-5-32-569": "BUILTIN\\Cryptographic Operators",
    "S-1-5-32-573": "BUILTIN\\Event Log Readers",
    "S-1-5-32-574": "BUILTIN\\Certificate Service DCOM Access",
    "S-1-5-32-575": "BUILTIN\\RDS Remote Access Servers",
    "S-1-5-32-576": "BUILTIN\\RDS Endpoint Servers",
    "S-1-5-32-577": "BUILTIN\\RDS Management Servers",
    "S-1-5-32-578": "BUILTIN\\Hyper-V Administrators",
    "S-1-5-32-579": "BUILTIN\\Access Control Assistance Operators",
    "S-1-5-32-580": "BUILTIN\\Remote Management Users",
}

# Presets: SID suffixes (RIDs) that can be appended to a domain SID
PRIVILEGED_PRESETS: Dict[str, int] = {
    "domain-admins": 512,
    "enterprise-admins": 519,
    "schema-admins": 518,
    "administrators": 544,  # BUILTIN - handled specially
    "domain-controllers": 516,
    "krbtgt": 502,
    "administrator": 500,
    "key-admins": 526,
    "enterprise-key-admins": 527,
    "group-policy-creators": 520,
}

# RIDs considered high-risk in sIDHistory
HIGH_RISK_RIDS = {500, 502, 512, 516, 518, 519, 526, 527}


class SIDConverter:
    """
    Utility class for converting between binary and string SID formats.
    """

    @staticmethod
    def bytes_to_string(sid_bytes: bytes) -> str:
        """
        Convert binary SID to string representation.

        Args:
            sid_bytes: Binary SID data

        Returns:
            SID as a string (e.g., 'S-1-5-21-...')
        """
        if len(sid_bytes) < 8:
            raise ValueError(f"SID too short: {len(sid_bytes)} bytes")

        revision = sid_bytes[0]
        sub_authority_count = sid_bytes[1]
        identifier_authority = int.from_bytes(sid_bytes[2:8], byteorder='big')

        sid = f"S-{revision}-{identifier_authority}"

        for i in range(sub_authority_count):
            offset = 8 + (i * 4)
            if offset + 4 > len(sid_bytes):
                break
            sub_authority = struct.unpack('<I', sid_bytes[offset:offset + 4])[0]
            sid += f"-{sub_authority}"

        return sid

    @staticmethod
    def string_to_bytes(sid_string: str) -> Optional[bytes]:
        """
        Convert string SID to binary representation.

        Args:
            sid_string: SID as a string (e.g., 'S-1-5-21-...')

        Returns:
            Binary SID data, or None if conversion fails
        """
        try:
            parts = sid_string.split('-')
            if len(parts) < 3 or parts[0] != 'S':
                logging.error("Invalid SID format: must start with 'S-'")
                return None

            revision = int(parts[1])
            identifier_authority = int(parts[2])
            sub_authorities = [int(x) for x in parts[3:]]

            sid_bytes = struct.pack('B', revision)
            sid_bytes += struct.pack('B', len(sub_authorities))
            sid_bytes += identifier_authority.to_bytes(6, byteorder='big')

            for sub_authority in sub_authorities:
                sid_bytes += struct.pack('<I', sub_authority)

            return sid_bytes

        except (ValueError, IndexError) as e:
            logging.error(f"Error converting SID string to bytes: {e}")
            return None

    @staticmethod
    def is_valid_sid(sid_string: str) -> bool:
        """Check if a string is a valid SID format."""
        try:
            parts = sid_string.split('-')
            if len(parts) < 3 or parts[0] != 'S':
                return False
            int(parts[1])
            int(parts[2])
            for p in parts[3:]:
                int(p)
            return True
        except (ValueError, IndexError):
            return False

    @staticmethod
    def extract_domain_sid(sid_string: str) -> Optional[str]:
        """
        Extract the domain SID from an object SID.
        E.g., 'S-1-5-21-111-222-333-1001' -> 'S-1-5-21-111-222-333'
        """
        parts = sid_string.split('-')
        if len(parts) < 5:
            return None
        # Domain SID is everything except the last RID
        return '-'.join(parts[:-1])

    @staticmethod
    def extract_rid(sid_string: str) -> Optional[int]:
        """Extract the RID (last sub-authority) from a SID."""
        parts = sid_string.split('-')
        if len(parts) < 4:
            return None
        try:
            return int(parts[-1])
        except ValueError:
            return None

    @staticmethod
    def build_sid(domain_sid: str, rid: int) -> str:
        """Build a full SID from a domain SID and RID."""
        return f"{domain_sid}-{rid}"

    @staticmethod
    def resolve_preset(preset_name: str, domain_sid: str) -> Optional[str]:
        """
        Resolve a preset name to a full SID.

        Args:
            preset_name: Preset name (e.g., 'domain-admins', 'enterprise-admins')
            domain_sid: The domain SID to use as base

        Returns:
            Full SID string or None if preset unknown
        """
        preset_lower = preset_name.lower()
        if preset_lower not in PRIVILEGED_PRESETS:
            return None

        rid = PRIVILEGED_PRESETS[preset_lower]

        # BUILTIN SIDs use S-1-5-32-xxx, not domain-relative
        if preset_lower == "administrators":
            return f"S-1-5-32-{rid}"

        return f"{domain_sid}-{rid}"

    @staticmethod
    def get_preset_list() -> List[str]:
        """Return list of available preset names."""
        return sorted(PRIVILEGED_PRESETS.keys())

    @staticmethod
    def resolve_sid_name(sid_string: str, domain_sid: Optional[str] = None) -> str:
        """
        Resolve a SID to a human-readable name using well-known SID tables.

        Args:
            sid_string: The SID to resolve
            domain_sid: Optional domain SID for domain-relative resolution

        Returns:
            Human-readable name or the SID itself if unknown
        """
        # Check builtin well-known SIDs first
        if sid_string in WELL_KNOWN_SIDS:
            return WELL_KNOWN_SIDS[sid_string]

        # Check domain-relative RIDs (resolve even for foreign domains)
        rid = SIDConverter.extract_rid(sid_string)
        if rid is not None and rid in WELL_KNOWN_RIDS:
            return WELL_KNOWN_RIDS[rid]

        return sid_string

    @staticmethod
    def is_privileged_sid(sid_string: str) -> bool:
        """Check if a SID corresponds to a high-risk/privileged group."""
        # Check builtin privileged SIDs
        if sid_string in ("S-1-5-32-544", "S-1-5-32-548", "S-1-5-32-549"):
            return True

        rid = SIDConverter.extract_rid(sid_string)
        if rid is not None and rid in HIGH_RISK_RIDS:
            return True

        return False

    @staticmethod
    def is_same_domain_sid(sid_string: str, domain_sid: str) -> bool:
        """Check if a SID belongs to the specified domain."""
        sid_domain = SIDConverter.extract_domain_sid(sid_string)
        return sid_domain == domain_sid

    @staticmethod
    def domain_to_dn(domain: str) -> str:
        """
        Convert domain name to distinguished name.

        Args:
            domain: Domain name (e.g., 'example.com')

        Returns:
            Distinguished name (e.g., 'DC=example,DC=com')
        """
        return ','.join([f'DC={part}' for part in domain.split('.')])

    @staticmethod
    def dn_to_domain(dn: str) -> str:
        """
        Convert distinguished name to domain name.

        Args:
            dn: Distinguished name (e.g., 'DC=example,DC=com')

        Returns:
            Domain name (e.g., 'example.com')
        """
        parts = []
        for component in dn.split(','):
            component = component.strip()
            if component.upper().startswith('DC='):
                parts.append(component[3:])
        return '.'.join(parts)
