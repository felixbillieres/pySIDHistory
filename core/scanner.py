"""
Domain Scanner & Blue Team Auditing Module

Provides:
- Domain-wide sIDHistory enumeration
- Same-domain SID detection (attack indicator)
- Privileged SID detection in sIDHistory
- Risk assessment and scoring
- Trust enumeration with SID filtering status
"""

import logging
from typing import Optional, List, Dict, Any
from dataclasses import dataclass, field

from .ldap_operations import LDAPOperations
from .sid_utils import SIDConverter, WELL_KNOWN_RIDS, HIGH_RISK_RIDS


@dataclass
class SIDHistoryFinding:
    """Represents a single sIDHistory finding for an object."""
    sam: str
    dn: str
    object_type: str
    sid: str
    sid_history: List[str] = field(default_factory=list)
    risk_level: str = 'info'  # info, low, medium, high, critical
    findings: List[str] = field(default_factory=list)
    description: str = ''


@dataclass
class AuditReport:
    """Complete audit report."""
    domain: str
    domain_sid: str
    total_objects_scanned: int = 0
    objects_with_sid_history: int = 0
    findings: List[SIDHistoryFinding] = field(default_factory=list)
    trusts: List[Dict[str, Any]] = field(default_factory=list)
    summary: Dict[str, int] = field(default_factory=dict)


class DomainScanner:
    """
    Scans Active Directory for sIDHistory-related security issues.
    Designed for blue team auditing and vulnerability assessment.
    """

    def __init__(self, ldap_ops: LDAPOperations, domain: str):
        self.ldap_ops = ldap_ops
        self.domain = domain
        self.domain_sid = None
        self.sid_converter = SIDConverter()

    def full_audit(self) -> AuditReport:
        """
        Perform a complete sIDHistory audit of the domain.

        Returns:
            AuditReport with all findings
        """
        logging.info("Starting full domain sIDHistory audit...")

        # Get domain SID
        self.domain_sid = self.ldap_ops.get_domain_sid()
        if not self.domain_sid:
            logging.warning("Could not determine domain SID - some checks will be limited")

        report = AuditReport(
            domain=self.domain,
            domain_sid=self.domain_sid or 'Unknown'
        )

        # Scan for all objects with sIDHistory
        logging.info("Scanning for objects with sIDHistory...")
        objects = self.ldap_ops.find_all_with_sid_history()
        report.total_objects_scanned = len(objects)

        for obj in objects:
            finding = self._analyze_object(obj)
            if finding:
                report.findings.append(finding)
                report.objects_with_sid_history += 1

        # Enumerate trusts
        logging.info("Enumerating domain trusts...")
        report.trusts = self.ldap_ops.enumerate_trusts()

        # Build summary
        report.summary = self._build_summary(report)

        logging.info(f"Audit complete: {report.objects_with_sid_history} objects "
                    f"with sIDHistory found")
        return report

    def scan_user(self, sam_account_name: str) -> Optional[SIDHistoryFinding]:
        """Scan a single user/object for sIDHistory issues."""
        if not self.domain_sid:
            self.domain_sid = self.ldap_ops.get_domain_sid()

        info = self.ldap_ops.get_object_info(sam_account_name)
        if not info:
            logging.error(f"Object '{sam_account_name}' not found")
            return None

        obj = {
            'sam': info['sam'],
            'dn': info['dn'],
            'sid': info.get('sid'),
            'sidHistory': info.get('sidHistory', []),
            'objectClass': info.get('objectClass', []),
            'description': info.get('description', ''),
        }

        return self._analyze_object(obj)

    def _analyze_object(self, obj: Dict[str, Any]) -> Optional[SIDHistoryFinding]:
        """Analyze a single object for sIDHistory security issues."""
        sid_history = obj.get('sidHistory', [])
        if not sid_history:
            return None

        # Determine object type
        obj_classes = obj.get('objectClass', [])
        if 'computer' in obj_classes:
            obj_type = 'computer'
        elif 'group' in obj_classes:
            obj_type = 'group'
        else:
            obj_type = 'user'

        finding = SIDHistoryFinding(
            sam=obj.get('sam', ''),
            dn=obj.get('dn', ''),
            object_type=obj_type,
            sid=obj.get('sid', ''),
            sid_history=sid_history,
            description=obj.get('description', ''),
        )

        # Analyze each SID in history
        max_risk = 'info'

        for hist_sid in sid_history:
            risk, issues = self._assess_sid_risk(hist_sid, finding.sid)
            finding.findings.extend(issues)

            if self._risk_level(risk) > self._risk_level(max_risk):
                max_risk = risk

        finding.risk_level = max_risk
        return finding

    def _assess_sid_risk(self, hist_sid: str, object_sid: str) -> tuple:
        """
        Assess the risk level of a single SID in sIDHistory.

        Returns:
            Tuple of (risk_level, list_of_issues)
        """
        issues = []
        risk = 'info'

        # Resolve the SID name
        sid_name = self.sid_converter.resolve_sid_name(hist_sid, self.domain_sid)
        rid = self.sid_converter.extract_rid(hist_sid)
        sid_domain = self.sid_converter.extract_domain_sid(hist_sid)

        # Check 1: Same-domain SID (strongest attack indicator)
        if self.domain_sid and self.sid_converter.is_same_domain_sid(hist_sid, self.domain_sid):
            issues.append(f"SAME-DOMAIN SID: {hist_sid} ({sid_name}) - "
                        f"This is likely an attack, not a legitimate migration")
            risk = 'critical'

        # Check 2: Privileged SID
        if self.sid_converter.is_privileged_sid(hist_sid):
            if rid in HIGH_RISK_RIDS:
                rid_name = WELL_KNOWN_RIDS.get(rid, str(rid))
                issues.append(f"PRIVILEGED SID: {hist_sid} ({rid_name}) - "
                            f"Grants {rid_name} privileges")
                if self._risk_level(risk) < self._risk_level('critical'):
                    risk = 'critical'

        # Check 3: Well-known builtin SIDs
        if hist_sid.startswith("S-1-5-32-"):
            builtin_name = sid_name
            issues.append(f"BUILTIN SID: {hist_sid} ({builtin_name})")
            if self._risk_level(risk) < self._risk_level('high'):
                risk = 'high'

        # Check 4: Enterprise Admins / Schema Admins (cross-domain escalation)
        if rid in (519, 518):
            issues.append(f"CROSS-DOMAIN ESCALATION: {hist_sid} ({sid_name}) - "
                        f"Forest-wide admin privileges")
            risk = 'critical'

        # Check 5: Low-RID from foreign domain (potentially SID-filtered)
        if (self.domain_sid and sid_domain and
            sid_domain != self.domain_sid and rid is not None and rid < 1000):
            issues.append(f"LOW-RID FOREIGN SID: {hist_sid} (RID {rid}) - "
                        f"Would be blocked by SID filtering")
            if self._risk_level(risk) < self._risk_level('medium'):
                risk = 'medium'

        # If no specific issues, mark as informational
        if not issues:
            issues.append(f"sIDHistory entry: {hist_sid} ({sid_name})")
            risk = 'low'

        return risk, issues

    def _build_summary(self, report: AuditReport) -> Dict[str, int]:
        """Build a summary of findings by risk level."""
        summary = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'info': 0,
            'total_sid_history_entries': 0,
            'same_domain_sids': 0,
            'privileged_sids': 0,
            'cross_domain_sids': 0,
        }

        for finding in report.findings:
            summary[finding.risk_level] = summary.get(finding.risk_level, 0) + 1
            summary['total_sid_history_entries'] += len(finding.sid_history)

            for hist_sid in finding.sid_history:
                if self.domain_sid and self.sid_converter.is_same_domain_sid(hist_sid, self.domain_sid):
                    summary['same_domain_sids'] += 1
                elif self.sid_converter.is_privileged_sid(hist_sid):
                    summary['privileged_sids'] += 1

                sid_domain = self.sid_converter.extract_domain_sid(hist_sid)
                if sid_domain and self.domain_sid and sid_domain != self.domain_sid:
                    summary['cross_domain_sids'] += 1

        return summary

    @staticmethod
    def _risk_level(level: str) -> int:
        """Convert risk level to numeric for comparison."""
        levels = {'info': 0, 'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
        return levels.get(level, 0)
