"""
Output Formatting Module

Supports:
- Colored console output with risk-level indicators
- JSON export for programmatic consumption
- CSV export for spreadsheet analysis
- SID enrichment (resolve to names)
"""

import json
import csv
import io
import logging
from typing import Optional, List, Dict, Any
from dataclasses import asdict

from .sid_utils import SIDConverter
from .scanner import AuditReport, SIDHistoryFinding


# ANSI color codes
class Colors:
    RESET = '\033[0m'
    BOLD = '\033[1m'
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    GRAY = '\033[90m'

    @classmethod
    def disable(cls):
        """Disable colors (for non-terminal output)."""
        cls.RESET = cls.BOLD = cls.RED = cls.GREEN = ''
        cls.YELLOW = cls.BLUE = cls.MAGENTA = cls.CYAN = ''
        cls.WHITE = cls.GRAY = ''


RISK_COLORS = {
    'critical': Colors.RED,
    'high': Colors.MAGENTA,
    'medium': Colors.YELLOW,
    'low': Colors.CYAN,
    'info': Colors.GRAY,
}

RISK_LABELS = {
    'critical': 'CRITICAL',
    'high': 'HIGH',
    'medium': 'MEDIUM',
    'low': 'LOW',
    'info': 'INFO',
}


class OutputFormatter:
    """Handles output formatting for the tool."""

    def __init__(self, format_type: str = 'console', no_color: bool = False,
                 domain_sid: Optional[str] = None):
        """
        Args:
            format_type: 'console', 'json', or 'csv'
            no_color: Disable ANSI colors
            domain_sid: Domain SID for name resolution
        """
        self.format_type = format_type
        self.domain_sid = domain_sid
        self.sid_converter = SIDConverter()

        if no_color or format_type != 'console':
            Colors.disable()

    # ─── AUDIT REPORT ─────────────────────────────────────────────────

    def format_audit_report(self, report: AuditReport) -> str:
        """Format a full audit report."""
        if self.format_type == 'json':
            return self._report_to_json(report)
        elif self.format_type == 'csv':
            return self._report_to_csv(report)
        else:
            return self._report_to_console(report)

    def _report_to_console(self, report: AuditReport) -> str:
        """Format audit report for console output."""
        lines = []

        # Header
        lines.append(f"\n{Colors.BOLD}{'=' * 70}{Colors.RESET}")
        lines.append(f"{Colors.BOLD}  SID History Audit Report - {report.domain}{Colors.RESET}")
        lines.append(f"{Colors.BOLD}{'=' * 70}{Colors.RESET}")
        lines.append(f"  Domain SID: {report.domain_sid}")
        lines.append(f"  Objects with sIDHistory: {report.objects_with_sid_history}")
        lines.append("")

        # Summary
        summary = report.summary
        lines.append(f"{Colors.BOLD}  Risk Summary:{Colors.RESET}")
        for level in ['critical', 'high', 'medium', 'low', 'info']:
            count = summary.get(level, 0)
            if count > 0:
                color = RISK_COLORS.get(level, '')
                lines.append(f"    {color}{RISK_LABELS[level]:10s}{Colors.RESET}: {count}")

        lines.append(f"\n  Total sIDHistory entries : {summary.get('total_sid_history_entries', 0)}")
        lines.append(f"  Same-domain SIDs        : {summary.get('same_domain_sids', 0)}")
        lines.append(f"  Privileged SIDs         : {summary.get('privileged_sids', 0)}")
        lines.append(f"  Cross-domain SIDs       : {summary.get('cross_domain_sids', 0)}")
        lines.append(f"{'─' * 70}")

        # Findings (sorted by risk, critical first)
        sorted_findings = sorted(report.findings,
                                key=lambda f: -self._risk_to_int(f.risk_level))

        for finding in sorted_findings:
            lines.append(self._format_finding(finding))

        # Trusts
        if report.trusts:
            lines.append(f"\n{Colors.BOLD}  Domain Trusts:{Colors.RESET}")
            lines.append(f"{'─' * 70}")
            for trust in report.trusts:
                lines.append(self._format_trust(trust))

        lines.append(f"\n{Colors.BOLD}{'=' * 70}{Colors.RESET}")
        lines.append(f"  MITRE ATT&CK: T1134.005 - SID-History Injection")
        lines.append(f"  Detection: Monitor Event IDs 4765, 4766, 4738")
        lines.append(f"{Colors.BOLD}{'=' * 70}{Colors.RESET}\n")

        return '\n'.join(lines)

    def _format_finding(self, finding: SIDHistoryFinding) -> str:
        """Format a single finding for console."""
        color = RISK_COLORS.get(finding.risk_level, '')
        label = RISK_LABELS.get(finding.risk_level, '')

        lines = []
        lines.append(f"\n  {color}[{label}]{Colors.RESET} {Colors.BOLD}{finding.sam}{Colors.RESET} "
                     f"({finding.object_type})")
        lines.append(f"    DN  : {finding.dn}")
        lines.append(f"    SID : {finding.sid}")

        for hist_sid in finding.sid_history:
            name = self.sid_converter.resolve_sid_name(hist_sid, self.domain_sid)
            if self.sid_converter.is_privileged_sid(hist_sid):
                lines.append(f"    {Colors.RED}sIDHistory: {hist_sid} ({name}){Colors.RESET}")
            else:
                lines.append(f"    sIDHistory: {hist_sid} ({name})")

        for issue in finding.findings:
            lines.append(f"    {color}> {issue}{Colors.RESET}")

        return '\n'.join(lines)

    def _format_trust(self, trust: Dict) -> str:
        """Format a trust for console output."""
        sid_hist_status = (f"{Colors.RED}SIDHistory ENABLED{Colors.RESET}"
                          if trust.get('sidHistoryEnabled')
                          else f"{Colors.GREEN}SIDHistory filtered{Colors.RESET}")

        return (f"  {trust['partner']} ({trust['flatName']})\n"
                f"    Direction : {trust['direction']}\n"
                f"    Type      : {trust['type']}\n"
                f"    SID       : {trust.get('sid', 'N/A')}\n"
                f"    Filtering : {sid_hist_status}\n"
                f"    Attributes: {', '.join(trust.get('attributes', [])) or 'None'}")

    def _report_to_json(self, report: AuditReport) -> str:
        """Format audit report as JSON."""
        data = {
            'domain': report.domain,
            'domainSid': report.domain_sid,
            'objectsWithSidHistory': report.objects_with_sid_history,
            'summary': report.summary,
            'findings': [],
            'trusts': report.trusts,
            'mitre': 'T1134.005',
            'detectionEventIds': [4765, 4766, 4738],
        }

        for finding in report.findings:
            f = {
                'sam': finding.sam,
                'dn': finding.dn,
                'objectType': finding.object_type,
                'sid': finding.sid,
                'riskLevel': finding.risk_level,
                'sidHistory': [],
                'issues': finding.findings,
            }

            for hist_sid in finding.sid_history:
                name = self.sid_converter.resolve_sid_name(hist_sid, self.domain_sid)
                f['sidHistory'].append({
                    'sid': hist_sid,
                    'name': name,
                    'isPrivileged': self.sid_converter.is_privileged_sid(hist_sid),
                    'isSameDomain': (self.domain_sid and
                                    self.sid_converter.is_same_domain_sid(hist_sid, self.domain_sid)),
                })

            data['findings'].append(f)

        return json.dumps(data, indent=2)

    def _report_to_csv(self, report: AuditReport) -> str:
        """Format audit report as CSV."""
        output = io.StringIO()
        writer = csv.writer(output)

        writer.writerow([
            'sAMAccountName', 'DN', 'ObjectType', 'ObjectSID',
            'RiskLevel', 'SIDHistory_SID', 'SIDHistory_Name',
            'IsPrivileged', 'IsSameDomain', 'Issues'
        ])

        for finding in report.findings:
            for hist_sid in finding.sid_history:
                name = self.sid_converter.resolve_sid_name(hist_sid, self.domain_sid)
                is_priv = self.sid_converter.is_privileged_sid(hist_sid)
                is_same = (self.domain_sid and
                          self.sid_converter.is_same_domain_sid(hist_sid, self.domain_sid))

                writer.writerow([
                    finding.sam, finding.dn, finding.object_type, finding.sid,
                    finding.risk_level, hist_sid, name,
                    is_priv, is_same, '; '.join(finding.findings)
                ])

        return output.getvalue()

    # ─── SINGLE OBJECT DISPLAY ────────────────────────────────────────

    def format_sid_history(self, sam: str, sid_history: List[str],
                           object_sid: Optional[str] = None) -> str:
        """Format sIDHistory for a single object."""
        if self.format_type == 'json':
            data = {
                'sam': sam,
                'sid': object_sid,
                'sidHistory': [
                    {
                        'sid': s,
                        'name': self.sid_converter.resolve_sid_name(s, self.domain_sid),
                        'isPrivileged': self.sid_converter.is_privileged_sid(s),
                    }
                    for s in sid_history
                ]
            }
            return json.dumps(data, indent=2)

        lines = []
        if sid_history:
            lines.append(f"\nSID History for {Colors.BOLD}{sam}{Colors.RESET}:")
            if object_sid:
                lines.append(f"  Object SID: {object_sid}")
            for s in sid_history:
                name = self.sid_converter.resolve_sid_name(s, self.domain_sid)
                if self.sid_converter.is_privileged_sid(s):
                    lines.append(f"  {Colors.RED}{s} ({name}){Colors.RESET}")
                else:
                    lines.append(f"  {s} ({name})")
        else:
            lines.append(f"\nNo SID History found for {sam}")

        return '\n'.join(lines)

    def format_sid_lookup(self, sam: str, sid: str) -> str:
        """Format SID lookup result."""
        if self.format_type == 'json':
            return json.dumps({'sam': sam, 'sid': sid}, indent=2)

        name = self.sid_converter.resolve_sid_name(sid, self.domain_sid)
        priv = f" {Colors.RED}[PRIVILEGED]{Colors.RESET}" if self.sid_converter.is_privileged_sid(sid) else ""
        return f"\nSID for {Colors.BOLD}{sam}{Colors.RESET}: {sid} ({name}){priv}"

    def format_trusts(self, trusts: List[Dict]) -> str:
        """Format trust enumeration results."""
        if self.format_type == 'json':
            return json.dumps({'trusts': trusts}, indent=2)

        if not trusts:
            return "\nNo domain trusts found."

        lines = [f"\n{Colors.BOLD}Domain Trusts:{Colors.RESET}", f"{'─' * 60}"]
        for trust in trusts:
            lines.append(self._format_trust(trust))
        return '\n'.join(lines)

    def format_presets(self, domain_sid: str) -> str:
        """Format available preset SIDs."""
        from .sid_utils import PRIVILEGED_PRESETS

        if self.format_type == 'json':
            presets = {}
            for name, rid in PRIVILEGED_PRESETS.items():
                if name == 'administrators':
                    sid = f"S-1-5-32-{rid}"
                else:
                    sid = f"{domain_sid}-{rid}"
                presets[name] = sid
            return json.dumps({'domainSid': domain_sid, 'presets': presets}, indent=2)

        lines = [f"\n{Colors.BOLD}Available Presets (Domain SID: {domain_sid}):{Colors.RESET}"]
        for name, rid in sorted(PRIVILEGED_PRESETS.items()):
            if name == 'administrators':
                sid = f"S-1-5-32-{rid}"
            else:
                sid = f"{domain_sid}-{rid}"
            lines.append(f"  {Colors.CYAN}{name:25s}{Colors.RESET} -> {sid}")
        return '\n'.join(lines)

    @staticmethod
    def _risk_to_int(level: str) -> int:
        return {'info': 0, 'low': 1, 'medium': 2, 'high': 3, 'critical': 4}.get(level, 0)
