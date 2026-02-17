"""
Authentication Manager
Dual-backend authentication supporting ldap3 and impacket.

Supports:
- NTLM with password (ldap3)
- Pass-the-Hash via impacket LDAP
- Kerberos (ldap3 SASL or impacket)
- Pass-the-Certificate (LDAPS with client cert)
- SIMPLE bind (ldap3)
"""

import logging
import os
from typing import Optional

from ldap3 import Server, Connection, ALL, NTLM, SIMPLE, SASL, KERBEROS, Tls
import ssl


class AuthenticationManager:
    """
    Manages different authentication methods for LDAP connections.
    Provides both ldap3 Connection and impacket LDAPConnection backends.
    """

    AUTH_NTLM = 'ntlm'
    AUTH_NTLM_HASH = 'ntlm-hash'
    AUTH_KERBEROS = 'kerberos'
    AUTH_SIMPLE = 'simple'
    AUTH_CERTIFICATE = 'certificate'

    def __init__(self, dc_ip: str, domain: str, dc_hostname: Optional[str] = None):
        self.dc_ip = dc_ip
        self.domain = domain
        self.dc_hostname = dc_hostname or dc_ip
        # Store credentials for DRSUAPI reuse
        self._username = None
        self._password = None
        self._lm_hash = ''
        self._nt_hash = ''
        self._do_kerberos = False
        self._aes_key = ''

    @property
    def credentials(self):
        """Return stored credentials tuple for impacket reuse."""
        return (self._username, self._password, self.domain,
                self._lm_hash, self._nt_hash, self._aes_key, self._do_kerberos)

    def create_server(self, use_ssl: bool = False, port: Optional[int] = None,
                     cert_file: Optional[str] = None, key_file: Optional[str] = None) -> Server:
        """Create ldap3 Server object."""
        if port is None:
            port = 636 if use_ssl else 389

        tls_config = None
        if use_ssl:
            tls_config = Tls(
                validate=ssl.CERT_NONE,
                version=ssl.PROTOCOL_TLSv1_2,
                local_certificate_file=cert_file,
                local_private_key_file=key_file
            )

        return Server(
            self.dc_hostname,
            port=port,
            get_info=ALL,
            use_ssl=use_ssl,
            tls=tls_config
        )

    def connect_ntlm(self, username: str, password: str,
                    use_ssl: bool = False, retries: int = 3) -> Optional[Connection]:
        """Connect using NTLM authentication with password."""
        import time
        user_dn = f"{self.domain}\\{username}"

        for attempt in range(retries):
            try:
                server = self.create_server(use_ssl=use_ssl)
                connection = Connection(
                    server,
                    user=user_dn,
                    password=password,
                    authentication=NTLM,
                    auto_bind=True
                )

                self._username = username
                self._password = password
                logging.info(f"Successfully authenticated via NTLM as {username}")
                return connection

            except Exception as e:
                if attempt < retries - 1:
                    logging.debug(f"NTLM auth attempt {attempt+1} failed: {e}, retrying...")
                    time.sleep(2)
                else:
                    logging.error(f"NTLM authentication failed: {e}")
                    return None

    def connect_ntlm_hash(self, username: str, nt_hash: str,
                         use_ssl: bool = False) -> Optional[Connection]:
        """
        Connect using Pass-the-Hash.
        Uses impacket's LDAP client for proper NTLM hash authentication,
        then establishes an ldap3 connection for operations.
        """
        if ':' in nt_hash:
            lm_hash, nt_part = nt_hash.split(':', 1)
        else:
            lm_hash = 'aad3b435b51404eeaad3b435b51404ee'
            nt_part = nt_hash

        self._username = username
        self._lm_hash = lm_hash
        self._nt_hash = nt_part

        # Try impacket first for proper PTH
        conn = self._pth_via_impacket(username, lm_hash, nt_part, use_ssl)
        if conn:
            return conn

        # Fallback: some ldap3 versions accept hash as password
        logging.warning("impacket PTH unavailable, trying ldap3 fallback")
        return self._pth_fallback_ldap3(username, lm_hash, nt_part, use_ssl)

    def _pth_via_impacket(self, username: str, lm_hash: str, nt_hash: str,
                          use_ssl: bool) -> Optional[Connection]:
        """Pass-the-Hash using impacket's native LDAP client."""
        try:
            from impacket.ldap import ldap as imp_ldap

            port = 636 if use_ssl else 389
            scheme = 'ldaps' if use_ssl else 'ldap'
            base_dn = ','.join([f'DC={p}' for p in self.domain.split('.')])
            url = f"{scheme}://{self.dc_hostname}:{port}"

            imp_conn = imp_ldap.LDAPConnection(url, base_dn)
            imp_conn.login(username, '', self.domain, lm_hash, nt_hash)
            logging.info(f"impacket PTH succeeded as {username}")

            # Now create ldap3 connection using the authenticated credentials
            # ldap3 should work with the hash as password for subsequent ops
            server = self.create_server(use_ssl=use_ssl)
            user_dn = f"{self.domain}\\{username}"
            password = f"{lm_hash}:{nt_hash}"

            connection = Connection(
                server,
                user=user_dn,
                password=password,
                authentication=NTLM,
                auto_bind=True
            )

            logging.info(f"Successfully authenticated via Pass-the-Hash as {username}")
            return connection

        except ImportError:
            logging.debug("impacket not available for PTH")
            return None
        except Exception as e:
            logging.debug(f"impacket PTH failed: {e}")
            return None

    def _pth_fallback_ldap3(self, username: str, lm_hash: str, nt_hash: str,
                            use_ssl: bool) -> Optional[Connection]:
        """Fallback PTH using ldap3 with hash as password."""
        try:
            server = self.create_server(use_ssl=use_ssl)
            user_dn = f"{self.domain}\\{username}"
            password = f"{lm_hash}:{nt_hash}"

            connection = Connection(
                server,
                user=user_dn,
                password=password,
                authentication=NTLM,
                auto_bind=True
            )

            logging.info(f"Successfully authenticated via PTH (ldap3 fallback) as {username}")
            return connection

        except Exception as e:
            logging.error(f"PTH authentication failed: {e}")
            return None

    def connect_kerberos(self, use_ssl: bool = False,
                        ccache_path: Optional[str] = None) -> Optional[Connection]:
        """Connect using Kerberos authentication."""
        try:
            if ccache_path:
                os.environ['KRB5CCNAME'] = ccache_path
                logging.debug(f"Using Kerberos ccache: {ccache_path}")

            self._do_kerberos = True
            server = self.create_server(use_ssl=use_ssl)

            connection = Connection(
                server,
                authentication=SASL,
                sasl_mechanism=KERBEROS,
                auto_bind=True
            )

            logging.info("Successfully authenticated via Kerberos")
            return connection

        except Exception as e:
            logging.error(f"Kerberos authentication failed: {e}")
            logging.debug("Ensure you have a valid Kerberos ticket (kinit)")
            return None

    def connect_certificate(self, cert_file: str, key_file: str,
                           username: Optional[str] = None) -> Optional[Connection]:
        """Connect using client certificate (Pass-the-Certificate via LDAPS)."""
        try:
            server = self.create_server(
                use_ssl=True,
                cert_file=cert_file,
                key_file=key_file
            )

            if username:
                self._username = username
                user_dn = f"{username}@{self.domain}"
                connection = Connection(
                    server,
                    user=user_dn,
                    authentication=SIMPLE,
                    auto_bind=True
                )
            else:
                # SASL EXTERNAL - server identifies client from TLS cert
                connection = Connection(
                    server,
                    authentication=SASL,
                    sasl_mechanism='EXTERNAL',
                    auto_bind=True
                )

            logging.info("Successfully authenticated via client certificate")
            return connection

        except Exception as e:
            logging.error(f"Certificate authentication failed: {e}")
            return None

    def connect_simple(self, username: str, password: str,
                      use_ssl: bool = True) -> Optional[Connection]:
        """Connect using SIMPLE bind."""
        try:
            if not use_ssl:
                logging.warning("SIMPLE auth without SSL sends credentials in clear text!")

            server = self.create_server(use_ssl=use_ssl)

            if username.lower().startswith(('cn=', 'uid=')):
                user_dn = username
            else:
                user_dn = f"{username}@{self.domain}"

            self._username = username
            self._password = password

            connection = Connection(
                server,
                user=user_dn,
                password=password,
                authentication=SIMPLE,
                auto_bind=True
            )

            logging.info(f"Successfully authenticated via SIMPLE as {username}")
            return connection

        except Exception as e:
            logging.error(f"SIMPLE authentication failed: {e}")
            return None

    def get_connection(self, auth_method: str, username: Optional[str] = None,
                      password: Optional[str] = None, nt_hash: Optional[str] = None,
                      use_ssl: bool = False, ccache_path: Optional[str] = None,
                      cert_file: Optional[str] = None, key_file: Optional[str] = None) -> Optional[Connection]:
        """Get connection using specified authentication method."""
        if auth_method == self.AUTH_NTLM:
            return self.connect_ntlm(username, password, use_ssl)
        elif auth_method == self.AUTH_NTLM_HASH:
            return self.connect_ntlm_hash(username, nt_hash, use_ssl)
        elif auth_method == self.AUTH_KERBEROS:
            return self.connect_kerberos(use_ssl, ccache_path)
        elif auth_method == self.AUTH_CERTIFICATE:
            return self.connect_certificate(cert_file, key_file, username)
        elif auth_method == self.AUTH_SIMPLE:
            return self.connect_simple(username, password, use_ssl)
        else:
            logging.error(f"Unknown authentication method: {auth_method}")
            return None
