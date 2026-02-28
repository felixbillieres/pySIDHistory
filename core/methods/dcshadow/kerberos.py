"""
Server-side Kerberos authentication for DCShadow DCE/RPC servers.

Handles AP-REQ decryption, AP-REP construction, and GSS-API wrap/unwrap
for both CFX (AES, RFC 4121) and legacy (RC4, RFC 1964) formats.
"""

import logging
import struct
import os
import hashlib
from typing import Dict, Tuple
from datetime import datetime, timezone

try:
    from impacket.krb5 import asn1 as krb5_asn1
    from impacket.krb5.crypto import Key, _enctype_table
    from impacket.ntlm import compute_nthash
    from pyasn1.codec.der import decoder as asn1_decoder
    from pyasn1.codec.der import encoder as asn1_encoder
    HAS_DEPS = True
except ImportError:
    HAS_DEPS = False

# Kerberos key usage numbers
KU_TICKET_DECRYPT = 2
KU_AUTHENTICATOR_DECRYPT = 11
KU_AP_REP_ENCRYPT = 12
KU_INITIATOR_SEAL = 24     # Client wraps for server
KU_ACCEPTOR_SEAL = 22      # Server wraps for client
KU_INITIATOR_SIGN = 25
KU_ACCEPTOR_SIGN = 23


class KerberosUtils:
    """Server-side Kerberos authentication for DCE/RPC."""

    @staticmethod
    def compute_keys(password: str, domain: str, computer_name: str) -> Dict[str, bytes]:
        """
        Compute Kerberos keys from a machine account password.

        Returns dict with 'rc4', 'aes128', 'aes256' keys.
        """
        # RC4 = NT hash
        rc4_key = compute_nthash(password)

        # AES keys use salt: <REALM>host<fqdn_lowercase>
        realm = domain.upper()
        fqdn = f"{computer_name.lower()}.{domain.lower()}"
        salt = f"{realm}host{fqdn}"

        aes256_key = KerberosUtils._string_to_key(18, password, salt)
        aes128_key = KerberosUtils._string_to_key(17, password, salt)

        return {
            'rc4': rc4_key,
            'aes128': aes128_key,
            'aes256': aes256_key,
        }

    @staticmethod
    def _string_to_key(etype: int, password: str, salt: str) -> bytes:
        """Derive Kerberos key from password + salt using string-to-key."""
        enc_cls = _enctype_table[etype]
        key = enc_cls.string_to_key(password, salt, None)
        return key.contents

    @staticmethod
    def decrypt_ap_req(ap_req_bytes: bytes, service_keys: Dict[str, bytes]) -> Tuple[bytes, int, int]:
        """
        Decrypt a Kerberos AP-REQ and extract the session key.

        Args:
            ap_req_bytes: Raw DER-encoded AP-REQ
            service_keys: Dict with 'rc4', 'aes128', 'aes256' keys

        Returns:
            (session_key_bytes, session_key_etype, seq_number)
        """
        ap_req, _ = asn1_decoder.decode(ap_req_bytes, asn1Spec=krb5_asn1.AP_REQ())

        ticket = ap_req['ticket']
        enc_part = ticket['enc-part']
        etype = int(enc_part['etype'])
        cipher = bytes(enc_part['cipher'])

        # Select the right key based on etype
        key_map = {23: 'rc4', 17: 'aes128', 18: 'aes256'}
        key_name = key_map.get(etype)
        if not key_name or key_name not in service_keys:
            raise ValueError(f"No key available for etype {etype}")

        enc_cls = _enctype_table[etype]
        service_key = Key(etype, service_keys[key_name])

        # Decrypt ticket (key usage 2)
        plain_ticket = enc_cls.decrypt(service_key, KU_TICKET_DECRYPT, cipher)

        # Parse EncTicketPart
        enc_ticket_part, _ = asn1_decoder.decode(
            plain_ticket, asn1Spec=krb5_asn1.EncTicketPart()
        )

        ticket_session_key = bytes(enc_ticket_part['key']['keyvalue'])
        ticket_session_etype = int(enc_ticket_part['key']['keytype'])

        # Decrypt authenticator (key usage 11)
        auth_enc = ap_req['authenticator']
        auth_etype = int(auth_enc['etype'])
        auth_cipher = bytes(auth_enc['cipher'])

        auth_enc_cls = _enctype_table[auth_etype]
        session_key_obj = Key(ticket_session_etype, ticket_session_key)

        plain_auth = auth_enc_cls.decrypt(
            session_key_obj, KU_AUTHENTICATOR_DECRYPT, auth_cipher
        )

        # Parse Authenticator to get seq-number and subkey
        authenticator, _ = asn1_decoder.decode(
            plain_auth, asn1Spec=krb5_asn1.Authenticator()
        )
        seq_number = 0
        try:
            seq_number = int(authenticator['seq-number'])
        except Exception:
            pass

        # Extract ctime/cusec from Authenticator (needed for AP-REP)
        ctime = None
        cusec = 0
        try:
            ctime = str(authenticator['ctime'])
            cusec = int(authenticator['cusec'])
        except Exception:
            pass

        # RFC 4121: if the client provides a subkey in the Authenticator,
        # it MUST be used as the session encryption key for GSS operations.
        # The subkey is used for GSS wrap/unwrap, but AP-REP is still
        # encrypted with the ticket session key.
        gss_key_bytes = ticket_session_key
        gss_key_etype = ticket_session_etype
        try:
            subkey = authenticator['subkey']
            if subkey.hasValue() and subkey['keyvalue'].hasValue():
                gss_key_bytes = bytes(subkey['keyvalue'])
                gss_key_etype = int(subkey['keytype'])
                logging.debug(f"Using Authenticator subkey (etype={gss_key_etype})")
        except Exception:
            pass  # No subkey — use ticket session key for everything

        return (ticket_session_key, ticket_session_etype,
                gss_key_bytes, gss_key_etype,
                seq_number, ctime, cusec)

    @staticmethod
    def build_ap_rep(session_key_bytes: bytes, session_key_etype: int,
                     seq_number: int = 0,
                     ctime: str = None, cusec: int = 0) -> bytes:
        """Build AP-REP response.

        The ctime/cusec should be echoed from the client's Authenticator
        to prove the server received and decrypted it.
        """
        # Build EncAPRepPart
        enc_ap_rep = krb5_asn1.EncAPRepPart()
        if ctime:
            enc_ap_rep['ctime'] = ctime
        else:
            now = datetime.now(timezone.utc)
            enc_ap_rep['ctime'] = now.strftime('%Y%m%d%H%M%SZ')
        enc_ap_rep['cusec'] = cusec
        enc_ap_rep['seq-number'] = seq_number

        # Encrypt with session key (key usage 12)
        enc_cls = _enctype_table[session_key_etype]
        session_key_obj = Key(session_key_etype, session_key_bytes)
        encrypted = enc_cls.encrypt(
            session_key_obj, KU_AP_REP_ENCRYPT,
            asn1_encoder.encode(enc_ap_rep), None
        )

        # Build AP-REP
        ap_rep = krb5_asn1.AP_REP()
        ap_rep['pvno'] = 5
        ap_rep['msg-type'] = 15
        ap_rep['enc-part']['etype'] = session_key_etype
        ap_rep['enc-part']['cipher'] = encrypted

        return asn1_encoder.encode(ap_rep)

    @staticmethod
    def gss_unwrap(data: bytes, session_key_bytes: bytes,
                   session_key_etype: int) -> bytes:
        """
        Unwrap (decrypt) a GSS-API wrapped message from the client.

        Handles both CFX (AES, RFC 4121) and legacy (RC4, RFC 1964) formats.
        """
        enc_cls = _enctype_table[session_key_etype]
        key = Key(session_key_etype, session_key_bytes)

        # Check token type
        tok_id = struct.unpack('>H', data[:2])[0]

        if tok_id == 0x0504:
            # CFX format (RFC 4121) - AES
            return KerberosUtils._cfx_unwrap(data, key, enc_cls)
        elif tok_id == 0x0201:
            # Legacy format (RFC 1964) - RC4
            return KerberosUtils._legacy_unwrap(data, key, enc_cls)
        else:
            raise ValueError(f"Unknown GSS wrap token ID: 0x{tok_id:04x}")

    @staticmethod
    def gss_wrap(plaintext: bytes, session_key_bytes: bytes,
                 session_key_etype: int, seq_number: int) -> bytes:
        """
        Wrap (encrypt) a message for sending to the client (server->client).

        Handles both CFX (AES) and legacy (RC4) formats.
        """
        enc_cls = _enctype_table[session_key_etype]
        key = Key(session_key_etype, session_key_bytes)

        if session_key_etype in (17, 18):
            return KerberosUtils._cfx_wrap(plaintext, key, enc_cls, seq_number)
        elif session_key_etype == 23:
            return KerberosUtils._legacy_wrap(plaintext, key, enc_cls, seq_number)
        else:
            raise ValueError(f"Unsupported etype for GSS wrap: {session_key_etype}")

    @staticmethod
    def _cfx_unwrap(data: bytes, key, enc_cls) -> bytes:
        """Unwrap CFX token (RFC 4121) - used with AES."""
        # Header: TOK_ID(2) + Flags(1) + Filler(1) + EC(2) + RRC(2) + SndSeq(8)
        flags = data[2]
        ec = struct.unpack('>H', data[4:6])[0]
        rrc = struct.unpack('>H', data[6:8])[0]

        # Undo rotation
        payload = data[16:]
        if rrc > 0:
            payload = payload[-rrc:] + payload[:-rrc]

        # Decrypt: header(16) is included as associated data
        # For initiator seal, key usage = KU_INITIATOR_SEAL (24)
        header = data[:16]
        # Zero out RRC and SndSeq for checksum verification
        header_for_decrypt = header[:4] + b'\x00\x00' + b'\x00\x00' + b'\x00' * 8

        plaintext_with_ec = enc_cls.decrypt(key, KU_INITIATOR_SEAL, header_for_decrypt + payload)

        # Remove EC bytes (padding + checksum at end)
        if ec > 0:
            return plaintext_with_ec[:-ec]
        return plaintext_with_ec

    @staticmethod
    def _cfx_wrap(plaintext: bytes, key, enc_cls, seq_number: int) -> bytes:
        """Wrap as CFX token (RFC 4121) for server->client."""
        # Build header
        tok_id = b'\x05\x04'
        flags = 0x04 | 0x02  # SentByAcceptor + Sealed
        filler = b'\xff'
        ec = struct.pack('>H', 16)  # EC = checksum length
        rrc = struct.pack('>H', 0)   # RRC = 0 initially
        snd_seq = struct.pack('>Q', seq_number)

        header = tok_id + bytes([flags]) + filler + ec + rrc + snd_seq

        # Encrypt: plaintext + header (with zeroed EC, RRC, SndSeq)
        header_for_encrypt = header[:4] + b'\x00\x00' + b'\x00\x00' + b'\x00' * 8
        encrypted = enc_cls.encrypt(key, KU_ACCEPTOR_SEAL, header_for_encrypt + plaintext, None)

        return header + encrypted

    @staticmethod
    def _legacy_unwrap(data: bytes, key, enc_cls) -> bytes:
        """Unwrap legacy GSS token (RFC 1964) - used with RC4."""
        # Format: TOK_ID(2) + SGN_ALG(2) + SEAL_ALG(2) + Filler(2) +
        #         SND_SEQ(8) + SGN_CKSUM(8) + Confounder(8) + Data(...)
        import hmac
        from Crypto.Cipher import ARC4

        # For RC4-HMAC, the confounder + data are RC4-encrypted
        sgn_cksum = data[16:24]
        encrypted = data[24:]  # confounder(8) + data

        # Derive the sealing key from session key
        seal_key = hmac.new(
            key.contents,
            b"session key to client-to-server sealing key magic constant\x00",
            hashlib.md5
        ).digest()

        # RC4 decrypt
        seq_bytes = data[8:16]
        rc4_key = hmac.new(seal_key, seq_bytes, hashlib.md5).digest()
        cipher = ARC4.new(rc4_key)
        decrypted = cipher.decrypt(encrypted)

        # First 8 bytes are confounder, rest is plaintext
        return decrypted[8:]

    @staticmethod
    def _legacy_wrap(plaintext: bytes, key, enc_cls, seq_number: int) -> bytes:
        """Wrap as legacy GSS token (RFC 1964) for server->client."""
        import hmac
        from Crypto.Cipher import ARC4

        tok_id = b'\x02\x01'
        sgn_alg = b'\x11\x00'  # HMAC-MD5
        seal_alg = b'\x10\x00'  # RC4
        filler = b'\xff\xff'

        # Generate random confounder
        confounder = os.urandom(8)

        # Derive seal key (server to client)
        seal_key = hmac.new(
            key.contents,
            b"session key to server-to-client sealing key magic constant\x00",
            hashlib.md5
        ).digest()

        # Derive sign key
        sign_key = hmac.new(
            key.contents,
            b"session key to server-to-client signing key magic constant\x00",
            hashlib.md5
        ).digest()

        # Compute SGN_CKSUM over header + confounder + plaintext
        header_bytes = tok_id + sgn_alg + seal_alg + filler
        cksum_input = header_bytes + confounder + plaintext
        sgn_cksum = hmac.new(sign_key, cksum_input, hashlib.md5).digest()[:8]

        # Encrypt SND_SEQ
        seq_bytes = struct.pack('>I', seq_number) + b'\x00' * 4
        seq_rc4_key = hmac.new(sign_key, sgn_cksum, hashlib.md5).digest()
        seq_cipher = ARC4.new(seq_rc4_key)
        encrypted_seq = seq_cipher.encrypt(seq_bytes)

        # Encrypt confounder + data
        data_rc4_key = hmac.new(seal_key, encrypted_seq, hashlib.md5).digest()
        data_cipher = ARC4.new(data_rc4_key)
        encrypted_data = data_cipher.encrypt(confounder + plaintext)

        return header_bytes + encrypted_seq + sgn_cksum + encrypted_data
