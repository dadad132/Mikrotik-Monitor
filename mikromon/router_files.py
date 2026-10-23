"""Copy a file off a router: a backup, to keep somewhere other than the router.

A backup that lives only on the router's flash is gone with the router --
stolen, burnt out, or reset by somebody who should not have. So the Backups
tab lets it be downloaded.

RouterOS's API cannot hand a .backup over: the file is binary, and the API
reads back only small text files. Its SSH server can, over SFTP, so that is
what this uses -- through the management tunnel, with the same login the
dashboard already pushes changes with (a "full" group login carries both the
ssh and ftp permissions SFTP needs).

SSH can be switched off on a router (the Security tab offers to), so the
service is read through the API first and a switched-off one is reported as
such, rather than as a connection that timed out for no stated reason.
"""
from __future__ import annotations

import logging
import socket

log = logging.getLogger(__name__)

# A RouterOS backup is tens to hundreds of kilobytes; an export is text. Far
# past this is not a backup, and holding it in memory to send would be wrong.
MAX_BYTES = 64 * 1024 * 1024
_TIMEOUT = 20.0


class RouterFileError(Exception):
    """The file could not be copied off the router, in words a person can
    act on."""


def ssh_service(api) -> dict:
    """The router's SSH service as /ip service has it:
    {"disabled": bool, "port": int}. Assumes the RouterOS default (on, port
    22) when the menu cannot be read."""
    try:
        rows = api.fetch(("ip", "service"))
    except Exception:  # noqa: BLE001 - fall back to the default
        rows = []
    row = next((r for r in rows if str(r.get("name")) == "ssh"), None)
    if row is None:
        return {"disabled": False, "port": 22}
    disabled = row.get("disabled")
    try:
        port = int(row.get("port") or 22)
    except (TypeError, ValueError):
        port = 22
    return {"disabled": disabled is True
            or str(disabled).strip().lower() in ("true", "yes"),
            "port": port}


def download(host: str, port: int, username: str, password: str,
             path: str, timeout: float = _TIMEOUT) -> bytes:
    """The bytes of `path` on the router, read over SFTP.

    The host key is not checked: the connection runs inside the WireGuard
    tunnel, which has already authenticated the router at both ends, and a
    router's SSH key changes whenever it is reset -- refusing then would
    stop exactly the download wanted most.
    """
    try:
        import paramiko
    except ImportError as exc:
        raise RouterFileError(
            "This server cannot copy files off routers yet: the paramiko "
            "package is missing. Re-run deploy/install.sh to install it."
        ) from exc
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        try:
            client.connect(host, port=int(port), username=username,
                           password=password, timeout=timeout,
                           banner_timeout=timeout, auth_timeout=timeout,
                           look_for_keys=False, allow_agent=False)
        except paramiko.AuthenticationException as exc:
            raise RouterFileError(
                f"The router refused the dashboard's login ({username}) over "
                f"SSH. The login needs the ssh and ftp permissions; the "
                f"'full' group has both.") from exc
        except (OSError, socket.timeout, paramiko.SSHException) as exc:
            raise RouterFileError(
                f"Could not open SSH on the router ({host}, port {port}): "
                f"{exc}. Check that SSH is allowed from the management "
                f"tunnel (IP > Services, and the firewall).") from exc
        try:
            sftp = client.open_sftp()
        except (OSError, paramiko.SSHException) as exc:
            raise RouterFileError(
                f"The router would not open a file transfer (SFTP) for "
                f"{username}: {exc}. The login needs the ftp permission.") \
                from exc
        try:
            try:
                size = sftp.stat(path).st_size or 0
            except FileNotFoundError as exc:
                raise RouterFileError(
                    f"{path} is no longer on the router.") from exc
            if size > MAX_BYTES:
                raise RouterFileError(
                    f"{path} is {size // (1024 * 1024)} MB, which is not a "
                    f"backup this page can hand over.")
            with sftp.open(path, "rb") as fh:
                data = fh.read()
        except OSError as exc:
            raise RouterFileError(
                f"Could not read {path} from the router: {exc}") from exc
        finally:
            sftp.close()
    finally:
        client.close()
    log.info("copied %s (%d bytes) off %s", path, len(data), host)
    return data
