from __future__ import annotations

import asyncio
import base64
import builtins
import hashlib
from pathlib import Path
from threading import Lock

import paramiko

from ...storage.database import async_session_scope
from ...storage.secrets import SecretStore
from ..config import PlatformSettings
from ..contracts.platform import RegisteredSystem, SSHIntegrationInput
from ..exceptions import AuthenticationError, TimeoutError, UpstreamError, ValidationError


class SSHConnectionPool:
    """Reusable SSH connections keyed by (host, port, username) for one scan's lifetime."""

    def __init__(self) -> None:
        self._lock = Lock()
        self._pool: dict[tuple[str, int, str], paramiko.SSHClient] = {}

    def get_or_connect(self, payload: SSHIntegrationInput, connect_kwargs: dict) -> paramiko.SSHClient:
        """Return a live SSH client for the target host, creating one if needed."""
        key = (payload.host, payload.port, payload.username)
        with self._lock:
            client = self._pool.get(key)
            if client is not None:
                transport = client.get_transport()
                if transport is not None and transport.is_active():
                    return client
            new_client = paramiko.SSHClient()
            new_client.load_system_host_keys()
            if payload.known_hosts_path:
                known_hosts_path = Path(payload.known_hosts_path).resolve()
                if known_hosts_path.exists():
                    new_client.load_host_keys(str(known_hosts_path))
                new_client.set_missing_host_key_policy(paramiko.RejectPolicy())
            else:
                new_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            new_client.connect(**connect_kwargs)
            self._pool[key] = new_client
            return new_client

    def close_all(self) -> None:
        """Close and remove all pooled SSH connections."""
        with self._lock:
            for client in self._pool.values():
                try:
                    client.close()
                except (paramiko.ssh_exception.SSHException, OSError):
                    pass
            self._pool.clear()


class SSHService:
    """Platform SSH execution service with optional connection pooling."""

    def __init__(self, settings: PlatformSettings, secret_store: SecretStore | None = None):
        self.settings = settings
        self.secret_store = secret_store or SecretStore(self.settings)

    async def run_command(
        self,
        integration: dict | SSHIntegrationInput | RegisteredSystem,
        command: str,
        timeout_seconds: float | None = None,
        pool: SSHConnectionPool | None = None,
        connect_timeout: float = 15.0,
    ) -> str:
        """Execute command over SSH and return decoded stdout.

        Resolves credentials asynchronously, then runs blocking paramiko I/O
        in a thread via asyncio.to_thread to avoid blocking the event loop.

        Args:
            connect_timeout: TCP + auth timeout in seconds for paramiko.connect().
                             Set lower (e.g. 3.0) for health probes so they fail
                             fast when a host is unreachable.
        """
        if isinstance(integration, dict):
            payload = self._to_ssh_integration(RegisteredSystem.model_validate(integration))
        elif isinstance(integration, RegisteredSystem):
            payload = self._to_ssh_integration(integration)
        else:
            payload = integration

        password = await self._resolve_password(payload)

        connect_kwargs: dict = {
            "hostname": payload.host,
            "port": payload.port,
            "username": payload.username,
            "timeout": connect_timeout,
        }
        if payload.private_key_path:
            connect_kwargs["key_filename"] = payload.private_key_path
        if password:
            connect_kwargs["password"] = password

        # `timeout_seconds` is an IDLE timeout (enforced inside
        # _run_command_blocking via channel.settimeout + exit-status polling),
        # not a wall-time deadline. Legitimate long-running commands
        # (dissect on 100GB disk, volatility on 32GB dump) may take tens of
        # minutes but still produce a steady trickle of output, so a
        # wall-clock wait_for here would kill them. We trust paramiko's
        # per-recv timer + the exit-ready poll to catch true hangs.
        return await asyncio.to_thread(
            self._run_command_blocking, payload, command, timeout_seconds, pool, connect_kwargs
        )

    def _run_command_blocking(
        self,
        payload: SSHIntegrationInput,
        command: str,
        timeout_seconds: float | None,
        pool: SSHConnectionPool | None,
        connect_kwargs: dict,
    ) -> str:
        """Blocking SSH execution — runs inside asyncio.to_thread."""
        if pool is not None:
            client = pool.get_or_connect(payload, connect_kwargs)
            SSHService._verify_fingerprint(client, payload)
            return SSHService._exec_command(client, command, timeout_seconds, payload)

        client = paramiko.SSHClient()
        client.load_system_host_keys()
        if payload.known_hosts_path:
            known_hosts_path = Path(payload.known_hosts_path).resolve()
            if not known_hosts_path.exists():
                raise ValidationError(f"Known hosts file {known_hosts_path} does not exist.")
            client.load_host_keys(str(known_hosts_path))
        # Use AutoAddPolicy when no known_hosts_path is configured (lab/CTF default).
        # When a known_hosts_path IS provided, enforce RejectPolicy so rogue hosts fail.
        if payload.known_hosts_path:
            client.set_missing_host_key_policy(paramiko.RejectPolicy())
        else:
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(**connect_kwargs)
            transport = client.get_transport()
            if transport is not None:
                transport.set_keepalive(60)
            SSHService._verify_fingerprint(client, payload)
            return SSHService._exec_command(client, command, timeout_seconds, payload)
        except paramiko.AuthenticationException as exc:
            raise AuthenticationError(
                f"SSH authentication failed for {payload.name} ({payload.username}@{payload.host}:{payload.port}). "
                "Verify the username and the configured stored password or private key."
            ) from exc
        except paramiko.BadHostKeyException as exc:
            raise UpstreamError(
                f"SSH host key verification failed for {payload.name} ({payload.host}). "
                "The server host key did not match the trusted known_hosts entry."
            ) from exc
        except paramiko.SSHException as exc:
            message = str(exc)
            if "not found in known_hosts" in message.lower():
                raise UpstreamError(
                    f"SSH host key verification failed for {payload.name} ({payload.host}). "
                    "Add the host key to a trusted known_hosts file or configure known_hosts_path."
                ) from exc
            raise UpstreamError(f"SSH transport error for {payload.name} ({payload.host}): {message}") from exc
        finally:
            client.close()

    @staticmethod
    def _exec_command(
        client: paramiko.SSHClient,
        command: str,
        timeout_seconds: float | None,
        payload: SSHIntegrationInput,
    ) -> str:
        try:
            _, stdout, stderr = client.exec_command(command)
            # `timeout_seconds` is an IDLE timeout applied to each recv() —
            # paramiko resets the timer every time data arrives, so a slow but
            # steady stream (dissect on a huge disk) never trips it. A genuine
            # hang (zero bytes for N seconds) raises builtins.TimeoutError.
            if timeout_seconds is not None:
                stdout.channel.settimeout(timeout_seconds)
            try:
                # Read first, exit-status second. Reversing this order (as the
                # original code did) can deadlock if the remote fills its stdout
                # buffer and waits for a reader before exiting.
                output = stdout.read().decode("utf-8", errors="ignore")
                error_output = stderr.read().decode("utf-8", errors="ignore")
                # Streams have closed — the remote is either already exited or
                # imminent. Poll for exit status with a tight grace (30s) so we
                # don't hang forever on a detached child that closed stdout but
                # didn't actually exit.
                import time as _time
                grace_deadline = _time.monotonic() + 30.0
                while not stdout.channel.exit_status_ready():
                    if _time.monotonic() > grace_deadline:
                        raise TimeoutError(
                            f"SSH command for {payload.name} ({payload.host}) closed "
                            f"its streams but did not emit an exit status within 30s "
                            f"(command likely detached a child). Command: {command[:200]}"
                        )
                    _time.sleep(0.1)
                exit_code = stdout.channel.recv_exit_status()
            except builtins.TimeoutError as exc:
                raise TimeoutError(
                    f"SSH command for {payload.name} ({payload.host}) idle "
                    f">{timeout_seconds}s with no output. Command: {command[:200]}"
                ) from exc
            if exit_code != 0:
                raise UpstreamError(
                    f"SSH command failed for {payload.name} ({payload.host}) with exit code {exit_code}: {error_output}"
                )
            return output
        except paramiko.AuthenticationException as exc:
            raise AuthenticationError(
                f"SSH authentication failed for {payload.name} ({payload.username}@{payload.host}:{payload.port}). "
                "Verify the username and the configured stored password or private key."
            ) from exc
        except paramiko.BadHostKeyException as exc:
            raise UpstreamError(
                f"SSH host key verification failed for {payload.name} ({payload.host}). "
                "The server host key did not match the trusted known_hosts entry."
            ) from exc
        except paramiko.SSHException as exc:
            message = str(exc)
            if "not found in known_hosts" in message.lower():
                raise UpstreamError(
                    f"SSH host key verification failed for {payload.name} ({payload.host}). "
                    "Add the host key to a trusted known_hosts file or configure known_hosts_path."
                ) from exc
            raise UpstreamError(f"SSH transport error for {payload.name} ({payload.host}): {message}") from exc

    async def upload_file(
        self,
        integration: dict | SSHIntegrationInput | RegisteredSystem,
        local_path: str | Path,
        remote_path: str,
        *,
        timeout_seconds: float | None = 120.0,
    ) -> None:
        """Upload a local file to the remote machine via SFTP.

        Uses the same credential resolution and host-key verification as
        ``run_command``.  Blocking paramiko I/O runs in a thread.
        """
        local_path = Path(local_path)
        if not local_path.is_file():
            raise ValidationError(f"Local file does not exist: {local_path}")

        if isinstance(integration, dict):
            payload = self._to_ssh_integration(RegisteredSystem.model_validate(integration))
        elif isinstance(integration, RegisteredSystem):
            payload = self._to_ssh_integration(integration)
        else:
            payload = integration

        password = await self._resolve_password(payload)

        connect_kwargs: dict = {
            "hostname": payload.host,
            "port": payload.port,
            "username": payload.username,
            "timeout": 15,
        }
        if payload.private_key_path:
            connect_kwargs["key_filename"] = payload.private_key_path
        if password:
            connect_kwargs["password"] = password

        await asyncio.to_thread(
            self._upload_file_blocking, payload, str(local_path), remote_path,
            timeout_seconds, connect_kwargs,
        )

    def _upload_file_blocking(
        self,
        payload: SSHIntegrationInput,
        local_path: str,
        remote_path: str,
        timeout_seconds: float | None,
        connect_kwargs: dict,
    ) -> None:
        """Blocking SFTP upload — runs inside asyncio.to_thread."""
        client = paramiko.SSHClient()
        client.load_system_host_keys()
        if payload.known_hosts_path:
            known_hosts_path = Path(payload.known_hosts_path).resolve()
            if not known_hosts_path.exists():
                raise ValidationError(f"Known hosts file {known_hosts_path} does not exist.")
            client.load_host_keys(str(known_hosts_path))
        # Use AutoAddPolicy when no known_hosts_path is configured (lab/CTF default).
        # When a known_hosts_path IS provided, enforce RejectPolicy so rogue hosts fail.
        if payload.known_hosts_path:
            client.set_missing_host_key_policy(paramiko.RejectPolicy())
        else:
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(**connect_kwargs)
            SSHService._verify_fingerprint(client, payload)
            transport = client.get_transport()
            if transport is not None:
                transport.set_keepalive(60)
            sftp = client.open_sftp()
            try:
                if timeout_seconds is not None:
                    channel = sftp.get_channel()
                    if channel is not None:
                        channel.settimeout(timeout_seconds)
                sftp.put(local_path, remote_path)
            finally:
                sftp.close()
        except paramiko.AuthenticationException as exc:
            raise AuthenticationError(
                f"SSH authentication failed for {payload.name} ({payload.username}@{payload.host}:{payload.port})."
            ) from exc
        except paramiko.SSHException as exc:
            raise UpstreamError(f"SFTP upload failed for {payload.name} ({payload.host}): {exc}") from exc
        finally:
            client.close()

    async def download_file(
        self,
        integration: dict | SSHIntegrationInput | RegisteredSystem,
        remote_path: str,
        local_path: str | Path,
        *,
        timeout_seconds: float | None = 600.0,
    ) -> None:
        """Download a remote file to the local machine via SFTP.

        Counterpart to ``upload_file``. Used by collectors that need to run
        commands whose output exceeds paramiko's ~2 MB stdout window — they
        redirect to a remote temp file and download it here instead of
        streaming stdout through the deadlock-prone channel path.
        """
        if isinstance(integration, dict):
            payload = self._to_ssh_integration(RegisteredSystem.model_validate(integration))
        elif isinstance(integration, RegisteredSystem):
            payload = self._to_ssh_integration(integration)
        else:
            payload = integration

        password = await self._resolve_password(payload)
        connect_kwargs: dict = {
            "hostname": payload.host,
            "port": payload.port,
            "username": payload.username,
            "timeout": 15.0,
        }
        if payload.private_key_path:
            connect_kwargs["key_filename"] = payload.private_key_path
        if password:
            connect_kwargs["password"] = password

        await asyncio.to_thread(
            self._download_file_blocking, payload, remote_path, str(local_path), timeout_seconds, connect_kwargs
        )

    def _download_file_blocking(
        self,
        payload: SSHIntegrationInput,
        remote_path: str,
        local_path: str,
        timeout_seconds: float | None,
        connect_kwargs: dict,
    ) -> None:
        client = paramiko.SSHClient()
        if payload.known_hosts_path:
            known_hosts_path = Path(payload.known_hosts_path)
            if not known_hosts_path.exists():
                raise ValidationError(f"Known hosts file {known_hosts_path} does not exist.")
            client.load_host_keys(str(known_hosts_path))
        if payload.known_hosts_path:
            client.set_missing_host_key_policy(paramiko.RejectPolicy())
        else:
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(**connect_kwargs)
            SSHService._verify_fingerprint(client, payload)
            transport = client.get_transport()
            if transport is not None:
                transport.set_keepalive(60)
            sftp = client.open_sftp()
            try:
                if timeout_seconds is not None:
                    channel = sftp.get_channel()
                    if channel is not None:
                        channel.settimeout(timeout_seconds)
                sftp.get(remote_path, local_path)
            finally:
                sftp.close()
        except paramiko.AuthenticationException as exc:
            raise AuthenticationError(
                f"SSH authentication failed for {payload.name} ({payload.username}@{payload.host}:{payload.port})."
            ) from exc
        except paramiko.SSHException as exc:
            raise UpstreamError(f"SFTP download failed for {payload.name} ({payload.host}): {exc}") from exc
        finally:
            client.close()

    @staticmethod
    def _verify_fingerprint(client: paramiko.SSHClient, payload: SSHIntegrationInput) -> None:
        """Verify the server's host key against the configured fingerprint."""
        if not payload.host_key_fingerprint:
            return
        transport = client.get_transport()
        if transport is None:
            raise UpstreamError(f"SSH transport for {payload.name} is not available after connection.")
        server_key = transport.get_remote_server_key()
        expected = payload.host_key_fingerprint.strip()
        if expected.startswith("SHA256:"):
            actual = SSHService._sha256_fingerprint(server_key)
            if actual != expected:
                raise UpstreamError(
                    f"SSH host key fingerprint mismatch for {payload.name} ({payload.host}). "
                    f"Expected {expected}, got {actual}."
                )
            return

        actual_md5 = SSHService._md5_fingerprint(server_key)
        normalized_expected = expected.lower().replace("-", ":")
        if ":" not in normalized_expected and len(normalized_expected) == 32:
            normalized_expected = ":".join(
                normalized_expected[index : index + 2] for index in range(0, len(normalized_expected), 2)
            )
        if actual_md5 != normalized_expected:
            raise UpstreamError(
                f"SSH host key fingerprint mismatch for {payload.name} ({payload.host}). "
                f"Expected {expected}, got {actual_md5}."
            )

    @staticmethod
    def _sha256_fingerprint(server_key) -> str:
        digest = hashlib.sha256(server_key.asbytes()).digest()
        encoded = base64.b64encode(digest).decode("ascii").rstrip("=")
        return f"SHA256:{encoded}"

    @staticmethod
    def _md5_fingerprint(server_key) -> str:
        digest = server_key.get_fingerprint().hex()
        return ":".join(digest[index : index + 2] for index in range(0, len(digest), 2))

    async def _resolve_password(self, payload: SSHIntegrationInput) -> str | None:
        """Load the SSH password from SecretStore if a password_secret_id is configured."""
        if payload.password_secret_id:
            async with async_session_scope(self.settings) as session:
                password = await self.secret_store.get_secret_by_id(session, payload.password_secret_id)
            if not password:
                raise ValidationError(f"Stored password secret {payload.password_secret_id} could not be loaded.")
            return password
        return None

    @staticmethod
    def _to_ssh_integration(system: RegisteredSystem) -> SSHIntegrationInput:
        return SSHIntegrationInput(
            name=system.name,
            host=system.host,
            username=system.username,
            port=system.port,
            distro=system.distro,
            description=system.description,
            private_key_path=system.private_key_path,
            password_secret_id=system.password_secret_id,
            known_hosts_path=system.known_hosts_path,
            host_key_fingerprint=system.host_key_fingerprint,
        )
