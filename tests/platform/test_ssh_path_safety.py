"""#42 SFTP path-traversal guards on the platform SSH service.

The SFTP upload/download surfaces reject empty paths and any path that
contains a ``..`` traversal segment before opening a network connection, so a
bad ``remote_path`` or ``local_path`` never reaches paramiko. The guard also
normalizes Windows separators so ``..\\foo`` cannot slip past the check by
choosing the non-POSIX style.
"""
from __future__ import annotations

import asyncio

import pytest

from aila.platform.services.ssh import SSHService, _reject_unsafe_path

# ---------------------------------------------------------------------------
# Direct helper tests -- the guard is a pure function, so we exercise it
# without any SSH machinery.
# ---------------------------------------------------------------------------


def test_reject_unsafe_path_rejects_dotdot_relative() -> None:
    with pytest.raises(ValueError, match="traversal"):
        _reject_unsafe_path("../etc/shadow", kind="remote")


def test_reject_unsafe_path_rejects_dotdot_deep() -> None:
    with pytest.raises(ValueError, match="traversal"):
        _reject_unsafe_path("inventory/../../etc/shadow", kind="remote")


def test_reject_unsafe_path_rejects_dotdot_windows_separator() -> None:
    with pytest.raises(ValueError, match="traversal"):
        _reject_unsafe_path("..\\..\\Windows\\System32\\config", kind="local")


def test_reject_unsafe_path_rejects_dotdot_absolute() -> None:
    with pytest.raises(ValueError, match="traversal"):
        _reject_unsafe_path("/tmp/foo/../../root/.ssh/id_rsa", kind="local")


def test_reject_unsafe_path_rejects_bare_dotdot() -> None:
    with pytest.raises(ValueError, match="traversal"):
        _reject_unsafe_path("..", kind="remote")


def test_reject_unsafe_path_rejects_trailing_dotdot() -> None:
    with pytest.raises(ValueError, match="traversal"):
        _reject_unsafe_path("/var/data/..", kind="remote")


def test_reject_unsafe_path_rejects_empty_string() -> None:
    with pytest.raises(ValueError, match="non-empty"):
        _reject_unsafe_path("", kind="remote")


def test_reject_unsafe_path_rejects_whitespace_only() -> None:
    with pytest.raises(ValueError, match="non-empty"):
        _reject_unsafe_path("   ", kind="local")


def test_reject_unsafe_path_rejects_non_string() -> None:
    with pytest.raises(ValueError, match="non-empty"):
        _reject_unsafe_path(None, kind="remote")  # type: ignore[arg-type]


def test_reject_unsafe_path_accepts_normal_relative() -> None:
    _reject_unsafe_path("inventory/report.txt", kind="remote")


def test_reject_unsafe_path_accepts_normal_absolute_posix() -> None:
    _reject_unsafe_path("/tmp/out.bin", kind="remote")


def test_reject_unsafe_path_accepts_ssh_known_hosts_path() -> None:
    # /home/user/.ssh/known_hosts is a legitimate absolute target that must
    # not be rejected just because it lives under a hidden directory.
    _reject_unsafe_path("/home/user/.ssh/known_hosts", kind="local")


def test_reject_unsafe_path_accepts_hidden_dot_prefix() -> None:
    # A single leading dot is fine; only a ``..`` segment is treated as
    # traversal.
    _reject_unsafe_path("/tmp/.hidden/output.log", kind="remote")


def test_reject_unsafe_path_accepts_trailing_slash() -> None:
    _reject_unsafe_path("/var/log/app/", kind="remote")


def test_reject_unsafe_path_accepts_dotdot_substring_inside_name() -> None:
    # ``foo..bar`` contains ``..`` as a substring but never as a full path
    # segment. The guard is segment-scoped and must let it through.
    _reject_unsafe_path("/tmp/foo..bar/output.log", kind="local")


def test_reject_unsafe_path_kind_label_appears_in_message() -> None:
    with pytest.raises(ValueError, match="remote"):
        _reject_unsafe_path("../foo", kind="remote")
    with pytest.raises(ValueError, match="local"):
        _reject_unsafe_path("../foo", kind="local")


# ---------------------------------------------------------------------------
# Surface tests -- confirm the guard fires from upload_file / download_file
# BEFORE any SSH connection is opened. The service is constructed without a
# real SecretStore, so any code path that reaches ``_resolve_password`` or
# paramiko would blow up with a different error. The guard is expected to
# raise ``ValueError`` first.
# ---------------------------------------------------------------------------


def _make_service_without_secret_store() -> SSHService:
    service = SSHService.__new__(SSHService)
    service.settings = None
    service.secret_store = None
    return service


_FAKE_INTEGRATION = {
    "name": "fake",
    "host": "127.0.0.1",
    "port": 22,
    "username": "user",
}


def test_upload_file_rejects_traversal_before_connecting() -> None:
    service = _make_service_without_secret_store()

    async def _drive() -> None:
        await service.upload_file(_FAKE_INTEGRATION, __file__, "../../etc/shadow")

    with pytest.raises(ValueError, match="traversal"):
        asyncio.run(_drive())


def test_download_file_rejects_remote_traversal_before_connecting() -> None:
    service = _make_service_without_secret_store()

    async def _drive() -> None:
        await service.download_file(_FAKE_INTEGRATION, "../../etc/shadow", "/tmp/out.bin")

    with pytest.raises(ValueError, match="traversal"):
        asyncio.run(_drive())


def test_download_file_rejects_local_traversal_before_connecting() -> None:
    service = _make_service_without_secret_store()

    async def _drive() -> None:
        await service.download_file(
            _FAKE_INTEGRATION,
            "/var/log/audit.log",
            "../../home/aila/.ssh/id_rsa",
        )

    with pytest.raises(ValueError, match="traversal"):
        asyncio.run(_drive())


def test_upload_file_rejects_empty_remote_before_connecting() -> None:
    service = _make_service_without_secret_store()

    async def _drive() -> None:
        await service.upload_file(_FAKE_INTEGRATION, __file__, "")

    with pytest.raises(ValueError, match="non-empty"):
        asyncio.run(_drive())


def test_download_file_rejects_empty_local_before_connecting() -> None:
    service = _make_service_without_secret_store()

    async def _drive() -> None:
        await service.download_file(_FAKE_INTEGRATION, "/var/log/audit.log", "")

    with pytest.raises(ValueError, match="non-empty"):
        asyncio.run(_drive())
