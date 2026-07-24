"""Tests for finding 58-3 (`.run/designs/DESIGN_injection_evidence.md` §3.3).

Contract change
---------------
``ScriptExecutorTool.forward`` used to call ``SSHService.run_command`` and
hard-code ``exit_code=0`` on the success branch, mapping every raised
exception to ``exit_code=1`` with a generic string. A remote script that
ran and called ``sys.exit(3)`` produced ``UpstreamError`` from
``run_command`` (its raise-on-nonzero contract), which was NOT in the
tool's ``except`` tuple ``(OSError, TimeoutError, ConnectionError,
RuntimeError)`` -- so the ``UpstreamError`` propagated uncaught and the
caller (``file_retriever._run_script_and_pull``) never saw an honest
``exit_code``. Meanwhile a successful exec returned ``exit_code=0`` no
matter what the remote actually exited with, because the return dict
was a hard-coded ``0``.

The rewrite switches to ``SSHService.run_command_full`` -- a new
platform method that returns the ``(stdout, stderr, exit_code)``
triple without converting non-zero exit into an error, and still
raises ``AuthenticationError`` / ``UpstreamError`` / platform
``TimeoutError`` for connection-level failures (those mean "the
script never ran"). These tests lock the new behaviour so a future
edit cannot silently regress to the old exit-code-lies-on-nonzero
shape.

Mocking strategy
----------------
The SSH layer is mocked with :class:`unittest.mock.AsyncMock` on the
``ScriptExecutorTool`` module's deferred import of ``get_ssh_service``
so no live host is required. ``analyzer_os="linux"`` is used so the
Windows-only ``echo %TEMP%`` probe (which would need a separate
``run_command`` stub) is not exercised -- the exit-code contract is
OS-agnostic.
"""
from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from aila.modules.forensics.tools.script_tool import ScriptExecutorTool
from aila.platform.exceptions import AuthenticationError

_INTEGRATION: dict = {
    "id": 1,
    "name": "test-host",
    "host": "192.168.1.10",
    "username": "user",
    "port": 22,
    "distro": "ubuntu",
    "description": "",
    "private_key_path": None,
    "password_secret_id": None,
    "known_hosts_path": None,
    "host_key_fingerprint": None,
}

_SCRIPT: str = "print('hello')\n"


def _mock_ssh(
    *,
    full_result: tuple[str, str, int] | None = None,
    full_exc: BaseException | None = None,
) -> AsyncMock:
    """Build an AsyncMock SSH service with the coroutines forward needs.

    ``run_command_full`` is either configured to return ``full_result`` or
    to raise ``full_exc`` -- exactly one MUST be supplied. ``upload_file``
    and the cleanup ``run_command`` are configured to succeed so they
    never mask the behaviour under test.
    """
    assert (full_result is None) ^ (full_exc is None), (
        "exactly one of full_result / full_exc must be provided"
    )
    ssh = AsyncMock()
    ssh.upload_file = AsyncMock(return_value=None)
    # Cleanup uses run_command; success is empty stdout on both linux/windows
    # cleanup shells so the finally-branch does nothing observable.
    ssh.run_command = AsyncMock(return_value="")
    if full_result is not None:
        ssh.run_command_full = AsyncMock(return_value=full_result)
    else:
        ssh.run_command_full = AsyncMock(side_effect=full_exc)
    return ssh


def _patch_get_ssh_service(mock_ssh: AsyncMock):
    """Patch the deferred import of get_ssh_service inside forward.

    ``forward`` does ``from aila.modules.forensics.tools._ssh_helper
    import get_ssh_service`` at call time, so the patch target is the
    ``_ssh_helper`` module attribute -- the ``from ... import ...``
    statement re-reads that attribute on every call.
    """
    return patch(
        "aila.modules.forensics.tools._ssh_helper.get_ssh_service",
        new=AsyncMock(return_value=mock_ssh),
    )


async def test_forward_surfaces_nonzero_exit_instead_of_hardcoded_zero() -> None:
    """A remote exit_code=3 MUST reach the caller as exit_code=3, not 0."""
    ssh = _mock_ssh(full_result=("some stdout", "some stderr", 3))
    tool = ScriptExecutorTool(settings=None)  # settings is only forwarded to the patched factory
    with _patch_get_ssh_service(ssh):
        result = await tool.forward(
            script_content=_SCRIPT,
            integration=_INTEGRATION,
            analyzer_os="linux",
        )
    assert result["stdout"] == "some stdout"
    assert result["stderr"] == "some stderr"
    # This is the regression that finding 58-3 named: the pre-fix code
    # produced exit_code=0 on any successful return path.
    assert result["exit_code"] == 3
    # script_hash is sha256(script)[:16] -- must remain the local
    # calculation, unaffected by the exit-code fix.
    assert isinstance(result["script_hash"], str)
    assert len(result["script_hash"]) == 16
    ssh.run_command_full.assert_awaited_once()
    # Cleanup MUST run even on non-zero exit (the try/finally shape).
    ssh.run_command.assert_awaited()


async def test_forward_returns_exit_code_zero_on_clean_exit() -> None:
    """A remote exit_code=0 stays 0; the fix does not accidentally invert success."""
    ssh = _mock_ssh(full_result=("ok\n", "", 0))
    tool = ScriptExecutorTool(settings=None)
    with _patch_get_ssh_service(ssh):
        result = await tool.forward(
            script_content=_SCRIPT,
            integration=_INTEGRATION,
            analyzer_os="linux",
        )
    assert result == {
        "stdout": "ok\n",
        "stderr": "",
        "exit_code": 0,
        "script_hash": result["script_hash"],
    }
    assert isinstance(result["script_hash"], str) and len(result["script_hash"]) == 16


async def test_forward_reraises_authentication_error() -> None:
    """AuthenticationError from run_command_full propagates -- no fake exit_code=1.

    The finally-branch cleanup MUST NOT mask the real exception. The
    prior implementation swallowed OSError/TimeoutError/ConnectionError/
    RuntimeError and returned ``exit_code=1``, but AuthenticationError
    is neither in that tuple nor an OS-level error -- so it already
    propagated. The rewrite keeps that contract explicitly and the
    broadened cleanup exception tuple prevents a follow-on failure in
    the finally branch from masking it.
    """
    ssh = _mock_ssh(full_exc=AuthenticationError("SSH authentication failed for test-host."))
    tool = ScriptExecutorTool(settings=None)
    with _patch_get_ssh_service(ssh):
        with pytest.raises(AuthenticationError, match="authentication failed"):
            await tool.forward(
                script_content=_SCRIPT,
                integration=_INTEGRATION,
                analyzer_os="linux",
            )
    # Cleanup still ran through the finally branch even though the main
    # try raised. This proves the fix keeps the "always clean up the
    # uploaded script" invariant.
    ssh.run_command.assert_awaited()
