"""#51 -- PoC runner sandbox: path confinement, isolation wrappers, sanitizers.

The tests assert the CONSTRUCTED remote command shape without a live target,
using an :class:`_SSHStub` that captures every ``run_command`` invocation.
End-to-end isolation efficacy (firejail blocks egress, unshare drops caps in
practice) needs a real Linux target with unshare/firejail installed for the
parent to verify.
"""
from __future__ import annotations

import asyncio
import logging
from unittest.mock import MagicMock

import pytest

from aila.modules.vr.tools.poc_runner import (
    ISOLATOR_FIREJAIL,
    ISOLATOR_ULIMIT,
    ISOLATOR_UNSHARE,
    PoCRunnerTool,
    apply_isolator,
    build_run_wrapper,
    build_workspace_prune_cmd,
    confine_remote_poc_path,
    new_run_dir,
    run_dir_of,
)

_INTEGRATION = {
    "id": 1,
    "name": "test-host",
    "host": "10.0.0.5",
    "username": "aila_vr",
    "port": 22,
}


# ---------------------------------------------------------------------------
# confine_remote_poc_path
# ---------------------------------------------------------------------------


def test_confine_accepts_path_under_sandbox_root():
    assert confine_remote_poc_path("/tmp/aila_vr/poc.py") is None
    assert confine_remote_poc_path("/tmp/aila_vr/sub/nested/poc") is None


def test_confine_rejects_none_and_empty():
    assert "required" in (confine_remote_poc_path(None) or "")
    assert "required" in (confine_remote_poc_path("") or "")


def test_confine_rejects_non_string_types():
    # Defense against caller-side bugs that pass a bytes/list. The signature
    # narrows to str|None; anything else is treated as missing.
    assert confine_remote_poc_path(b"/tmp/aila_vr/poc.py") == "poc_path is required"  # type: ignore[arg-type]


def test_confine_rejects_relative_path():
    err = confine_remote_poc_path("poc.py")
    assert err and "absolute" in err


def test_confine_rejects_dotdot_segments():
    # Even a nominally-under-sandbox prefix with `..` is refused; a caller
    # relying on lexical string prefix would otherwise accept
    # /tmp/aila_vr/../etc/passwd.
    err = confine_remote_poc_path("/tmp/aila_vr/../etc/passwd")
    assert err and ".." in err


def test_confine_rejects_paths_outside_sandbox():
    for candidate in (
        "/etc/passwd",
        "/usr/bin/id",
        "/root/.ssh/id_rsa",
        "/tmp/other/poc.py",
    ):
        err = confine_remote_poc_path(candidate)
        assert err and "escapes" in err, candidate


def test_confine_rejects_deceptive_prefix():
    # /tmp/aila_vr_evil/foo shares a lexical prefix with /tmp/aila_vr but
    # sits in a sibling directory. is_relative_to on PurePosixPath rejects
    # it correctly; a naive `str.startswith` would have accepted it.
    err = confine_remote_poc_path("/tmp/aila_vr_evil/foo")
    assert err and "escapes" in err


def test_confine_rejects_sandbox_root_itself():
    err = confine_remote_poc_path("/tmp/aila_vr")
    assert err and "escapes" in err


# ---------------------------------------------------------------------------
# apply_isolator
# ---------------------------------------------------------------------------


def test_apply_isolator_firejail_blocks_network_and_drops_caps():
    wrapped = apply_isolator("python3 /tmp/aila_vr/poc.py /bin/id", ISOLATOR_FIREJAIL)
    # Network egress blocked -- the audit's exfiltration example
    # `requests.post('host', ...)` fails inside this wrap.
    assert "--net=none" in wrapped
    # Capability set dropped -- no CAP_NET_ADMIN, no CAP_DAC_READ_SEARCH.
    assert "--caps.drop=all" in wrapped
    # Default seccomp filter -- syscall surface reduced.
    assert "--seccomp" in wrapped
    # Private tmpfs so /tmp writes do not leak between runs.
    assert "--private-tmp" in wrapped
    # The PoC command is preserved verbatim inside bash -c.
    assert "python3 /tmp/aila_vr/poc.py /bin/id" in wrapped


def test_apply_isolator_unshare_opens_all_namespaces_and_drops_privs():
    wrapped = apply_isolator("/tmp/aila_vr/poc /bin/id", ISOLATOR_UNSHARE)
    for flag in ("--user", "--net", "--pid", "--mount", "--ipc", "--uts", "--cgroup"):
        assert flag in wrapped, flag
    # setpriv sets PR_SET_NO_NEW_PRIVS + drops ambient/inheritable caps.
    assert "setpriv" in wrapped
    assert "--no-new-privs" in wrapped
    assert "--inh-caps=-all" in wrapped
    assert "--ambient-caps=-all" in wrapped


def test_apply_isolator_ulimit_is_bare_bash_wrap():
    # Last-resort fallback -- the outer wrapper's ulimit + timeout are
    # the only remaining fences. Caller logs a WARNING.
    wrapped = apply_isolator("python3 /tmp/aila_vr/poc.py /bin/id", ISOLATOR_ULIMIT)
    assert wrapped.startswith("bash -c ")
    assert "firejail" not in wrapped
    assert "unshare" not in wrapped


def test_apply_isolator_unknown_raises():
    with pytest.raises(ValueError):
        apply_isolator("cmd", "docker")


# ---------------------------------------------------------------------------
# build_run_wrapper
# ---------------------------------------------------------------------------


def test_build_run_wrapper_composes_isolator_ulimit_and_timeout():
    wrapper = build_run_wrapper(
        "python3 /tmp/aila_vr/poc.py /bin/id",
        timeout_s=30.0,
        mem_kb=2048 * 1024,
        isolator=ISOLATOR_UNSHARE,
    )
    # Memory cap enforced via bash builtin `ulimit -v`.
    assert "ulimit -v 2097152" in wrapper
    # Wall-time cap + hard kill grace so SIGTERM-ignoring PoCs cannot camp.
    assert "timeout --kill-after=5s 30s" in wrapper
    # Isolator flags must reach the wrapper.
    assert "unshare --user --net --pid --mount" in wrapper
    assert "setpriv --no-new-privs" in wrapper
    # Markers so paramiko's non-zero-raises path cannot swallow crash signals.
    assert "__AILA_POC_EXIT__:" in wrapper
    assert "__AILA_POC_OUT_BEGIN__" in wrapper
    assert "__AILA_POC_OUT_END__" in wrapper
    assert "__AILA_POC_ERR_BEGIN__" in wrapper
    assert "__AILA_POC_ERR_END__" in wrapper


def test_build_run_wrapper_firejail_flavor():
    wrapper = build_run_wrapper(
        "/tmp/aila_vr/poc /bin/id",
        timeout_s=10.0,
        mem_kb=524288,
        isolator=ISOLATOR_FIREJAIL,
    )
    assert "firejail" in wrapper
    assert "--net=none" in wrapper
    assert "--seccomp" in wrapper
    assert "timeout --kill-after=5s 10s" in wrapper


# ---------------------------------------------------------------------------
# PoCRunnerTool._run: end-to-end path confinement + isolator wrap
# ---------------------------------------------------------------------------


class _SSHStub:
    """Captures every ``run_command`` command sent to the target."""

    def __init__(self) -> None:
        self.commands: list[tuple[str, dict]] = []

    async def run_command(self, integration: dict, command: str, timeout_seconds: float | None = None) -> str:
        del timeout_seconds
        self.commands.append((command, integration))
        # Marker-framed output the run wrapper's parser expects, exit 0 clean.
        return (
            "__AILA_POC_EXIT__:0\n"
            "__AILA_POC_OUT_BEGIN__\n\n__AILA_POC_OUT_END__\n"
            "__AILA_POC_ERR_BEGIN__\n\n__AILA_POC_ERR_END__\n"
        )


def _tool() -> PoCRunnerTool:
    return PoCRunnerTool(MagicMock())


async def test_run_rejects_poc_path_outside_sandbox_without_touching_ssh():
    tool = _tool()
    ssh = _SSHStub()
    result = await tool._run(
        ssh,  # type: ignore[arg-type]
        _INTEGRATION,
        poc_path="/etc/passwd",
        target_binary="/bin/id",
    )
    assert result["status"] == "error"
    assert "escapes" in result["error"]
    # Critical: the arbitrary-path attempt never reaches the shell.
    assert ssh.commands == []


async def test_run_rejects_relative_poc_path():
    tool = _tool()
    ssh = _SSHStub()
    result = await tool._run(
        ssh,  # type: ignore[arg-type]
        _INTEGRATION,
        poc_path="poc.py",
        target_binary="/bin/id",
    )
    assert result["status"] == "error"
    assert ssh.commands == []


async def test_run_wraps_command_in_unshare_via_env_override(monkeypatch):
    """When AILA_VR_POC_ISOLATOR forces unshare, the constructed remote
    command MUST carry the namespace + no_new_privs wrap and MUST NOT run
    the bare `python3 poc.py` invocation.
    """
    monkeypatch.setenv("AILA_VR_POC_ISOLATOR", ISOLATOR_UNSHARE)
    tool = _tool()
    ssh = _SSHStub()
    result = await tool._run(
        ssh,  # type: ignore[arg-type]
        _INTEGRATION,
        poc_path="/tmp/aila_vr/poc.py",
        target_binary="/tmp/aila_vr/target",
        timeout_seconds=15.0,
        memory_limit_mb=512,
    )
    assert result["status"] == "ready"
    assert len(ssh.commands) == 1
    cmd, _integ = ssh.commands[0]
    assert "unshare --user --net --pid --mount" in cmd
    assert "setpriv --no-new-privs" in cmd
    assert "--inh-caps=-all" in cmd
    assert "ulimit -v 524288" in cmd
    assert "timeout --kill-after=5s 15s" in cmd
    assert "python3 /tmp/aila_vr/poc.py /tmp/aila_vr/target" in cmd


async def test_run_wraps_command_in_firejail_via_env_override(monkeypatch):
    monkeypatch.setenv("AILA_VR_POC_ISOLATOR", ISOLATOR_FIREJAIL)
    tool = _tool()
    ssh = _SSHStub()
    await tool._run(
        ssh,  # type: ignore[arg-type]
        _INTEGRATION,
        poc_path="/tmp/aila_vr/poc.py",
        target_binary="/tmp/aila_vr/target",
    )
    cmd = ssh.commands[0][0]
    assert "firejail" in cmd
    assert "--net=none" in cmd
    assert "--caps.drop=all" in cmd
    assert "--seccomp" in cmd


async def test_run_probes_firejail_first_then_unshare(monkeypatch):
    """Detection order: firejail first (batteries-included). When the probe
    reports firejail is present, no unshare probe is issued and the wrapper
    uses firejail."""
    # Clear any test-level env override so detection actually runs.
    monkeypatch.delenv("AILA_VR_POC_ISOLATOR", raising=False)

    class _ProbeSSH(_SSHStub):
        async def run_command(self, integration: dict, command: str, timeout_seconds: float | None = None) -> str:
            self.commands.append((command, integration))
            if "command -v firejail" in command:
                return "OK\n"
            if "command -v unshare" in command:
                # Would return OK, but firejail wins first -- unshare should
                # never be probed.
                return "OK\n"
            return await super().run_command(integration, command, timeout_seconds)

    tool = _tool()
    ssh = _ProbeSSH()
    await tool._run(
        ssh,  # type: ignore[arg-type]
        _INTEGRATION,
        poc_path="/tmp/aila_vr/poc.py",
        target_binary="/tmp/aila_vr/target",
    )
    # Two commands: the firejail probe, then the wrapped run. No unshare probe.
    probe_cmds = [c for c, _ in ssh.commands if "command -v" in c]
    assert len(probe_cmds) == 1
    assert "firejail" in probe_cmds[0]
    run_cmd = [c for c, _ in ssh.commands if "__AILA_POC_EXIT__" in c][0]
    assert "firejail" in run_cmd


async def test_run_refuses_when_no_isolator_available(monkeypatch, caplog):
    """fix #51 fail-close: when neither firejail nor unshare+setpriv is
    installed on the target, the runner MUST refuse to execute instead
    of falling back to a fenceless bash wrap. No run command reaches
    the target; the caller receives ``status="error"`` with a clear
    refusal reason so the operator sees why the PoC did not launch."""
    monkeypatch.delenv("AILA_VR_POC_ISOLATOR", raising=False)

    class _NoIsolatorSSH(_SSHStub):
        async def run_command(self, integration: dict, command: str, timeout_seconds: float | None = None) -> str:
            self.commands.append((command, integration))
            if "command -v" in command:
                return "MISSING\n"
            return await super().run_command(integration, command, timeout_seconds)

    tool = _tool()
    ssh = _NoIsolatorSSH()
    with caplog.at_level(logging.WARNING, logger="aila.modules.vr.tools.poc_runner"):
        result = await tool._run(
            ssh,  # type: ignore[arg-type]
            _INTEGRATION,
            poc_path="/tmp/aila_vr/poc.py",
            target_binary="/tmp/aila_vr/target",
        )
    assert result["status"] == "error"
    assert "refusing to execute" in result["error"]
    assert "firejail" in result["error"] and "unshare" in result["error"]
    # Refusal was logged at WARNING so the operator sees it.
    assert any("refusing to execute" in rec.message for rec in caplog.records)
    # Critical: no PoC-invocation command was dispatched. Only the two
    # detection probes (firejail then unshare) hit the SSH transport;
    # the marker-framed run command is absent.
    run_cmds = [c for c, _ in ssh.commands if "__AILA_POC_EXIT__" in c]
    assert run_cmds == []
    # Confirm the probes ran but nothing else -- ulimit / bash -c wrapping
    # never left the tool.
    probe_cmds = [c for c, _ in ssh.commands if "command -v" in c]
    assert len(probe_cmds) == 2


async def test_run_refusal_not_cached_so_later_probe_can_recover(monkeypatch):
    """fix #51 -- a refusal on one call MUST NOT lock the workflow into
    permanent refusal. If the operator installs firejail between attempts,
    the next probe finds it and the PoC runs."""
    monkeypatch.delenv("AILA_VR_POC_ISOLATOR", raising=False)

    class _FlippingSSH(_SSHStub):
        def __init__(self) -> None:
            super().__init__()
            self.probe_calls = 0
            self.firejail_present = False

        async def run_command(self, integration: dict, command: str, timeout_seconds: float | None = None) -> str:
            self.commands.append((command, integration))
            if "command -v firejail" in command:
                self.probe_calls += 1
                return "OK\n" if self.firejail_present else "MISSING\n"
            if "command -v unshare" in command:
                self.probe_calls += 1
                return "MISSING\n"
            return await super().run_command(integration, command, timeout_seconds)

    tool = _tool()
    ssh = _FlippingSSH()
    first = await tool._run(
        ssh,  # type: ignore[arg-type]
        _INTEGRATION,
        poc_path="/tmp/aila_vr/poc.py",
        target_binary="/tmp/aila_vr/target",
    )
    assert first["status"] == "error"
    # Operator installs firejail on the target between attempts.
    ssh.firejail_present = True
    second = await tool._run(
        ssh,  # type: ignore[arg-type]
        _INTEGRATION,
        poc_path="/tmp/aila_vr/poc.py",
        target_binary="/tmp/aila_vr/target",
    )
    assert second["status"] == "ready"
    run_cmd = [c for c, _ in ssh.commands if "__AILA_POC_EXIT__" in c][0]
    assert "firejail" in run_cmd


async def test_isolator_result_cached_per_integration(monkeypatch):
    """Second `_run` on the same integration MUST skip the probe."""
    monkeypatch.delenv("AILA_VR_POC_ISOLATOR", raising=False)

    class _CountingSSH(_SSHStub):
        def __init__(self) -> None:
            super().__init__()
            self.probe_calls = 0

        async def run_command(self, integration: dict, command: str, timeout_seconds: float | None = None) -> str:
            self.commands.append((command, integration))
            if "command -v" in command:
                self.probe_calls += 1
                return "OK\n" if "firejail" in command else "MISSING\n"
            return await super().run_command(integration, command, timeout_seconds)

    tool = _tool()
    ssh = _CountingSSH()
    for _ in range(3):
        await tool._run(
            ssh,  # type: ignore[arg-type]
            _INTEGRATION,
            poc_path="/tmp/aila_vr/poc.py",
            target_binary="/tmp/aila_vr/target",
        )
    # First call probes firejail once (hit); next two hit the cache.
    assert ssh.probe_calls == 1


# ---------------------------------------------------------------------------
# _compile: ASAN + UBSAN on C PoCs
# ---------------------------------------------------------------------------


async def test_compile_c_uses_asan_and_ubsan_sanitizers(monkeypatch, tmp_path):
    tool = _tool()

    class _CompileSSH(_SSHStub):
        async def run_command(self, integration: dict, command: str, timeout_seconds: float | None = None) -> str:
            self.commands.append((command, integration))
            if command.startswith("mkdir -p"):
                return ""
            # Compile step -- return marker with exit 0 so _compile returns ready.
            return "__AILA_POC_EXIT__:0\n"

        async def upload_file(self, integration: dict, local_path: str, remote_path: str, timeout_seconds: float | None = None) -> None:
            del integration, local_path, remote_path, timeout_seconds

    ssh = _CompileSSH()
    result = await tool._compile(
        ssh,  # type: ignore[arg-type]
        _INTEGRATION,
        code="int main(){return 0;}",
        language="c",
        filename="poc.c",
    )
    assert result["status"] == "ready"
    # The compile command captured on the wire MUST carry both sanitizers.
    compile_cmd = [c for c, _ in ssh.commands if "gcc " in c][0]
    assert "-fsanitize=address,undefined" in compile_cmd
    # -fno-omit-frame-pointer keeps the sanitizer's unwinder honest;
    # -g emits DWARF so ASAN reports resolve to file:line.
    assert "-fno-omit-frame-pointer" in compile_cmd
    assert " -g " in compile_cmd


# ---------------------------------------------------------------------------
# Env override robustness
# ---------------------------------------------------------------------------


async def test_env_override_ignored_when_not_in_chain(monkeypatch):
    """Unknown isolator names must NOT be selected; detection proceeds."""
    monkeypatch.setenv("AILA_VR_POC_ISOLATOR", "kubernetes")

    class _AlwaysFirejailSSH(_SSHStub):
        async def run_command(self, integration: dict, command: str, timeout_seconds: float | None = None) -> str:
            self.commands.append((command, integration))
            if "command -v firejail" in command:
                return "OK\n"
            return await super().run_command(integration, command, timeout_seconds)

    tool = _tool()
    ssh = _AlwaysFirejailSSH()
    await tool._run(
        ssh,  # type: ignore[arg-type]
        _INTEGRATION,
        poc_path="/tmp/aila_vr/poc.py",
        target_binary="/tmp/aila_vr/target",
    )
    run_cmd = [c for c, _ in ssh.commands if "__AILA_POC_EXIT__" in c][0]
    assert "firejail" in run_cmd


def test_ulimit_env_override_refuses_to_execute(monkeypatch, caplog):
    """fix #51 fail-close: forcing the fenceless ``ulimit`` shape via env
    MUST refuse to execute. The audit's ``no code path executes an
    untrusted PoC without network isolation + cap drop`` acceptance
    means an operator override cannot silently downgrade past the
    firejail/unshare gate."""
    monkeypatch.setenv("AILA_VR_POC_ISOLATOR", ISOLATOR_ULIMIT)

    tool = _tool()
    ssh = _SSHStub()
    with caplog.at_level(logging.WARNING, logger="aila.modules.vr.tools.poc_runner"):
        result = asyncio.run(
            tool._run(
                ssh,  # type: ignore[arg-type]
                _INTEGRATION,
                poc_path="/tmp/aila_vr/poc.py",
                target_binary="/tmp/aila_vr/target",
            )
        )
    assert result["status"] == "error"
    assert "AILA_VR_POC_ISOLATOR=ulimit" in result["error"]
    assert any("refusing to execute" in rec.message for rec in caplog.records)
    # No command reached the wire -- not even a detection probe fires when
    # the env override was explicit.
    assert ssh.commands == []


# ---------------------------------------------------------------------------
# Per-run workspace teardown + quota prune (fix #51)
# ---------------------------------------------------------------------------


def test_new_run_dir_produces_unique_paths_under_sandbox_root():
    a = new_run_dir()
    b = new_run_dir()
    assert a != b
    assert a.startswith("/tmp/aila_vr/run_")
    assert b.startswith("/tmp/aila_vr/run_")
    # Both live inside the confined workspace root so the existing
    # confine_remote_poc_path checker accepts a poc file under them.
    assert confine_remote_poc_path(f"{a}/poc.py") is None
    assert confine_remote_poc_path(f"{b}/poc") is None


def test_run_dir_of_extracts_per_run_parent():
    rd = new_run_dir()
    assert run_dir_of(f"{rd}/poc.py") == rd
    assert run_dir_of(f"{rd}/subdir/poc") == rd


def test_run_dir_of_returns_none_for_paths_outside_a_run_subdir():
    # Legacy path directly under the sandbox root -- not owned by any run.
    assert run_dir_of("/tmp/aila_vr/poc.py") is None
    # Non-run prefix -- do NOT treat as a per-run subdir.
    assert run_dir_of("/tmp/aila_vr/notarun_x/poc") is None
    # Escapes the sandbox root -- refuse.
    assert run_dir_of("/etc/passwd") is None
    # Relative path -- refuse.
    assert run_dir_of("poc.py") is None
    # Contains .. -- refuse.
    assert run_dir_of("/tmp/aila_vr/run_x/../etc") is None


def test_build_workspace_prune_cmd_age_and_size_pipeline():
    cmd = build_workspace_prune_cmd("/tmp/aila_vr", 45, 262144)
    # Age pass -- 45-minute cap targets only run_* subdirs of the root.
    assert "find /tmp/aila_vr -maxdepth 1 -type d -name 'run_*'" in cmd
    assert "-mmin +45" in cmd
    # Size pass -- oldest-first eviction until du reports under CAP_KB.
    assert "CAP_KB=262144" in cmd
    assert "sort -n" in cmd
    # mkdir bootstraps a missing workspace so the prune is a no-op on
    # a fresh worker.
    assert cmd.startswith("mkdir -p /tmp/aila_vr")


async def test_compile_c_provisions_per_run_workspace_and_prunes(monkeypatch):
    """fix #51 -- ``compile_poc`` creates ``/tmp/aila_vr/run_<hex>``,
    runs the age+size prune BEFORE gcc, and returns paths inside the
    per-run subdirectory. Assert both the mkdir shape and the prune
    signature so a regression that skips either is caught.

    The workspace caps are supplied via env var so ``ConfigRegistry.get``
    resolves without touching the DB (the tool's registry read is a live
    async call; the env-first layer keeps the unit test hermetic).
    """
    monkeypatch.setenv("AILA_VR_POC_WORKSPACE_MAX_AGE_MINUTES", "45")
    monkeypatch.setenv("AILA_VR_POC_WORKSPACE_MAX_TOTAL_MB", "256")
    tool = _tool()

    class _CompileSSH(_SSHStub):
        async def run_command(self, integration: dict, command: str, timeout_seconds: float | None = None) -> str:
            self.commands.append((command, integration))
            if command.startswith("mkdir -p") and "find " in command:
                # Prune pipeline (mkdir -p ... && find ...); nothing to return.
                return ""
            if command.startswith("mkdir -p"):
                return ""
            return "__AILA_POC_EXIT__:0\n"

        async def upload_file(self, integration: dict, local_path: str, remote_path: str, timeout_seconds: float | None = None) -> None:
            del integration, local_path, remote_path, timeout_seconds

    ssh = _CompileSSH()
    result = await tool._compile(
        ssh,  # type: ignore[arg-type]
        _INTEGRATION,
        code="int main(){return 0;}",
        language="c",
        filename="poc.c",
    )
    assert result["status"] == "ready"
    # Per-run subdirectory returned + threaded into paths.
    assert result["run_dir"].startswith("/tmp/aila_vr/run_")
    assert result["binary_path"].startswith(result["run_dir"] + "/")
    assert result["source_path"].startswith(result["run_dir"] + "/")
    # A dedicated mkdir for the run subdir hit the wire.
    mkdir_cmds = [c for c, _ in ssh.commands if c.startswith("mkdir -p /tmp/aila_vr/run_")]
    assert len(mkdir_cmds) == 1
    # Prune pipeline ran with the workspace root as scope.
    prune_cmds = [
        c for c, _ in ssh.commands
        if "-name 'run_*'" in c and "-mmin +" in c and "CAP_KB=" in c
    ]
    assert len(prune_cmds) == 1


async def test_cleanup_workspace_removes_per_run_subdir():
    """fix #51 -- ``cleanup_workspace`` issues an ``rm -rf`` against the
    per-run subdir resolved from ``poc_path``."""
    tool = _tool()
    ssh = _SSHStub()
    run_dir = new_run_dir()
    result = await tool._cleanup(
        ssh,  # type: ignore[arg-type]
        _INTEGRATION,
        poc_path=f"{run_dir}/poc.py",
    )
    assert result["status"] == "cleaned"
    assert result["run_dir"] == run_dir
    rm_cmds = [c for c, _ in ssh.commands if c.startswith("rm -rf --")]
    assert len(rm_cmds) == 1
    assert run_dir in rm_cmds[0]


async def test_cleanup_workspace_skips_legacy_paths():
    """A ``poc_path`` directly under the sandbox root (pre-per-run layout)
    is not owned by any run subdir -- ``cleanup_workspace`` returns
    ``skipped`` and issues no rm."""
    tool = _tool()
    ssh = _SSHStub()
    result = await tool._cleanup(
        ssh,  # type: ignore[arg-type]
        _INTEGRATION,
        poc_path="/tmp/aila_vr/poc.py",
    )
    assert result["status"] == "skipped"
    assert ssh.commands == []


async def test_cleanup_workspace_refuses_paths_outside_sandbox():
    tool = _tool()
    ssh = _SSHStub()
    result = await tool._cleanup(
        ssh,  # type: ignore[arg-type]
        _INTEGRATION,
        poc_path="/etc/passwd",
    )
    assert result["status"] == "error"
    assert "escapes" in result["error"]
    assert ssh.commands == []


async def test_cleanup_workspace_refuses_sandbox_root_via_run_dir():
    """An explicit ``run_dir=/tmp/aila_vr`` (or any path outside the
    ``run_<hex>`` layout) MUST NOT trigger an ``rm -rf`` of the shared
    workspace root. Belt+suspenders check inside ``_cleanup``."""
    tool = _tool()
    ssh = _SSHStub()
    for candidate in (
        "/tmp/aila_vr",
        "/tmp/aila_vr/sub/child",
        "/tmp/aila_vr/notarun_x",
        "/etc",
    ):
        result = await tool._cleanup(
            ssh,  # type: ignore[arg-type]
            _INTEGRATION,
            run_dir=candidate,
        )
        assert result["status"] == "error", candidate
    assert ssh.commands == []
