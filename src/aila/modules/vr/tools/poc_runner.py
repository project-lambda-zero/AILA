"""PoC runner -- uploads, compiles, and executes vulnerability PoCs over SSH.

Sandbox model (fix #51):

1. ``poc_path`` is confined to :data:`_REMOTE_DIR` -- any request whose
   normalized POSIX path is not absolute, contains ``..``, or does not lie
   under ``/tmp/aila_vr`` is rejected before it reaches the shell. Mirrors
   the report-path confinement pattern in
   :mod:`aila.platform.tools.reporting` (#53).
2. Every remote invocation is wrapped in an isolation layer with a
   documented fallback chain: ``firejail`` (preferred; wraps net=none +
   caps.drop=all + seccomp + private tmp) -> ``unshare + setpriv``
   (fresh user/net/pid/mount/ipc/uts/cgroup namespaces + no_new_privs +
   dropped ambient/inheritable capabilities) -> bare ``ulimit + timeout``
   with a logged WARNING when neither of the first two is available.
3. C PoCs are compiled ``-fsanitize=address,undefined -fno-omit-frame-pointer
   -g`` so a hallucinated write / UAF surfaces as an ASAN report the crash
   parser can attribute reliably.
4. The wrapper always exits 0 and embeds the real PoC exit code between
   ``__AILA_POC_*__`` markers so paramiko's non-zero-raises path doesn't
   swallow legitimate crash signals (139/134/136).

End-to-end isolation efficacy needs a live Linux target with unshare or
firejail installed for the parent to verify.
"""
from __future__ import annotations

import logging
import os
import re
import shlex
import tempfile
from pathlib import PurePosixPath
from typing import Any

from aila.config import Settings
from aila.platform.config import build_platform_settings
from aila.platform.services import SSHService
from aila.platform.tools import Tool

__all__ = [
    "PoCRunnerTool",
    "apply_isolator",
    "build_run_wrapper",
    "confine_remote_poc_path",
]

_log = logging.getLogger(__name__)

_REMOTE_DIR = "/tmp/aila_vr"
_EXIT_MARKER = "__AILA_POC_EXIT__:"
_OUT_BEGIN = "__AILA_POC_OUT_BEGIN__"
_OUT_END = "__AILA_POC_OUT_END__"
_ERR_BEGIN = "__AILA_POC_ERR_BEGIN__"
_ERR_END = "__AILA_POC_ERR_END__"
_TAIL_LIMIT = 2000
# 128 + signal: SIGABRT=6, SIGFPE=8, SIGSEGV=11. 124 is GNU timeout's hit code.
_CRASH_EXIT_CODES = frozenset({134, 136, 139})
_TIMEOUT_EXIT_CODE = 124

# Isolation layer identifiers -- exposed for the operator config override
# and referenced by :func:`apply_isolator` / :func:`build_run_wrapper`.
ISOLATOR_FIREJAIL = "firejail"
ISOLATOR_UNSHARE = "unshare"
ISOLATOR_ULIMIT = "ulimit"
# Fallback chain (fix #51). Prefer firejail because it batteries-includes
# seccomp, netns, and a private tmp; then unshare+setpriv, which util-linux
# 2.34+ ships on every modern distro and which needs no root because the
# user namespace grants CAP_SYS_ADMIN inside the sandbox; else the
# ulimit-only path with a logged WARNING so the operator sees the missing
# isolation surface.
_ISOLATOR_FALLBACK_CHAIN: tuple[str, ...] = (
    ISOLATOR_FIREJAIL,
    ISOLATOR_UNSHARE,
    ISOLATOR_ULIMIT,
)
# Env override for tests and operator escape hatches. Values outside the
# chain are ignored and detection proceeds normally.
_ISOLATOR_ENV_OVERRIDE = "AILA_VR_POC_ISOLATOR"
_ULIMIT_FALLBACK_WARNING = (
    "poc_runner: neither firejail nor unshare+setpriv found on the target; "
    "falling back to bare ulimit+timeout -- no network isolation, no "
    "capability drop. Install firejail or util-linux>=2.34 on the analyzer "
    "workstation to close this gap."
)


def _between(text: str, begin: str, end: str) -> str:
    a = text.find(begin)
    if a < 0:
        return ""
    start = a + len(begin)
    b = text.find(end, start)
    return (text[start:b] if b >= 0 else text[start:]).strip("\n")


def _parse_exit(text: str) -> int | None:
    m = re.search(rf"{re.escape(_EXIT_MARKER)}(-?\d+)", text)
    return int(m.group(1)) if m else None


def _err(message: str) -> dict:
    return {"status": "error", "error": message}


def confine_remote_poc_path(poc_path: str | None) -> str | None:
    """Validate that ``poc_path`` sits inside :data:`_REMOTE_DIR` (fix #51).

    Mirrors the report-path confinement pattern in
    :mod:`aila.platform.tools.reporting` (#53). ``poc_path`` is a POSIX
    path on the analyzer workstation, so we normalize with
    :class:`PurePosixPath` and refuse any input that is not absolute,
    contains ``..`` segments, resolves outside ``_REMOTE_DIR``, or
    points at the sandbox root itself. Returns ``None`` when the path
    is safe, else a human-readable error message the caller should
    surface via :func:`_err`.

    Path resolution happens locally without touching the target so a
    tampered compile response or a direct API call cannot execute an
    arbitrary binary via a crafted absolute path (``shlex.quote`` only
    stops arg injection, not path selection).
    """
    if not poc_path or not isinstance(poc_path, str):
        return "poc_path is required"
    candidate = PurePosixPath(poc_path)
    if not candidate.is_absolute():
        return f"poc_path must be an absolute path under {_REMOTE_DIR}"
    if ".." in candidate.parts:
        return "poc_path must not contain '..' segments"
    root = PurePosixPath(_REMOTE_DIR)
    if candidate == root or not candidate.is_relative_to(root):
        return f"poc_path {poc_path!r} escapes sandbox root {_REMOTE_DIR}"
    return None


def apply_isolator(invoke: str, isolator: str) -> str:
    """Return ``invoke`` wrapped in the chosen isolation layer (fix #51).

    - :data:`ISOLATOR_FIREJAIL`: ``--net=none`` blocks all network egress,
      ``--caps.drop=all`` drops every ambient capability,
      ``--seccomp`` installs the default seccomp-bpf filter,
      ``--private-tmp`` gives a private ``/tmp``, ``--nogroups`` drops
      supplementary groups, ``--disable-mnt`` hides ``/mnt``, and
      ``--noprofile`` disables the operator's default firejail profile so
      the fenced arguments are the sole policy source.
    - :data:`ISOLATOR_UNSHARE`: opens fresh ``user`` / ``net`` / ``pid``
      / ``mount`` / ``ipc`` / ``uts`` / ``cgroup`` namespaces, then chains
      ``setpriv --no-new-privs --inh-caps=-all --ambient-caps=-all`` so
      the PoC executes with the ``no_new_privs`` bit set and no
      inheritable or ambient capabilities. Available on every modern
      Linux (util-linux 2.34+); needs no root because the user
      namespace grants CAP_SYS_ADMIN inside the sandbox.
    - :data:`ISOLATOR_ULIMIT`: last-resort fallback; a bare bash wrap so
      the outer wrapper's ``ulimit -v`` and ``timeout`` still apply.
      Callers log a WARNING at this level so the operator sees the
      missing isolation surface.

    Constructed as a pure text transform so unit tests can assert the
    command shape without a live target.
    """
    quoted = shlex.quote(invoke)
    if isolator == ISOLATOR_FIREJAIL:
        return (
            "firejail --quiet --net=none --caps.drop=all --seccomp "
            "--nogroups --disable-mnt --private-tmp --noprofile "
            f"-- bash -c {quoted}"
        )
    if isolator == ISOLATOR_UNSHARE:
        return (
            "unshare --user --net --pid --mount --ipc --uts --cgroup "
            "--fork --map-root-user --mount-proc "
            "setpriv --no-new-privs --inh-caps=-all --ambient-caps=-all "
            f"-- bash -c {quoted}"
        )
    if isolator == ISOLATOR_ULIMIT:
        return f"bash -c {quoted}"
    raise ValueError(f"unknown isolator: {isolator!r}")


def build_run_wrapper(
    invoke: str,
    timeout_s: float,
    mem_kb: int,
    isolator: str,
) -> str:
    """Compose the outer bash wrapper that runs ``invoke`` inside
    ``isolator`` under ``ulimit -v`` and GNU ``timeout``.

    Structure (single line for ``bash -lc`` friendliness)::

        so=$(mktemp); se=$(mktemp);
        { ulimit -v <mem_kb>;
          timeout --kill-after=5s <timeout>s <isolated>; } >"$so" 2>"$se";
        ec=$?;
        printf "__AILA_POC_EXIT__:%s\\n" "$ec";
        printf "__AILA_POC_OUT_BEGIN__\\n"; cat "$so";
        printf "\\n__AILA_POC_OUT_END__\\n";
        printf "__AILA_POC_ERR_BEGIN__\\n"; cat "$se";
        printf "\\n__AILA_POC_ERR_END__\\n";
        rm -f "$so" "$se"

    The wrapper always exits 0 (paramiko's non-zero-raises path would
    otherwise swallow crash signals 134/136/139); the PoC's real exit
    code sits between the ``__AILA_POC_EXIT__:`` marker and the newline.
    ``timeout --kill-after=5s`` sends SIGTERM at the deadline, then
    SIGKILL after a 5s grace so a PoC ignoring SIGTERM cannot camp on
    the SSH channel indefinitely.
    """
    isolated = apply_isolator(invoke, isolator)
    return (
        "so=$(mktemp); se=$(mktemp); "
        f'{{ ulimit -v {mem_kb}; timeout --kill-after=5s {timeout_s:g}s {isolated}; }} '
        f'>"$so" 2>"$se"; ec=$?; '
        f'printf "{_EXIT_MARKER}%s\\n" "$ec"; '
        f'printf "{_OUT_BEGIN}\\n"; cat "$so"; printf "\\n{_OUT_END}\\n"; '
        f'printf "{_ERR_BEGIN}\\n"; cat "$se"; printf "\\n{_ERR_END}\\n"; '
        'rm -f "$so" "$se"'
    )


class PoCRunnerTool(Tool):
    name = "vr.poc_runner"
    description = (
        "Upload, compile, and execute vulnerability PoC scripts on the research "
        "workstation. Verifies crash on vulnerable version and clean exit on "
        "patched version."
    )
    inputs = {"action": {"type": "string", "description": "compile_poc, run_poc, verify_reliability"}}
    output_type = "object"
    skip_forward_signature_validation = True

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        # Isolator detection is one SSH round-trip per (host,port,user);
        # cache per integration so a `verify_reliability` action that
        # calls `_run` N times only probes once.
        self._isolator_cache: dict[str, str] = {}

    async def _resolve_isolator(
        self, ssh: SSHService, integration: dict,
    ) -> tuple[str, str | None]:
        """Return the isolator to use plus an optional warning message (fix #51).

        Resolution order:

        1. ``AILA_VR_POC_ISOLATOR`` env override (values outside the
           fallback chain are ignored). Ops escape hatch + test seam.
        2. Cached decision for this ``(host, port, username)`` triple.
        3. Probe ``firejail`` then ``unshare``+``setpriv``. First hit wins.
        4. Fall back to :data:`ISOLATOR_ULIMIT` with the documented
           WARNING so the operator sees the missing isolation surface.

        Probe failures (OS error, timeout) are logged and treated as
        "tool missing" rather than propagated -- we would rather run
        under the next fallback than crash the PoC pipeline.
        """
        override = os.environ.get(_ISOLATOR_ENV_OVERRIDE)
        if override in _ISOLATOR_FALLBACK_CHAIN:
            warning = _ULIMIT_FALLBACK_WARNING if override == ISOLATOR_ULIMIT else None
            return override, warning

        key = (
            f"{integration.get('host', '')}:{integration.get('port', '')}"
            f":{integration.get('username', '')}"
        )
        cached = self._isolator_cache.get(key)
        if cached is not None:
            warning = _ULIMIT_FALLBACK_WARNING if cached == ISOLATOR_ULIMIT else None
            return cached, warning

        probes: tuple[tuple[str, str], ...] = (
            (ISOLATOR_FIREJAIL, "command -v firejail"),
            (ISOLATOR_UNSHARE, "command -v unshare && command -v setpriv"),
        )
        for tool, probe in probes:
            try:
                out = await ssh.run_command(
                    integration,
                    f"{probe} >/dev/null 2>&1 && echo OK || echo MISSING",
                    timeout_seconds=15.0,
                )
            except (OSError, RuntimeError, TimeoutError) as exc:
                _log.warning(
                    "poc_runner: isolator probe %s failed (%s: %s); "
                    "trying next fallback",
                    tool, type(exc).__name__, exc,
                )
                continue
            if "OK" in out:
                self._isolator_cache[key] = tool
                return tool, None
        self._isolator_cache[key] = ISOLATOR_ULIMIT
        return ISOLATOR_ULIMIT, _ULIMIT_FALLBACK_WARNING

    async def forward(self, action: str | None = None, **kwargs: Any) -> dict:
        if not action:
            return _err("action is required")
        integration = kwargs.pop("integration", None)
        if not isinstance(integration, dict) or not integration:
            return _err("integration (SSH config) is required")
        ssh = SSHService(build_platform_settings(self.settings))
        handlers = {"compile_poc": self._compile, "run_poc": self._run, "verify_reliability": self._reliability}
        handler = handlers.get(action)
        if handler is None:
            return _err(f"unknown action: {action}")
        return await handler(ssh, integration, **kwargs)

    async def _compile(
        self, ssh: SSHService, integration: dict,
        code: str | None = None, language: str = "python",
        filename: str | None = None, **_extra: Any,
    ) -> dict:
        if not isinstance(code, str) or not code:
            return _err("code is required")
        if not isinstance(filename, str) or not filename or "/" in filename or "\\" in filename:
            return _err("filename must be a bare basename")
        if language not in ("python", "c"):
            return _err(f"unsupported language: {language}")

        remote_src = f"{_REMOTE_DIR}/{filename}"
        await ssh.run_command(integration, f"mkdir -p {shlex.quote(_REMOTE_DIR)}", timeout_seconds=30.0)

        local_fd, local_path = tempfile.mkstemp(prefix="aila_vr_", suffix=f"_{filename}")
        os.close(local_fd)
        try:
            with open(local_path, "w", encoding="utf-8", newline="\n") as fh:
                fh.write(code)
            await ssh.upload_file(integration, local_path, remote_src, timeout_seconds=120.0)
        finally:
            try:
                os.unlink(local_path)
            except OSError:
                pass

        if language == "python":
            return {"status": "ready", "language": "python", "script_path": remote_src}

        binary_path = f"{_REMOTE_DIR}/{PurePosixPath(filename).stem or 'poc'}"
        # fix #51 -- ASAN + UBSAN so untrusted C surfaces OOB writes / UAF /
        # signed-overflow with a full stack trace instead of a bare SIGSEGV,
        # letting the crash-triage tool attribute the frames reliably.
        # -fno-omit-frame-pointer keeps the sanitizer's unwinder honest;
        # -g emits DWARF for symbol/line resolution in the ASAN report.
        compile_cmd = (
            f"{{ gcc -o {shlex.quote(binary_path)} {shlex.quote(remote_src)} "
            f"-fsanitize=address,undefined -fno-omit-frame-pointer -g -lpthread; }} "
            f'2>&1; printf "{_EXIT_MARKER}%s\\n" "$?"'
        )
        output = await ssh.run_command(integration, compile_cmd, timeout_seconds=180.0)
        exit_code = _parse_exit(output)
        compile_output = re.sub(rf"\n?{re.escape(_EXIT_MARKER)}-?\d+\s*$", "", output).rstrip("\n")
        compile_output = compile_output[-_TAIL_LIMIT:]
        if exit_code != 0:
            return {"status": "error", "error": "compilation failed",
                    "exit_code": exit_code, "compile_output": compile_output,
                    "source_path": remote_src}
        return {"status": "ready", "language": "c",
                "binary_path": binary_path, "compile_output": compile_output,
                "source_path": remote_src}

    async def _run(
        self, ssh: SSHService, integration: dict,
        poc_path: str | None = None, target_binary: str | None = None,
        timeout_seconds: float = 30.0, memory_limit_mb: int = 2048,
        **_extra: Any,
    ) -> dict:
        # fix #51 -- confine poc_path to the sandbox root BEFORE any
        # shell construction so a tampered compile response or a direct
        # API call cannot select an existing host binary. shlex.quote
        # blocks arg injection; it does NOT block path selection.
        if not isinstance(poc_path, str) or not poc_path:
            return _err("poc_path is required")
        confinement_error = confine_remote_poc_path(poc_path)
        if confinement_error:
            return _err(confinement_error)
        if not isinstance(target_binary, str) or not target_binary:
            return _err("target_binary is required")
        try:
            timeout = float(timeout_seconds)
            mem_kb = max(int(memory_limit_mb), 256) * 1024
        except (TypeError, ValueError):
            return _err("invalid timeout/memory args")

        invoke = (
            f"python3 {shlex.quote(poc_path)} {shlex.quote(target_binary)}"
            if poc_path.endswith(".py")
            else f"{shlex.quote(poc_path)} {shlex.quote(target_binary)}"
        )
        # fix #51 -- resolve the isolation layer (firejail -> unshare ->
        # ulimit) then compose the wrapper as a pure text transform so
        # tests can assert the constructed command without a live target.
        isolator, isolator_warning = await self._resolve_isolator(ssh, integration)
        if isolator_warning:
            _log.warning("%s", isolator_warning)
        wrapper = build_run_wrapper(invoke, timeout, mem_kb, isolator)
        cmd = f"bash -lc {shlex.quote(wrapper)}"
        # timeout --kill-after=5s in build_run_wrapper adds a 5s grace,
        # so give paramiko's idle timer a matching cushion above the
        # PoC deadline.
        ssh_idle_timeout = max(timeout + 35.0, 60.0)
        output = await ssh.run_command(integration, cmd, timeout_seconds=ssh_idle_timeout)

        exit_code = _parse_exit(output)
        stdout_text = _between(output, _OUT_BEGIN, _OUT_END)
        stderr_text = _between(output, _ERR_BEGIN, _ERR_END)
        asan_report = "ERROR: AddressSanitizer" in stderr_text or "ERROR: AddressSanitizer" in stdout_text
        return {
            "status": "ready",
            "exit_code": exit_code,
            "crash_detected": bool(exit_code in _CRASH_EXIT_CODES or asan_report),
            "clean_exit": bool(exit_code == 0 and not asan_report),
            "timeout": bool(exit_code == _TIMEOUT_EXIT_CODE),
            "asan_report": asan_report,
            "stderr_tail": stderr_text[-_TAIL_LIMIT:],
            "stdout_tail": stdout_text[-_TAIL_LIMIT:],
        }

    async def _reliability(
        self, ssh: SSHService, integration: dict,
        poc_path: str | None = None, target_binary: str | None = None,
        runs: int = 5, timeout_seconds: float = 30.0,
        memory_limit_mb: int = 2048, **_extra: Any,
    ) -> dict:
        try:
            total = max(1, int(runs))
        except (TypeError, ValueError):
            return _err("runs must be an integer")

        all_results: list[dict] = []
        crashes = 0
        for _ in range(total):
            result = await self._run(ssh, integration, poc_path=poc_path, target_binary=target_binary,
                                     timeout_seconds=timeout_seconds, memory_limit_mb=memory_limit_mb)
            all_results.append(result)
            if result.get("crash_detected"):
                crashes += 1
        return {
            "status": "ready",
            "crashes": crashes,
            "total": total,
            "reliability": f"{crashes}/{total}",
            "all_results": all_results,
        }
