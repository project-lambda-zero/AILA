"""PoC runner -- uploads, compiles, and executes vulnerability PoCs over SSH.

Follow-up (issue #147): the platform now owns a real sandbox primitive at
``aila.platform.services.sandbox`` (nsjail / Firecracker over SSH, exposed
as the ``sandbox_exec`` platform tool). Once an operator provisions a
sandbox host for a given deployment, the module MUST migrate this file
to route every ``firejail`` / ``unshare`` invocation through
``SandboxService.run``, deleting the local isolator resolver + wrapper
plumbing below. The migration is deliberately deferred here because the
sandbox has no configured host on the current deployment, and removing
the local firejail/unshare fallback before that would leave VR PoC
execution un-isolated -- exactly the failure mode the new primitive is
supposed to prevent. See ``docs/CLAUDE.md`` follow-ups section.

Sandbox model (fix #51):

1. ``poc_path`` is confined to :data:`_REMOTE_DIR` -- any request whose
   normalized POSIX path is not absolute, contains ``..``, or does not lie
   under ``/tmp/aila_vr`` is rejected before it reaches the shell. Mirrors
   the report-path confinement pattern in
   :mod:`aila.platform.tools.reporting` (#53).
2. Every remote invocation is wrapped in an isolation layer with a
   fail-closed resolution: ``firejail`` (preferred; wraps net=none +
   caps.drop=all + seccomp + private tmp) -> ``unshare + setpriv``
   (fresh user/net/pid/mount/ipc/uts/cgroup namespaces + no_new_privs +
   dropped ambient/inheritable capabilities). When neither is present
   on the target the runner REFUSES to execute: it returns
   ``status="error"`` with a clear reason instead of running the
   untrusted PoC under bare ``ulimit + timeout`` (which offers no
   network isolation and no capability drop). The ``ulimit`` shape is
   retained on :func:`apply_isolator` and :func:`build_run_wrapper` so
   tests can still exercise the wrapper composition, but the runtime
   resolver never selects it.
3. C PoCs are compiled ``-fsanitize=address,undefined -fno-omit-frame-pointer
   -g`` so a hallucinated write / UAF surfaces as an ASAN report the crash
   parser can attribute reliably.
4. The wrapper always exits 0 and embeds the real PoC exit code between
   ``__AILA_POC_*__`` markers so paramiko's non-zero-raises path doesn't
   swallow legitimate crash signals (139/134/136).
5. Every compile allocates a per-run subdirectory
   ``/tmp/aila_vr/run_<hex>`` and returns paths inside it. The
   workflow reclaims that subdirectory via the ``cleanup_workspace``
   action in a ``finally``. Additionally, every compile triggers an
   age + total-size prune pass over the shared workspace root, so an
   orphaned subdirectory (crashed workflow, aborted run) does not let
   ``/tmp/aila_vr`` grow without bound. Both caps are read live via
   :class:`ConfigRegistry` in the ``vr`` namespace so an operator can
   tune them without a worker restart.

End-to-end isolation efficacy needs a live Linux target with unshare or
firejail installed for the parent to verify.
"""
from __future__ import annotations

import logging
import os
import re
import shlex
import tempfile
import uuid
from pathlib import PurePosixPath
from typing import Any

from sqlalchemy.exc import SQLAlchemyError

from aila.config import Settings
from aila.platform.config import build_platform_settings
from aila.platform.services import SSHService
from aila.platform.tools import Tool
from aila.storage.registry import ConfigRegistry

__all__ = [
    "PoCRunnerTool",
    "apply_isolator",
    "build_run_wrapper",
    "build_workspace_prune_cmd",
    "confine_remote_poc_path",
    "new_run_dir",
    "run_dir_of",
]

_log = logging.getLogger(__name__)

_REMOTE_DIR = "/tmp/aila_vr"
_RUN_DIR_PREFIX = "run_"
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
# Fail-closed resolver chain (fix #51). Only real sandboxes appear here.
# firejail is preferred because it batteries-includes seccomp, netns, and
# a private tmp; then unshare+setpriv, which util-linux 2.34+ ships on
# every modern distro and which needs no root because the user namespace
# grants CAP_SYS_ADMIN inside the sandbox. ``ISOLATOR_ULIMIT`` is a
# fenceless bash wrap -- it stays valid as an identifier so tests can
# assert the wrapper composition without a live target, but the runtime
# resolver never selects it. Auto-detection failure and an explicit env
# override to ``ulimit`` both refuse to execute (see ``_resolve_isolator``).
_ISOLATOR_RESOLVE_CHAIN: tuple[str, ...] = (ISOLATOR_FIREJAIL, ISOLATOR_UNSHARE)
# Env override for tests and operator escape hatches. Only firejail or
# unshare are accepted; ``ulimit`` explicitly REFUSES so no code path
# executes an untrusted PoC without a real network + capability fence.
_ISOLATOR_ENV_OVERRIDE = "AILA_VR_POC_ISOLATOR"
_NO_ISOLATOR_REFUSAL = (
    "poc_runner: refusing to execute -- neither firejail nor unshare+setpriv "
    "is available on the target. Install firejail or util-linux>=2.34 on the "
    "analyzer workstation so untrusted PoC code can be fenced with network "
    "isolation and capability drop."
)
_ULIMIT_OVERRIDE_REFUSAL = (
    "poc_runner: refusing to execute -- AILA_VR_POC_ISOLATOR=ulimit is a "
    "fenceless bash wrap with no network isolation and no capability drop. "
    "Set the override to 'firejail' or 'unshare', or unset it to auto-detect."
)

# Workspace quota + age caps (fix #51). Resolved live from ConfigRegistry
# so an operator ``PUT /config/vr/*`` lands on the next compile without a
# worker restart. Defaults kick in when the schema has not yet been
# registered (bootstrap window) or the registry read fails.
_WORKSPACE_MAX_AGE_KEY = "poc_workspace_max_age_minutes"
_WORKSPACE_MAX_TOTAL_KEY = "poc_workspace_max_total_mb"
_WORKSPACE_MAX_AGE_DEFAULT_MIN = 60
_WORKSPACE_MAX_TOTAL_DEFAULT_MB = 512
_WORKSPACE_PRUNE_TIMEOUT_S = 60.0
_WORKSPACE_CLEANUP_TIMEOUT_S = 60.0

_registry: ConfigRegistry | None = None


def _get_registry() -> ConfigRegistry:
    """Lazy singleton -- one registry instance per worker process.

    Mirrors the pattern in :mod:`aila.modules.vr.services.investigation_reaper`
    so PoC-runner reads amortize construction over the workflow.
    """
    global _registry
    if _registry is None:
        _registry = ConfigRegistry()
    return _registry


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


def new_run_dir() -> str:
    """Return a fresh per-run absolute POSIX subdirectory of :data:`_REMOTE_DIR`.

    Format ``/tmp/aila_vr/run_<32-hex>``. A ``uuid4`` supplies the suffix
    so two concurrent compile calls on the same worker never collide, and
    the ``run_`` prefix lets :func:`build_workspace_prune_cmd` and
    :func:`run_dir_of` recognize per-run subdirectories without confusing
    them with an operator-created sibling under ``/tmp/aila_vr``.
    """
    return f"{_REMOTE_DIR}/{_RUN_DIR_PREFIX}{uuid.uuid4().hex}"


def run_dir_of(poc_path: str) -> str | None:
    """Return the ``/tmp/aila_vr/run_<hex>`` parent for ``poc_path``, else None.

    ``poc_path`` MUST already be a confined absolute POSIX path under
    :data:`_REMOTE_DIR`; callers pass ``confine_remote_poc_path``'s output
    or a value it accepts. The function returns ``None`` when the path
    does not sit inside a per-run subdirectory (e.g. a legacy value
    directly under ``_REMOTE_DIR``) so callers can skip cleanup instead
    of removing the shared root.
    """
    candidate = PurePosixPath(poc_path)
    if not candidate.is_absolute() or ".." in candidate.parts:
        return None
    root = PurePosixPath(_REMOTE_DIR)
    try:
        rel = candidate.relative_to(root)
    except ValueError:
        return None
    parts = rel.parts
    if not parts or not parts[0].startswith(_RUN_DIR_PREFIX):
        return None
    return str(root / parts[0])


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
    - :data:`ISOLATOR_ULIMIT`: fenceless bash wrap retained ONLY so tests
      can assert the wrapper composition without a live target. The
      runtime resolver never selects it (fail-closed policy, fix #51);
      the outer :func:`build_run_wrapper` still layers ``ulimit -v`` and
      ``timeout`` around whatever isolator is composed here.

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


def build_workspace_prune_cmd(root: str, max_age_min: int, max_total_kb: int) -> str:
    """Return a bash pipeline that bounds ``root`` by age and total size.

    Two independent passes, both scoped to ``root/run_*`` subdirectories
    so a stray operator-owned sibling under ``/tmp/aila_vr`` is never
    touched:

    1. Age pass: ``find ... -mmin +N -exec rm -rf {} +`` removes every
       ``run_*`` subdirectory whose mtime is older than ``max_age_min``
       minutes. This alone reclaims workspaces left behind by crashed
       workflows or an aborted worker.
    2. Size pass: iterates the remaining ``run_*`` oldest-first via
       ``find -printf '%T@ %p\\n' | sort -n`` and deletes until
       ``du -sk`` reports the tree below ``max_total_kb`` KiB. Bounded
       by a per-iteration break so a broken ``du`` cannot spin forever.

    ``mkdir -p`` runs first so the prune is a no-op on a fresh worker
    where ``root`` does not yet exist. Every command tolerates missing
    binaries with ``|| true`` so a target without GNU ``find`` cannot
    surface a prune failure to the caller's compile path -- the prune
    is a best-effort quota, not a correctness gate.
    """
    quoted_root = shlex.quote(root)
    return (
        f"mkdir -p {quoted_root} && "
        f"find {quoted_root} -maxdepth 1 -type d -name '{_RUN_DIR_PREFIX}*' "
        f"-mmin +{int(max_age_min)} -exec rm -rf -- {{}} + 2>/dev/null || true; "
        f"CAP_KB={int(max_total_kb)}; "
        f"for _ in $(seq 1 1024); do "
        f"  TOT=$(du -sk {quoted_root} 2>/dev/null | awk '{{print $1}}'); "
        f'  if [ -z "$TOT" ] || [ "$TOT" -le "$CAP_KB" ]; then break; fi; '
        f"  OLDEST=$(find {quoted_root} -maxdepth 1 -type d "
        f"-name '{_RUN_DIR_PREFIX}*' -printf '%T@\\t%p\\n' 2>/dev/null "
        f"| sort -n | head -1 | cut -f2-); "
        f'  if [ -z "$OLDEST" ]; then break; fi; '
        f'  rm -rf -- "$OLDEST" 2>/dev/null || break; '
        f"done"
    )


class PoCRunnerTool(Tool):
    name = "vr.poc_runner"
    description = (
        "Upload, compile, and execute vulnerability PoC scripts on the research "
        "workstation. Verifies crash on vulnerable version and clean exit on "
        "patched version."
    )
    inputs = {
        "action": {
            "type": "string",
            "description": (
                "compile_poc, run_poc, verify_reliability, cleanup_workspace"
            ),
        },
    }
    output_type = "object"
    skip_forward_signature_validation = True

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        # Isolator detection is one SSH round-trip per (host,port,user);
        # cache per integration so a `verify_reliability` action that
        # calls `_run` N times only probes once.
        self._isolator_cache: dict[str, str] = {}

    async def _resolve_workspace_caps(self) -> tuple[int, int]:
        """Return ``(max_age_minutes, max_total_kb)`` for the workspace prune.

        Layered lookup via :class:`ConfigRegistry` in the ``vr`` namespace:
        ``AILA_VR_POC_WORKSPACE_MAX_*`` env -> DB -> schema default. The
        registry may return ``None`` during the bootstrap window before
        the VR schema has been registered; the module-scoped defaults
        (60 minutes, 512 MiB) fill that gap so a compile pre-registration
        still runs a coherent prune. A registry or coercion failure never
        aborts the compile path; the fallback keeps growth bounded even
        when the operator config surface is down.
        """
        reg = _get_registry()
        try:
            raw_age = await reg.get("vr", _WORKSPACE_MAX_AGE_KEY)
            raw_total = await reg.get("vr", _WORKSPACE_MAX_TOTAL_KEY)
        except (OSError, RuntimeError, ValueError, TimeoutError, SQLAlchemyError) as exc:
            _log.warning(
                "poc_runner: workspace-cap registry read failed (%s: %s); "
                "using defaults",
                type(exc).__name__, exc,
            )
            raw_age = None
            raw_total = None
        try:
            age_min = int(
                raw_age if raw_age is not None else _WORKSPACE_MAX_AGE_DEFAULT_MIN,
            )
            total_mb = int(
                raw_total if raw_total is not None else _WORKSPACE_MAX_TOTAL_DEFAULT_MB,
            )
        except (TypeError, ValueError):
            age_min = _WORKSPACE_MAX_AGE_DEFAULT_MIN
            total_mb = _WORKSPACE_MAX_TOTAL_DEFAULT_MB
        age_min = max(1, age_min)
        total_mb = max(1, total_mb)
        return age_min, total_mb * 1024

    async def _prune_workspace(self, ssh: SSHService, integration: dict) -> None:
        """Best-effort quota + age prune of the shared workspace root.

        Invoked at every ``_compile`` so the analyzer workstation never
        grows an unbounded ``/tmp/aila_vr`` tree even when a workflow
        crashes before its ``cleanup_workspace`` finally fires. Failures
        are logged and swallowed -- a broken prune must not abort the
        compile path.
        """
        try:
            age_min, total_kb = await self._resolve_workspace_caps()
            cmd = build_workspace_prune_cmd(_REMOTE_DIR, age_min, total_kb)
            await ssh.run_command(
                integration, cmd, timeout_seconds=_WORKSPACE_PRUNE_TIMEOUT_S,
            )
        except (OSError, RuntimeError, ValueError, TimeoutError, SQLAlchemyError) as exc:
            _log.warning(
                "poc_runner: workspace prune failed (%s: %s); continuing compile",
                type(exc).__name__, exc,
            )

    async def _resolve_isolator(
        self, ssh: SSHService, integration: dict,
    ) -> tuple[str | None, str | None]:
        """Return ``(isolator, refusal_reason)`` -- fail-closed (fix #51).

        Resolution order:

        1. ``AILA_VR_POC_ISOLATOR`` env override. Only ``firejail`` and
           ``unshare`` are accepted; ``ulimit`` explicitly refuses so a
           misconfigured override cannot execute an untrusted PoC without
           a real network + capability fence. Unknown values are ignored
           and detection proceeds normally.
        2. Cached decision for this ``(host, port, username)`` triple.
        3. Probe ``firejail`` then ``unshare``+``setpriv``. First hit wins.
        4. Refuse: return ``(None, _NO_ISOLATOR_REFUSAL)`` so the caller
           surfaces the reason via :func:`_err` and never dispatches a
           bare bash wrap.

        Probe failures (OS error, timeout) are logged and treated as
        "tool missing" rather than propagated -- we would rather refuse
        cleanly than crash the workflow, and a subsequent compile pass
        will re-probe.
        """
        override = os.environ.get(_ISOLATOR_ENV_OVERRIDE)
        if override == ISOLATOR_ULIMIT:
            return None, _ULIMIT_OVERRIDE_REFUSAL
        if override in _ISOLATOR_RESOLVE_CHAIN:
            return override, None

        key = (
            f"{integration.get('host', '')}:{integration.get('port', '')}"
            f":{integration.get('username', '')}"
        )
        cached = self._isolator_cache.get(key)
        if cached is not None:
            return cached, None

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
        # Fail closed. Do NOT cache the refusal -- a later probe may
        # succeed if the operator installs firejail/unshare on the target
        # between attempts. Cross-attempt caching would freeze the whole
        # workflow into refusal even after remediation.
        return None, _NO_ISOLATOR_REFUSAL

    async def forward(self, action: str | None = None, **kwargs: Any) -> dict:
        if not action:
            return _err("action is required")
        integration = kwargs.pop("integration", None)
        if not isinstance(integration, dict) or not integration:
            return _err("integration (SSH config) is required")
        ssh = SSHService(build_platform_settings(self.settings))
        handlers = {
            "compile_poc": self._compile,
            "run_poc": self._run,
            "verify_reliability": self._reliability,
            "cleanup_workspace": self._cleanup,
        }
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

        # fix #51 -- allocate a fresh per-run subdirectory under the shared
        # workspace root so each compile owns its own scratch space. The
        # workflow's ``finally`` reclaims it via ``cleanup_workspace``; the
        # prune below bounds growth if the workflow crashes before finally.
        run_dir = new_run_dir()
        remote_src = f"{run_dir}/{filename}"
        await ssh.run_command(
            integration, f"mkdir -p {shlex.quote(run_dir)}", timeout_seconds=30.0,
        )
        # Run the age + size prune BEFORE upload so the compile never
        # dispatches into a full workspace. Best-effort: prune failure is
        # logged and swallowed.
        await self._prune_workspace(ssh, integration)

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
            return {
                "status": "ready", "language": "python",
                "script_path": remote_src, "run_dir": run_dir,
            }

        binary_path = f"{run_dir}/{PurePosixPath(filename).stem or 'poc'}"
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
                    "source_path": remote_src, "run_dir": run_dir}
        return {"status": "ready", "language": "c",
                "binary_path": binary_path, "compile_output": compile_output,
                "source_path": remote_src, "run_dir": run_dir}

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
        # fix #51 -- resolve the isolation layer fail-closed. If neither
        # firejail nor unshare is present, or the operator override is
        # ``ulimit``, refuse to execute instead of running the untrusted
        # PoC under a fenceless bash wrap.
        isolator, refusal_reason = await self._resolve_isolator(ssh, integration)
        if isolator is None:
            _log.warning("%s", refusal_reason)
            return _err(refusal_reason or _NO_ISOLATOR_REFUSAL)
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
            "isolator": isolator,
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

    async def _cleanup(
        self, ssh: SSHService, integration: dict,
        poc_path: str | None = None, run_dir: str | None = None,
        **_extra: Any,
    ) -> dict:
        """Remove the per-run workspace subdirectory for a compiled PoC (fix #51).

        Accepts either ``poc_path`` (any path inside the run
        subdirectory) or ``run_dir`` (the ``/tmp/aila_vr/run_<hex>``
        directly). The workflow calls this from a ``finally`` block so a
        completed or aborted PoC session releases its scratch space
        promptly instead of waiting for the age-based prune.

        Refuses to touch anything outside the ``run_<hex>`` subdirectory
        layout so a caller bug (empty string, ``_REMOTE_DIR`` itself,
        crafted path) cannot escalate into an ``rm -rf`` of the shared
        workspace root or the host filesystem. Returns ``status="skipped"``
        for legacy paths that predate per-run subdirectories -- the prune
        pass will reclaim them by age.
        """
        candidate = run_dir if isinstance(run_dir, str) and run_dir else None
        if candidate is None and isinstance(poc_path, str) and poc_path:
            confinement_error = confine_remote_poc_path(poc_path)
            if confinement_error:
                return _err(confinement_error)
            candidate = run_dir_of(poc_path)
        if candidate is None:
            return {
                "status": "skipped",
                "reason": "poc_path/run_dir does not name a per-run workspace",
            }
        # Belt+suspenders: re-validate the resolved run_dir before rm.
        # A well-formed run_dir has the shape ``/tmp/aila_vr/run_<hex>``;
        # anything else (empty, sandbox root, missing prefix, extra path
        # segments) is refused so a caller bug cannot escalate the rm.
        try:
            candidate_pp = PurePosixPath(candidate)
        except (TypeError, ValueError):
            return _err(f"run_dir {candidate!r} is not a valid POSIX path")
        root = PurePosixPath(_REMOTE_DIR)
        if not candidate_pp.is_absolute() or ".." in candidate_pp.parts:
            return _err(f"run_dir {candidate!r} is not a safe absolute path")
        try:
            rel = candidate_pp.relative_to(root)
        except ValueError:
            return _err(
                f"run_dir {candidate!r} escapes sandbox root {_REMOTE_DIR}",
            )
        parts = rel.parts
        if len(parts) != 1 or not parts[0].startswith(_RUN_DIR_PREFIX):
            return _err(
                f"run_dir {candidate!r} is not a per-run subdirectory of "
                f"{_REMOTE_DIR}",
            )
        try:
            await ssh.run_command(
                integration,
                f"rm -rf -- {shlex.quote(candidate)}",
                timeout_seconds=_WORKSPACE_CLEANUP_TIMEOUT_S,
            )
        except (OSError, RuntimeError, TimeoutError) as exc:
            _log.warning(
                "poc_runner: cleanup_workspace failed for %s (%s: %s)",
                candidate, type(exc).__name__, exc,
            )
            return _err(f"cleanup failed: {type(exc).__name__}: {exc}")
        return {"status": "cleaned", "run_dir": candidate}
