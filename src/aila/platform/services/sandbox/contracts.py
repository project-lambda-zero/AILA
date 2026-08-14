"""Public contracts for the platform sandbox service (issue #147).

Every module that needs to execute an agent-derived or untrusted command
targets these types instead of building its own isolation layer. The
service dispatches to a Linux-only backend (``nsjail`` or ``firecracker``)
reached over SSH; when no backend host is configured, callers see
:class:`SandboxUnavailableError` -- there is deliberately no
un-isolated local fallback (that would defeat the point of the primitive).

Types exported here:

* :class:`SandboxSpec`       -- declarative one-shot execution request.
* :class:`SandboxResult`     -- typed result the caller receives back.
* :class:`SandboxBackend`    -- Protocol every concrete backend satisfies.
* :class:`SandboxUnavailableError`
* :class:`SandboxExecutionError`

The contract is intentionally minimal and JSON-serializable so it can flow
through the task queue and the ``POST /platform/sandbox/exec`` admin
surface without translation.
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field, field_validator

if TYPE_CHECKING:  # pragma: no cover -- import guard, avoid platform-cycle
    from ...contracts.platform import SSHIntegrationInput
    from ..ssh import SSHService

__all__ = [
    "SandboxSpec",
    "SandboxResult",
    "SandboxBackend",
    "SandboxUnavailableError",
    "SandboxExecutionError",
]


def _reject_unsafe_relative(path: str, *, field: str) -> str:
    """Reject empty strings, absolute paths, and ``..`` traversal segments.

    ``input_files`` keys and ``output_globs`` entries are written and read
    relative to the sandbox workdir; an absolute path or a ``..`` segment
    would let a caller escape the workdir on the host side (where the
    files are staged before upload and re-materialised after download).
    """
    if not path or not path.strip():
        raise ValueError(f"{field}: entries must be non-empty relative paths.")
    if path.startswith("/") or path.startswith("\\"):
        raise ValueError(
            f"{field}: absolute path {path!r} is not allowed; use a workdir-relative path."
        )
    # Normalise Windows separators so ``..\\foo`` collapses to the same
    # segment view as ``../foo`` before the traversal check runs.
    segments = path.replace("\\", "/").split("/")
    if any(segment == ".." for segment in segments):
        raise ValueError(f"{field}: path {path!r} contains a '..' traversal segment.")
    return path


class SandboxSpec(BaseModel):
    """One sandboxed command execution request.

    Callers build a spec, hand it to :class:`SandboxService.run`, and get
    back a :class:`SandboxResult`. The spec is a pure value object -- no
    hidden mutation, no callbacks -- so it can be serialised into a task
    payload or an admin API body without translation.
    """

    model_config = ConfigDict(extra="forbid")

    argv: list[str] = Field(
        min_length=1,
        description="Command + arguments to exec inside the sandbox. argv[0] is the program.",
    )
    stdin: str | None = Field(
        default=None,
        description="Optional UTF-8 text to feed the program on stdin.",
    )
    input_files: dict[str, str] = Field(
        default_factory=dict,
        description=(
            "Relative-path -> UTF-8 content. Each entry is written into the "
            "sandbox workdir before the program runs. Paths must be relative "
            "and free of '..' segments."
        ),
    )
    env: dict[str, str] = Field(
        default_factory=dict,
        description="Extra environment variables exported inside the sandbox.",
    )
    timeout_s: float = Field(
        default=30.0,
        gt=0.0,
        description="Wall-clock ceiling on program execution (seconds). Clamped by the service policy.",
    )
    network: bool = Field(
        default=False,
        description="Grant network access inside the sandbox. Forced False unless the service policy allows it.",
    )
    vcpu: int = Field(default=1, ge=1, description="Virtual CPUs assigned to the sandbox (Firecracker only).")
    mem_mb: int = Field(default=512, ge=1, description="Memory ceiling in MiB.")
    workdir: str = Field(
        default="/work",
        description="Absolute path inside the sandbox where input_files are staged and output_globs are resolved.",
    )
    output_globs: list[str] = Field(
        default_factory=list,
        description=(
            "Workdir-relative glob patterns collected back after the program "
            "exits. Each match is returned as SandboxResult.output_files."
        ),
    )

    @field_validator("argv")
    @classmethod
    def _argv_entries_non_empty(cls, argv: list[str]) -> list[str]:
        # Pydantic ``min_length=1`` covers the empty list; this catches
        # ``argv=[""]``, ``argv=[None]``, and any non-string entry so the
        # backend does not receive a malformed exec vector.
        if not argv:
            raise ValueError("argv must contain at least one entry.")
        for entry in argv:
            if not isinstance(entry, str) or entry == "":
                raise ValueError("argv entries must be non-empty strings.")
        return argv

    @field_validator("input_files")
    @classmethod
    def _input_files_paths(cls, files: dict[str, str]) -> dict[str, str]:
        for path in files:
            _reject_unsafe_relative(path, field="input_files")
        return files

    @field_validator("output_globs")
    @classmethod
    def _output_globs_paths(cls, globs: list[str]) -> list[str]:
        for pattern in globs:
            _reject_unsafe_relative(pattern, field="output_globs")
        return globs

    @field_validator("workdir")
    @classmethod
    def _workdir_absolute(cls, workdir: str) -> str:
        # The workdir is the mount point inside the sandbox; require an
        # absolute POSIX path so the guest-side runner + nsjail --cwd both
        # know exactly which directory to enter.
        if not workdir.startswith("/"):
            raise ValueError(f"workdir must be an absolute POSIX path, got {workdir!r}.")
        if ".." in workdir.split("/"):
            raise ValueError(f"workdir {workdir!r} must not contain '..' segments.")
        return workdir


class SandboxResult(BaseModel):
    """Typed result returned from :meth:`SandboxService.run`.

    ``exit_code`` is ``None`` iff the program was killed (timeout, OOM,
    or backend abort) before the guest could report an exit. ``stdout`` /
    ``stderr`` are UTF-8 strings, decoded with ``errors="replace"`` so a
    binary-writing program never fails the decode. ``output_files`` is
    ``relative-path -> UTF-8 content`` for every match of the spec's
    ``output_globs``.
    """

    model_config = ConfigDict(extra="forbid")

    backend: str = Field(description="Concrete backend that ran the spec (nsjail | firecracker).")
    exit_code: int | None = Field(
        default=None,
        description="Program exit code, or None if the program was killed before reporting one.",
    )
    stdout: str = Field(default="", description="Captured stdout, possibly truncated (see ``truncated``).")
    stderr: str = Field(default="", description="Captured stderr, possibly truncated (see ``truncated``).")
    output_files: dict[str, str] = Field(
        default_factory=dict,
        description="Collected output_globs matches, keyed by workdir-relative path.",
    )
    duration_s: float = Field(default=0.0, ge=0.0, description="Wall-clock seconds spent executing the spec.")
    timed_out: bool = Field(default=False, description="Program was killed by the sandbox timeout.")
    oom: bool = Field(default=False, description="Program was killed for exceeding its memory ceiling.")
    truncated: bool = Field(
        default=False,
        description="Stdout, stderr, or an output_file was truncated to fit sandbox_output_max_bytes.",
    )


@runtime_checkable
class SandboxBackend(Protocol):
    """Protocol every concrete backend (nsjail, firecracker) satisfies.

    Backends receive:
      * ``spec``  -- the policy-normalised :class:`SandboxSpec`.
      * ``ssh``   -- the :class:`SSHService` instance to reach the host.
      * ``host_payload`` -- :class:`SSHIntegrationInput` naming the host.
      * ``cfg``   -- a service-owned config snapshot (frozen dataclass).

    ``run`` MUST raise :class:`SandboxExecutionError` on any infra failure
    (missing binary, jail launch failed, guest never produced a result)
    and MUST return a :class:`SandboxResult` on any normal outcome --
    including a non-zero exit code, a timeout, or an OOM kill. The
    result flags are the caller-facing signal, not exceptions.
    """

    name: str

    async def run(
        self,
        spec: SandboxSpec,
        *,
        ssh: SSHService,
        host_payload: SSHIntegrationInput,
        cfg: Any,
    ) -> SandboxResult: ...


class SandboxUnavailableError(RuntimeError):
    """Raised when no sandbox backend is provisioned for this deployment.

    Callers MUST treat this as an operator-visible configuration gap --
    NOT a hint that the platform should silently fall back to running the
    payload un-isolated on the local host. There is no local fallback:
    the sandbox is the whole point.
    """


class SandboxExecutionError(RuntimeError):
    """Raised when a backend cannot deliver a :class:`SandboxResult`.

    Wraps SSH transport faults, missing sandbox binaries on the host, or
    a guest-side runner that never wrote its result marker. A non-zero
    program exit is NOT an execution error -- it is a normal result and
    surfaces as ``SandboxResult.exit_code != 0``.
    """
