"""Platform dynamic-execution primitive (issue #21).

Draws the platform / module boundary the same way the fuzz + symbolic
work (#148) does: the platform owns the *dynamic-execution primitives*
(sandboxed one-shot run, stdout / exit-code capture, coverage-artifact
capture, kind + polarity observation emission) and the *observable
vocabulary* callers speak to the reasoning loop with; modules keep
target selection and interpretation (which binary, which seed, what a
crash means for this hypothesis).

Design contract
---------------

* One entry point -- :func:`run_dynamic` -- takes a target descriptor +
  an input descriptor and returns a typed :class:`DynamicRunResult`.
* Execution reuses :class:`aila.platform.services.sandbox.SandboxService`
  end-to-end. There is deliberately no local-host fallback: an
  unconfigured sandbox surfaces as ``status=UNAVAILABLE`` with no
  observation written, the same shape a caller sees when the platform
  flag is off (``status=DISABLED``). The reasoning loop can distinguish
  the two without new plumbing.
* Observations are burned through the existing #137 writer
  (:func:`aila.platform.agents.observation.record_observation`) into the
  workspace-scoped ``{module}.observation.workspace.{workspace_id}``
  bucket the module retrievers already read. The kill-criteria layer and
  the reasoning loop consume ``dynamic.*`` kinds through the same
  retrieval path they consume ``read_hit`` / ``dead_end``; no new
  channel, no new table, no migration.
* The observable vocabulary is intentionally small and namespaced:

  - :data:`DYNAMIC_RUN`           -- the run happened; polarity encodes
    success / failure of the executed target.
  - :data:`DYNAMIC_CRASH`         -- the run terminated abnormally
    (non-zero exit for a program the caller declared should succeed,
    OOM, timeout, or signal-derived exit). Always ``POSITIVE`` polarity
    -- a crash confirms the hypothesis "this input reaches a fault".
  - :data:`DYNAMIC_COVERAGE_DELTA` -- coverage capture was requested,
    the sandbox returned a coverage payload, and the payload contains
    edges the caller had not seen before. ``POSITIVE`` polarity: new
    reachability is confirming evidence.

* Gated behind a platform flag (``dynamic_execution_enabled``) default
  ``False``. Flag off = inert: :func:`run_dynamic` returns a
  ``DISABLED`` result before the sandbox is even reached and emits
  nothing. A flag flip lands on the next call via ConfigRegistry with
  no worker restart.

Module use pattern
------------------

::

    from aila.platform.services.dynamic_execution import (
        run_dynamic, DynamicTarget, DynamicInputs, DynamicRunStatus,
    )

    result = await run_dynamic(
        target=DynamicTarget(
            module="vr",
            workspace_id=workspace_id,
            subject=f"probe:{binary_name}:{input_fingerprint}",
            argv=["/work/target", "@@"],
            investigation_id=investigation_id,
            branch_id=branch_id,
            turn_number=turn,
        ),
        inputs=DynamicInputs(
            input_files={"seed.bin": seed_bytes.decode("latin-1")},
            timeout_s=15.0,
            expected_exit_code=0,
            prior_coverage_edges=list(prior_edges),
        ),
        capture_coverage=True,
    )

    if result.status is DynamicRunStatus.CRASHED:
        # kill_criterion for the hypothesis fires via the emitted
        # ``dynamic.crash`` observation in the workspace bucket the
        # module retriever already reads.
        ...

Every module keeps its own target-selection code (which binary,
which seed corpus, which fingerprint) and its own crash interpretation
(what a crash on this specific target means for the reasoning). The
platform only knows: run it, capture the outcome, name the observable.
"""
from __future__ import annotations

import hashlib
import logging
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, field_validator

from aila.config import Settings, get_settings
from aila.platform.agents.observation import (
    ObservationPolarity,
    PlatformObservation,
    record_observation,
)
from aila.platform.config import PlatformSettings, build_platform_settings
from aila.platform.services.knowledge import KnowledgeService
from aila.platform.services.sandbox import (
    SandboxExecutionError,
    SandboxResult,
    SandboxService,
    SandboxSpec,
    SandboxUnavailableError,
)
from aila.storage.registry import ConfigRegistry

__all__ = [
    "DYNAMIC_COVERAGE_DELTA",
    "DYNAMIC_CRASH",
    "DYNAMIC_RUN",
    "DynamicInputs",
    "DynamicRunResult",
    "DynamicRunStatus",
    "DynamicTarget",
    "run_dynamic",
]

_log = logging.getLogger(__name__)

# --- Observable vocabulary (platform-owned) ---------------------------
#
# Dotted names so retrieval + kill-criterion code can filter by prefix
# (``dynamic.*``) without a hard enum coupling. Modules that emit
# domain-specific dynamic-adjacent kinds MUST prefix them with the
# module id (``vr.dynamic.reproducer_confirmed``) to keep the platform
# namespace clean.
DYNAMIC_RUN: str = "dynamic.run"
DYNAMIC_CRASH: str = "dynamic.crash"
DYNAMIC_COVERAGE_DELTA: str = "dynamic.coverage_delta"

# Config key on ``platform`` namespace. Master switch: when False the
# primitive is inert -- a call returns ``DISABLED`` and writes nothing.
# Reads live via ConfigRegistry so an operator PUT /config edit lands
# on the next dispatch without a worker restart.
_FLAG_ENABLED: str = "dynamic_execution_enabled"
_FLAG_ENABLED_DEFAULT: bool = False

# Default workdir-relative filename the primitive expects the caller's
# target to write coverage to when ``capture_coverage`` is set. Newline-
# separated edges (each line is one covered edge / bb id / hash). The
# format is deliberately trivial -- a callable can produce it from any
# coverage instrumentation the module owns. Callers MAY override via
# :attr:`DynamicInputs.coverage_output_path`.
_DEFAULT_COVERAGE_OUTPUT_PATH: str = "coverage.txt"


class DynamicRunStatus(StrEnum):
    """Terminal status of a :func:`run_dynamic` call."""

    # Platform flag is off. No sandbox dispatch, no observation.
    DISABLED = "disabled"
    # Sandbox backend not configured for this deployment. No dispatch,
    # no observation. Operator-visible configuration gap.
    UNAVAILABLE = "unavailable"
    # Ran cleanly. ``exit_code`` matched ``expected_exit_code`` (or
    # ``expected_exit_code`` was unset and the run returned an exit
    # code without being killed).
    EXECUTED = "executed"
    # Ran but exited abnormally: exit code did not match the caller's
    # expectation, or the sandbox killed the run for a policy
    # violation (timeout / OOM). Emits ``dynamic.crash``.
    CRASHED = "crashed"
    # Backend transport / infra failure. No SandboxResult produced.
    # No observation -- a transport hiccup is not evidence about the
    # target.
    BACKEND_ERROR = "backend_error"


class DynamicTarget(BaseModel):
    """Identity + executable envelope for one dynamic run.

    ``module`` + ``workspace_id`` + ``subject`` together form the
    observation identity every ``dynamic.*`` row written by this call
    hashes into (via :func:`observation_dedup_key`), so re-invoking
    :func:`run_dynamic` with the same target descriptor supersedes the
    prior observation instead of appending noise.
    """

    model_config = ConfigDict(extra="forbid")

    # Owning module id. Matches the module id every ``_bridge_module_id``
    # elsewhere uses (``vr``, ``malware``, ...); routed into the
    # ``{module}.observation.workspace.{workspace_id}`` namespace.
    module: str = Field(min_length=1, max_length=32)
    # Workspace scope. Same value the module retrievers already resolve
    # off the investigation / target / workspace chain.
    workspace_id: str = Field(min_length=1, max_length=64)
    # Identity of the *thing under test* in a form the caller controls
    # (a probe id, a target-name + input-fingerprint pair, a CVE id +
    # PoC index). Distinct subjects produce distinct observation rows;
    # a repeat call with the same subject supersedes.
    subject: str = Field(min_length=1, max_length=256)
    # Command + arguments to exec inside the sandbox. Passed through to
    # :class:`SandboxSpec.argv` verbatim.
    argv: list[str] = Field(min_length=1)
    # Extra environment variables exported inside the sandbox.
    env: dict[str, str] = Field(default_factory=dict)
    # Absolute POSIX path inside the sandbox where ``input_files`` are
    # staged and ``output_globs`` are resolved.
    workdir: str = Field(default="/work")
    # Provenance -- optional. When present, stamped into the observation
    # metadata so the reasoning loop can trace which branch / turn
    # produced this dynamic fact.
    investigation_id: str | None = Field(default=None, max_length=64)
    branch_id: str | None = Field(default=None, max_length=64)
    turn_number: int | None = None

    @field_validator("argv")
    @classmethod
    def _argv_entries_non_empty(cls, argv: list[str]) -> list[str]:
        for entry in argv:
            if not isinstance(entry, str) or entry == "":
                raise ValueError("argv entries must be non-empty strings.")
        return argv


class DynamicInputs(BaseModel):
    """One-shot inputs handed to the target on this dispatch."""

    model_config = ConfigDict(extra="forbid")

    # Optional UTF-8 text on stdin.
    stdin: str | None = None
    # Workdir-relative path -> UTF-8 content. Written into the sandbox
    # workdir before the program runs. For binary seeds, decode with
    # ``latin-1`` to survive the UTF-8 round-trip losslessly.
    input_files: dict[str, str] = Field(default_factory=dict)
    # Wall-clock ceiling. Clamped by the platform sandbox policy.
    timeout_s: float = Field(default=30.0, gt=0.0)
    # Grant network access inside the sandbox. Forced ``False`` unless
    # the platform policy allows it.
    network: bool = False
    # Extra workdir-relative globs collected back after exit, in
    # addition to the coverage output path when ``capture_coverage``
    # is set. Populates :attr:`DynamicRunResult.output_files`.
    output_globs: list[str] = Field(default_factory=list)

    # --- Crash-classification ------------------------------------------
    # Exit code the caller declares as "the program ran to normal
    # completion". Any other terminal outcome (different exit, timeout,
    # OOM) is classified as a crash. Leaving this unset means "any
    # returned exit code is fine, only kills are crashes" -- useful for
    # probing programs whose exit code is not deterministic.
    expected_exit_code: int | None = None

    # --- Coverage -------------------------------------------------------
    # When ``capture_coverage=True``, the primitive collects this
    # workdir-relative file back and parses it as one edge / bb / hash
    # per line. Defaults to :data:`_DEFAULT_COVERAGE_OUTPUT_PATH` on
    # the run itself; set explicitly to override.
    coverage_output_path: str | None = None
    # Coverage edges observed on prior runs of this subject. The
    # primitive computes ``new_edges = observed - prior`` and emits
    # ``dynamic.coverage_delta`` iff the new set is non-empty. Callers
    # own persistence of the cumulative-edges set (typically in the
    # same workspace-scoped store the observation lands in).
    prior_coverage_edges: list[str] = Field(default_factory=list)


class DynamicRunResult(BaseModel):
    """Typed outcome of :func:`run_dynamic`."""

    model_config = ConfigDict(extra="forbid")

    status: DynamicRunStatus
    # Underlying sandbox result, present iff the sandbox actually ran
    # the spec. ``None`` for DISABLED / UNAVAILABLE / BACKEND_ERROR.
    sandbox_result: SandboxResult | None = None
    # Human-readable reason for a non-EXECUTED status. Not embedded in
    # the observation body -- surfaced to the caller for logging /
    # operator UI.
    reason: str | None = None
    # Coverage edges observed on THIS run (sorted, deduped). Empty
    # when coverage capture was not requested, no coverage payload was
    # returned, or the payload was empty.
    coverage_edges: list[str] = Field(default_factory=list)
    # Coverage edges NEW to this run relative to
    # :attr:`DynamicInputs.prior_coverage_edges`. Sorted, deduped.
    # Non-empty iff ``dynamic.coverage_delta`` was emitted.
    coverage_delta_edges: list[str] = Field(default_factory=list)
    # Emitted observation kinds (``dynamic.run``, ``dynamic.crash``,
    # ``dynamic.coverage_delta``) in the order they were written, for
    # logging / test assertion. Actual persistence goes through
    # :func:`record_observation`.
    observations_emitted: list[str] = Field(default_factory=list)


async def run_dynamic(
    target: DynamicTarget,
    inputs: DynamicInputs,
    *,
    capture_coverage: bool = False,
    settings: PlatformSettings | None = None,
    sandbox_service: SandboxService | None = None,
    config_registry: ConfigRegistry | None = None,
    knowledge_writer: KnowledgeService | None = None,
) -> DynamicRunResult:
    """Execute ``target`` in the platform sandbox and burn observations.

    Returns a :class:`DynamicRunResult`. NEVER raises for the
    ``platform-off`` / ``sandbox-unavailable`` / ``backend-error``
    cases -- those become typed statuses on the result. Argument-shape
    validation on the pydantic models is the only exceptional path.

    ``target`` and ``inputs`` are separate models on purpose: the target
    is a durable identity (module + workspace + subject + argv) the
    caller re-uses across many inputs; the inputs are per-dispatch
    variables. This mirrors how a module would keep a ``TargetRecord``
    around and probe it with successive seeds.

    ``capture_coverage`` is opt-in per call. When ``True`` the primitive
    adds the coverage-output path to the sandbox spec's ``output_globs``,
    reads the returned file, computes the delta against
    :attr:`DynamicInputs.prior_coverage_edges`, and emits
    :data:`DYNAMIC_COVERAGE_DELTA` iff new edges appeared. Modules that
    do not instrument their targets simply leave ``capture_coverage``
    unset -- the run still executes and ``dynamic.run`` still fires.
    """
    # Effective config: allow callers to inject a registry for tests;
    # otherwise use the process-wide singleton. Reading via ConfigRegistry
    # each call keeps operator PUT /config flips live.
    registry = config_registry or ConfigRegistry()
    if not await _resolve_flag_enabled(registry):
        return DynamicRunResult(
            status=DynamicRunStatus.DISABLED,
            reason=(
                "platform.dynamic_execution_enabled is False; "
                "enable it via ConfigRegistry to activate dynamic runs."
            ),
        )

    resolved_settings = settings or _lazy_platform_settings()
    service = sandbox_service or SandboxService(
        resolved_settings, config_registry=registry,
    )

    spec_output_globs = list(inputs.output_globs)
    coverage_output_path = _effective_coverage_path(inputs, capture_coverage)
    # The sandbox output-cap engine only ships back paths the caller
    # explicitly asked for -- add ours so the coverage file survives
    # the ``collect_outputs`` scan even when the caller left
    # ``output_globs`` empty.
    if coverage_output_path is not None and coverage_output_path not in spec_output_globs:
        spec_output_globs.append(coverage_output_path)

    spec = SandboxSpec(
        argv=list(target.argv),
        stdin=inputs.stdin,
        input_files=dict(inputs.input_files),
        env=dict(target.env),
        timeout_s=float(inputs.timeout_s),
        network=bool(inputs.network),
        workdir=target.workdir,
        output_globs=spec_output_globs,
    )

    try:
        sandbox_result = await service.run(spec)
    except SandboxUnavailableError as exc:
        _log.info(
            "run_dynamic: sandbox unavailable module=%s workspace=%s "
            "subject=%r -- %s",
            target.module, target.workspace_id, target.subject, exc,
        )
        return DynamicRunResult(
            status=DynamicRunStatus.UNAVAILABLE, reason=str(exc),
        )
    except SandboxExecutionError as exc:
        _log.warning(
            "run_dynamic: sandbox backend error module=%s workspace=%s "
            "subject=%r -- %s",
            target.module, target.workspace_id, target.subject, exc,
        )
        return DynamicRunResult(
            status=DynamicRunStatus.BACKEND_ERROR, reason=str(exc),
        )

    crashed, crash_reason = _classify_crash(sandbox_result, inputs)
    status = DynamicRunStatus.CRASHED if crashed else DynamicRunStatus.EXECUTED

    coverage_edges, coverage_delta = _extract_coverage(
        sandbox_result, inputs, coverage_output_path,
    )

    emitted: list[str] = []
    await _emit_dynamic_run(
        target=target,
        inputs=inputs,
        result=sandbox_result,
        crashed=crashed,
        crash_reason=crash_reason,
        writer=knowledge_writer,
        emitted=emitted,
    )
    if crashed:
        await _emit_dynamic_crash(
            target=target,
            inputs=inputs,
            result=sandbox_result,
            crash_reason=crash_reason or "abnormal termination",
            writer=knowledge_writer,
            emitted=emitted,
        )
    if capture_coverage and coverage_delta:
        await _emit_coverage_delta(
            target=target,
            inputs=inputs,
            new_edges=coverage_delta,
            total_edges=len(coverage_edges),
            writer=knowledge_writer,
            emitted=emitted,
        )

    return DynamicRunResult(
        status=status,
        sandbox_result=sandbox_result,
        reason=crash_reason,
        coverage_edges=coverage_edges,
        coverage_delta_edges=coverage_delta,
        observations_emitted=emitted,
    )


# ----------------------------------------------------------------------
# Internals
# ----------------------------------------------------------------------


def _lazy_platform_settings() -> PlatformSettings:
    """Build :class:`PlatformSettings` from the process-wide :class:`Settings`.

    Kept in a helper so tests can inject a fully-formed :class:`SandboxService`
    without ever constructing a real ``Settings`` (which would want a
    database URL etc.). The production caller path -- module code fires
    :func:`run_dynamic` without threading settings -- still works because
    :func:`aila.config.get_settings` is the same cached singleton the rest
    of the platform reads.
    """
    source: Settings = get_settings()
    return build_platform_settings(source)


async def _resolve_flag_enabled(registry: ConfigRegistry) -> bool:
    """Read ``platform.dynamic_execution_enabled`` -- fail-closed default.

    A registry read failure returns the default (``False``) so a
    bootstrap window or a transient DB hiccup errs on the side of
    inert, not the side of accidentally dispatching untrusted code.
    """
    try:
        raw = await registry.get("platform", _FLAG_ENABLED)
    except (RuntimeError, OSError):
        return _FLAG_ENABLED_DEFAULT
    if raw is None:
        return _FLAG_ENABLED_DEFAULT
    if isinstance(raw, bool):
        return raw
    if isinstance(raw, str):
        return raw.strip().lower() in {"1", "true", "yes", "on"}
    try:
        return bool(int(raw))
    except (TypeError, ValueError):
        return _FLAG_ENABLED_DEFAULT


def _effective_coverage_path(
    inputs: DynamicInputs, capture_coverage: bool,
) -> str | None:
    """Resolve the workdir-relative coverage output path, or ``None``.

    ``None`` when coverage capture is not requested -- the primitive
    skips the delta path entirely and never emits
    ``dynamic.coverage_delta``.
    """
    if not capture_coverage:
        return None
    if inputs.coverage_output_path is not None:
        path = inputs.coverage_output_path.strip()
        if path:
            return path
    return _DEFAULT_COVERAGE_OUTPUT_PATH


def _classify_crash(
    result: SandboxResult, inputs: DynamicInputs,
) -> tuple[bool, str | None]:
    """Return ``(crashed, reason)`` from the sandbox result.

    A run counts as a crash when the sandbox kill flags fire
    (``timed_out`` / ``oom``), when the guest never reported an exit
    code (``exit_code is None`` and no kill flag -- backend abort), or
    when the caller declared an ``expected_exit_code`` and the observed
    exit did not match. Callers with no expectation only see
    kill-derived crashes; a non-zero exit alone is not a crash.
    """
    if result.timed_out:
        return True, f"timed out after {result.duration_s:.1f}s"
    if result.oom:
        return True, "killed for exceeding memory ceiling"
    if result.exit_code is None:
        return True, "backend killed the run before an exit code was reported"
    if (
        inputs.expected_exit_code is not None
        and int(result.exit_code) != int(inputs.expected_exit_code)
    ):
        return (
            True,
            f"exit_code={result.exit_code} != expected={inputs.expected_exit_code}",
        )
    return False, None


def _extract_coverage(
    result: SandboxResult,
    inputs: DynamicInputs,
    coverage_output_path: str | None,
) -> tuple[list[str], list[str]]:
    """Parse the coverage output file and diff against ``prior_coverage_edges``.

    Returns ``(observed_edges_sorted, delta_edges_sorted)``. Both lists
    are empty when coverage capture was not requested, no coverage file
    came back, or the file was empty.
    """
    if coverage_output_path is None:
        return [], []
    payload = result.output_files.get(coverage_output_path)
    if not payload:
        return [], []
    observed: set[str] = set()
    for raw_line in payload.splitlines():
        edge = raw_line.strip()
        if edge:
            observed.add(edge)
    if not observed:
        return [], []
    prior = {e.strip() for e in inputs.prior_coverage_edges if e.strip()}
    delta = observed - prior
    return sorted(observed), sorted(delta)


def _observation_content(
    *, subject: str, workspace_id: str, body: str,
) -> str:
    """Compose a self-contained observation body.

    The knowledge store embeds ``content`` for semantic recall, so the
    string MUST be self-contained (subject + workspace + fact) rather
    than a raw dump the retriever cannot re-anchor without the
    metadata blob.
    """
    return f"[{subject} @ workspace {workspace_id[:8]}] {body}"


def _truncated_head(text: str, limit: int) -> str:
    """Head-truncate ``text`` to ``limit`` bytes, marking a truncation.

    Observation bodies are embedded and read by the reasoning loop; a
    raw multi-megabyte stderr dump would poison retrieval. Keep the
    first ``limit`` bytes and note truncation.
    """
    if len(text) <= limit:
        return text
    return text[:limit].rstrip() + f" ... [truncated, {len(text)} bytes total]"


def _subject_variant(subject: str, suffix: str) -> str:
    """Derive a distinct observation-identity variant for ``subject``.

    The three ``dynamic.*`` kinds SHARE the workspace namespace but
    hash to different observation rows via ``(subject, kind)``; the
    kind alone gives them separate dedup slots. The ``_variant`` here
    is an extra tolerance for kind-collisions when a caller registers
    their own kind alongside a platform one (the SHA prefix keeps the
    row bounded).
    """
    digest = hashlib.sha256(f"{subject}|{suffix}".encode()).hexdigest()[:8]
    return f"{subject}#{suffix}:{digest}"


async def _emit_dynamic_run(
    *,
    target: DynamicTarget,
    inputs: DynamicInputs,
    result: SandboxResult,
    crashed: bool,
    crash_reason: str | None,
    writer: KnowledgeService | None,
    emitted: list[str],
) -> None:
    """Emit the ``dynamic.run`` observation summarising the dispatch."""
    polarity = (
        ObservationPolarity.NEGATIVE if crashed else ObservationPolarity.POSITIVE
    )
    body_lines = [
        f"ran argv[0]={target.argv[0]!r} via sandbox backend "
        f"{result.backend} in {result.duration_s:.2f}s; "
        f"exit_code={result.exit_code} timed_out={result.timed_out} "
        f"oom={result.oom}",
    ]
    if crash_reason:
        body_lines.append(f"outcome: {crash_reason}")
    stdout_head = _truncated_head(result.stdout, 512)
    if stdout_head:
        body_lines.append(f"stdout: {stdout_head}")
    stderr_head = _truncated_head(result.stderr, 512)
    if stderr_head:
        body_lines.append(f"stderr: {stderr_head}")
    content = _observation_content(
        subject=target.subject,
        workspace_id=target.workspace_id,
        body="\n".join(body_lines),
    )
    await record_observation(
        PlatformObservation(
            module=target.module,
            workspace_id=target.workspace_id,
            subject=target.subject,
            kind=DYNAMIC_RUN,
            polarity=polarity,
            content=content,
            investigation_id=target.investigation_id,
            branch_id=target.branch_id,
            turn_number=target.turn_number,
            extra={
                "sandbox_backend": result.backend,
                "exit_code": result.exit_code,
                "duration_s": result.duration_s,
                "timed_out": result.timed_out,
                "oom": result.oom,
                "expected_exit_code": inputs.expected_exit_code,
            },
        ),
        writer=writer,
    )
    emitted.append(DYNAMIC_RUN)


async def _emit_dynamic_crash(
    *,
    target: DynamicTarget,
    inputs: DynamicInputs,
    result: SandboxResult,
    crash_reason: str,
    writer: KnowledgeService | None,
    emitted: list[str],
) -> None:
    """Emit the ``dynamic.crash`` observation for an abnormal termination.

    Polarity is always ``POSITIVE`` -- a crash *confirms* the
    hypothesis "this input reaches a fault on this target". The
    kill-criterion layer keys off this kind + polarity.
    """
    body = (
        f"crash confirmed: {crash_reason}. "
        f"backend={result.backend} exit_code={result.exit_code} "
        f"stderr_head={_truncated_head(result.stderr, 256)!r}"
    )
    content = _observation_content(
        subject=target.subject,
        workspace_id=target.workspace_id,
        body=body,
    )
    await record_observation(
        PlatformObservation(
            module=target.module,
            workspace_id=target.workspace_id,
            subject=_subject_variant(target.subject, "crash"),
            kind=DYNAMIC_CRASH,
            polarity=ObservationPolarity.POSITIVE,
            content=content,
            investigation_id=target.investigation_id,
            branch_id=target.branch_id,
            turn_number=target.turn_number,
            extra={
                "sandbox_backend": result.backend,
                "exit_code": result.exit_code,
                "timed_out": result.timed_out,
                "oom": result.oom,
                "expected_exit_code": inputs.expected_exit_code,
                "crash_reason": crash_reason,
            },
        ),
        writer=writer,
    )
    emitted.append(DYNAMIC_CRASH)


async def _emit_coverage_delta(
    *,
    target: DynamicTarget,
    inputs: DynamicInputs,
    new_edges: list[str],
    total_edges: int,
    writer: KnowledgeService | None,
    emitted: list[str],
) -> None:
    """Emit ``dynamic.coverage_delta`` for a run that opened new edges."""
    sample = ", ".join(new_edges[:8])
    body = (
        f"coverage delta: {len(new_edges)} new edges "
        f"(total observed this run: {total_edges}). "
        f"sample: {sample}"
    )
    content = _observation_content(
        subject=target.subject,
        workspace_id=target.workspace_id,
        body=body,
    )
    await record_observation(
        PlatformObservation(
            module=target.module,
            workspace_id=target.workspace_id,
            subject=_subject_variant(target.subject, "coverage"),
            kind=DYNAMIC_COVERAGE_DELTA,
            polarity=ObservationPolarity.POSITIVE,
            content=content,
            investigation_id=target.investigation_id,
            branch_id=target.branch_id,
            turn_number=target.turn_number,
            extra={
                "new_edge_count": len(new_edges),
                "total_edge_count": total_edges,
                "prior_edge_count": len(
                    {e for e in inputs.prior_coverage_edges if e},
                ),
            },
        ),
        writer=writer,
    )
    emitted.append(DYNAMIC_COVERAGE_DELTA)
