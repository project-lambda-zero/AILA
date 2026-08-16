"""Platform auto-patch synthesis + verifier (issue #149).

After :class:`aila.platform.agents.claim_verifier.ClaimVerifierAgentBase`
writes a ``confirmed`` verdict onto the canonical outcome, the emit-state
chokepoint (:func:`aila.platform.workflows.investigation_emit_base
._maybe_trigger_patcher`) enqueues a per-module patcher task when the
operator has flipped ``platform.autopatch_enabled`` to True. The task
constructs :class:`PatchingService`, calls :meth:`synthesize_patch`
(cheap coder model plus ``read_lines`` / ``ast_edit`` produce a minimal
unified diff), then :meth:`verify_patch` (re-run the finding's PoC or
fuzz reproducer against the patched source inside the platform
:class:`SandboxService`), and stores the whole attempt as a single
:class:`PlatformPatchAttemptRecord` row (migration ``130_auto_patch``).

Default OFF so a base install is byte-identical to the pre-#149 flow --
no patcher trigger fires, no ``platform_patch_attempt`` rows accumulate,
and the verifier's ``confirmed`` verdict alone drives auto-promote as
before. When the flag is on but the sandbox backend is not provisioned,
:meth:`verify_patch` records ``verify_status='skipped'`` with reason
``sandbox_unavailable`` and returns rather than raising: the primary
investigation flow is never disturbed by an infra defect.

Buttercup (Trail of Bits) and Big Sleep + CodeMender (Google) established
"find + prove + patch" as the 2026 deliverable bar; this service is the
minimum credible implementation of the third step, gated behind an
explicit operator opt-in so a deployment without the sandbox or a trusted
coder model sees no behavior change.
"""
from __future__ import annotations

import hashlib
import json
import logging
import re
import time
from dataclasses import dataclass
from typing import Any

from pydantic import BaseModel, ConfigDict, Field
from sqlmodel import select as _select

from aila.platform.agents.idempotent_llm import idempotent_llm_call
from aila.platform.config import PlatformSettings
from aila.platform.contracts import utc_now
from aila.platform.llm.client import AilaLLMClient
from aila.platform.llm.cost import calculate_cost_usd
from aila.platform.services.factory import ServiceFactory
from aila.platform.services.sandbox import (
    SandboxExecutionError,
    SandboxResult,
    SandboxSpec,
    SandboxUnavailableError,
)
from aila.platform.services.sandbox.service import SandboxService
from aila.platform.uow import UnitOfWork
from aila.storage.db_models import PlatformPatchAttemptRecord
from aila.storage.registry import ConfigRegistry

__all__ = [
    "PatchAttempt",
    "PatchFinding",
    "PatchHarness",
    "PatchSourceContext",
    "PatchSynthesisResult",
    "PatchVerifyResult",
    "PatchingService",
]

_log = logging.getLogger(__name__)


# Match a unified-diff header line and pull the target file path.
# GNU diff / git diff both emit ``+++ b/<path>`` on the "new file" side;
# tools that emit unprefixed paths (``+++ foo.c``) also parse.
_DIFF_TARGET_RX = re.compile(r"^\+\+\+\s+(?:b/)?([^\s\t]+)", re.MULTILINE)

# Extract the first fenced code block content from an LLM response so a
# coder model that wraps the diff in ```diff ... ``` still parses.
_FENCED_BLOCK_RX = re.compile(r"```(?:diff|patch)?\s*\n(.*?)\n```", re.DOTALL)

# Coder model system prompt. Kept inline (rather than a PromptRegistry
# entry) because the whole file is a single self-contained
# implementation and #149 does not carry a prompt-version corpus yet.
_SYNTH_SYSTEM_PROMPT = (
    "You are a security-focused coder producing a MINIMAL unified diff "
    "that closes exactly one vulnerability. Output ONLY the unified diff "
    "in standard GNU / git format (``--- a/<path>`` / ``+++ b/<path>`` / "
    "``@@`` hunks). Do not include commentary, prose, or code fences. "
    "Touch the smallest possible region of the smallest possible number "
    "of files. If the fix requires a design change larger than a few "
    "lines, respond with the literal string ``DECLINE: <reason>`` on a "
    "single line instead of a diff -- do not synthesise a wide-blast "
    "refactor. Preserve the file's existing indentation, brace style, "
    "and comment voice. Do not rename identifiers unless the rename is "
    "the fix. Never emit binary hunks."
)


# ---------------------------------------------------------------------------
# Value objects -- JSON-serialisable inputs the caller (per-module patcher
# task) builds from the module's finding record + source context.
# ---------------------------------------------------------------------------


class PatchFinding(BaseModel):
    """The finding being patched. All fields are opaque strings so every
    module (vr / malware / forensics / ...) can build this from its own
    record model without a per-module base class.
    """

    model_config = ConfigDict(extra="forbid")

    finding_ref: str = Field(
        description=(
            "Module-side identifier for the finding (typically the module's "
            "finding-record primary key). Used as the third component of "
            "the ``platform_patch_attempt`` unique key so re-fires update "
            "the prior row in place."
        ),
    )
    module_id: str = Field(description="Owning module id (``vr`` / ``malware`` / ...).")
    investigation_id: str | None = None
    outcome_id: str | None = None
    team_id: str | None = None
    title: str = Field(default="", description="One-line finding title / summary.")
    root_cause: str = Field(
        default="",
        description="Free-form root-cause narrative (the finding's ``root_cause`` field or equivalent).",
    )
    vulnerable_function: str = Field(
        default="",
        description="Function or symbol identifier the fix should target (may be empty).",
    )
    cwe_id: str = Field(default="", description="CWE identifier when known.")
    verifier_report: dict[str, Any] = Field(
        default_factory=dict,
        description=(
            "The ``verifier_report`` dict the claim verifier wrote onto the "
            "canonical outcome. Passed to the synthesiser prompt as ground "
            "truth so the coder model sees the same preconditions the "
            "verifier confirmed."
        ),
    )


class PatchSourceContext(BaseModel):
    """A slice of source the coder model reasons over.

    Callers assemble this from ``read_lines`` / ``ast_edit`` /
    ``search_functions`` / ``read_function`` results before invoking
    :meth:`PatchingService.synthesize_patch`. The service does not open
    files itself: every module owns its own MCP transport (audit-mcp
    for source-grounded work, ida-headless for binary-only work) and
    already carries the retrieval logic the finding was born from.
    """

    model_config = ConfigDict(extra="forbid")

    file_path: str = Field(description="Repository-relative path of the source file being patched.")
    start_line: int = Field(default=1, ge=1, description="Line-1 origin of ``content``.")
    content: str = Field(default="", description="Verbatim source text (utf-8) the coder model reasons about.")
    language: str = Field(default="", description="Source language hint (``c`` / ``rust`` / ``py`` / ...).")
    notes: str = Field(
        default="",
        description="Optional free-form retrieval / ast-edit provenance the caller wants the coder model to see.",
    )


class PatchHarness(BaseModel):
    """A reproducer that returns non-zero (or crashes) on the vulnerable
    source and returns zero on the patched source.

    Modelled as one :class:`SandboxSpec` payload with a caller-supplied
    baseline expectation: the verifier sees the sandbox result and
    decides ``accepted`` vs ``rejected`` from the ``expected_exit`` /
    ``crash_signature`` hints. When the harness is not available (the
    finding never got a runnable PoC), the caller passes
    ``PatchHarness(available=False)`` and the service records
    ``verify_status='skipped'`` with reason ``no_harness``.
    """

    model_config = ConfigDict(extra="forbid")

    available: bool = Field(
        default=True,
        description="False -> :meth:`verify_patch` short-circuits to ``skipped`` / ``no_harness``.",
    )
    argv: list[str] = Field(
        default_factory=list,
        description="argv passed to the sandbox spec. Empty when ``available=False``.",
    )
    stdin: str | None = None
    env: dict[str, str] = Field(default_factory=dict)
    input_files: dict[str, str] = Field(
        default_factory=dict,
        description=(
            "Extra input files staged into the sandbox workdir alongside the "
            "patched source. The patched source itself is injected by "
            ":meth:`verify_patch` under the target file's path -- callers do "
            "NOT need to include it here."
        ),
    )
    timeout_s: float = Field(default=60.0, gt=0.0)
    workdir: str = Field(default="/work")
    expected_exit: int | None = Field(
        default=0,
        description=(
            "Exit code the reproducer produces on a patched source. When set, "
            "the verifier flips ``verify_status='accepted'`` iff the observed "
            "exit code matches AND the run did not time out or OOM. ``None`` "
            "means ``accepted iff not crashed`` (any exit code is fine)."
        ),
    )
    crash_signature: str = Field(
        default="",
        description=(
            "Optional substring the verifier greps for in stderr / stdout. When "
            "non-empty, presence of the substring on the patched run flips "
            "``verify_status='rejected'`` regardless of exit code."
        ),
    )


# ---------------------------------------------------------------------------
# Result objects the caller inspects and the service persists.
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class PatchSynthesisResult:
    """Outcome of :meth:`PatchingService.synthesize_patch`.

    ``diff`` is the unified diff the coder model produced (empty when
    the synthesiser declined or the LLM was kill-switched). ``declined``
    means the model refused to synthesise a small patch and returned a
    ``DECLINE:`` sentinel -- no diff, no verify call. ``model`` / usage
    / cost feed the persisted attempt row.
    """

    diff: str
    files: tuple[str, ...]
    model: str
    prompt_tokens: int
    completion_tokens: int
    cost_usd: float
    task_type: str
    declined: bool = False
    disabled: bool = False
    reason: str = ""


@dataclass(frozen=True, slots=True)
class PatchVerifyResult:
    """Outcome of :meth:`PatchingService.verify_patch`.

    ``status`` mirrors ``PlatformPatchAttemptRecord.verify_status`` so
    the row insert is a straight field copy. ``sandbox_result`` is the
    raw :class:`SandboxResult` for callers that want to inspect the run
    without re-loading it from the DB; not persisted verbatim.
    """

    status: str
    reason: str
    backend: str = ""
    exit_code: int | None = None
    stdout: str = ""
    stderr: str = ""
    duration_s: float = 0.0
    sandbox_result: SandboxResult | None = None


@dataclass(frozen=True, slots=True)
class PatchAttempt:
    """Full round-trip: synthesise + verify + persisted row id."""

    attempt_id: str
    finding_ref: str
    synthesis: PatchSynthesisResult
    verify: PatchVerifyResult
    total_cost_usd: float


# ---------------------------------------------------------------------------
# Small config snapshot -- the service loads every ``autopatch_*`` platform
# key once per call so an operator's PUT /config takes effect on the next
# fire without a worker restart.
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class _PatchConfig:
    enabled: bool
    synth_task_type: str
    max_source_chars: int
    verify_timeout_s: float
    cost_per_1k_prompt: float
    cost_per_1k_completion: float


# ---------------------------------------------------------------------------
# Service
# ---------------------------------------------------------------------------


class PatchingService:
    """Auto-patch synthesis + verifier facade.

    Constructed with the platform :class:`PlatformSettings` (mirrors
    :class:`SandboxService` so a caller who already holds the settings
    does not have to build them again). Every collaborator may be
    injected for tests; production wiring uses the process-wide
    :class:`ServiceFactory` for the LLM client and constructs a fresh
    :class:`SandboxService` per verify (so a config change to
    ``sandbox_*`` lands on the next call).
    """

    def __init__(
        self,
        settings: PlatformSettings,
        *,
        llm_client: AilaLLMClient | None = None,
        sandbox_service: SandboxService | None = None,
        config_registry: ConfigRegistry | None = None,
    ) -> None:
        self._settings = settings
        self._registry = config_registry or ConfigRegistry()
        # Fresh factory so the injected client (tests) and the default
        # (services) route through the same construction path.
        self._llm = llm_client or ServiceFactory().llm_client
        self._sandbox = sandbox_service or SandboxService(
            settings, config_registry=self._registry,
        )

    # -- public --------------------------------------------------------

    async def is_enabled(self) -> bool:
        """Live check on ``platform.autopatch_enabled``.

        Callers (the emit-chokepoint trigger, the per-module task) use
        this to short-circuit before doing any work when the operator
        has not opted in. Reads through :class:`ConfigRegistry` so a
        PUT /config flip lands on the next call.
        """
        return (await self._load_config()).enabled

    async def synthesize_patch(
        self,
        finding: PatchFinding,
        source_ctx: list[PatchSourceContext] | PatchSourceContext,
    ) -> PatchSynthesisResult:
        """Ask the coder model for a minimal unified diff.

        Routes through :func:`idempotent_llm_call` so a worker retry
        replays the cached decision instead of double-paying the model.
        Any diff-shaped response (with or without a triple-backtick
        ``diff`` fence) parses; a ``DECLINE:`` prefix short-circuits
        to ``declined=True`` with no diff.
        """
        cfg = await self._load_config()
        if isinstance(source_ctx, PatchSourceContext):
            source_ctx = [source_ctx]
        rendered_source = self._render_source_ctx(source_ctx, cfg.max_source_chars)
        prompt = self._render_synth_user_prompt(finding, rendered_source)

        try:
            resp, _cache_hit = await idempotent_llm_call(
                self._llm,
                method="chat",
                task_type=cfg.synth_task_type,
                messages=[
                    {"role": "system", "content": _SYNTH_SYSTEM_PROMPT},
                    {"role": "user", "content": prompt},
                ],
                investigation_id=finding.investigation_id or f"autopatch:{finding.finding_ref}",
                team_id=finding.team_id,
            )
        except (RuntimeError, OSError, TimeoutError) as exc:
            _log.warning(
                "autopatch.synthesize_patch LLM failed finding=%s err=%s",
                finding.finding_ref, exc,
            )
            return PatchSynthesisResult(
                diff="",
                files=(),
                model="",
                prompt_tokens=0,
                completion_tokens=0,
                cost_usd=0.0,
                task_type=cfg.synth_task_type,
                declined=False,
                disabled=False,
                reason=f"llm_error:{type(exc).__name__}",
            )

        if resp.disabled:
            return PatchSynthesisResult(
                diff="", files=(), model=resp.model or "",
                prompt_tokens=0, completion_tokens=0, cost_usd=0.0,
                task_type=cfg.synth_task_type,
                declined=False, disabled=True, reason="llm_kill_switch_active",
            )

        usage = dict(resp.usage or {})
        prompt_tokens = int(usage.get("prompt_tokens") or 0)
        completion_tokens = int(usage.get("completion_tokens") or 0)
        cost_usd = await self._estimate_synth_cost(
            resp.model, prompt_tokens, completion_tokens, cfg,
        )

        content = (resp.content or "").strip()
        if content.startswith("DECLINE:"):
            reason = content.split(":", 1)[1].strip() or "declined"
            return PatchSynthesisResult(
                diff="", files=(),
                model=resp.model or "",
                prompt_tokens=prompt_tokens,
                completion_tokens=completion_tokens,
                cost_usd=cost_usd,
                task_type=cfg.synth_task_type,
                declined=True, disabled=False,
                reason=f"synthesis_declined:{reason[:96]}",
            )

        diff = self._extract_unified_diff(content)
        if not diff:
            return PatchSynthesisResult(
                diff="", files=(),
                model=resp.model or "",
                prompt_tokens=prompt_tokens,
                completion_tokens=completion_tokens,
                cost_usd=cost_usd,
                task_type=cfg.synth_task_type,
                declined=False, disabled=False,
                reason="unparseable_response",
            )

        files = tuple(sorted(set(_DIFF_TARGET_RX.findall(diff))))
        return PatchSynthesisResult(
            diff=diff,
            files=files,
            model=resp.model or "",
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            cost_usd=cost_usd,
            task_type=cfg.synth_task_type,
            declined=False,
            disabled=False,
            reason="",
        )

    async def verify_patch(
        self,
        patch: PatchSynthesisResult,
        harness: PatchHarness,
        source_ctx: list[PatchSourceContext] | PatchSourceContext,
    ) -> PatchVerifyResult:
        """Re-run *harness* against the patched source in a sandbox.

        Applies *patch* on top of the original ``source_ctx`` slices
        (a text-level ``patch(1)``-equivalent inside the guest, so we
        do not need the entire repo staged) and dispatches
        :meth:`SandboxService.run` with the patched files staged into
        the sandbox workdir alongside the harness inputs. The result
        maps 1:1 to ``PlatformPatchAttemptRecord.verify_status``.
        """
        if isinstance(source_ctx, PatchSourceContext):
            source_ctx = [source_ctx]

        if not patch.diff:
            reason = patch.reason or ("synthesis_declined" if patch.declined else "no_patch_synthesised")
            return PatchVerifyResult(status="skipped", reason=reason)
        if not harness.available or not harness.argv:
            return PatchVerifyResult(status="skipped", reason="no_harness")

        cfg = await self._load_config()
        patched_files = self._apply_diff_to_ctx(patch.diff, source_ctx)
        if not patched_files:
            return PatchVerifyResult(status="skipped", reason="diff_did_not_apply")

        # Sandbox spec: stage harness inputs first, then overlay the
        # patched files. The overlay wins so a harness input_files entry
        # that happens to name the vulnerable source (uncommon) does not
        # shadow the patched copy.
        input_files: dict[str, str] = dict(harness.input_files or {})
        input_files.update(patched_files)

        effective_timeout = harness.timeout_s
        if cfg.verify_timeout_s > 0:
            effective_timeout = min(effective_timeout, cfg.verify_timeout_s)

        spec = SandboxSpec(
            argv=list(harness.argv),
            stdin=harness.stdin,
            input_files=input_files,
            env=dict(harness.env or {}),
            timeout_s=effective_timeout,
            network=False,
            workdir=harness.workdir,
            output_globs=[],
        )

        started = time.monotonic()
        try:
            result = await self._sandbox.run(spec)
        except SandboxUnavailableError as exc:
            _log.info(
                "autopatch.verify_patch sandbox unavailable: %s -- recording as skipped",
                exc,
            )
            return PatchVerifyResult(
                status="skipped",
                reason="sandbox_unavailable",
                duration_s=time.monotonic() - started,
            )
        except SandboxExecutionError as exc:
            _log.warning("autopatch.verify_patch backend failure: %s", exc)
            return PatchVerifyResult(
                status="error",
                reason=f"sandbox_execution_error:{type(exc).__name__}",
                duration_s=time.monotonic() - started,
            )

        status, reason = self._classify_verify_result(result, harness)
        return PatchVerifyResult(
            status=status,
            reason=reason,
            backend=result.backend,
            exit_code=result.exit_code,
            stdout=result.stdout,
            stderr=result.stderr,
            duration_s=result.duration_s or (time.monotonic() - started),
            sandbox_result=result,
        )

    async def record_attempt(
        self,
        finding: PatchFinding,
        synthesis: PatchSynthesisResult,
        verify: PatchVerifyResult,
        harness: PatchHarness,
    ) -> PatchAttempt:
        """Persist one attempt row (INSERT or UPDATE by unique key).

        The unique key on ``platform_patch_attempt`` is
        ``(investigation_id, outcome_id, finding_ref)`` so a worker
        retry after :meth:`synthesize_patch` or :meth:`verify_patch`
        updates the prior attempt in place instead of accumulating
        duplicates.
        """
        total_cost = float(synthesis.cost_usd)  # sandbox time is free today
        # Trim output tails so the admin pager stays paginable. 4 KiB of
        # each stream is enough context to see the crash / clean exit
        # without turning the row into a log dump.
        max_out = 4096
        stdout_tail = verify.stdout[-max_out:] if verify.stdout else ""
        stderr_tail = verify.stderr[-max_out:] if verify.stderr else ""
        harness_snapshot: dict[str, Any] = {
            "available": harness.available,
            "argv": list(harness.argv),
            "timeout_s": harness.timeout_s,
            "workdir": harness.workdir,
            "expected_exit": harness.expected_exit,
            "crash_signature": harness.crash_signature,
            "input_file_names": sorted((harness.input_files or {}).keys()),
        }
        now = utc_now()
        async with UnitOfWork() as uow:
            existing = (await uow.session.exec(
                _select(PlatformPatchAttemptRecord).where(
                    PlatformPatchAttemptRecord.investigation_id == finding.investigation_id,
                    PlatformPatchAttemptRecord.outcome_id == finding.outcome_id,
                    PlatformPatchAttemptRecord.finding_ref == finding.finding_ref,
                ),
            )).first()
            if existing is None:
                row = PlatformPatchAttemptRecord(
                    investigation_id=finding.investigation_id,
                    outcome_id=finding.outcome_id,
                    module_id=finding.module_id,
                    team_id=finding.team_id,
                    finding_ref=finding.finding_ref,
                    synth_model=synthesis.model,
                    synth_task_type=synthesis.task_type,
                    synth_prompt_tokens=synthesis.prompt_tokens,
                    synth_completion_tokens=synthesis.completion_tokens,
                    synth_cost_usd=synthesis.cost_usd,
                    patch_diff=synthesis.diff,
                    patch_files_json=json.dumps(list(synthesis.files)),
                    verify_status=verify.status,
                    verify_backend=verify.backend,
                    verify_exit_code=verify.exit_code,
                    verify_stdout=stdout_tail,
                    verify_stderr=stderr_tail,
                    verify_duration_s=verify.duration_s,
                    verify_reason=verify.reason[:128],
                    harness_json=json.dumps(harness_snapshot),
                    total_cost_usd=total_cost,
                    created_at=now,
                    updated_at=now,
                )
                uow.session.add(row)
                await uow.commit()
                attempt_id = row.id
            else:
                existing.module_id = finding.module_id or existing.module_id
                existing.team_id = finding.team_id or existing.team_id
                existing.synth_model = synthesis.model
                existing.synth_task_type = synthesis.task_type
                existing.synth_prompt_tokens = synthesis.prompt_tokens
                existing.synth_completion_tokens = synthesis.completion_tokens
                existing.synth_cost_usd = synthesis.cost_usd
                existing.patch_diff = synthesis.diff
                existing.patch_files_json = json.dumps(list(synthesis.files))
                existing.verify_status = verify.status
                existing.verify_backend = verify.backend
                existing.verify_exit_code = verify.exit_code
                existing.verify_stdout = stdout_tail
                existing.verify_stderr = stderr_tail
                existing.verify_duration_s = verify.duration_s
                existing.verify_reason = verify.reason[:128]
                existing.harness_json = json.dumps(harness_snapshot)
                existing.total_cost_usd = total_cost
                existing.updated_at = now
                uow.session.add(existing)
                await uow.commit()
                attempt_id = existing.id

        _log.info(
            "autopatch RECORD attempt_id=%s finding=%s verdict=%s reason=%s cost_usd=%.4f",
            attempt_id, finding.finding_ref, verify.status, verify.reason, total_cost,
        )
        return PatchAttempt(
            attempt_id=attempt_id,
            finding_ref=finding.finding_ref,
            synthesis=synthesis,
            verify=verify,
            total_cost_usd=total_cost,
        )

    async def run(
        self,
        finding: PatchFinding,
        source_ctx: list[PatchSourceContext] | PatchSourceContext,
        harness: PatchHarness,
    ) -> PatchAttempt:
        """Convenience: synthesize + verify + record in one call.

        The per-module patcher task is the primary caller. Tests that
        want to exercise the pieces independently call
        :meth:`synthesize_patch` / :meth:`verify_patch` /
        :meth:`record_attempt` directly.
        """
        synthesis = await self.synthesize_patch(finding, source_ctx)
        verify = await self.verify_patch(synthesis, harness, source_ctx)
        return await self.record_attempt(finding, synthesis, verify, harness)

    # -- helpers -------------------------------------------------------

    async def _load_config(self) -> _PatchConfig:
        async def _get(name: str, default: Any) -> Any:
            raw = await self._registry.get("platform", name)
            if raw is None:
                return default
            return raw

        raw_enabled = await _get("autopatch_enabled", False)
        enabled = bool(raw_enabled) if isinstance(raw_enabled, bool) else (
            str(raw_enabled).strip().lower() in ("1", "true", "yes", "on")
        )
        synth_task_type = str(
            await _get("autopatch_synth_task_type", "platform.autopatch.synthesize"),
        ).strip() or "platform.autopatch.synthesize"
        try:
            max_source_chars = int(await _get("autopatch_max_source_chars", 24_000))
        except (TypeError, ValueError):
            max_source_chars = 24_000
        try:
            verify_timeout_s = float(await _get("autopatch_verify_timeout_s", 120.0))
        except (TypeError, ValueError):
            verify_timeout_s = 120.0
        try:
            cost_prompt = float(await _get("autopatch_synth_cost_per_1k_prompt", 0.0003))
        except (TypeError, ValueError):
            cost_prompt = 0.0003
        try:
            cost_completion = float(await _get("autopatch_synth_cost_per_1k_completion", 0.0015))
        except (TypeError, ValueError):
            cost_completion = 0.0015

        return _PatchConfig(
            enabled=enabled,
            synth_task_type=synth_task_type,
            max_source_chars=max(1_000, max_source_chars),
            verify_timeout_s=max(0.0, verify_timeout_s),
            cost_per_1k_prompt=max(0.0, cost_prompt),
            cost_per_1k_completion=max(0.0, cost_completion),
        )

    async def _estimate_synth_cost(
        self,
        model_id: str,
        prompt_tokens: int,
        completion_tokens: int,
        cfg: _PatchConfig,
    ) -> float:
        """Prefer the operator's llm_cost_per_1k_* pricing; fall back to
        the autopatch-scoped defaults so the row never records $0 when
        real tokens were burned."""
        cost, configured = await calculate_cost_usd(
            model_id, prompt_tokens, completion_tokens, self._registry,
        )
        if configured:
            return cost
        fallback = (
            (prompt_tokens / 1000.0) * cfg.cost_per_1k_prompt
            + (completion_tokens / 1000.0) * cfg.cost_per_1k_completion
        )
        return max(0.0, fallback)

    @staticmethod
    def _render_source_ctx(
        ctxs: list[PatchSourceContext], max_source_chars: int,
    ) -> str:
        """Render one or more source slices for the coder model prompt.

        Trims from the tail of the concatenated blob so the vulnerable
        region (which the caller placed first) always survives an
        oversize context; the operator sees the truncation marker.
        """
        parts: list[str] = []
        for c in ctxs:
            header = f"## {c.file_path} (line {c.start_line}, lang={c.language or 'auto'})"
            notes = f"\n_notes_: {c.notes}\n" if c.notes.strip() else ""
            parts.append(f"{header}{notes}\n```{c.language}\n{c.content}\n```")
        blob = "\n\n".join(parts)
        if len(blob) > max_source_chars:
            keep = max_source_chars - 64
            return blob[:keep] + f"\n\n[source truncated at {max_source_chars} chars]"
        return blob

    @staticmethod
    def _render_synth_user_prompt(finding: PatchFinding, source: str) -> str:
        vr = finding.verifier_report or {}
        verdict_line = (
            f"Verifier verdict: {vr.get('verdict', 'unknown')} "
            f"(confidence={vr.get('confidence')})"
        )
        preconditions = vr.get("preconditions") or []
        precond_block = ""
        if preconditions:
            lines: list[str] = []
            for i, p in enumerate(preconditions, start=1):
                if not isinstance(p, dict):
                    continue
                lines.append(
                    f"{i}. {p.get('id', '?')}: {p.get('claim') or p.get('description') or ''}",
                )
            if lines:
                precond_block = "\n\n## Verifier preconditions (confirmed)\n" + "\n".join(lines)
        return (
            f"# Finding: {finding.title or finding.finding_ref}\n"
            f"module={finding.module_id} cwe={finding.cwe_id or 'unknown'} "
            f"vuln_fn={finding.vulnerable_function or 'unknown'}\n\n"
            f"{verdict_line}{precond_block}\n\n"
            f"## Root cause\n{finding.root_cause or '(none provided)'}\n\n"
            f"## Source context\n{source}\n\n"
            "## Task\nProduce ONE minimal unified diff that closes the finding "
            "described above without changing any unrelated behavior. Output "
            "the diff only -- no prose, no code fences, no commentary. If a "
            "minimal fix is not possible, reply with a single ``DECLINE: "
            "<reason>`` line."
        )

    @staticmethod
    def _extract_unified_diff(content: str) -> str:
        """Return the diff body from an LLM response.

        Accepts a bare diff (starts with ``--- ``), a diff wrapped in a
        ```diff / ```patch fence, or a diff following a leading prose
        sentence (falls back to the first ``--- `` line onward).
        """
        content = content.strip()
        if not content:
            return ""
        # Fenced block wins if present.
        m = _FENCED_BLOCK_RX.search(content)
        if m:
            body = m.group(1).strip()
            if body.startswith("---") or body.startswith("diff --git"):
                return body
        # Bare diff.
        if content.startswith("---") or content.startswith("diff --git"):
            return content
        # Prose-preceded diff -- drop lead-in.
        idx = content.find("\n--- ")
        if idx != -1:
            return content[idx + 1 :].strip()
        idx = content.find("\ndiff --git ")
        if idx != -1:
            return content[idx + 1 :].strip()
        return ""

    @staticmethod
    def _apply_diff_to_ctx(
        diff: str, ctxs: list[PatchSourceContext],
    ) -> dict[str, str]:
        """Apply *diff* to the in-memory ``PatchSourceContext`` blobs.

        Returns ``{workdir-relative-path: patched-content}`` for every
        source ctx the diff touched. Skips any file whose hunks fail to
        apply so the verifier records ``diff_did_not_apply`` instead of
        running the harness against a half-patched tree.

        Deliberately minimal: this is an in-memory port of ``patch -p1``
        for the same handful of lines the coder model saw; it does not
        need the full patch(1) fuzz / offset / rejection dance. If the
        hunks do not apply cleanly we abandon that file (the harness
        run would just re-crash), which is the correct signal.
        """
        by_path = {c.file_path: c.content for c in ctxs}
        touched = _split_diff_by_file(diff)
        if not touched:
            return {}
        result: dict[str, str] = {}
        for path, file_diff in touched.items():
            base = by_path.get(path)
            if base is None:
                # Also accept the ``b/<path>`` prefix stripped and try a
                # basename match so a diff that renamed the top-level
                # directory still applies to a ctx keyed by tail path.
                base = _match_ctx_by_basename(by_path, path)
                if base is None:
                    _log.info(
                        "autopatch apply_diff: no ctx for %r; skipping file",
                        path,
                    )
                    continue
            patched = _apply_unified_hunks(base, file_diff)
            if patched is None:
                _log.info("autopatch apply_diff: hunks did not apply for %r", path)
                return {}
            result[path] = patched
        return result

    @staticmethod
    def _classify_verify_result(
        result: SandboxResult, harness: PatchHarness,
    ) -> tuple[str, str]:
        """Map a :class:`SandboxResult` + expectation to (status, reason)."""
        if result.timed_out:
            return ("rejected", "reproducer_timed_out")
        if result.oom:
            return ("rejected", "reproducer_oom")
        if harness.crash_signature:
            haystack = f"{result.stderr}\n{result.stdout}"
            if harness.crash_signature in haystack:
                return ("rejected", "crash_signature_still_present")
        expected = harness.expected_exit
        exit_code = result.exit_code
        if exit_code is None:
            # Killed without an exit code -> reproducer took the process down.
            return ("rejected", "reproducer_killed_no_exit")
        if expected is None:
            # No explicit expectation -> a non-crash exit is acceptance.
            return ("accepted", "reproducer_completed_without_crash")
        if exit_code == expected:
            return ("accepted", "reproducer_exit_matches_expected")
        return ("rejected", f"reproducer_exit_{exit_code}_wanted_{expected}")


# ---------------------------------------------------------------------------
# Module-private helpers -- kept top-level so the class body stays short.
# ---------------------------------------------------------------------------


def _split_diff_by_file(diff: str) -> dict[str, str]:
    """Split a multi-file unified diff into one blob per target path."""
    result: dict[str, list[str]] = {}
    current: list[str] | None = None
    current_path = ""
    for line in diff.splitlines():
        if line.startswith("+++ "):
            path = line[4:].strip()
            if path.startswith("b/"):
                path = path[2:]
            if path == "/dev/null":
                current = None
                current_path = ""
                continue
            current = result.setdefault(path, [])
            current_path = path
            continue
        if line.startswith("--- "):
            # Header pair; keep collecting the same file until we see the
            # +++ line above.
            continue
        if current is not None:
            current.append(line)
        _ = current_path
    return {p: "\n".join(lines) for p, lines in result.items() if lines}


def _match_ctx_by_basename(
    by_path: dict[str, str], diff_path: str,
) -> str | None:
    """Fallback lookup by basename when the coder model emits a
    differently-prefixed path (e.g. it kept ``b/`` or dropped a leading
    subdir). Returns the ctx content, not the ctx key, so the caller can
    still write under the diff's own path in the sandbox.
    """
    base = diff_path.rsplit("/", 1)[-1]
    for ctx_path, content in by_path.items():
        if ctx_path.rsplit("/", 1)[-1] == base:
            return content
    return None


def _apply_unified_hunks(base: str, file_diff: str) -> str | None:
    """Apply the unified-diff hunks in *file_diff* to *base*.

    Returns the patched text on success, ``None`` when any hunk failed
    to apply (context did not match). Handles standard ``@@ -a,b +c,d @@``
    hunk headers; ignores git-specific extension lines (``diff --git``,
    ``index``, ``similarity``, ``rename``, etc.).
    """
    base_lines = base.splitlines()
    # Build the patched buffer as we consume hunks in file order.
    out: list[str] = []
    src_cursor = 0  # 0-indexed pointer into base_lines
    hunk_header_rx = re.compile(r"^@@\s+-(\d+)(?:,(\d+))?\s+\+(\d+)(?:,(\d+))?\s*@@")

    lines = file_diff.splitlines()
    i = 0
    while i < len(lines):
        line = lines[i]
        m = hunk_header_rx.match(line)
        if not m:
            i += 1
            continue
        old_start = int(m.group(1))
        # Old-line index into base_lines (0-based).
        old_idx = max(0, old_start - 1)
        # Copy the untouched prefix between the last hunk and this one.
        if old_idx < src_cursor:
            # Overlapping / out-of-order hunk -- refuse rather than
            # produce silently-wrong output.
            return None
        out.extend(base_lines[src_cursor:old_idx])
        src_cursor = old_idx
        i += 1
        # Consume hunk body until the next hunk header or diff header.
        while i < len(lines):
            body = lines[i]
            if body.startswith("@@") and hunk_header_rx.match(body):
                break
            if body.startswith("--- ") or body.startswith("+++ ") or body.startswith("diff --git "):
                break
            if not body:
                # Blank line inside a hunk is a context line for an
                # actual blank in the source; treat it as ``' '`` + ''.
                if src_cursor < len(base_lines) and base_lines[src_cursor] == "":
                    out.append("")
                    src_cursor += 1
                    i += 1
                    continue
                # Also tolerate a truly empty separator between hunks --
                # some coder models emit them. Advance without touching
                # src_cursor.
                i += 1
                continue
            tag = body[0]
            payload = body[1:]
            if tag == " ":
                if src_cursor >= len(base_lines) or base_lines[src_cursor] != payload:
                    return None
                out.append(payload)
                src_cursor += 1
            elif tag == "-":
                if src_cursor >= len(base_lines) or base_lines[src_cursor] != payload:
                    return None
                src_cursor += 1
            elif tag == "+":
                out.append(payload)
            elif tag == "\\":
                # ``\ No newline at end of file`` -- keep semantics as-is.
                pass
            else:
                # Unknown line kind -- refuse rather than accept garbage.
                return None
            i += 1
    # Copy the untouched suffix.
    out.extend(base_lines[src_cursor:])
    # Preserve trailing newline when the source had one.
    trailing_nl = base.endswith("\n")
    joined = "\n".join(out)
    if trailing_nl and not joined.endswith("\n"):
        joined += "\n"
    return joined


def _fingerprint_ctx(ctxs: list[PatchSourceContext]) -> str:
    """Stable sha256 over the source ctx blobs -- exposed for tests /
    tools that want to detect a stale attempt without re-running the
    LLM (unused by the service today, but the field belongs with the
    other in-memory helpers)."""
    h = hashlib.sha256()
    for c in ctxs:
        h.update(c.file_path.encode("utf-8"))
        h.update(b"\0")
        h.update(c.content.encode("utf-8", errors="replace"))
        h.update(b"\0")
    return h.hexdigest()
