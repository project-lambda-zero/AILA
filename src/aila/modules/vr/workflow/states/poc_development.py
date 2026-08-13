"""PoC development state -- generate, compile, run, and verify a PoC.

Loop shape (bounded by ``config.poc_max_attempts``):
1. Ask the LLM for PoC source given the research findings.
2. Compile via PoCRunnerTool.compile_poc (Python or C).
3. Execute via PoCRunnerTool.run_poc against the vulnerable target binary.
4. On crash: verify reliability over 5 runs, then run once against the
   patched target binary to confirm clean-exit semantics.
5. On clean exit / no crash: feed the failure summary back to the LLM
   for revision and retry until the attempt budget is consumed.
6. Parse the captured ASAN output (if any) and compute a dedup signature.

If no SSH integration is available the loop short-circuits with a
``status="untested"`` payload -- useful for offline analysis where the PoC
can only be drafted, not executed.

Compilation failure is recorded against the attempt count and surfaced in
the per-attempt log; it is not raised, so a single bad code emission
cannot crash the workflow.

Sandbox containment (fix #51). The ``Stay within /tmp/aila_vr/`` line in
``system_poc_development.md`` is guidance to the LLM, NOT a security
control. The runtime enforcement lives in :mod:`aila.modules.vr.tools.poc_runner`:
``confine_remote_poc_path`` refuses any ``poc_path`` that is not absolute
and under ``/tmp/aila_vr``, and every remote invocation is wrapped in
``firejail`` or ``unshare + setpriv`` (fail-closed -- when neither is
present the tool REFUSES to execute with a clear reason instead of
degrading to an unsandboxed shell). Each ``compile_poc`` allocates a
fresh ``/tmp/aila_vr/run_<hex>`` subdirectory and returns paths inside
it; this state's ``finally`` block invokes ``cleanup_workspace`` for
every provisioned subdirectory so the analyzer workstation does not
accumulate scratch space across runs. A hallucinated
``requests.post(...)`` cannot reach the network and a hallucinated
``open('/etc/shadow')`` cannot exfiltrate host files.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import random
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, Field

from aila.modules.vr.tools.poc_runner import confine_remote_poc_path
from aila.platform.llm.correlation import (
    correlation_scope,
    current_join_keys,
    current_prompt_version,
)
from aila.platform.prompts import PromptRegistry
from aila.platform.workflows.types import StateResult

__all__ = [
    "LLMDisabledByOperatorError",
    "parse_reliability_target",
    "state_poc_development",
]

_log = logging.getLogger(__name__)


# fix #209 -- wire ``config.poc_reliability_target``. The config key was
# defined + documented as "successful_runs/total_runs before the PoC is
# considered acceptance-ready", but the state hardcoded ``runs=5`` on
# ``verify_reliability`` and never gated the result. ``5/5`` (default)
# therefore preserved the prior behaviour end-to-end: 5 runs, and any
# non-``5/5`` return still surfaced as ``verified`` with no acceptance
# signal for downstream consumers. Parsing the operator-tunable
# ``M/N`` spec here means a PUT /config override of e.g. ``3/5`` now
# both drives the sample size AND stamps ``acceptance_ready`` on the
# poc payload so the advisory / operator surfaces can distinguish
# "reproduces but flaky" from "meets the operator's reliability bar".
def parse_reliability_target(spec: str) -> tuple[int, int]:
    """Parse an ``M/N`` reliability spec into ``(required, total)``.

    Both integers must be positive and ``required <= total``. Any
    malformed value logs a warning and falls back to the schema
    default ``5/5`` so a bad config row does not crash the workflow.
    """
    default_required, default_total = 5, 5
    try:
        raw = str(spec or "").strip()
        num_str, denom_str = raw.split("/", 1)
        required = int(num_str.strip())
        total = int(denom_str.strip())
    except (AttributeError, TypeError, ValueError):
        _log.warning(
            "poc_reliability_target %r is not a valid M/N spec; using 5/5",
            spec,
        )
        return default_required, default_total
    if required <= 0 or total <= 0 or required > total:
        _log.warning(
            "poc_reliability_target %r is out of range (need 0 < M <= N); "
            "using 5/5", spec,
        )
        return default_required, default_total
    return required, total

_PROMPT_DIR = Path(__file__).resolve().parent.parent / "prompts"
_PROMPT_REGISTRY = PromptRegistry(
    _PROMPT_DIR, fallback_base="system_poc_development.md",
)


def _load_system_prompt() -> str:
    """Return the PoC-generator system prompt from the registry.

    RFC-09 criterion 1: prompt lives in a versionable ``.md`` file, not
    inline. Reads ``system_poc_development.md`` under the VR workflow
    prompts directory.
    """
    return _PROMPT_REGISTRY.load("poc_development")


# fix §303 -- dedicated exception for the LLM kill-switch state. The
# prior code raised `RuntimeError("LLM disabled by operator")` which
# the outer try/except caught alongside transient httpx errors and
# transient pydantic ValidationErrors, smearing operator intent into
# the same retry bucket as flake. With a dedicated subclass, the
# attempt loop can distinguish "this attempt failed; revise and try
# again" (RuntimeError, ValueError, OSError, TimeoutError) from
# "operator pulled the kill switch; STOP burning attempts" and
# short-circuit accordingly.
class LLMDisabledByOperatorError(Exception):
    """Raised when the LLM kill switch is engaged.

    Engine-side semantics: do NOT retry the attempt loop; the
    operator has explicitly disabled LLM usage. The state handler
    catches this once and exits with an untested payload tagged
    `llm_kill_switch_active`.
    """


# fix §302 -- schema for chat_structured. Replaces the prior
# brace-counting `find("{")` / `rfind("}")` JSON parse that §301
# names as a bug -- anything resembling a JSON object inside the
# rationale or a markdown code fence would defeat the parser. The
# strict json_schema response_format on the LLM side guarantees a
# valid PoCResponse on success, and chat_structured handles the
# one-shot correction retry on parse failure.
class PoCResponse(BaseModel):
    """Validated PoC emission from the LLM."""

    language: Literal["python", "c"] = Field(
        description="Source language for the PoC; only python or c are runnable.",
    )
    filename: str = Field(
        description="Filename suggestion, e.g. poc.py or poc.c.",
        min_length=1,
        max_length=128,
    )
    code: str = Field(
        description="Full PoC source. Single file. No commentary outside.",
        min_length=1,
    )
    rationale: str = Field(
        description="One sentence explaining the trigger mechanism.",
        max_length=512,
    )

_REVISION_HEADER = "Previous PoC attempt failed to crash. Revise the code."


def _slim_research(research: dict[str, Any]) -> str:
    return json.dumps({
        "vulnerable_function": research.get("vulnerable_function"),
        "root_cause": research.get("root_cause"),
        "crash_type": research.get("crash_type"),
        "evidence": (research.get("evidence") or [])[:4],
    })


def _build_user_prompt(
    research: dict[str, Any],
    mitigations: dict[str, Any],
    history: list[dict[str, Any]],
) -> str:
    parts = [
        "Research findings:",
        _slim_research(research),
        "",
        f"Mitigations: {json.dumps(mitigations or {})}",
        "",
    ]
    if history:
        parts.append(_REVISION_HEADER)
        for entry in history[-3:]:
            parts.append(
                f"  attempt {entry['attempt']} ({entry['language']}): "
                f"{entry['outcome']} -- {entry.get('detail', '')[:240]}"
            )
        parts.append("")
    parts.append("Return a single JSON object matching the response contract.")
    return "\n".join(parts)


# fix §307 -- first 3 attempts are routed to a cheaper draft task type;
# attempts ≥ 4 escalate to the full vulnerability_research model. The
# rationale: early attempts iterate on the rough shape (does the
# pwntools layout look right? does the C buffer math line up?) and a
# small/fast model is enough. By attempt 4 the pipeline has burned
# 3× LLM + compile + run; the remaining attempts deserve the
# highest-quality model the routing tier exposes. Operator can rewire
# either task_type independently via the platform routing config.
_POC_DRAFT_TASK_TYPE = "vulnerability_research.poc_draft"
_POC_FINAL_TASK_TYPE = "vulnerability_research"
_POC_DRAFT_ATTEMPTS_BEFORE_ESCALATION = 3


def _task_type_for_attempt(attempt: int) -> str:
    """Return the LLM task_type to use for the given 1-indexed attempt."""
    if attempt <= _POC_DRAFT_ATTEMPTS_BEFORE_ESCALATION:
        return _POC_DRAFT_TASK_TYPE
    return _POC_FINAL_TASK_TYPE


async def _llm_poc(
    services: Any,
    user_prompt: str,
    *,
    task_type: str = _POC_FINAL_TASK_TYPE,
) -> PoCResponse:
    """Ask the LLM for one PoC; return a validated PoCResponse.

    fix §302 -- swapped `chat` for `chat_structured` against PoCResponse.
    The strict JSON-schema response_format on the LLM side eliminates
    the prior `find("{") / rfind("}")` heuristic that §301 flags as
    fragile: anything resembling a JSON object inside the rationale or
    a wrapping markdown fence used to land the parser on the wrong
    boundaries. chat_structured ALSO handles the one-shot retry on
    parse failure, so a transient JSON malformation no longer aborts
    a whole attempt.

    fix §307 -- task_type is now a parameter (default: final tier) so
    the attempt loop can pass the cheaper draft task_type for early
    iterations.
    """
    # fix §309 -- cap completion tokens at 2048. The PoCResponse schema
    # is bounded (filename ≤128 chars, rationale ≤512 chars, code is
    # the dominant component but a single-file PoC is rarely more
    # than ~1200-1500 tokens of source). Without a cap, a misbehaving
    # model can emit pages of commentary outside the schema (chat_json
    # strips fences but still pays for the burst), or stall on a
    # truncation-induced JSON error that re-fires the correction
    # retry. 2048 gives ~1.5× headroom over the expected payload
    # and short-circuits runaway emissions.
    system_prompt = _load_system_prompt()
    # RFC-09 criterion 2: stamp the resolved system prompt's content hash
    # so this LLM call's LLMCostRecord + AuditSealRecord attribute back to
    # the exact PoC-generator prompt template. Preserve any outer join keys
    # so an investigation-scoped caller keeps its attribution.
    prompt_hash = hashlib.sha256(system_prompt.encode("utf-8")).hexdigest()
    _inv, _br, _turn = current_join_keys()
    with correlation_scope(
        investigation_id=_inv, branch_id=_br, turn_number=_turn,
        prompt_content_hash=prompt_hash,
        prompt_version=current_prompt_version(),
    ):
        response = await services.llm_client.chat_structured(
            task_type=task_type,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            model_class=PoCResponse,
            run_id=services.run_id,
            max_output_tokens=2048,
        )
    if response.disabled:
        raise LLMDisabledByOperatorError("LLM disabled by operator")
    # chat_structured guarantees the content matches PoCResponse on
    # success, but LLMResponse carries it as a JSON string (no
    # `.parsed` field -- see synthesis_agent for the same pattern).
    try:
        return PoCResponse.model_validate_json(response.content)
    except ValueError as exc:
        raise ValueError(
            f"LLM returned content that failed PoCResponse schema: {exc}",
        ) from exc


def _has_ssh(integration: Any) -> bool:
    return isinstance(integration, dict) and bool(integration)


def _untested_payload(reason: str, code: str | None, language: str | None) -> dict[str, Any]:
    return {
        "status": "untested",
        "reason": reason,
        "language": language or "python",
        "code": code or "",
        "exit_code": None,
        "crash_detected": False,
        "asan_report": "",
        "crash_signature": None,
        "reliability": None,
        "patched_clean_exit": None,
    }


async def state_poc_development(input: dict[str, Any], services: Any) -> StateResult:
    """Generate, compile, and verify a PoC bounded by config.poc_max_attempts."""
    research = input.get("research") or {}
    integration = input.get("integration") or {}
    target_path = str(input.get("target_path") or "")
    patched_path = input.get("patched_path") or None
    mitigations = input.get("mitigations") or {}

    if not _has_ssh(integration):
        _log.info("poc_development: no SSH integration; skipping execution")
        try:
            generated = await _llm_poc(
                services,
                _build_user_prompt(research, mitigations, []),
                task_type=_POC_DRAFT_TASK_TYPE,
            )
        except LLMDisabledByOperatorError:
            return StateResult(
                next_state="advisory",
                output={
                    **input,
                    "poc": _untested_payload(
                        "llm_kill_switch_active", None, None,
                    ),
                },
            )
        except (RuntimeError, ValueError, OSError, TimeoutError) as exc:
            return StateResult(
                next_state="advisory",
                output={
                    **input,
                    "poc": _untested_payload(f"llm error: {exc}", None, None),
                },
            )
        return StateResult(
            next_state="advisory",
            output={
                **input,
                "poc": _untested_payload(
                    "no SSH integration available",
                    generated.code,
                    generated.language,
                ),
            },
        )

    # fix #51 -- per-run workspace teardown. Each successful compile
    # allocates a fresh ``/tmp/aila_vr/run_<hex>`` subdirectory on the
    # analyzer workstation; the ``finally`` block below reclaims every
    # one via ``cleanup_workspace`` so the state exit path (crash,
    # untested, LLM kill-switch) does not leak scratch space. Bounding
    # workspace growth is the ``poc_runner`` prune's job even when this
    # cleanup is skipped; the explicit ``finally`` is the fast path.
    compiled_run_dirs: list[str] = []
    try:
        return await _run_ssh_attempts(
            input=input,
            services=services,
            research=research,
            integration=integration,
            target_path=target_path,
            patched_path=patched_path,
            mitigations=mitigations,
            compiled_run_dirs=compiled_run_dirs,
        )
    finally:
        await _cleanup_compiled_workspaces(
            services, integration, compiled_run_dirs,
        )


async def _cleanup_compiled_workspaces(
    services: Any,
    integration: dict[str, Any],
    compiled_run_dirs: list[str],
) -> None:
    """Best-effort teardown of every per-run workspace this state provisioned.

    fix #51 -- invoked from ``state_poc_development``'s ``finally`` block
    so crash, untested, LLM kill-switch, and exception exit paths all
    reclaim their scratch space. Cleanup failures are logged and
    swallowed: an exit-path exception must NOT mask the original
    workflow result, and the ``poc_runner`` prune pass will collect the
    stragglers on the next compile.
    """
    for run_dir in compiled_run_dirs:
        try:
            result = await services.poc_runner.forward(
                action="cleanup_workspace",
                integration=integration,
                run_dir=run_dir,
            )
        except (OSError, RuntimeError, TimeoutError) as exc:
            _log.warning(
                "poc_development: cleanup_workspace raised for %s (%s: %s)",
                run_dir, type(exc).__name__, exc,
            )
            continue
        status = result.get("status") if isinstance(result, dict) else None
        if status not in ("cleaned", "skipped"):
            _log.warning(
                "poc_development: cleanup_workspace did not clean %s: %s",
                run_dir, result,
            )


async def _run_ssh_attempts(
    *,
    input: dict[str, Any],
    services: Any,
    research: dict[str, Any],
    integration: dict[str, Any],
    target_path: str,
    patched_path: Any,
    mitigations: dict[str, Any],
    compiled_run_dirs: list[str],
) -> StateResult:
    """SSH-driven PoC compile/run/verify attempt loop (fix #51 factor-out).

    Split out from :func:`state_poc_development` so the caller can wrap
    it in a ``try/finally`` that reclaims every ``compile_poc`` workspace
    via ``cleanup_workspace`` regardless of which return path fires.
    The behavior of the loop itself is unchanged from the pre-fix
    version -- only the workspace bookkeeping is threaded through
    ``compiled_run_dirs`` (mutated in place).
    """
    history: list[dict[str, Any]] = []
    crash_payload: dict[str, Any] | None = None
    last_code: str = ""
    last_language: str = "python"
    last_filename: str = "poc.py"

    # fix \u00a7308 -- track the "best" non-crashing attempt by a closeness
    # heuristic. The prior code surfaced LAST attempt's language/code
    # in the untested_payload, which biased the operator's manual
    # follow-up toward whatever the LLM emitted last (often a
    # regressed simpler attempt after several rich ones failed). Score
    # = len(stderr_tail) + 100 * (exit_code != 0). Higher score is
    # closer to a crash. \`best_*\` stays at the highest-scored attempt
    # so the untested_payload below reports the strongest candidate
    # the operator should look at, not the chronologically last one.
    best_code: str = ""
    best_language: str = "python"
    best_score: int = -1

    # fix §304 -- hard cap the operator-tunable poc_max_attempts at 25.
    # The config row is operator-editable through the platform config
    # UI and a misconfigured value of 1000 would launch a $500+ PoC
    # session (every attempt is one LLM call + one compile + one run
    # against the analyzer workstation). 25 is the published maximum
    # in the operator runbook; surface the clamp loudly so a runaway
    # config doesn't go unnoticed.
    operator_max_attempts_ceiling = 25
    raw_max = max(1, int(services.config.poc_max_attempts))
    max_attempts = min(raw_max, operator_max_attempts_ceiling)
    if raw_max > operator_max_attempts_ceiling:
        _log.warning(
            "poc_development: poc_max_attempts=%d exceeds ceiling %d -- "
            "clamping. Operator should fix the config or raise the ceiling.",
            raw_max, operator_max_attempts_ceiling,
        )
    for attempt in range(1, max_attempts + 1):
        # fix §305 -- exponential backoff with jitter between attempts.
        # The prior implementation re-fired the full LLM + compile + run
        # pipeline immediately on every continue, so a flaky LLM tier
        # (rate-limited / transient 503) or a wedged poc_runner socket
        # would burn the whole attempt budget against the same broken
        # backend inside a few hundred milliseconds. Sleep before
        # attempts 2..N (NOT attempt 1) with the standard
        # \`min(30, 2 ** attempt + jitter)\` shape.
        if attempt > 1:
            backoff_s = min(30.0, (2 ** attempt) + random.uniform(0, 1))
            _log.info(
                "poc_development: attempt %d backoff %.1fs", attempt, backoff_s,
            )
            await asyncio.sleep(backoff_s)
        try:
            generated = await _llm_poc(
                services,
                _build_user_prompt(research, mitigations, history),
                task_type=_task_type_for_attempt(attempt),
            )
        except LLMDisabledByOperatorError:
            # fix §303 -- operator pulled the kill switch. Do NOT burn
            # additional attempts; surface the untested payload now.
            return StateResult(
                next_state="advisory",
                output={
                    **input,
                    "poc": {
                        **_untested_payload(
                            "llm_kill_switch_active", last_code, last_language,
                        ),
                        "history": history,
                    },
                },
            )
        except (RuntimeError, ValueError, OSError, TimeoutError) as exc:
            history.append({
                "attempt": attempt, "language": last_language,
                "outcome": "llm_error", "detail": f"{type(exc).__name__}: {exc}",
            })
            continue

        last_language = generated.language.strip().lower()
        last_filename = generated.filename or (
            "poc.py" if last_language == "python" else "poc.c"
        )
        last_code = generated.code

        compile_result = await services.poc_runner.forward(
            action="compile_poc",
            integration=integration,
            code=last_code,
            language=last_language,
            filename=last_filename,
        )
        # fix #51 -- track the per-run workspace subdir for ``finally``
        # cleanup regardless of compile success. A ``ready`` compile
        # returns ``run_dir``; a compile that raced past ``mkdir`` and
        # failed at gcc may still return one. Missing values (an older
        # tool response) are skipped without erroring so the workflow
        # stays forward-compatible.
        compile_run_dir = compile_result.get("run_dir")
        if isinstance(compile_run_dir, str) and compile_run_dir:
            compiled_run_dirs.append(compile_run_dir)
        if compile_result.get("status") != "ready":
            history.append({
                "attempt": attempt, "language": last_language,
                "outcome": "compile_failed",
                "detail": str(compile_result.get("error") or compile_result),
            })
            continue

        poc_path = compile_result.get("script_path") or compile_result.get("binary_path")
        # fix #51 -- belt+suspenders confinement at the state boundary. The
        # tool re-validates on _run entry, but a compile-result mutation
        # (bug or tampering) should never reach the shell wrapper. Fail
        # the attempt closed with an audit-visible outcome so the
        # operator sees the escape attempt in the per-attempt log.
        confinement_error = confine_remote_poc_path(str(poc_path or ""))
        if confinement_error:
            _log.warning(
                "poc_development: compile_result poc_path escaped sandbox root: %s",
                confinement_error,
            )
            history.append({
                "attempt": attempt, "language": last_language,
                "outcome": "poc_path_escaped_sandbox",
                "detail": confinement_error,
            })
            continue
        run_result = await services.poc_runner.forward(
            action="run_poc",
            integration=integration,
            poc_path=poc_path,
            target_binary=target_path,
            timeout_seconds=services.config.poc_timeout_seconds,
            memory_limit_mb=services.config.poc_memory_limit_mb,
        )
        # fix §306 -- explicit \`is True\` check. The previous
        # \`if run_result.get(\"crash_detected\"):\` would treat the string
        # \"false\", the integer 0 wrapped in a string, or any non-empty
        # JSON-serialized truthy-looking value as a crash. The
        # poc_runner JSON contract says crash_detected is a bool, so
        # accept only literal True; anything else (None, missing key,
        # string \"false\", int 0) is a non-crash.
        if run_result.get("crash_detected") is True:
            crash_payload = {
                "poc_path": poc_path,
                "first_run": run_result,
            }
            history.append({
                "attempt": attempt, "language": last_language, "outcome": "crashed",
                "detail": f"exit={run_result.get('exit_code')}",
            })
            break
        # fix §308 -- score this attempt's closeness-to-crash. Longer
        # stderr_tail or any non-zero exit code is "closer" than a
        # clean 0-byte stderr exit. Update best_* whenever this
        # attempt outscores the prior best so the untested_payload
        # ultimately surfaces the strongest candidate.
        stderr_tail = run_result.get("stderr_tail") or ""
        exit_code = run_result.get("exit_code")
        score = len(stderr_tail) + (100 if exit_code not in (0, None) else 0)
        if score > best_score:
            best_score = score
            best_code = last_code
            best_language = last_language
        history.append({
            "attempt": attempt, "language": last_language,
            "outcome": "no_crash",
            "detail": (
                f"exit={exit_code} timeout={run_result.get('timeout')} "
                f"stderr={stderr_tail[:200]} score={score}"
            ),
        })

    if crash_payload is None:
        # fix §308 -- fall back to best_* (highest closeness-to-crash
        # score) instead of last_*. If no attempts produced any
        # measurable signal (best_score stayed at -1), fall back to
        # last_* -- that's still the only thing we can show.
        surfaced_code = best_code if best_score >= 0 else last_code
        surfaced_lang = best_language if best_score >= 0 else last_language
        return StateResult(
            next_state="advisory",
            output={
                **input,
                "poc": {
                    **_untested_payload(
                        "no crash within attempt budget",
                        surfaced_code,
                        surfaced_lang,
                    ),
                    "history": history,
                    "best_score": best_score,
                },
            },
        )

    # fix #209 -- drive both the sample size and the acceptance gate
    # from the operator-tunable ``poc_reliability_target``. Default
    # ``5/5`` matches the prior hardcoded ``runs=5`` behaviour; a
    # ``3/5`` override now runs 5 samples AND stamps
    # ``acceptance_ready=(crashes >= 3)`` so downstream consumers can
    # separate "meets the operator's bar" from "reproduces but flaky".
    reliability_required, reliability_total = parse_reliability_target(
        services.config.poc_reliability_target,
    )
    reliability_result = await services.poc_runner.forward(
        action="verify_reliability",
        integration=integration,
        poc_path=crash_payload["poc_path"],
        target_binary=target_path,
        runs=reliability_total,
        timeout_seconds=services.config.poc_timeout_seconds,
        memory_limit_mb=services.config.poc_memory_limit_mb,
    )
    try:
        reliability_crashes = int(reliability_result.get("crashes") or 0)
    except (TypeError, ValueError):
        reliability_crashes = 0
    acceptance_ready = (
        reliability_result.get("status") == "ready"
        and reliability_crashes >= reliability_required
    )

    patched_clean: bool | None = None
    if patched_path:
        patched_run = await services.poc_runner.forward(
            action="run_poc",
            integration=integration,
            poc_path=crash_payload["poc_path"],
            target_binary=str(patched_path),
            timeout_seconds=services.config.poc_timeout_seconds,
            memory_limit_mb=services.config.poc_memory_limit_mb,
        )
        patched_clean = bool(patched_run.get("clean_exit"))

    asan_text = (
        crash_payload["first_run"].get("stderr_tail")
        or crash_payload["first_run"].get("stdout_tail")
        or ""
    )
    parsed_asan = await services.crash_triage.forward(
        action="parse_asan", asan_output=asan_text,
    )
    if parsed_asan.get("status") != "ready":
        parsed_asan = {
            "status": "ready",
            "crash_type": research.get("crash_type") or "info_disclosure",
            "stack_frames": [],
        }

    signature = await services.crash_triage.forward(
        action="compute_signature",
        crash_type=parsed_asan.get("crash_type") or research.get("crash_type"),
        frames=parsed_asan.get("stack_frames") or [],
    )

    poc_payload = {
        "status": "verified",
        "language": last_language,
        "code": last_code,
        "exit_code": crash_payload["first_run"].get("exit_code"),
        "crash_detected": True,
        "asan_report": asan_text,
        "crash_signature": signature if signature.get("status") == "ready" else None,
        "reliability": reliability_result.get("reliability"),
        "reliability_target": f"{reliability_required}/{reliability_total}",
        "acceptance_ready": acceptance_ready,
        "patched_clean_exit": patched_clean,
        "parsed_asan": parsed_asan,
        "history": history,
    }

    return StateResult(
        next_state="advisory",
        output={**input, "poc": poc_payload},
    )
