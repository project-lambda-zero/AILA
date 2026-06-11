"""PoC development state — generate, compile, run, and verify a PoC.

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
``status="untested"`` payload — useful for offline analysis where the PoC
can only be drafted, not executed.

Compilation failure is recorded against the attempt count and surfaced in
the per-attempt log; it is not raised, so a single bad code emission
cannot crash the workflow.
"""
from __future__ import annotations

import asyncio
import json
import logging
import random
from typing import Any, Literal

from pydantic import BaseModel, Field

from aila.platform.workflows.types import StateResult

__all__ = ["LLMDisabledByOperatorError", "state_poc_development"]

_log = logging.getLogger(__name__)


# fix §303 — dedicated exception for the LLM kill-switch state. The
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


# fix §302 — schema for chat_structured. Replaces the prior
# brace-counting `find("{")` / `rfind("}")` JSON parse that §301
# names as a bug — anything resembling a JSON object inside the
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

_SYSTEM_PROMPT = """You write proof-of-concept exploits for vulnerability \
research. Given a root-cause description, vulnerable function, and crash \
type, emit a single PoC that triggers the bug. Default language is Python \
(uses pwntools when helpful); use C only when stack/heap layout requires it.

Return ONE JSON object exactly matching:
{
  "language": "python | c",
  "filename": "poc.py | poc.c",
  "code": "...full source...",
  "rationale": "one sentence on the trigger mechanism"
}

Constraints:
- The PoC will run with `python3 poc.py <target_binary>` (Python) or be \
compiled and run with `./poc <target_binary>` (C).
- Stay within /tmp/aila_vr/ for any side files.
- Prefer ASAN-visible primitives (out-of-bounds writes, UAF, double free).
- Do NOT include hash banners, license headers, or commentary outside the \
JSON object."""

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
                f"{entry['outcome']} — {entry.get('detail', '')[:240]}"
            )
        parts.append("")
    parts.append("Return a single JSON object matching the response contract.")
    return "\n".join(parts)


# fix §307 — first 3 attempts are routed to a cheaper draft task type;
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

    fix §302 — swapped `chat` for `chat_structured` against PoCResponse.
    The strict JSON-schema response_format on the LLM side eliminates
    the prior `find("{") / rfind("}")` heuristic that §301 flags as
    fragile: anything resembling a JSON object inside the rationale or
    a wrapping markdown fence used to land the parser on the wrong
    boundaries. chat_structured ALSO handles the one-shot retry on
    parse failure, so a transient JSON malformation no longer aborts
    a whole attempt.

    fix §307 — task_type is now a parameter (default: final tier) so
    the attempt loop can pass the cheaper draft task_type for early
    iterations.
    """
    # fix §309 — cap completion tokens at 2048. The PoCResponse schema
    # is bounded (filename ≤128 chars, rationale ≤512 chars, code is
    # the dominant component but a single-file PoC is rarely more
    # than ~1200-1500 tokens of source). Without a cap, a misbehaving
    # model can emit pages of commentary outside the schema (chat_json
    # strips fences but still pays for the burst), or stall on a
    # truncation-induced JSON error that re-fires the correction
    # retry. 2048 gives ~1.5× headroom over the expected payload
    # and short-circuits runaway emissions.
    response = await services.llm_client.chat_structured(
        task_type=task_type,
        messages=[
            {"role": "system", "content": _SYSTEM_PROMPT},
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
    # `.parsed` field — see synthesis_agent for the same pattern).
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

    history: list[dict[str, Any]] = []
    crash_payload: dict[str, Any] | None = None
    last_code: str = ""
    last_language: str = "python"
    last_filename: str = "poc.py"

    # fix §308 — track the "best" non-crashing attempt by a closeness
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

    # fix §304 — hard cap the operator-tunable poc_max_attempts at 25.
    # The config row is operator-editable through the platform config
    # UI and a misconfigured value of 1000 would launch a $500+ PoC
    # session (every attempt is one LLM call + one compile + one run
    # against the analyzer workstation). 25 is the published maximum
    # in the operator runbook; surface the clamp loudly so a runaway
    # config doesn't go unnoticed.
    _OPERATOR_MAX_ATTEMPTS_CEILING = 25
    raw_max = max(1, int(services.config.poc_max_attempts))
    max_attempts = min(raw_max, _OPERATOR_MAX_ATTEMPTS_CEILING)
    if raw_max > _OPERATOR_MAX_ATTEMPTS_CEILING:
        _log.warning(
            "poc_development: poc_max_attempts=%d exceeds ceiling %d — "
            "clamping. Operator should fix the config or raise the ceiling.",
            raw_max, _OPERATOR_MAX_ATTEMPTS_CEILING,
        )
    for attempt in range(1, max_attempts + 1):
        # fix §305 — exponential backoff with jitter between attempts.
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
            # fix §303 — operator pulled the kill switch. Do NOT burn
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
        if compile_result.get("status") != "ready":
            history.append({
                "attempt": attempt, "language": last_language,
                "outcome": "compile_failed",
                "detail": str(compile_result.get("error") or compile_result),
            })
            continue

        poc_path = compile_result.get("script_path") or compile_result.get("binary_path")
        run_result = await services.poc_runner.forward(
            action="run_poc",
            integration=integration,
            poc_path=poc_path,
            target_binary=target_path,
            timeout_seconds=services.config.poc_timeout_seconds,
            memory_limit_mb=services.config.poc_memory_limit_mb,
        )
        # fix §306 — explicit \`is True\` check. The previous
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
        # fix §308 — score this attempt's closeness-to-crash. Longer
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
        # fix §308 — fall back to best_* (highest closeness-to-crash
        # score) instead of last_*. If no attempts produced any
        # measurable signal (best_score stayed at -1), fall back to
        # last_* — that's still the only thing we can show.
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

    reliability_result = await services.poc_runner.forward(
        action="verify_reliability",
        integration=integration,
        poc_path=crash_payload["poc_path"],
        target_binary=target_path,
        runs=5,
        timeout_seconds=services.config.poc_timeout_seconds,
        memory_limit_mb=services.config.poc_memory_limit_mb,
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
        "patched_clean_exit": patched_clean,
        "parsed_asan": parsed_asan,
        "history": history,
    }

    return StateResult(
        next_state="advisory",
        output={**input, "poc": poc_payload},
    )
