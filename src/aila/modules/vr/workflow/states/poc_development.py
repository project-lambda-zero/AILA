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
from typing import Any

from aila.platform.workflows.types import StateResult

__all__ = ["state_poc_development"]

_log = logging.getLogger(__name__)

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


async def _llm_poc(services: Any, user_prompt: str) -> dict[str, Any]:
    response = await services.llm_client.chat(
        task_type="vulnerability_research",
        messages=[
            {"role": "system", "content": _SYSTEM_PROMPT},
            {"role": "user", "content": user_prompt},
        ],
        run_id=services.run_id,
    )
    if response.disabled:
        raise RuntimeError("LLM disabled by operator")
    raw = response.content or "{}"
    start = raw.find("{")
    end = raw.rfind("}")
    if start < 0 or end < 0:
        raise ValueError(f"LLM returned no JSON object: {raw[:200]}")
    return json.loads(raw[start : end + 1])


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
                services, _build_user_prompt(research, mitigations, []),
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
                    str(generated.get("code") or ""),
                    str(generated.get("language") or "python"),
                ),
            },
        )

    history: list[dict[str, Any]] = []
    crash_payload: dict[str, Any] | None = None
    last_code: str = ""
    last_language: str = "python"
    last_filename: str = "poc.py"

    max_attempts = max(1, int(services.config.poc_max_attempts))
    for attempt in range(1, max_attempts + 1):
        try:
            generated = await _llm_poc(
                services, _build_user_prompt(research, mitigations, history),
            )
        except (RuntimeError, ValueError, OSError, TimeoutError) as exc:
            history.append({
                "attempt": attempt, "language": last_language,
                "outcome": "llm_error", "detail": f"{type(exc).__name__}: {exc}",
            })
            continue

        last_language = (generated.get("language") or "python").strip().lower()
        last_filename = generated.get("filename") or (
            "poc.py" if last_language == "python" else "poc.c"
        )
        last_code = str(generated.get("code") or "")

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
        if run_result.get("crash_detected"):
            crash_payload = {
                "poc_path": poc_path,
                "first_run": run_result,
            }
            history.append({
                "attempt": attempt, "language": last_language, "outcome": "crashed",
                "detail": f"exit={run_result.get('exit_code')}",
            })
            break
        history.append({
            "attempt": attempt, "language": last_language,
            "outcome": "no_crash",
            "detail": (
                f"exit={run_result.get('exit_code')} timeout={run_result.get('timeout')} "
                f"stderr={(run_result.get('stderr_tail') or '')[:200]}"
            ),
        })

    if crash_payload is None:
        return StateResult(
            next_state="advisory",
            output={
                **input,
                "poc": {
                    **_untested_payload("no crash within attempt budget", last_code, last_language),
                    "history": history,
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
    parsed_asan = await asyncio.to_thread(
        services.crash_triage.forward,
        action="parse_asan", asan_output=asan_text,
    )
    if parsed_asan.get("status") != "ready":
        parsed_asan = {
            "status": "ready",
            "crash_type": research.get("crash_type") or "info_disclosure",
            "stack_frames": [],
        }

    signature = await asyncio.to_thread(
        services.crash_triage.forward,
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
