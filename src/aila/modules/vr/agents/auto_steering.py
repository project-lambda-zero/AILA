"""Automatic operator-steering injector.

Watches every tool result. When the result matches a known dead-end
pattern (agent reading past EOF, agent looping on broken indexer,
agent re-fetching a hallucinated symbol), the system POSTS an
operator message to the investigation with the corrective info —
the exact same DB write the human operator does through the UI's
chat composer.

The auto-posted message lands at the TOP of every branch's prompt
on the next turn under ``*** OPERATOR STEERING — MANDATORY OVERRIDE ***``
just like an operator-typed message. The agent has no way to tell
human steering apart from auto steering — that's intentional. The
goal is to short-circuit predictable loops without waiting for the
operator to notice.

Each rule has three parts:

* ``detect(server_id, tool_name, args, raw_result) -> bool``
  Fast check; cheap enough to run on every tool call.
* ``derive_correction(investigation_id, branch_id, server_id,
  tool_name, args, raw_result) -> str | None``
  Optional async lookup (e.g. fire semantic_search to find the
  real location). Returns the steering text, or None if no
  correction can be derived.
* posting is shared: write a row to
  ``vr_investigation_messages`` with ``sender_kind='operator'``,
  ``sender_id='auto_steering'``, ``operator_intent='steering'``.

Each rule is keyed so duplicate corrections within the same
investigation don't spam — a row already posted with the same
``auto_steering_key`` is skipped.
"""
from __future__ import annotations

import json
import logging
from typing import Any

import httpx
from sqlmodel import select as _select

from aila.modules.vr.contracts import (
    OperatorIntent,
    PayloadKind,
    SenderKind,
)
from aila.modules.vr.db_models import VRInvestigationMessageRecord
from aila.platform.contracts._common import utc_now
from aila.platform.uow import UnitOfWork

__all__ = ["maybe_post_auto_steering"]

_log = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────
# Detectors
# ─────────────────────────────────────────────────────────────────


def _detect_read_lines_past_eof(
    server_id: str, tool_name: str, args: dict, raw: dict,
) -> bool:
    """``read_lines`` returned in-bounds slice but requested range
    extended past file end. Bridge already sets ``total_lines_in_file``
    in its response — we just compare against the requested ``end``."""
    if (server_id, tool_name) != ("audit_mcp", "read_lines"):
        return False
    if not isinstance(raw, dict):
        return False
    total = raw.get("total_lines_in_file")
    if not isinstance(total, int) or total <= 0:
        return False
    try:
        requested_end = int(args.get("end") or 0)
    except (TypeError, ValueError):
        return False
    # Trigger when the agent asked for content past EOF AND the gap
    # is not trivial (50+ lines). Small overshoots are common when
    # the agent estimates a range and isn't worth the steering noise.
    return requested_end > total + 50


def _detect_read_function_returned_file_header(
    server_id: str, tool_name: str, args: dict, raw: dict,
) -> bool:
    """``read_function`` indexer fault: returns the file's license
    header instead of the requested function body. Symptom: ``line``
    < 50 (suspiciously low for a deep function) AND content starts
    with a comment or include block."""
    if (server_id, tool_name) != ("audit_mcp", "read_function"):
        return False
    if not isinstance(raw, dict):
        return False
    line = raw.get("line")
    if not isinstance(line, int) or line > 50:
        return False
    content = str(raw.get("content") or raw.get("source") or "")[:200].lstrip()
    if not content:
        return False
    # File-header markers: C-style comment, copyright, include block
    return any(
        content.startswith(prefix) for prefix in
        ("/*", "//", "#include", "Copyright", "/**", "/* Copyright")
    )


# ─────────────────────────────────────────────────────────────────
# Correction derivation
# ─────────────────────────────────────────────────────────────────


async def _derive_eof_correction(
    base_url: str, index_id: str, file_path: str, total: int,
    requested_end: int, branch_recent_queries: list[str],
) -> str | None:
    """For past-EOF: try to identify the symbol the agent was looking
    for (from recent semantic_search queries on this branch) and fire
    a new semantic_search to find the real location."""
    if not index_id or not file_path:
        return None
    # Best signal for "what was the agent looking for": the most
    # recent semantic_search query on this branch. Falls back to
    # the file's basename if no prior query.
    query: str | None = None
    for q in reversed(branch_recent_queries):
        if q and len(q) > 6:
            query = q[:200]
            break
    if not query:
        basename = file_path.split("/")[-1].split(".")[0]
        if not basename:
            return None
        query = f"{basename} class declaration definition"
    # Hit semantic_search
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(
                f"{base_url}/tools/semantic_search",
                json={"index_id": index_id, "query": query, "top_k": 3},
            )
            data = resp.json()
    except (httpx.ConnectError, httpx.TimeoutException, ValueError):
        return None
    results = data.get("results") or data.get("matches") or []
    if not results:
        return (
            f"AUTO-STEERING: you asked read_lines for lines past line "
            f"{total} of `{file_path}` but the file ends at {total}. "
            f"A semantic_search for {query!r} returned zero hits — the "
            f"symbol you're looking for may not exist in this codebase. "
            f"Stop re-requesting the same range; either pivot to a "
            f"different symbol or submit a no-finding."
        )
    hits = []
    for r in results[:3]:
        if not isinstance(r, dict):
            continue
        fp = r.get("file_path") or "?"
        ls = r.get("start_line") or "?"
        le = r.get("end_line") or "?"
        score = r.get("score")
        score_tag = f" score={score:.3f}" if isinstance(score, (int, float)) else ""
        hits.append(f"  - {fp}:{ls}-{le}{score_tag}")
    return (
        f"AUTO-STEERING: you asked read_lines for lines past line "
        f"{total} of `{file_path}` but the file ends at {total}. "
        f"A semantic_search for {query!r} found the real location:\n"
        + "\n".join(hits) + "\n"
        f"Call read_lines on one of those file:line ranges. STOP "
        f"re-requesting lines past line {total} of `{file_path}` — "
        f"the content you expect there does not exist in this file."
    )


async def _derive_file_header_correction(
    base_url: str, index_id: str, file_path: str, function_name: str,
) -> str | None:
    """For read_function returning file header: fire semantic_search
    for the function name to locate its real body."""
    if not index_id or not function_name:
        return None
    query = f"{function_name} function definition body"
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(
                f"{base_url}/tools/semantic_search",
                json={"index_id": index_id, "query": query, "top_k": 3},
            )
            data = resp.json()
    except (httpx.ConnectError, httpx.TimeoutException, ValueError):
        return None
    results = data.get("results") or data.get("matches") or []
    real_hits = []
    for r in results[:3]:
        if not isinstance(r, dict):
            continue
        fp = r.get("file_path") or "?"
        ls = r.get("start_line") or "?"
        le = r.get("end_line") or "?"
        # Skip the file we already tried if the chunk is too high
        # (the indexer-broken match)
        if fp == file_path and isinstance(ls, int) and ls < 50:
            continue
        real_hits.append((fp, ls, le, r.get("score")))
    if not real_hits:
        return (
            f"AUTO-STEERING: read_function({function_name!r}) returned the "
            f"file header instead of the function body — audit_mcp's "
            f"indexer has lost the symbol's true location. semantic_search "
            f"for {function_name!r} also did not surface a clear chunk. "
            f"Try semantic_search with a more specific query that "
            f"includes the function's expected signature or surrounding "
            f"context."
        )
    lines = []
    for fp, ls, le, score in real_hits:
        score_tag = f" score={score:.3f}" if isinstance(score, (int, float)) else ""
        lines.append(f"  - {fp}:{ls}-{le}{score_tag}")
    return (
        f"AUTO-STEERING: read_function({function_name!r}) returned the "
        f"file header (audit_mcp's symbol indexer lost the true "
        f"location). semantic_search found:\n"
        + "\n".join(lines) + "\n"
        f"Call read_lines on one of those ranges to get the actual "
        f"function body."
    )


# ─────────────────────────────────────────────────────────────────
# Posting
# ─────────────────────────────────────────────────────────────────


async def _recent_semantic_queries(
    investigation_id: str, branch_id: str, limit: int = 6,
) -> list[str]:
    """Pull the most recent semantic_search queries this branch ran.
    Used to derive the agent's current search intent for the EOF
    correction."""
    queries: list[str] = []
    async with UnitOfWork() as uow:
        rows = (await uow.session.exec(
            _select(VRInvestigationMessageRecord)
            .where(VRInvestigationMessageRecord.branch_id == branch_id)
            .where(VRInvestigationMessageRecord.payload_kind == PayloadKind.TOOL_CALL.value)
            .order_by(VRInvestigationMessageRecord.created_at.desc())
            .limit(limit)
        )).all()
    for row in rows:
        try:
            payload = json.loads(row.payload_json or "{}")
            cmd = json.loads(payload.get("command") or "{}")
        except (ValueError, TypeError):
            continue
        tool = cmd.get("tool") or ""
        if not tool.endswith("semantic_search"):
            continue
        q = (cmd.get("args") or {}).get("query")
        if isinstance(q, str) and q.strip():
            queries.append(q.strip())
    return queries


async def _already_posted(
    investigation_id: str, auto_steering_key: str,
) -> bool:
    """De-dupe: skip when an auto-steering with the same key already
    exists for this investigation. Each rule passes a stable key
    derived from (rule_id, target_file, target_symbol, ...)."""
    async with UnitOfWork() as uow:
        rows = (await uow.session.exec(
            _select(VRInvestigationMessageRecord)
            .where(VRInvestigationMessageRecord.investigation_id == investigation_id)
            .where(VRInvestigationMessageRecord.sender_kind == SenderKind.OPERATOR.value)
            .where(VRInvestigationMessageRecord.sender_id == "auto_steering")
            .order_by(VRInvestigationMessageRecord.created_at.desc())
            .limit(40)
        )).all()
    for row in rows:
        try:
            payload = json.loads(row.payload_json or "{}")
        except (ValueError, TypeError):
            continue
        if payload.get("auto_steering_key") == auto_steering_key:
            return True
    return False


async def _post(
    investigation_id: str, branch_id: str | None,
    text: str, auto_steering_key: str,
) -> str:
    """Write the auto-steering as an operator-kind message. Same shape
    the UI's chat composer produces (sender_kind='operator', payload
    is JSON with the message text + auto_steering metadata).

    branch_id is the PRIMARY branch so the message is visible to
    every sibling (the message loader treats primary-addressed as
    broadcast)."""
    async with UnitOfWork() as uow:
        # Resolve primary branch for broadcast
        from aila.modules.vr.db_models import VRInvestigationBranchRecord  # noqa: PLC0415
        primary_id = (await uow.session.exec(
            _select(VRInvestigationBranchRecord.id)
            .where(VRInvestigationBranchRecord.investigation_id == investigation_id)
            .where(VRInvestigationBranchRecord.parent_branch_id.is_(None))
            .limit(1)
        )).first()
        addressed_branch = primary_id or branch_id
        payload = {
            "text": text,
            "auto_steering_key": auto_steering_key,
        }
        msg = VRInvestigationMessageRecord(
            investigation_id=investigation_id,
            branch_id=addressed_branch,
            sender_kind=SenderKind.OPERATOR.value,
            sender_id="auto_steering",
            payload_kind=PayloadKind.TEXT.value,
            payload_json=json.dumps(payload),
            operator_intent=OperatorIntent.STEERING.value,
            created_at=utc_now(),
        )
        uow.session.add(msg)
        await uow.commit()
        await uow.session.refresh(msg)
        return msg.id


# ─────────────────────────────────────────────────────────────────
# Orchestration
# ─────────────────────────────────────────────────────────────────


async def maybe_post_auto_steering(
    *,
    investigation_id: str,
    branch_id: str,
    server_id: str,
    tool_name: str,
    args: dict,
    raw_result: dict,
    bridge_base_url: str,
) -> str | None:
    """Examine ``raw_result`` against all rules. If one fires AND
    a correction can be derived AND the same auto-steering hasn't
    already been posted for this investigation, post it.

    Returns the posted message id on success, None otherwise.

    Best-effort: any error is logged and swallowed so a failure in
    the auto-steering path can never derail the actual tool result.
    """
    if not raw_result or not isinstance(raw_result, dict):
        return None
    if raw_result.get("status") not in ("ready", None):
        return None

    try:
        # Rule 1: read_lines past EOF
        if _detect_read_lines_past_eof(server_id, tool_name, args, raw_result):
            file_path = str(args.get("file_path") or "")
            total = int(raw_result.get("total_lines_in_file") or 0)
            requested_end = int(args.get("end") or 0)
            index_id = str(args.get("index_id") or "")
            key = f"read_lines_past_eof:{file_path}:{requested_end}"
            if await _already_posted(investigation_id, key):
                return None
            queries = await _recent_semantic_queries(investigation_id, branch_id)
            correction = await _derive_eof_correction(
                bridge_base_url, index_id, file_path, total, requested_end, queries,
            )
            if not correction:
                return None
            return await _post(investigation_id, branch_id, correction, key)

        # Rule 2: read_function returned file header
        if _detect_read_function_returned_file_header(server_id, tool_name, args, raw_result):
            file_path = str(args.get("file_path") or "")
            fn_name = str(args.get("name") or "")
            index_id = str(args.get("index_id") or "")
            key = f"read_function_indexer_fault:{file_path}:{fn_name}"
            if await _already_posted(investigation_id, key):
                return None
            correction = await _derive_file_header_correction(
                bridge_base_url, index_id, file_path, fn_name,
            )
            if not correction:
                return None
            return await _post(investigation_id, branch_id, correction, key)

    except Exception as exc:  # noqa: BLE001 — auto-steering must never fail loud
        _log.warning(
            "auto_steering: rule evaluation failed inv=%s branch=%s "
            "tool=%s err=%s",
            investigation_id, branch_id, tool_name, exc,
        )
        return None

    return None
