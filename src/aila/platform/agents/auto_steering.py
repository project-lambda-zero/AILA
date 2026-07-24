"""Automatic operator-steering injector.

Watches every tool result. When the result matches a known dead-end
pattern (agent reading past EOF, agent looping on broken indexer,
agent re-fetching a hallucinated symbol), the system POSTS an
operator message to the investigation with the corrective info --
the exact same DB write the human operator does through the UI's
chat composer.

The auto-posted message lands at the TOP of every branch's prompt
on the next turn under ``*** OPERATOR STEERING -- MANDATORY OVERRIDE ***``
just like an operator-typed message. The agent has no way to tell
human steering apart from auto steering -- that's intentional. The
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
  the module investigation-messages table with ``sender_kind='operator'``,
  ``sender_id='auto_steering'``, ``operator_intent='steering'``.

Each rule is keyed so duplicate corrections within the same
investigation don't spam -- a row already posted with the same
``auto_steering_key`` is skipped.
"""
from __future__ import annotations

import json
import logging
from typing import Any

import httpx
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlmodel import select as _select

from aila.platform.contracts import utc_now
from aila.platform.contracts.enums import OperatorIntent, SenderKind
from aila.platform.contracts.mcp_payload import PayloadKind
from aila.platform.uow import UnitOfWork

__all__ = ["maybe_post_auto_steering"]

_log = logging.getLogger(__name__)

# fix §337 -- auto-steering swallows every error so a tool result is
# never derailed by a rule-evaluation bug. The swallow hides systemic
# failures (bridge unreachable, schema drift in raw_result, …). Track
# consecutive failures: after _FAILURE_ESCALATION_THRESHOLD in a row,
# escalate to ERROR + reset the counter so the operator log surfaces
# the systemic problem instead of one-off warnings drowning in noise.
# Module-level int is safe -- auto-steering runs serially per tool call
# inside a single worker; the GIL makes the read-modify-write atomic
# enough for a coarse threshold counter (no precision needed).
_FAILURE_ESCALATION_THRESHOLD = 5
_consecutive_failures = 0


def _normalize_acked_observable(raw: object) -> list[str]:
    """Canonicalise the ``_acked_operator_messages`` observable shape.

    fix §333 -- the agent prompt historically demonstrated a comma-separated
    string, but the new canonical shape is a list-of-strings. Both shapes
    are accepted at read time so legacy case_state rows still resolve;
    new prompt guidance demonstrates the list shape exclusively.

    Returns a list of stripped, non-empty string ids. Never raises;
    unrecognised shapes (None, dict, int, …) collapse to ``[]``.
    """
    if raw is None:
        return []
    if isinstance(raw, str):
        return [x.strip() for x in raw.split(",") if x.strip()]
    if isinstance(raw, list):
        return [str(x).strip() for x in raw if x is not None and str(x).strip()]
    return []


# ─────────────────────────────────────────────────────────────────
# Detectors
# ─────────────────────────────────────────────────────────────────


def _detect_read_lines_past_eof(
    server_id: str, tool_name: str, args: dict, raw: dict,
) -> bool:
    """``read_lines`` returned in-bounds slice but requested range
    extended past file end. Bridge already sets ``total_lines_in_file``
    in its response -- we just compare against the requested ``end``."""
    if (server_id, tool_name) != ("audit_mcp", "read_lines"):
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
    server_id: str, tool_name: str, _args: dict, raw: dict,
) -> bool:
    """``read_function`` indexer fault: returns the file's license
    header instead of the requested function body. Symptom: ``line``
    < 50 (suspiciously low for a deep function) AND content starts
    with a comment or include block."""
    if (server_id, tool_name) != ("audit_mcp", "read_function"):
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


def _detect_read_lines_file_not_found(
    server_id: str, tool_name: str, _args: dict, raw: dict,
) -> bool:
    """``read_lines`` returned ``status=error`` with a file-not-found
    message. Symptom of an agent chasing a path that doesn't exist in
    the indexed tree -- most commonly a function whose canonical path
    sits in a sibling repo not indexed alongside the primary target
    (e.g. ``srclib/apr-util/...`` querying the httpd-only index).

    Without this rule, branches loop on the same dead path for hundreds
    of turns because every retry returns the same error and no rule
    fires (the existing past-EOF rule requires ``total_lines_in_file``
    in the response, which an error response never has).
    """
    if (server_id, tool_name) != ("audit_mcp", "read_lines"):
        return False
    if raw.get("status") != "error":
        return False
    err = str(raw.get("error") or "").lower()
    # Accept both audit-mcp's "file not found" and the bridge's wrapped
    # variants ("read_lines: file not found: <path>").
    return "file not found" in err or "no such file" in err


def _detect_tool_kwarg_rejected(
    server_id: str, _tool_name: str, _args: dict, raw: dict,
) -> bool:
    """Bridge rejected the call because the kwargs don't match the
    tool's signature (missing required, unknown keyword, wrong shape).
    Agent retries are guaranteed to fail until the kwargs name+shape
    change, so a steering message naming the correct signature is the
    only thing that unblocks the loop.

    Restricted to audit_mcp for now -- the bridge validator at
    ``audit_mcp_bridge._validate_kwargs`` is the source of these
    rejections. Other MCP servers may use different phrasings.
    """
    if server_id != "audit_mcp":
        return False
    if raw.get("status") != "error":
        return False
    err = str(raw.get("error") or "").lower()
    return any(
        marker in err for marker in (
            "missing required kwarg",
            "unknown keyword",
            "unexpected keyword",
            "rejected: missing",
            "rejected: unknown",
        )
    )


# ─────────────────────────────────────────────────────────────────
# Correction derivation
# ─────────────────────────────────────────────────────────────────


async def _derive_eof_correction(
    base_url: str, index_id: str, file_path: str, total: int,
    branch_recent_queries: list[str],
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
        basename = file_path.rsplit("/", maxsplit=1)[-1].split(".", maxsplit=1)[0]
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
    except (httpx.ConnectError, httpx.TimeoutException, ValueError) as exc:
        _log.warning(
            "auto_steering: derive_eof_correction semantic_search failed "
            "index_id=%s file=%s err=%s",
            index_id, file_path, exc, exc_info=True,
        )
        return None
    results = data.get("results") or data.get("matches") or []
    if not results:
        return (
            f"AUTO-STEERING: you asked read_lines for lines past line "
            f"{total} of `{file_path}` but the file ends at {total}. "
            f"A semantic_search for {query!r} returned zero hits -- the "
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
        f"re-requesting lines past line {total} of `{file_path}` -- "
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
    except (httpx.ConnectError, httpx.TimeoutException, ValueError) as exc:
        _log.warning(
            "auto_steering: derive_file_header_correction semantic_search failed "
            "index_id=%s function=%s err=%s",
            index_id, function_name, exc, exc_info=True,
        )
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
            f"file header instead of the function body -- audit_mcp's "
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
        "Call read_lines on one of those ranges to get the actual "
        "function body."
    )


async def _derive_file_not_found_correction(
    base_url: str, index_id: str, file_path: str,
    branch_recent_queries: list[str],
) -> str | None:
    """For read_lines file-not-found: surface semantic_search hits for
    whatever the branch was last looking for, then explicitly warn that
    the requested path is not in the indexed tree. This is the most
    common "chasing a phantom" failure mode -- the agent assumes a
    canonical upstream layout (e.g. ``srclib/apr-util/...``) that the
    actual indexed repo doesn't carry.
    """
    if not index_id:
        return None
    query: str | None = None
    for q in reversed(branch_recent_queries):
        if q and len(q) > 6:
            query = q[:200]
            break
    if not query and file_path:
        basename = file_path.rstrip("/").split("/")[-1].split(".")[0]
        if basename:
            query = f"{basename} definition implementation"
    if not query:
        return None
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(
                f"{base_url}/tools/semantic_search",
                json={"index_id": index_id, "query": query, "top_k": 5},
            )
            data = resp.json()
    except (httpx.ConnectError, httpx.TimeoutException, ValueError):
        data = {}
    results = (data or {}).get("results") or (data or {}).get("matches") or []
    hits: list[str] = []
    for r in results[:5]:
        if not isinstance(r, dict):
            continue
        fp = r.get("file_path") or "?"
        ls = r.get("start_line") or "?"
        le = r.get("end_line") or "?"
        score = r.get("score")
        score_tag = f" score={score:.3f}" if isinstance(score, (int, float)) else ""
        hits.append(f"  - {fp}:{ls}-{le}{score_tag}")
    if not hits:
        return (
            f"AUTO-STEERING: read_lines({file_path!r}) returned "
            f"`file not found`. The path is not in the index "
            f"(index_id={index_id!r}). A semantic_search for "
            f"{query!r} ALSO returned zero hits -- the symbol is "
            f"almost certainly NOT in this indexed tree. The function "
            f"may live in a sibling repo (e.g. apr-util sits outside "
            f"httpd trunk, MozillaIPDL outside Firefox-core, etc.). "
            f"STOP retrying this path. Either:\n"
            f"  (1) re-target the investigation to the correct repo, or\n"
            f"  (2) terminal_submit with a no-finding outcome explaining "
            f"that the symbol is out-of-scope for this index."
        )
    return (
        f"AUTO-STEERING: read_lines({file_path!r}) returned "
        f"`file not found`. That path is NOT in the index "
        f"(index_id={index_id!r}). A semantic_search for {query!r} "
        f"found these candidate locations instead:\n"
        + "\n".join(hits) + "\n"
        "Call read_lines on one of those file:line ranges. If none "
        "matches the function you mean, the function likely lives in "
        "a sibling repo not indexed here -- terminal_submit with a "
        "no-finding outcome rather than retry the same dead path."
    )


async def _derive_kwarg_rejected_correction(
    tool_name: str, raw_error: str, attempted_args: dict,
) -> str:
    """For bridge kwarg rejections: surface the bridge's error message
    verbatim (it already names the bad/missing kwarg) and explicitly
    instruct the agent that retrying with the same arg shape will keep
    failing. The correction is synchronous -- no remote calls needed
    since the bridge already produced the actionable detail."""
    arg_names = sorted(attempted_args.keys())
    return (
        f"AUTO-STEERING: {tool_name} REJECTED your call signature. "
        f"Bridge error:\n\n  {raw_error}\n\n"
        f"You passed kwargs: {arg_names}. The error names the missing "
        f"or unknown kwarg -- VARYING THE VALUE will not help, the arg "
        f"NAME or SHAPE is wrong. Re-read the tool signature from the "
        f"# Available tools section of your prompt. If the tool isn't "
        f"listed there, it is not available to you and you must use "
        f"a different one. Do NOT call {tool_name} again with the "
        f"same kwarg shape -- pivot or submit a finding noting the "
        f"obstacle."
    )


# ─────────────────────────────────────────────────────────────────
# Posting
# ─────────────────────────────────────────────────────────────────


async def _recent_semantic_queries(
    branch_id: str, message_model: Any, limit: int = 6,
) -> list[str]:
    """Pull the most recent semantic_search queries this branch ran.
    Used to derive the agent's current search intent for the EOF
    correction."""
    queries: list[str] = []
    async with UnitOfWork() as uow:
        rows = (await uow.session.exec(
            _select(message_model)
            .where(message_model.branch_id == branch_id)
            .where(message_model.payload_kind == PayloadKind.TOOL_CALL.value)
            .order_by(message_model.created_at.desc())
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
    *, message_model: Any, branch_model: Any,
) -> bool:
    """De-dupe: skip when an auto-steering with the same key already
    exists for this investigation AND has not yet been acknowledged.

    fix §331 + §332 -- query by the new indexed
    ``auto_steering_key`` column (migration 063) instead of scanning
    a fixed LIMIT 40 of recent messages and parsing payload_json. The
    old LIMIT was too small for the 6-branch fan-out where each branch
    can produce >40 tool calls in one wall-clock minute, so the dedup
    silently fell off the end of the window. Exact-match indexed
    lookup is O(log n) and has no recency horizon.

    Once the agent ACKs a steering (sets the message's id in any
    branch's ``_acked_operator_messages`` observable), the condition
    is considered addressed. If the same condition recurs later, the
    steering can re-post. Without this, an agent that ignored the
    first auto-steering blocked every future steering on the same
    condition forever.
    """
    async with UnitOfWork() as uow:
        rows = (await uow.session.exec(
            _select(message_model)
            .where(message_model.investigation_id == investigation_id)
            .where(message_model.auto_steering_key == auto_steering_key)
        )).all()
        if not rows:
            return False
        matching_ids: list[str] = [row.id for row in rows]
        # fix §334 -- bound the branch scan to the most recent 50 branches
        # by created_at. Investigations with hundreds of sibling branches
        # were paying O(N branches × case_state size) on every auto-steering
        # check; this caps it at 50 which still covers every live persona
        # plus a wide margin for ACK propagation latency.
        branches = (await uow.session.exec(
            _select(branch_model)
            .where(
                branch_model.investigation_id == investigation_id,
            )
            .order_by(branch_model.created_at.desc())
            .limit(50)
        )).all()
        all_acks: set[str] = set()
        for b in branches:
            try:
                cs = json.loads(b.case_state_json or "{}")
            except (json.JSONDecodeError, AttributeError):
                continue
            acked_raw = (cs.get("observables") or {}).get("_acked_operator_messages")
            all_acks.update(_normalize_acked_observable(acked_raw))
        # If any matching steering is still un-ack'd, block re-post
        # (agent hasn't yet acted on the existing one). When ALL
        # matching steerings are ack'd, allow re-post -- the agent
        # has formally acknowledged the prior corrections and the
        # condition is recurring fresh.
        unacked = [m for m in matching_ids if m not in all_acks]
        return len(unacked) > 0


async def _post(
    investigation_id: str, branch_id: str | None,
    text: str, auto_steering_key: str,
    *, message_model: Any, branch_model: Any,
) -> str | None:
    """Write the auto-steering as an operator-kind message. Same shape
    the UI's chat composer produces (sender_kind='operator', payload
    is JSON with the message text + auto_steering metadata).

    branch_id is the PRIMARY branch so the message is visible to
    every sibling (the message loader treats primary-addressed as
    broadcast).

    fix §331/§332 -- populate the new ``auto_steering_key`` column on
    the row itself so :func:`_already_posted` can dedup via an exact
    indexed lookup. The legacy ``payload_json.auto_steering_key`` is
    kept for one release so older message renderers still surface
    the metadata.

    fix §338 -- the partial-UNIQUE index on
    ``(investigation_id, auto_steering_key)`` (migration 063) collapses
    the fire-then-check race to a database-level no-op: a concurrent
    second writer that observed an empty ``_already_posted`` will hit
    ``IntegrityError`` on insert, which is the correct outcome. We
    catch it and return ``None`` -- the first writer wins, the second
    silently observes the row.
    """
    async with UnitOfWork() as uow:
        # Resolve primary branch for broadcast
        primary_id = (await uow.session.exec(
            _select(branch_model.id)
            .where(branch_model.investigation_id == investigation_id)
            .where(branch_model.parent_branch_id.is_(None))
            .limit(1)
        )).first()
        addressed_branch = primary_id or branch_id
        payload = {
            "text": text,
            "auto_steering_key": auto_steering_key,
        }
        msg = message_model(
            investigation_id=investigation_id,
            branch_id=addressed_branch,
            sender_kind=SenderKind.OPERATOR.value,
            sender_id="auto_steering",
            payload_kind=PayloadKind.TEXT.value,
            payload_json=json.dumps(payload),
            operator_intent=OperatorIntent.STEERING.value,
            auto_steering_key=auto_steering_key,
            created_at=utc_now(),
        )
        uow.session.add(msg)
        try:
            await uow.commit()
        except IntegrityError as exc:
            # fix §338 -- unique constraint on (inv, key) raced us. The
            # first writer wins; we return None so the caller sees
            # "already posted". Rollback is automatic on session exit.
            _log.info(
                "auto_steering insert race lost inv=%s key=%s err=%s",
                investigation_id, auto_steering_key, exc,
            )
            return None
        await uow.session.refresh(msg)
        return msg.id


# ─────────────────────────────────────────────────────────────────
# Orchestration
# ─────────────────────────────────────────────────────────────────


async def _evaluate_rules(
    *,
    investigation_id: str,
    branch_id: str,
    server_id: str,
    tool_name: str,
    args: dict,
    raw_result: dict,
    bridge_base_url: str,
    message_model: Any,
    branch_model: Any,
) -> str | None:
    """Run every rule against ``raw_result`` and post the first match.

    Extracted from :func:`maybe_post_auto_steering` so the outer
    function can wrap one call in the §337 failure-counter try/except
    and reset the counter on every clean return (whether or not a
    steering was actually posted). Returns the posted message id, or
    ``None`` when no rule fired or the correction could not be derived.
    """
    # Rule 1: read_lines past EOF (successful response, EOF overshoot)
    if _detect_read_lines_past_eof(server_id, tool_name, args, raw_result):
        file_path = str(args.get("file_path") or "")
        total = int(raw_result.get("total_lines_in_file") or 0)
        requested_end = int(args.get("end") or 0)
        index_id = str(args.get("index_id") or "")
        key = f"read_lines_past_eof:{file_path}:{requested_end}"
        if await _already_posted(investigation_id, key,
                                     message_model=message_model,
                                     branch_model=branch_model):
            return None
        queries = await _recent_semantic_queries(branch_id, message_model=message_model)
        correction = await _derive_eof_correction(
            bridge_base_url, index_id, file_path, total, queries,
        )
        if not correction:
            return None
        return await _post(investigation_id, branch_id, correction, key,
                           message_model=message_model, branch_model=branch_model)

    # Rule 2: read_function returned file header (indexer fault)
    if _detect_read_function_returned_file_header(server_id, tool_name, args, raw_result):
        file_path = str(args.get("file_path") or "")
        fn_name = str(args.get("name") or "")
        index_id = str(args.get("index_id") or "")
        key = f"read_function_indexer_fault:{file_path}:{fn_name}"
        if await _already_posted(investigation_id, key,
                                     message_model=message_model,
                                     branch_model=branch_model):
            return None
        correction = await _derive_file_header_correction(
            bridge_base_url, index_id, file_path, fn_name,
        )
        if not correction:
            return None
        return await _post(investigation_id, branch_id, correction, key,
                           message_model=message_model, branch_model=branch_model)

    # Rule 3: read_lines returned file-not-found error
    if _detect_read_lines_file_not_found(server_id, tool_name, args, raw_result):
        file_path = str(args.get("file_path") or "")
        index_id = str(args.get("index_id") or "")
        key = f"read_lines_file_not_found:{index_id}:{file_path}"
        if await _already_posted(investigation_id, key,
                                     message_model=message_model,
                                     branch_model=branch_model):
            return None
        queries = await _recent_semantic_queries(branch_id, message_model=message_model)
        correction = await _derive_file_not_found_correction(
            bridge_base_url, index_id, file_path, queries,
        )
        if not correction:
            return None
        return await _post(investigation_id, branch_id, correction, key,
                           message_model=message_model, branch_model=branch_model)

    # Rule 4: bridge rejected kwarg shape
    if _detect_tool_kwarg_rejected(server_id, tool_name, args, raw_result):
        raw_err = str(raw_result.get("error") or "")
        # fix §339 -- replace fragile ``raw_err.split(':', 1)[0]``
        # err_class extraction (drifts whenever the bridge changes
        # its error wording) with a structural key based on the
        # call shape itself. Same tool + same arg-name set always
        # share the key; a genuinely different rejection (different
        # arg names) gets a different key and re-posts.
        arg_keys = ",".join(sorted(str(k) for k in (args or {}).keys()))
        key = f"kwarg_rejected:{tool_name}:{arg_keys}"
        if await _already_posted(investigation_id, key,
                                     message_model=message_model,
                                     branch_model=branch_model):
            return None
        correction = await _derive_kwarg_rejected_correction(
            f"{server_id}.{tool_name}", raw_err, args,
        )
        return await _post(investigation_id, branch_id, correction, key,
                           message_model=message_model, branch_model=branch_model)

    return None


async def maybe_post_auto_steering(
    *,
    investigation_id: str,
    branch_id: str,
    server_id: str,
    tool_name: str,
    args: dict,
    raw_result: dict,
    bridge_base_url: str,
    message_model: Any,
    branch_model: Any,
) -> str | None:
    """Examine ``raw_result`` against all rules. If one fires AND
    a correction can be derived AND the same auto-steering hasn't
    already been posted for this investigation, post it.

    Returns the posted message id on success, None otherwise.

    Best-effort: any error is logged and swallowed so a failure in
    the auto-steering path can never derail the actual tool result.
    fix §337 -- consecutive failures are counted; the
    :data:`_FAILURE_ESCALATION_THRESHOLD`-th failure in a row escalates
    the swallowed warning to ERROR so a systemic problem (bridge down,
    raw_result schema drift) surfaces instead of drowning in noise.
    """
    global _consecutive_failures
    if not raw_result:
        return None
    # NOTE: do NOT early-return on status != "ready" -- error responses
    # are the trigger for Rule 3 (file_not_found) and Rule 4 (kwarg
    # rejected). Each rule's detector decides whether it cares about
    # the response shape.
    try:
        result = await _evaluate_rules(
            investigation_id=investigation_id,
            branch_id=branch_id,
            server_id=server_id,
            tool_name=tool_name,
            args=args,
            raw_result=raw_result,
            bridge_base_url=bridge_base_url,
            message_model=message_model,
            branch_model=branch_model,
        )
    except (
        OSError, RuntimeError, ValueError, TypeError, AttributeError,
        KeyError, httpx.HTTPError, json.JSONDecodeError, SQLAlchemyError,
    ) as exc:
        _consecutive_failures += 1
        if _consecutive_failures >= _FAILURE_ESCALATION_THRESHOLD:
            # fix §350 -- escalation includes traceback so operator can
            # diagnose systemic root cause from a single log line.
            _log.error(
                "auto_steering: %d consecutive rule-evaluation failures -- "
                "likely systemic (bridge down, raw_result schema drift, "
                "ack-observable corruption). Latest inv=%s branch=%s "
                "tool=%s err=%s",
                _consecutive_failures, investigation_id, branch_id,
                tool_name, exc,
                exc_info=True,
            )
            _consecutive_failures = 0
        else:
            # fix §350 -- traceback also on the per-occurrence warning;
            # first-failure debugging shouldn't have to wait for the
            # escalation threshold.
            _log.warning(
                "auto_steering: rule evaluation failed inv=%s branch=%s "
                "tool=%s err=%s (consecutive=%d)",
                investigation_id, branch_id, tool_name, exc,
                _consecutive_failures,
                exc_info=True,
            )
        return None
    # Clean run -- reset the counter so transient hiccups don't
    # accumulate forever.
    if _consecutive_failures:
        _consecutive_failures = 0
    return result
