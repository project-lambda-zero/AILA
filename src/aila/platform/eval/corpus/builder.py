"""TrajectoryCorpusBuilder -- mine stored trajectories into SFT + DPO corpora.

Reads the platform's already-persisted trajectory substrate and emits
two shapes:

* ShareGPT-style multi-turn SFT records, one per CHOSEN branch (a
  branch whose outcome state is ``approved`` / ``dispatched``).
* Agentic-DPO state-conditioned preference pairs, one per matched turn
  where a CHOSEN branch and a REJECTED sibling branch exist on the
  same investigation.

Boundary contract: this module lives on the PLATFORM. It NEVER imports
from ``aila.modules.*``. Per-module outcome state is read through raw
SQL over the ``<module>_investigation_outcomes`` tables (13 shared
columns declared by ``OutcomeRecordBase``), so the addition of a new
module never requires a builder code change beyond passing the module
id at collect time.
"""
from __future__ import annotations

import json
import logging
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sqlalchemy import text as _sql_text
from sqlalchemy.exc import SQLAlchemyError
from sqlmodel import select

from aila.config import _resolve_project_path
from aila.platform.config import PlatformConfigSchema
from aila.platform.eval.corpus.contracts import (
    CorpusManifest,
    DpoRecord,
    SftMessage,
    SftMeta,
    SftRecord,
)
from aila.storage.database import async_session_scope
from aila.storage.registry import ConfigRegistry

__all__ = [
    "CorpusOutputPaths",
    "TrajectoryCorpusBuilder",
    "export_corpus",
    "resolve_corpus_output_dir",
]

_log = logging.getLogger(__name__)

# Journal kinds we mine, mirroring the constants in
# :mod:`aila.platform.eval.transcript`. Both llm_prompt and llm_response
# ride the shared ``platform_journal`` table with (investigation_id,
# branch_id, turn_number) columns, so a per-turn lookup joins cleanly
# without touching any module-specific table.
_JOURNAL_KIND_LLM_PROMPT = "llm_prompt"
_JOURNAL_KIND_LLM_RESPONSE = "llm_response"
_JOURNAL_KIND_TOOL_CALL = "tool_call"

# Outcome states that mean "this branch's trajectory is CHOSEN / expert".
# Left configurable via ``platform.corpus_sft_states``.
_DEFAULT_SFT_STATES: tuple[str, ...] = ("approved", "dispatched")
# The single outcome state we treat as REJECTED for DPO pair building.
_REJECTED_STATE: str = "rejected"

# Errors we downgrade to a warning at scan time. A dead outcome table
# (schema drift, DB down) MUST NOT abort the whole export.
_SCAN_ERRORS: tuple[type[BaseException], ...] = (
    SQLAlchemyError, OSError, TimeoutError, RuntimeError, ValueError, TypeError,
)


# ---------------------------------------------------------------------------
# Small dataclasses used internally by the builder. Kept dataclass rather than
# Pydantic to avoid the per-instance validation overhead on large scans -- the
# public contract types (SftRecord/DpoRecord/CorpusManifest) already validate.
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class _OutcomeRow:
    """One outcome-review row scanned from a module's outcome table.

    Not frozen so the scanner can attach the outcome-created wall-clock
    for the manifest's date-range header without a parallel dict.
    """

    investigation_id: str
    branch_id: str
    outcome_kind: str
    state: str
    module_id: str
    created_at: datetime | None = None


@dataclass(slots=True)
class _TurnRecord:
    """One reconstructed agent turn from platform_journal."""

    turn_number: int
    system_message: str | None
    user_message: str
    assistant_message: str
    tool_messages: list[str] = field(default_factory=list)


@dataclass(frozen=True, slots=True)
class CorpusOutputPaths:
    """The three files written by an export."""

    corpus_dir: Path
    sft_path: Path
    dpo_path: Path
    manifest_path: Path


def resolve_corpus_output_dir(configured: str | None) -> Path:
    """Turn the ``corpus_output_dir`` config value into an absolute directory.

    Empty string / None -> ``<PROJECT_ROOT>/data/eval_corpus`` so a
    fresh install has a usable default that lives under the same
    ``data/`` tree the platform already claims (mirrors the
    ``secret_keyring_path`` default). Explicit values are resolved
    through :func:`aila.config._resolve_project_path` so a relative
    path hangs off the project root and an absolute path is kept as
    is.
    """
    if not configured:
        return _resolve_project_path("data/eval_corpus")
    return _resolve_project_path(configured)


# ---------------------------------------------------------------------------
# Helpers -- kept module-level (not method-scoped) so the tests can exercise
# the JSON shape assumptions without instantiating the builder.
# ---------------------------------------------------------------------------


def _clip(text: str | None, max_chars: int) -> str:
    """Cap a single content field at ``max_chars`` characters.

    Chosen over a byte-cap because tokenizers count characters (near
    enough) and the operator sees character counts in the UI. A None
    collapses to empty string.
    """
    if not text:
        return ""
    if max_chars <= 0 or len(text) <= max_chars:
        return text
    # Mark the truncation so a human inspecting the corpus knows why a
    # decision got cut off. The training loader ignores the marker.
    return text[:max_chars] + "\n… [truncated]"


def _decode_messages_from_prompt_payload(payload: dict[str, Any]) -> list[dict[str, Any]]:
    """Decode the messages list persisted under kind=llm_prompt.

    :mod:`aila.platform.services.replay` serialises the assembled
    messages list via ``json.dumps(...)`` before writing to the journal
    (``payload["messages"]`` is a JSON string, NOT a list). An empty
    or invalid body collapses to ``[]`` so a stray row cannot crash
    the whole export.
    """
    raw = payload.get("messages")
    if isinstance(raw, list):
        return [m for m in raw if isinstance(m, dict)]
    if not isinstance(raw, str) or not raw.strip():
        return []
    try:
        decoded = json.loads(raw)
    except (json.JSONDecodeError, TypeError, ValueError) as exc:
        # A malformed messages body means the journal row was written by
        # a caller who bypassed the standard replay-body serializer; that
        # is rare enough that we log + drop rather than fail the whole
        # export. The caller sees ``skipped_unparseable_decisions`` if
        # the drop propagates to a full turn.
        _log.debug("corpus.decode messages_body invalid: %s", exc)
        return []
    if not isinstance(decoded, list):
        _log.debug(
            "corpus.decode messages_body not a list (%s) -- dropping",
            type(decoded).__name__,
        )
        return []
    return [m for m in decoded if isinstance(m, dict)]


def _content_to_text(content: Any) -> str:
    """Reduce an OpenAI/Anthropic-style content field to plain text.

    ``content`` may be a plain string, a list of dicts with ``type``
    and ``text`` (Anthropic content-blocks), or a nested structure a
    caller invented. We flatten to a string so the fine-tune corpus
    carries something concrete for every recorded turn.
    """
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts: list[str] = []
        for block in content:
            if isinstance(block, dict):
                if isinstance(block.get("text"), str):
                    parts.append(block["text"])
                elif isinstance(block.get("content"), str):
                    parts.append(block["content"])
                else:
                    parts.append(json.dumps(block, ensure_ascii=False, default=str))
            else:
                parts.append(str(block))
        return "\n".join(p for p in parts if p)
    return str(content)


def _extract_user_and_system(messages: list[dict[str, Any]]) -> tuple[str | None, str]:
    """Split a recorded messages list into (system_prompt, user_prompt).

    The last non-system message is the user/observation prompt; every
    role-``system`` message is concatenated (in order) into the system
    block. This mirrors the assembly path in
    :class:`aila.platform.agents.turn_runner.TurnRunner`.
    """
    system_parts: list[str] = []
    user_text = ""
    for message in messages:
        role = str(message.get("role") or "").lower()
        text = _content_to_text(message.get("content"))
        if role == "system":
            if text:
                system_parts.append(text)
        else:
            # User / assistant / tool -- the LAST non-system message is
            # the turn's user-side observation prompt. Overwrite so a
            # multi-message assembly still surfaces the latest.
            user_text = text
    return ("\n\n".join(system_parts) if system_parts else None, user_text)


def _extract_response_text(payload: dict[str, Any]) -> str:
    """Read the assistant response text from an ``llm_response`` payload."""
    raw = payload.get("response")
    if isinstance(raw, str):
        return raw
    # Some paths write an already-parsed dict; fall back to a JSON dump so
    # a caller who inspects the record still sees the same tokens the model
    # emitted.
    if raw is None:
        return ""
    return json.dumps(raw, ensure_ascii=False, default=str)


def _extract_tool_text(payload: dict[str, Any]) -> str:
    """Render one tool-call journal payload into a training-friendly line.

    Keeps the tool name + normalized output, which is what the model
    would see in the next-turn observation. Falls back to a JSON dump so
    nothing is silently dropped.
    """
    tool = str(payload.get("tool") or payload.get("name") or "tool")
    result = payload.get("result") or payload.get("output") or payload.get("body")
    if isinstance(result, str):
        return f"[{tool}]\n{result}"
    if result is None:
        return f"[{tool}]\n" + json.dumps(payload, ensure_ascii=False, default=str)
    return f"[{tool}]\n" + json.dumps(result, ensure_ascii=False, default=str)


def _is_parseable_decision(text: str) -> bool:
    """Guard: a CHOSEN assistant decision that failed to parse is dropped.

    The reasoning engine's ``TurnRunner`` produces JSON-shaped decisions
    for every non-terminal turn; anything else is either a raw scaffold
    reply or a broken cache row and would poison SFT if kept.
    """
    if not text.strip():
        return False
    try:
        obj = json.loads(text)
    except (json.JSONDecodeError, TypeError, ValueError):
        return False
    return isinstance(obj, dict | list)


# ---------------------------------------------------------------------------
# The builder itself.
# ---------------------------------------------------------------------------


class TrajectoryCorpusBuilder:
    """Assembles :class:`SftRecord` + :class:`DpoRecord` batches on demand."""

    def __init__(
        self,
        *,
        max_field_chars: int = 24_000,
        sft_states: Sequence[str] = _DEFAULT_SFT_STATES,
    ) -> None:
        self._max_field_chars = max(0, int(max_field_chars))
        self._sft_states = tuple(s.strip() for s in sft_states if s and s.strip())

    async def collect(
        self,
        *,
        modules: list[str],
        since: datetime | None = None,
        until: datetime | None = None,
        min_turns: int = 2,
    ) -> tuple[list[SftRecord], list[DpoRecord], CorpusManifest]:
        """Assemble SFT + DPO records over the requested modules and window.

        ``since`` / ``until`` are optional; both are compared against
        the outcome-row ``created_at`` column so a nightly export can
        walk the last N days without re-processing older investigations.
        ``min_turns`` drops CHOSEN branches with fewer recorded turns
        than the threshold -- typical fine-tune runs need a couple of
        turns of context to be useful.
        """
        min_turns = max(0, int(min_turns))
        sft_records: list[SftRecord] = []
        dpo_records: list[DpoRecord] = []
        module_breakdown: dict[str, int] = {}
        investigations: set[str] = set()
        earliest: datetime | None = None
        latest: datetime | None = None
        skipped_short: int = 0
        skipped_unparseable: int = 0

        async with async_session_scope() as session:
            for module_id in modules:
                outcomes = await self._scan_outcomes(
                    session,
                    module_id=module_id,
                    since=since,
                    until=until,
                )
                if not outcomes:
                    continue
                # Group by investigation so we can emit DPO pairs when a
                # CHOSEN branch shares an investigation with a REJECTED
                # sibling.
                by_investigation: dict[str, list[_OutcomeRow]] = {}
                for row in outcomes:
                    by_investigation.setdefault(row.investigation_id, []).append(row)

                for inv_id, rows in by_investigation.items():
                    chosen = [r for r in rows if r.state in self._sft_states]
                    rejected = [r for r in rows if r.state == _REJECTED_STATE]
                    if not chosen and not rejected:
                        continue
                    investigations.add(inv_id)

                    # Rebuild per-branch turns once per unique branch so
                    # the DPO pair loop can look up either side without
                    # re-querying the journal.
                    turn_cache: dict[str, list[_TurnRecord]] = {}
                    for row in list(chosen) + list(rejected):
                        if row.branch_id in turn_cache:
                            continue
                        turn_cache[row.branch_id] = await self._load_branch_turns(
                            session,
                            investigation_id=inv_id,
                            branch_id=row.branch_id,
                        )

                    # SftRecords come only from CHOSEN branches.
                    for row in chosen:
                        turns = turn_cache.get(row.branch_id, [])
                        if len(turns) < min_turns:
                            skipped_short += 1
                            continue
                        # The last turn's assistant text is the branch's
                        # terminal decision; if THAT one is unparseable
                        # we drop the whole SftRecord as poisoned.
                        if not _is_parseable_decision(turns[-1].assistant_message):
                            skipped_unparseable += 1
                            continue
                        sft = self._build_sft_record(row=row, turns=turns)
                        sft_records.append(sft)
                        module_breakdown[module_id] = module_breakdown.get(module_id, 0) + 1

                    # DPO pairs: every (chosen, rejected) combination on
                    # the same investigation contributes one terminal-
                    # decision pair. Cheap and always well-defined.
                    for cho in chosen:
                        cho_turns = turn_cache.get(cho.branch_id, [])
                        if not cho_turns:
                            continue
                        cho_terminal = cho_turns[-1]
                        if not _is_parseable_decision(cho_terminal.assistant_message):
                            continue
                        for rej in rejected:
                            rej_turns = turn_cache.get(rej.branch_id, [])
                            if not rej_turns:
                                continue
                            rej_terminal = rej_turns[-1]
                            if not rej_terminal.assistant_message.strip():
                                continue
                            dpo = self._build_dpo_record(
                                chosen_row=cho,
                                rejected_row=rej,
                                chosen_terminal=cho_terminal,
                                rejected_terminal=rej_terminal,
                            )
                            dpo_records.append(dpo)

                    # Track the outcome-created_at window from the
                    # scanned rows for the manifest header.
                    for row in rows:
                        if row.created_at is None:
                            continue
                        if earliest is None or row.created_at < earliest:
                            earliest = row.created_at
                        if latest is None or row.created_at > latest:
                            latest = row.created_at

        manifest = CorpusManifest(
            generated_at=datetime.now(UTC),
            sft_count=len(sft_records),
            dpo_count=len(dpo_records),
            module_breakdown=module_breakdown,
            investigations=len(investigations),
            date_range={"since": since or earliest, "until": until or latest},
            modules=list(modules),
            min_turns=min_turns,
            max_field_chars=self._max_field_chars,
            skipped_short_branches=skipped_short,
            skipped_unparseable_decisions=skipped_unparseable,
        )
        return sft_records, dpo_records, manifest

    # ------------------------------------------------------------------
    # Outcome-table scan (raw SQL -- no module import allowed).
    # ------------------------------------------------------------------

    async def _scan_outcomes(
        self,
        session: Any,
        *,
        module_id: str,
        since: datetime | None,
        until: datetime | None,
    ) -> list[_OutcomeRow]:
        """Return the outcome rows for a module in the requested state set."""
        # Defense-in-depth: module_id is operator-config-controlled
        # (corpus_modules), but it is interpolated into the table name
        # below, so refuse anything that is not a plain identifier before
        # it reaches the SQL text.
        if not module_id.isidentifier():
            _log.warning(
                "corpus.outcome_scan refused non-identifier module_id=%r",
                module_id,
            )
            return []
        table = f"{module_id}_investigation_outcomes"
        states = tuple(sorted({*self._sft_states, _REJECTED_STATE}))
        clauses = ["state = ANY(:states)"]
        params: dict[str, Any] = {"states": list(states)}
        if since is not None:
            clauses.append("created_at >= :since")
            params["since"] = since
        if until is not None:
            clauses.append("created_at <= :until")
            params["until"] = until
        where = " AND ".join(clauses)
        stmt = _sql_text(
            f"SELECT investigation_id, branch_id, outcome_kind, state, created_at "
            f"FROM {table} WHERE {where} "
            f"ORDER BY investigation_id, created_at ASC",
        )
        try:
            result = await session.exec(stmt.bindparams(**params))
        except _SCAN_ERRORS as exc:
            _log.warning(
                "corpus.outcome_scan skipped module=%s (%s): %s",
                module_id, type(exc).__name__, exc,
            )
            return []
        rows: list[_OutcomeRow] = []
        for record in result:
            inv, branch, kind, state, created_at = record
            if not inv or not branch:
                continue
            rows.append(
                _OutcomeRow(
                    investigation_id=str(inv),
                    branch_id=str(branch),
                    outcome_kind=str(kind or ""),
                    state=str(state or ""),
                    module_id=module_id,
                    created_at=created_at if isinstance(created_at, datetime) else None,
                ),
            )
        return rows

    # ------------------------------------------------------------------
    # Per-branch turn reconstruction from platform_journal.
    # ------------------------------------------------------------------

    async def _load_branch_turns(
        self,
        session: Any,
        *,
        investigation_id: str,
        branch_id: str,
    ) -> list[_TurnRecord]:
        """Return every turn on a branch, ordered by ``turn_number``."""
        # Deferred import: eval package initialization loads through
        # db_models -> eval.calibration -> eval/__init__ -> runner, so
        # importing db_models at module import time would close a cycle.
        # Mirrors the same pattern documented in ``transcript.py``.
        from aila.storage.db_models import PlatformJournalRecord
        stmt = (
            select(PlatformJournalRecord)
            .where(
                PlatformJournalRecord.investigation_id == investigation_id,
                PlatformJournalRecord.branch_id == branch_id,
                PlatformJournalRecord.kind.in_((  # type: ignore[union-attr]
                    _JOURNAL_KIND_LLM_PROMPT,
                    _JOURNAL_KIND_LLM_RESPONSE,
                    _JOURNAL_KIND_TOOL_CALL,
                )),
            )
            .order_by(
                PlatformJournalRecord.turn_number.asc(),
                PlatformJournalRecord.seq.asc(),
            )
        )
        try:
            rows = list((await session.exec(stmt)).all())
        except _SCAN_ERRORS as exc:
            _log.warning(
                "corpus.journal_scan skipped inv=%s branch=%s (%s): %s",
                investigation_id, branch_id, type(exc).__name__, exc,
            )
            return []

        by_turn: dict[int, _TurnRecord] = {}
        # Iterate ordered by turn_number then seq so an llm_prompt and its
        # llm_response for the same turn arrive contiguously.
        for row in rows:
            turn = row.turn_number
            if turn is None:
                continue
            payload = row.payload_json or {}
            rec = by_turn.setdefault(
                turn,
                _TurnRecord(
                    turn_number=int(turn),
                    system_message=None,
                    user_message="",
                    assistant_message="",
                ),
            )
            if row.kind == _JOURNAL_KIND_LLM_PROMPT:
                messages = _decode_messages_from_prompt_payload(payload)
                system, user = _extract_user_and_system(messages)
                # First writer for the turn's system prompt wins so a
                # follow-up mid-turn prompt does not overwrite the branch
                # system message; last user prompt wins because the newest
                # observation is the one the assistant is answering.
                if rec.system_message is None and system:
                    rec.system_message = system
                if user:
                    rec.user_message = user
            elif row.kind == _JOURNAL_KIND_LLM_RESPONSE:
                text = _extract_response_text(payload)
                if text:
                    rec.assistant_message = text
            elif row.kind == _JOURNAL_KIND_TOOL_CALL:
                text = _extract_tool_text(payload)
                if text:
                    rec.tool_messages.append(text)

        return [by_turn[t] for t in sorted(by_turn.keys())]

    # ------------------------------------------------------------------
    # Record shaping.
    # ------------------------------------------------------------------

    def _build_sft_record(
        self,
        *,
        row: _OutcomeRow,
        turns: list[_TurnRecord],
    ) -> SftRecord:
        """Turn a CHOSEN branch's ordered turns into one ShareGPT record."""
        cap = self._max_field_chars
        messages: list[SftMessage] = []
        # System prompt: prefer the first turn's system message. Every
        # subsequent turn's system message is either identical (the shared
        # persona) or a minor refresh; carrying one keeps the record clean.
        for turn in turns:
            if turn.system_message:
                messages.append(SftMessage(role="system", content=_clip(turn.system_message, cap)))
                break
        for turn in turns:
            messages.append(SftMessage(role="user", content=_clip(turn.user_message, cap)))
            for tool_text in turn.tool_messages:
                messages.append(SftMessage(role="tool", content=_clip(tool_text, cap)))
            messages.append(SftMessage(role="assistant", content=_clip(turn.assistant_message, cap)))
        meta = SftMeta(
            investigation_id=row.investigation_id,
            branch_id=row.branch_id,
            module_id=row.module_id,
            outcome_kind=row.outcome_kind,
            outcome_state=row.state,
            turns=len(turns),
        )
        return SftRecord(messages=messages, meta=meta)

    def _build_dpo_record(
        self,
        *,
        chosen_row: _OutcomeRow,
        rejected_row: _OutcomeRow,
        chosen_terminal: _TurnRecord,
        rejected_terminal: _TurnRecord,
    ) -> DpoRecord:
        """Build one Agentic-DPO preference pair at the terminal decision.

        ``prompt`` is the CHOSEN branch's terminal-turn observation
        context (system + user). Both siblings observed the same
        investigation-scoped input at that point -- if the rejected
        sibling's terminal prompt differs textually (branches often
        diverge), the preference is still valid on the CHOSEN prompt
        because DPO conditions the pair on the CHOSEN state.
        """
        cap = self._max_field_chars
        parts: list[SftMessage] = []
        if chosen_terminal.system_message:
            parts.append(
                SftMessage(role="system", content=_clip(chosen_terminal.system_message, cap)),
            )
        parts.append(
            SftMessage(role="user", content=_clip(chosen_terminal.user_message, cap)),
        )
        return DpoRecord(
            prompt=parts,
            chosen=_clip(chosen_terminal.assistant_message, cap),
            rejected=_clip(rejected_terminal.assistant_message, cap),
            meta={
                "investigation_id": chosen_row.investigation_id,
                "chosen_branch_id": chosen_row.branch_id,
                "rejected_branch_id": rejected_row.branch_id,
                "module_id": chosen_row.module_id,
                "chosen_outcome_kind": chosen_row.outcome_kind,
                "rejected_outcome_kind": rejected_row.outcome_kind,
                "chosen_state": chosen_row.state,
                "rejected_state": rejected_row.state,
            },
        )


# ---------------------------------------------------------------------------
# Top-level export helper -- what the ARQ task and the admin endpoint call.
# ---------------------------------------------------------------------------


async def export_corpus(
    *,
    modules: Sequence[str] | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
) -> CorpusManifest:
    """Assemble + write ``sft.jsonl``, ``dpo.jsonl`` and ``manifest.json``.

    Resolves every knob through :class:`ConfigRegistry` so operator
    overrides land without a code change. Returns the manifest so the
    caller (the ARQ task, the admin endpoint) can pass the counts back
    without re-reading the file.
    """
    schema = PlatformConfigSchema()
    registry = ConfigRegistry()
    output_dir_raw = await _read_str(registry, "corpus_output_dir", schema.corpus_output_dir)
    modules_raw = await _read_str(registry, "corpus_modules", schema.corpus_modules)
    min_turns = await _read_int(registry, "corpus_min_turns", schema.corpus_min_turns)
    max_field_chars = await _read_int(
        registry, "corpus_max_field_chars", schema.corpus_max_field_chars,
    )
    sft_states_raw = await _read_str(registry, "corpus_sft_states", schema.corpus_sft_states)

    module_list = (
        list(modules)
        if modules is not None
        else [m.strip() for m in modules_raw.split(",") if m.strip()]
    )
    sft_states = tuple(s.strip() for s in sft_states_raw.split(",") if s.strip())

    output_dir = resolve_corpus_output_dir(output_dir_raw)
    output_dir.mkdir(parents=True, exist_ok=True)

    builder = TrajectoryCorpusBuilder(
        max_field_chars=max_field_chars,
        sft_states=sft_states or _DEFAULT_SFT_STATES,
    )
    sft, dpo, manifest = await builder.collect(
        modules=module_list, since=since, until=until, min_turns=min_turns,
    )

    paths = CorpusOutputPaths(
        corpus_dir=output_dir,
        sft_path=output_dir / "sft.jsonl",
        dpo_path=output_dir / "dpo.jsonl",
        manifest_path=output_dir / "manifest.json",
    )
    _write_jsonl(paths.sft_path, (r.model_dump(mode="json") for r in sft))
    _write_jsonl(paths.dpo_path, (r.model_dump(mode="json") for r in dpo))

    # Backfill the on-disk paths so a downstream reader (the stats
    # endpoint) can locate the artifacts without repeating the config
    # resolution.
    manifest = manifest.model_copy(update={
        "corpus_dir": str(paths.corpus_dir),
        "sft_path": str(paths.sft_path),
        "dpo_path": str(paths.dpo_path),
    })
    paths.manifest_path.write_text(
        manifest.model_dump_json(indent=2),
        encoding="utf-8",
    )
    _log.info(
        "corpus.export wrote sft=%d dpo=%d modules=%s dir=%s",
        manifest.sft_count, manifest.dpo_count,
        ",".join(module_list), str(paths.corpus_dir),
    )
    return manifest


def _write_jsonl(path: Path, records: Any) -> None:
    """Write an iterable of dicts as newline-delimited JSON."""
    with path.open("w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record, ensure_ascii=False, default=str))
            handle.write("\n")


async def _read_str(registry: ConfigRegistry, key: str, default: str) -> str:
    """Read a platform-namespaced config string with schema-default fallback."""
    try:
        raw = await registry.get("platform", key)
    except (SQLAlchemyError, OSError, RuntimeError, ValueError, TypeError):
        return default
    if raw is None:
        return default
    return str(raw)


async def _read_int(registry: ConfigRegistry, key: str, default: int) -> int:
    """Read a platform-namespaced config int with schema-default fallback."""
    try:
        raw = await registry.get("platform", key)
    except (SQLAlchemyError, OSError, RuntimeError, ValueError, TypeError):
        return default
    if raw is None:
        return default
    try:
        return int(raw)
    except (TypeError, ValueError):
        return default
