"""Pydantic contracts for the trajectory-mined SFT/DPO corpus (issue #158).

The corpus turns AILA's already-persisted trajectory substrate (per-turn
LLM prompt + response rows in ``platform_journal``, wall-clock + prompt
attribution in ``llm_idempotency_cache`` + ``llm_cost_records``, and the
module outcome-review state that decides "chosen vs rejected") into two
training-ready shapes:

* :class:`SftRecord` -- one ShareGPT-style multi-turn conversation per
  branch whose outcome was accepted (``state`` in ``approved`` /
  ``dispatched``). This is the supervised-fine-tune corpus. ``messages``
  is ordered per turn: the branch's system prompt (once, at index 0)
  followed by ``user``/``assistant``/``tool`` triplets, one triplet per
  recorded turn.
* :class:`DpoRecord` -- one Agentic-DPO state-conditioned preference
  pair per (investigation, matched-turn) where a CHOSEN branch (accepted
  outcome) and a REJECTED sibling branch exist. The ``prompt`` is the
  shared observation context up to and including that turn; ``chosen``
  is the accepted-branch decision; ``rejected`` is the rejected-branch
  decision. arxiv 2607.10601.

:class:`CorpusManifest` is the on-disk manifest a corpus export writes
alongside ``sft.jsonl`` and ``dpo.jsonl`` so the admin stats endpoint
can read counts + coverage without re-scanning the corpus files.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

__all__ = [
    "CorpusManifest",
    "DpoRecord",
    "SftMeta",
    "SftMessage",
    "SftRecord",
]


class SftMessage(BaseModel):
    """One ShareGPT-style message inside a :class:`SftRecord`.

    ``role`` is intentionally free-form (``system`` / ``user`` /
    ``assistant`` / ``tool``) so the emitter can carry tool-result
    turns without a second contract. ``content`` is the raw text that
    would be shown to the model at fine-tune time; the builder caps it
    to ``corpus_max_field_chars`` before construction.
    """

    model_config = ConfigDict(extra="forbid")

    role: str = Field(min_length=1, max_length=16)
    content: str = Field(default="")


class SftMeta(BaseModel):
    """Provenance metadata attached to every :class:`SftRecord`."""

    model_config = ConfigDict(extra="forbid")

    investigation_id: str
    branch_id: str | None = None
    module_id: str
    outcome_kind: str
    outcome_state: str
    turns: int = Field(ge=0)


class SftRecord(BaseModel):
    """One ShareGPT conversation minted from a CHOSEN branch trajectory."""

    model_config = ConfigDict(extra="forbid")

    messages: list[SftMessage] = Field(default_factory=list)
    meta: SftMeta


class DpoRecord(BaseModel):
    """One Agentic-DPO preference pair for the same (investigation, turn).

    ``prompt`` is either a plain string (the terminal-decision shared
    context) or a list of :class:`SftMessage` when the shared context
    is a multi-turn history. The reader (TRL DPOTrainer) accepts both
    shapes as long as ``chosen`` and ``rejected`` are strings.
    """

    model_config = ConfigDict(extra="forbid")

    prompt: str | list[SftMessage]
    chosen: str
    rejected: str
    meta: dict[str, Any] = Field(default_factory=dict)


class CorpusManifest(BaseModel):
    """On-disk manifest written next to ``sft.jsonl`` + ``dpo.jsonl``."""

    model_config = ConfigDict(extra="forbid")

    generated_at: datetime
    sft_count: int = Field(ge=0)
    dpo_count: int = Field(ge=0)
    module_breakdown: dict[str, int] = Field(default_factory=dict)
    investigations: int = Field(ge=0)
    date_range: dict[str, datetime | None] = Field(default_factory=dict)
    corpus_dir: str = ""
    sft_path: str = ""
    dpo_path: str = ""
    modules: list[str] = Field(default_factory=list)
    min_turns: int = Field(ge=0)
    max_field_chars: int = Field(ge=0)
    skipped_short_branches: int = Field(default=0, ge=0)
    skipped_unparseable_decisions: int = Field(default=0, ge=0)
