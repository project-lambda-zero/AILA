"""RFC-12 D2: the semantic consolidator MUST read the ledger with
``confirmed_only=True`` so it never distills facts from unconfirmed
recon-hypothesis discoveries. This test isolates the read contract by
monkeypatching every helper that would otherwise touch the DB / LLM.
"""
from __future__ import annotations

from typing import Any

import pytest

import aila.platform.services.memory.consolidator as consolidator_mod
from aila.platform.services.memory.consolidator import (
    _Candidate,
    consolidate_recent_investigations,
)

pytestmark = pytest.mark.asyncio


class _CapturingLedger:
    """Records the kwargs of every ``read_general`` call."""

    def __init__(self) -> None:
        self.read_calls: list[dict[str, Any]] = []

    async def read_general(
        self,
        investigation_id: str,
        *,
        kinds: list[str] | None = None,
        confirmed_only: bool = False,
        limit: int = 200,
        session: Any = None,
    ) -> list[dict[str, Any]]:
        self.read_calls.append(
            {
                "investigation_id": investigation_id,
                "kinds": list(kinds or []),
                "confirmed_only": confirmed_only,
                "limit": limit,
            },
        )
        # Return no entries so the sweep short-circuits before touching
        # the LLM or the knowledge writer.
        return []


async def test_consolidator_reads_ledger_with_confirmed_only(monkeypatch) -> None:
    candidate: _Candidate = {
        "investigation_id": "inv-conf-1",
        "module_id": "vr",
        "team_id": None,
        "target_id": "tgt-1",
        "target_tablename": "vr_targets",
    }

    async def _fake_scan(session, **_kwargs):
        return [candidate]

    async def _fake_resolve(session, cand):
        return "ws-1"

    async def _fake_prior(session, namespace, investigation_id):
        return False

    monkeypatch.setattr(consolidator_mod, "_scan_candidates", _fake_scan)
    monkeypatch.setattr(consolidator_mod, "_resolve_workspace_id", _fake_resolve)
    monkeypatch.setattr(
        consolidator_mod, "_has_prior_consolidation", _fake_prior,
    )

    ledger = _CapturingLedger()
    report = await consolidate_recent_investigations(
        ledger_service=ledger,  # type: ignore[arg-type]
        knowledge_service=object(),  # type: ignore[arg-type]  # never reached: read_general returns []
        llm_client=object(),
    )

    assert report["scanned"] == 1
    assert len(ledger.read_calls) == 1
    call = ledger.read_calls[0]
    assert call["investigation_id"] == "inv-conf-1"
    assert call["confirmed_only"] is True
    # kinds contract is unchanged: discoveries + notes only.
    assert set(call["kinds"]) == {"discovery", "note"}
