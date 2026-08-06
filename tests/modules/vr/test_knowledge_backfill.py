"""RFC-12 Phase 6: VR knowledge backfill (re-embed historical findings).

Deterministic, no live DB or embedder: the backfill's own UnitOfWork and the
KnowledgeService are stubbed so we lock the eligibility logic (content +
workspace resolution), the dry-run report, and the store call shape.
"""
from __future__ import annotations

from types import SimpleNamespace

import aila.modules.vr.services.knowledge_backfill as bf


def _finding(fid, target_id, root_cause):
    return SimpleNamespace(
        id=fid, target_id=target_id, root_cause=root_cause,
        crash_type=None, vulnerable_function=None,
        evidence_refs_json="[]", team_id=None,
    )


class _Result:
    def __init__(self, rows):
        self._rows = rows

    def all(self):
        return self._rows


class _Session:
    def __init__(self, findings, targets):
        self._findings = findings
        self._targets = targets
        self._n = 0

    async def exec(self, _stmt):
        self._n += 1
        return _Result(self._findings if self._n == 1 else self._targets)


class _UoW:
    def __init__(self, session):
        self.session = session

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_a):
        return False


def _install_db(monkeypatch, findings, targets):
    monkeypatch.setattr(bf, "UnitOfWork", lambda: _UoW(_Session(findings, targets)))


async def test_backfill_dry_run_reports_eligibility(monkeypatch) -> None:
    findings = [
        _finding("f-ok", "t-1", "real root cause text"),
        _finding("f-stub", None, "orphan finding, no target"),
        _finding("f-empty", "t-1", "   "),
    ]
    targets = [SimpleNamespace(id="t-1", workspace_id="ws-1")]
    _install_db(monkeypatch, findings, targets)

    report = await bf.backfill_vr_knowledge(dry_run=True)
    assert report["dry_run"] is True
    assert report["scanned"] == 3
    assert report["eligible"] == 1
    assert report["skipped_no_workspace"] == 1
    assert report["skipped_empty"] == 1
    assert report["sample"][0]["finding_id"] == "f-ok"
    assert report["sample"][0]["workspace_id"] == "ws-1"


async def test_backfill_embeds_eligible_findings(monkeypatch) -> None:
    calls: list[dict] = []

    class _FakeKnowledge:
        async def store(self, **kwargs):
            calls.append(kwargs)
            return {"entry_id": len(calls)}

    findings = [
        _finding("f-ok", "t-1", "container escape check: none found"),
        _finding("f-nows", "t-missing", "has content but no workspace"),
    ]
    targets = [SimpleNamespace(id="t-1", workspace_id="ws-1")]
    _install_db(monkeypatch, findings, targets)
    monkeypatch.setattr(bf, "KnowledgeService", _FakeKnowledge)

    report = await bf.backfill_vr_knowledge(dry_run=False)
    assert report["embedded"] == 1
    assert report["skipped_no_workspace"] == 1
    assert report["errors"] == 0
    assert len(calls) == 1
    call = calls[0]
    assert call["namespace"] == "vr.finding.workspace.ws-1"
    assert call["dedup_key"] == "finding:f-ok"
    assert call["metadata"]["source"] == "backfill"
    assert call["metadata"]["finding_id"] == "f-ok"
    assert call["extract_entities"] is True


async def test_backfill_survives_store_failure(monkeypatch) -> None:
    class _BoomKnowledge:
        async def store(self, **kwargs):
            raise RuntimeError("embedder down")

    findings = [_finding("f-ok", "t-1", "some finding text")]
    targets = [SimpleNamespace(id="t-1", workspace_id="ws-1")]
    _install_db(monkeypatch, findings, targets)
    monkeypatch.setattr(bf, "KnowledgeService", _BoomKnowledge)

    report = await bf.backfill_vr_knowledge(dry_run=False)
    assert report["embedded"] == 0
    assert report["errors"] == 1  # counted + logged, sweep did not abort
