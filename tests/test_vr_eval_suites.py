"""Unit + integration tests for the VR benchmark-measurement harness (#157).

Pure tests cover the manifest loader and the reference-answer matcher. The
DB tests run against the aila_test Postgres fixture and exercise the real
start / collect / leaderboard orchestration with a fake task queue (no live
Redis or model is involved).
"""
from __future__ import annotations

import json
from uuid import uuid4

import pytest

from aila.modules.vr.contracts.investigation import InvestigationStatus
from aila.modules.vr.db_models import (
    VRInvestigationBranchRecord,
    VRInvestigationOutcomeRecord,
    VRInvestigationRecord,
    VRTargetRecord,
    VRWorkspaceRecord,
)
from aila.modules.vr.db_models.eval_suite import (
    VREvalSuiteRunRecord,
    VREvalTaskResultRecord,
)
from aila.modules.vr.eval_suites.answer_match import is_match, normalize_answer
from aila.modules.vr.eval_suites.manifest_loader import (
    ManifestError,
    load_suite_manifest,
)
from aila.modules.vr.eval_suites.suite_runner import (
    collect_suite_run,
    leaderboard,
    run_summary,
    start_suite_run,
)
from aila.platform.uow import UnitOfWork

# --------------------------------------------------------------------------
# answer_match (pure)
# --------------------------------------------------------------------------

def test_normalize_strips_wrapper_and_whitespace() -> None:
    assert normalize_answer("  flag{abc}  ") == "abc"
    assert normalize_answer("CTF{AbC}", case_insensitive=False) == "AbC"
    assert normalize_answer("plain") == "plain"


@pytest.mark.parametrize(
    ("reference", "candidates", "expected"),
    [
        ("flag{win}", ["the answer is flag{win} done"], True),
        ("flag{win}", ["win"], True),
        ("flag{WIN}", ["flag{win}"], True),
        ("flag{win}", ["flag{lose}"], False),
        ("flag{win}", [""], False),
        ("", ["flag{win}"], False),
        ("flag{win}", [], False),
    ],
)
def test_is_match_truth_table(
    reference: str, candidates: list[str], expected: bool,
) -> None:
    assert is_match(reference, candidates) is expected


def test_is_match_case_sensitive_mode() -> None:
    assert is_match("flag{Win}", ["flag{win}"], case_insensitive=False) is False
    assert is_match("flag{Win}", ["flag{Win}"], case_insensitive=False) is True


# --------------------------------------------------------------------------
# manifest_loader (pure, tmp_path)
# --------------------------------------------------------------------------

def _write_manifest(root, suite: str, tasks: list[dict]) -> None:
    suite_dir = root / suite
    suite_dir.mkdir(parents=True, exist_ok=True)
    (suite_dir / "manifest.json").write_text(json.dumps({"tasks": tasks}), encoding="utf-8")


def test_load_manifest_ok(tmp_path) -> None:
    _write_manifest(tmp_path, "cybench", [
        {"task_id": "t1", "name": "one", "reference_answer": "flag{a}", "target_id": "tg1"},
    ])
    manifest = load_suite_manifest(str(tmp_path), "cybench")
    assert manifest.suite == "cybench"
    assert len(manifest.tasks) == 1
    assert manifest.tasks[0].task_id == "t1"
    assert manifest.tasks[0].budget_usd == 50.0


def test_load_manifest_unknown_suite(tmp_path) -> None:
    with pytest.raises(ManifestError, match="unknown suite"):
        load_suite_manifest(str(tmp_path), "not_a_suite")


def test_load_manifest_missing_root() -> None:
    with pytest.raises(ManifestError, match="not configured"):
        load_suite_manifest("", "cybench")


def test_load_manifest_missing_file(tmp_path) -> None:
    with pytest.raises(ManifestError, match="manifest not found"):
        load_suite_manifest(str(tmp_path), "cybench")


def test_load_manifest_missing_field(tmp_path) -> None:
    _write_manifest(tmp_path, "nyu_ctf", [{"task_id": "t1", "name": "x"}])
    with pytest.raises(ManifestError, match="invalid"):
        load_suite_manifest(str(tmp_path), "nyu_ctf")


def test_load_manifest_empty_tasks(tmp_path) -> None:
    _write_manifest(tmp_path, "htb_lite", [])
    with pytest.raises(ManifestError, match="no 'tasks'"):
        load_suite_manifest(str(tmp_path), "htb_lite")


# --------------------------------------------------------------------------
# orchestration (Postgres test_db)
# --------------------------------------------------------------------------

class _FakeHandle:
    def __init__(self, task_id: str) -> None:
        self.task_id = task_id


class _FakeTaskQueue:
    def __init__(self) -> None:
        self.calls: list[dict] = []

    async def submit(self, **kwargs) -> _FakeHandle:
        self.calls.append(kwargs)
        return _FakeHandle(f"task-{len(self.calls)}")


async def _seed_target() -> str:
    async with UnitOfWork() as uow:
        slug = f"eval-{uuid4().hex[:12]}"
        ws = VRWorkspaceRecord(
            name=slug, slug=slug, description="", theme="custom", team_id="admin",
        )
        uow.session.add(ws)
        await uow.session.flush()
        tgt = VRTargetRecord(
            workspace_id=ws.id, team_id="admin", display_name="t",
            kind="native_binary",
            descriptor_json=json.dumps({"binary_path": "/dev/null"}),
            primary_language="c", secondary_languages_json="[]",
            tags_json="[]", mcp_handles_json="{}", status="active",
            capability_profile_json="{}",
        )
        uow.session.add(tgt)
        await uow.session.commit()
        return tgt.id


async def test_start_suite_run_spawns_and_enqueues(tmp_path, test_db) -> None:
    del test_db
    target_id = await _seed_target()
    _write_manifest(tmp_path, "cybench", [
        {"task_id": "ok", "name": "solvable", "reference_answer": "flag{a}", "target_id": target_id},
        {"task_id": "bad", "name": "missing-target", "reference_answer": "flag{b}", "target_id": "does-not-exist"},
    ])
    queue = _FakeTaskQueue()

    async with UnitOfWork() as uow:
        run = await start_suite_run(
            uow,
            suite="cybench",
            dataset_root=str(tmp_path),
            default_budget_usd=50.0,
            requested_by="admin",
            team_id="admin",
            task_queue=queue,
        )
        run_id = run.id

    # One investigation enqueued (the valid target); the bad target did not.
    assert len(queue.calls) == 1
    call = queue.calls[0]
    assert call["track"] == "vr"
    # @platform_task sets __name__ to the module-qualified registry name.
    assert call["fn"].__name__.endswith("run_vr_investigate")

    summary = None
    async with UnitOfWork() as uow:
        summary = await run_summary(uow, run_id)
    assert summary is not None
    assert summary.total_count == 2
    statuses = {r.task_id: r.status for r in summary.results}
    assert statuses["ok"] == "pending"
    assert statuses["bad"] == "error"
    # The valid task got a real investigation id; the bad one did not.
    by_task = {r.task_id: r for r in summary.results}
    assert by_task["ok"].investigation_id is not None
    assert by_task["bad"].investigation_id is None


async def _seed_run_with_terminal_investigation(
    *, flag: str, produced_text: str, status: str,
) -> tuple[str, str]:
    """Create a run + pending result pointing at a terminal investigation."""
    target_id = await _seed_target()
    async with UnitOfWork() as uow:
        inv = VRInvestigationRecord(
            target_id=target_id, team_id="admin", kind="discovery",
            title="t", initial_question="q", status=status, auto_pilot=True,
            strategy_family="vulnerability_research.discovery_research",
            cost_budget_usd=50.0, primary_outcome_polarity="finding",
        )
        uow.session.add(inv)
        await uow.session.flush()
        branch = VRInvestigationBranchRecord(
            investigation_id=inv.id, status="active", fork_reason="primary",
        )
        uow.session.add(branch)
        await uow.session.flush()
        uow.session.add(VRInvestigationOutcomeRecord(
            investigation_id=inv.id, branch_id=branch.id,
            outcome_kind="direct_finding", confidence="high",
            payload_json=json.dumps({"summary": f"recovered {produced_text}"}),
        ))
        run = VREvalSuiteRunRecord(suite="cybench", status="running", total_count=1)
        uow.session.add(run)
        await uow.session.flush()
        uow.session.add(VREvalTaskResultRecord(
            run_id=run.id, task_id="t1", name="one", investigation_id=inv.id,
            status="pending", reference_answer=flag,
        ))
        await uow.session.commit()
        return run.id, inv.id


async def test_collect_scores_solved(test_db) -> None:
    del test_db
    run_id, _ = await _seed_run_with_terminal_investigation(
        flag="flag{found}", produced_text="flag{found}",
        status=InvestigationStatus.COMPLETED.value,
    )
    async with UnitOfWork() as uow:
        run = await collect_suite_run(uow, run_id)
    assert run is not None
    assert run.status == "collected"
    assert run.solved_count == 1
    async with UnitOfWork() as uow:
        summary = await run_summary(uow, run_id)
    assert summary is not None
    result = summary.results[0]
    assert result.solved is True
    assert result.status == "scored"
    assert result.polarity == "finding"
    assert result.cost_usd == 0.0


async def test_collect_scores_unsolved(test_db) -> None:
    del test_db
    run_id, _ = await _seed_run_with_terminal_investigation(
        flag="flag{expected}", produced_text="nothing useful here",
        status=InvestigationStatus.COMPLETED.value,
    )
    async with UnitOfWork() as uow:
        run = await collect_suite_run(uow, run_id)
    assert run is not None
    assert run.solved_count == 0
    async with UnitOfWork() as uow:
        summary = await run_summary(uow, run_id)
    assert summary is not None
    assert summary.results[0].solved is False
    assert summary.results[0].status == "scored"


async def test_collect_skips_non_terminal(test_db) -> None:
    del test_db
    run_id, _ = await _seed_run_with_terminal_investigation(
        flag="flag{x}", produced_text="flag{x}",
        status=InvestigationStatus.RUNNING.value,
    )
    async with UnitOfWork() as uow:
        run = await collect_suite_run(uow, run_id)
    assert run is not None
    # The investigation is still running, so the run is not yet collected.
    assert run.status == "running"
    async with UnitOfWork() as uow:
        summary = await run_summary(uow, run_id)
    assert summary is not None
    assert summary.results[0].status == "pending"


async def test_leaderboard_takes_latest_per_suite(test_db) -> None:
    del test_db
    async with UnitOfWork() as uow:
        uow.session.add(VREvalSuiteRunRecord(
            suite="cybench", status="collected", total_count=10, solved_count=3,
            total_cost_usd=30.0,
        ))
        await uow.session.commit()
    async with UnitOfWork() as uow:
        rows = await leaderboard(uow)
    cybench = [r for r in rows if r.suite == "cybench"]
    assert cybench, "expected a cybench leaderboard row"
    row = cybench[0]
    assert row.total_count >= 10
    assert 0.0 <= row.solve_rate <= 1.0
