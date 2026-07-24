"""API tests for the RFC-10 admin agent-lifecycle router.

Covers the operator loop the RFC-10 acceptance criterion demands: a
promote without a passing evaluate row returns 409, an evaluate +
approve + promote flow succeeds and flips the production alias, a
promote with a passing evaluate but no approval returns 409 with the
quorum message surfaced, an approve without a prior passing evaluate
returns 409, and the transitions listing reads the append-only journal.

The tests seed data through the sibling admin routers (RFC-09
``/admin/prompts/versions`` and RFC-08 ``/admin/eval/benchmarks``) so
the router-under-test is exercised through the same HTTP contract an
operator would drive by hand -- no shortcut through the controller.

Importing ``LifecycleTransitionRecord`` at module scope keeps
``SQLModel.metadata`` in sync when the shared ``test_db`` fixture runs
``create_all``; the platform-owned db_models.py already re-exports it,
but the explicit import here documents the dependency at the API
layer.
"""
from __future__ import annotations

from uuid import uuid4

import pytest
from httpx import AsyncClient

# Top-level import ensures SQLModel.metadata includes the table when
# the session-scoped test_db fixture runs create_all.
from aila.platform.lifecycle.models import LifecycleTransitionRecord

__all__: list[str] = []


def _key() -> str:
    return f"vr/lifecycle-api-{uuid4().hex[:8]}"


def _passing_cases(version: str, n: int = 8) -> list[dict[str, object]]:
    """Cases matching the truth at high confidence -- eval verdict = 'pass'.

    Mirrors ``tests/platform/lifecycle/test_controller.py::_perfect_cases``:
    a balanced mix of outcome_kinds with predicted == verified at high
    confidence produces a passing report that beats any absent baseline
    (first-ever eval auto-passes) and any regressing baseline.
    """
    out: list[dict[str, object]] = []
    for i in range(n):
        kind = "sqli" if i % 2 == 0 else "xss"
        out.append({
            "outcome_kind": kind,
            "predicted_verdict": "accept",
            "verified_verdict": "accept",
            "confidence": 0.95,
            "version": version,
        })
    return out


async def _register_version(
    client: AsyncClient, hdr: dict[str, str], key: str, body: str,
) -> str:
    resp = await client.post(
        "/admin/prompts/versions",
        json={"key": key, "body": body},
        headers=hdr,
    )
    assert resp.status_code == 201, resp.text
    return resp.json()["data"]["version"]


async def _register_benchmark(
    client: AsyncClient, hdr: dict[str, str], key: str,
    cases: list[dict[str, object]],
) -> str:
    resp = await client.post(
        "/admin/eval/benchmarks",
        json={"key": key, "name": "lifecycle-api-bench", "cases": cases},
        headers=hdr,
    )
    assert resp.status_code == 201, resp.text
    return resp.json()["data"]["id"]


@pytest.mark.asyncio
async def test_promote_without_evaluate_returns_409(
    async_client: AsyncClient, admin_token: str, test_db,
) -> None:
    """A promote against a version that has no passing evaluate journal
    row surfaces ``StageTransitionError`` as HTTP 409 and leaves the
    production alias untouched."""
    del test_db
    hdr = {"Authorization": f"Bearer {admin_token}"}
    key = _key()

    version = await _register_version(async_client, hdr, key, "PROMPT BODY")

    resp = await async_client.post(
        "/admin/lifecycle/promote",
        json={"key": key, "version": version, "reason": "premature"},
        headers=hdr,
    )
    assert resp.status_code == 409, resp.text
    detail = resp.json()["detail"]
    assert "no prior passing" in detail
    assert version in detail

    # Alias must not have been created -- the aliases listing stays empty.
    aliases = await async_client.get(
        "/admin/prompts/aliases", params={"key": key}, headers=hdr,
    )
    assert aliases.status_code == 200
    assert aliases.json()["data"] == []


@pytest.mark.asyncio
async def test_evaluate_then_promote_flips_alias(
    async_client: AsyncClient, admin_token: str, test_db,
) -> None:
    """The RFC-10 golden path: evaluate returns a passing transition,
    approve records a quorum vote, promote returns a production
    transition, and the RFC-09 production alias points at the promoted
    version."""
    del test_db
    hdr = {"Authorization": f"Bearer {admin_token}"}
    key = _key()

    version = await _register_version(async_client, hdr, key, "PROMPT BODY")
    benchmark_id = await _register_benchmark(
        async_client, hdr, key, _passing_cases(version),
    )

    eval_resp = await async_client.post(
        "/admin/lifecycle/evaluate",
        json={
            "key": key,
            "version": version,
            "benchmark_id": benchmark_id,
        },
        headers=hdr,
    )
    assert eval_resp.status_code == 201, eval_resp.text
    eval_data = eval_resp.json()["data"]
    assert eval_data["key"] == key
    assert eval_data["version"] == version
    assert eval_data["from_stage"] == "built"
    assert eval_data["to_stage"] == "evaluated"
    snapshot = eval_data["metrics_snapshot"]
    assert snapshot is not None
    assert snapshot["verdict"] == "pass"
    assert snapshot["eval_run_id"]

    approve_resp = await async_client.post(
        "/admin/lifecycle/approve",
        json={"key": key, "version": version, "reason": "looks good"},
        headers=hdr,
    )
    assert approve_resp.status_code == 201, approve_resp.text
    approve_data = approve_resp.json()["data"]
    assert approve_data["from_stage"] == "evaluated"
    assert approve_data["to_stage"] == "approved"
    assert approve_data["reason"] == "looks good"

    promote_resp = await async_client.post(
        "/admin/lifecycle/promote",
        json={"key": key, "version": version, "reason": "ship"},
        headers=hdr,
    )
    assert promote_resp.status_code == 201, promote_resp.text
    promote_data = promote_resp.json()["data"]
    assert promote_data["from_stage"] == "evaluated"
    assert promote_data["to_stage"] == "production"
    assert promote_data["reason"] == "ship"
    promote_snapshot = promote_data["metrics_snapshot"]
    assert promote_snapshot is not None
    assert promote_snapshot["verdict"] == "pass"
    assert promote_snapshot["approver_count"] == 1
    assert promote_snapshot["quorum_threshold"] == 1

    aliases = await async_client.get(
        "/admin/prompts/aliases", params={"key": key}, headers=hdr,
    )
    assert aliases.status_code == 200
    alias_map = {a["alias"]: a["version"] for a in aliases.json()["data"]}
    assert alias_map["production"] == version


@pytest.mark.asyncio
async def test_promote_without_approve_returns_409(
    async_client: AsyncClient, admin_token: str, test_db,
) -> None:
    """Eval passes but no approve on record -> promote surfaces the
    quorum-not-met StageTransitionError as 409 and leaves the alias
    untouched. This is the RFC-10 quorum gate at the HTTP layer."""
    del test_db
    hdr = {"Authorization": f"Bearer {admin_token}"}
    key = _key()

    version = await _register_version(async_client, hdr, key, "PROMPT BODY")
    benchmark_id = await _register_benchmark(
        async_client, hdr, key, _passing_cases(version),
    )

    eval_resp = await async_client.post(
        "/admin/lifecycle/evaluate",
        json={
            "key": key,
            "version": version,
            "benchmark_id": benchmark_id,
        },
        headers=hdr,
    )
    assert eval_resp.status_code == 201, eval_resp.text

    promote_resp = await async_client.post(
        "/admin/lifecycle/promote",
        json={"key": key, "version": version, "reason": "skip approval"},
        headers=hdr,
    )
    assert promote_resp.status_code == 409, promote_resp.text
    detail = promote_resp.json()["detail"]
    assert "quorum not met" in detail
    assert "1 required" in detail

    aliases = await async_client.get(
        "/admin/prompts/aliases", params={"key": key}, headers=hdr,
    )
    assert aliases.status_code == 200
    assert aliases.json()["data"] == []


@pytest.mark.asyncio
async def test_approve_without_passing_evaluate_returns_409(
    async_client: AsyncClient, admin_token: str, test_db,
) -> None:
    """Approve on a (key, version) with no passing evaluate row surfaces
    the StageTransitionError as HTTP 409 and writes no journal row."""
    del test_db
    hdr = {"Authorization": f"Bearer {admin_token}"}
    key = _key()

    version = await _register_version(async_client, hdr, key, "PROMPT BODY")

    approve_resp = await async_client.post(
        "/admin/lifecycle/approve",
        json={"key": key, "version": version, "reason": "early"},
        headers=hdr,
    )
    assert approve_resp.status_code == 409, approve_resp.text
    detail = approve_resp.json()["detail"]
    assert "no prior passing" in detail
    assert version in detail

    listing = await async_client.get(
        "/admin/lifecycle/transitions", params={"key": key}, headers=hdr,
    )
    assert listing.status_code == 200
    assert listing.json()["data"] == []


@pytest.mark.asyncio
async def test_transitions_lists_journal_newest_first(
    async_client: AsyncClient, admin_token: str, test_db,
) -> None:
    """GET /transitions returns every journal row for the key in the
    controller's canonical newest-first order."""
    del test_db
    hdr = {"Authorization": f"Bearer {admin_token}"}
    key = _key()

    version = await _register_version(async_client, hdr, key, "PROMPT BODY")
    benchmark_id = await _register_benchmark(
        async_client, hdr, key, _passing_cases(version),
    )

    await async_client.post(
        "/admin/lifecycle/evaluate",
        json={
            "key": key,
            "version": version,
            "benchmark_id": benchmark_id,
        },
        headers=hdr,
    )
    await async_client.post(
        "/admin/lifecycle/approve",
        json={"key": key, "version": version, "reason": "lgtm"},
        headers=hdr,
    )
    await async_client.post(
        "/admin/lifecycle/promote",
        json={"key": key, "version": version, "reason": "ship"},
        headers=hdr,
    )

    listing = await async_client.get(
        "/admin/lifecycle/transitions",
        params={"key": key},
        headers=hdr,
    )
    assert listing.status_code == 200, listing.text
    rows = listing.json()["data"]
    assert len(rows) == 3

    to_stages = [r["to_stage"] for r in rows]
    assert to_stages == ["production", "approved", "evaluated"], (
        "list_transitions must return rows newest first"
    )
    assert {r["key"] for r in rows} == {key}
    assert {r["version"] for r in rows} == {version}

    # Confirm the table imported at module scope is the same table the
    # journal wrote to -- catches a schema drift regression cheaply.
    assert LifecycleTransitionRecord.__tablename__ == "lifecycle_transitions"


@pytest.mark.asyncio
async def test_rollback_without_prior_production_returns_409(
    async_client: AsyncClient, admin_token: str, test_db,
) -> None:
    """A rollback with no prior production transition and no explicit
    ``target_version`` surfaces ``StageTransitionError`` as 409."""
    del test_db
    hdr = {"Authorization": f"Bearer {admin_token}"}
    key = _key()

    version = await _register_version(async_client, hdr, key, "PROMPT BODY")

    resp = await async_client.post(
        "/admin/lifecycle/rollback",
        json={"key": key, "version": version, "reason": "revert"},
        headers=hdr,
    )
    assert resp.status_code == 409, resp.text
    detail = resp.json()["detail"]
    assert "no prior production" in detail


@pytest.mark.asyncio
async def test_evaluate_unknown_benchmark_returns_404(
    async_client: AsyncClient, admin_token: str, test_db,
) -> None:
    """An evaluate against a benchmark_id that does not resolve surfaces
    ``BenchmarkNotFoundError`` as HTTP 404 (mirrors admin_eval)."""
    del test_db
    hdr = {"Authorization": f"Bearer {admin_token}"}
    key = _key()

    version = await _register_version(async_client, hdr, key, "PROMPT BODY")

    resp = await async_client.post(
        "/admin/lifecycle/evaluate",
        json={
            "key": key,
            "version": version,
            "benchmark_id": "does-not-exist",
        },
        headers=hdr,
    )
    assert resp.status_code == 404, resp.text


@pytest.mark.asyncio
async def test_requires_admin(
    async_client: AsyncClient, reader_token: str, test_db,
) -> None:
    """A non-admin token is refused on every method with 403."""
    del test_db
    hdr = {"Authorization": f"Bearer {reader_token}"}
    key = _key()

    evaluate_resp = await async_client.post(
        "/admin/lifecycle/evaluate",
        json={"key": key, "version": "1.0.0", "benchmark_id": "b1"},
        headers=hdr,
    )
    assert evaluate_resp.status_code == 403

    approve_resp = await async_client.post(
        "/admin/lifecycle/approve",
        json={"key": key, "version": "1.0.0"},
        headers=hdr,
    )
    assert approve_resp.status_code == 403

    promote_resp = await async_client.post(
        "/admin/lifecycle/promote",
        json={"key": key, "version": "1.0.0"},
        headers=hdr,
    )
    assert promote_resp.status_code == 403

    rollback_resp = await async_client.post(
        "/admin/lifecycle/rollback",
        json={"key": key, "version": "1.0.0"},
        headers=hdr,
    )
    assert rollback_resp.status_code == 403

    listing_resp = await async_client.get(
        "/admin/lifecycle/transitions", params={"key": key}, headers=hdr,
    )
    assert listing_resp.status_code == 403
