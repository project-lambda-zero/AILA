"""End-to-end tests for the fuzzing campaign + crash endpoints.

Covers create → list → get → patch → register crash → dedup → triage.
"""
from __future__ import annotations

import pytest
from httpx import AsyncClient


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


async def _make_workspace_and_target(
    async_client: AsyncClient, admin_token: str, slug: str,
) -> tuple[str, str]:
    ws = await async_client.post(
        "/vr/workspaces", headers=_auth(admin_token),
        json={"name": f"F {slug}", "slug": slug, "theme": "browser_engines"},
    )
    assert ws.status_code == 201, ws.text
    wid = ws.json()["data"]["id"]
    t = await async_client.post(
        "/vr/targets", headers=_auth(admin_token),
        json={
            "workspace_id": wid,
            "display_name": "fuzz-target",
            "kind": "native_binary",
            "descriptor": {"binary_path": "/dev/null"},
            "primary_language": "c",
        },
    )
    assert t.status_code == 201, t.text
    return wid, t.json()["data"]["id"]


@pytest.mark.asyncio
async def test_create_campaign_returns_created_state(
    async_client: AsyncClient, admin_token: str,
) -> None:
    wid, tid = await _make_workspace_and_target(
        async_client, admin_token, "f-create",
    )
    resp = await async_client.post(
        "/vr/fuzz/campaigns", headers=_auth(admin_token),
        json={
            "target_id": tid,
            "workspace_id": wid,
            "name": "afl++ on parse_request",
            "engine_id": "afl++_qemu",
            "strategy_id": "mutational",
            "engine_config": {"parallel_jobs": 8},
            "strategy_config": {"dict_path": "/dev/null"},
            "duration_hours": 24,
        },
    )
    assert resp.status_code == 201, resp.text
    data = resp.json()["data"]
    assert data["status"] == "created"
    assert data["engine_id"] == "afl++_qemu"
    assert data["strategy_id"] == "mutational"
    assert data["crashes_found"] == 0
    assert data["total_execs"] == 0


@pytest.mark.asyncio
async def test_patch_campaign_advances_state_and_records_progress(
    async_client: AsyncClient, admin_token: str,
) -> None:
    wid, tid = await _make_workspace_and_target(
        async_client, admin_token, "f-patch",
    )
    create = await async_client.post(
        "/vr/fuzz/campaigns", headers=_auth(admin_token),
        json={
            "target_id": tid, "workspace_id": wid, "name": "c1",
            "engine_id": "fuzzilli_v8", "strategy_id": "generative",
        },
    )
    cid = create.json()["data"]["id"]

    # created → running (started_at populated)
    p1 = await async_client.patch(
        f"/vr/fuzz/campaigns/{cid}", headers=_auth(admin_token),
        json={"status": "running"},
    )
    assert p1.status_code == 200, p1.text
    d1 = p1.json()["data"]
    assert d1["status"] == "running"
    assert d1["started_at"] is not None

    # progress update
    p2 = await async_client.patch(
        f"/vr/fuzz/campaigns/{cid}", headers=_auth(admin_token),
        json={
            "execs_per_sec": 12500.5,
            "total_execs": 5_000_000,
            "corpus_size": 2934,
            "coverage_pct": 9.26,
        },
    )
    assert p2.status_code == 200
    d2 = p2.json()["data"]
    assert d2["execs_per_sec"] == 12500.5
    assert d2["total_execs"] == 5_000_000
    assert d2["corpus_size"] == 2934
    assert d2["coverage_pct"] == 9.26

    # running → completed (stopped_at populated)
    p3 = await async_client.patch(
        f"/vr/fuzz/campaigns/{cid}", headers=_auth(admin_token),
        json={"status": "completed"},
    )
    assert p3.status_code == 200
    assert p3.json()["data"]["status"] == "completed"
    assert p3.json()["data"]["stopped_at"] is not None


@pytest.mark.asyncio
async def test_register_crash_auto_triages_security_relevant(
    async_client: AsyncClient, admin_token: str,
) -> None:
    wid, tid = await _make_workspace_and_target(
        async_client, admin_token, "f-crash-sec",
    )
    create = await async_client.post(
        "/vr/fuzz/campaigns", headers=_auth(admin_token),
        json={
            "target_id": tid, "workspace_id": wid, "name": "c-sec",
            "engine_id": "afl++_qemu", "strategy_id": "coverage_guided",
        },
    )
    cid = create.json()["data"]["id"]

    crash = await async_client.post(
        "/vr/fuzz/crashes", headers=_auth(admin_token),
        json={
            "campaign_id": cid,
            "stack_hash": "abcdef0123456789",
            "crash_type": "heap-buffer-overflow WRITE 8",
            "crash_signature": "WRITE of size 8 at 0x602000000010 in parse_request",
            "stack_trace": "#0 parse_request\n#1 main",
        },
    )
    assert crash.status_code == 201, crash.text
    data = crash.json()["data"]
    assert data["triage_verdict"] == "security_relevant"
    assert "heap-buffer-overflow" in data["triage_reason"]
    # severity auto-elevated from UNKNOWN → HIGH because heap-buffer-overflow
    assert data["severity"] == "high"


@pytest.mark.asyncio
async def test_register_crash_dedups_on_stack_hash(
    async_client: AsyncClient, admin_token: str,
) -> None:
    wid, tid = await _make_workspace_and_target(
        async_client, admin_token, "f-crash-dedup",
    )
    create = await async_client.post(
        "/vr/fuzz/campaigns", headers=_auth(admin_token),
        json={
            "target_id": tid, "workspace_id": wid, "name": "c-dedup",
            "engine_id": "fuzzilli_v8", "strategy_id": "generative",
        },
    )
    cid = create.json()["data"]["id"]

    body = {
        "campaign_id": cid,
        "stack_hash": "deadbeef",
        "crash_type": "SIGSEGV",
        "crash_signature": "SEGV in JIT codegen",
    }

    first = await async_client.post(
        "/vr/fuzz/crashes", headers=_auth(admin_token), json=body,
    )
    assert first.status_code == 201
    first_id = first.json()["data"]["id"]

    # Same stack_hash → returns existing crash (no new row)
    second = await async_client.post(
        "/vr/fuzz/crashes", headers=_auth(admin_token), json=body,
    )
    assert second.status_code == 201
    assert second.json()["data"]["id"] == first_id

    listing = await async_client.get(
        "/vr/fuzz/crashes", headers=_auth(admin_token),
        params={"campaign_id": cid},
    )
    assert listing.status_code == 200
    rows = listing.json()["data"]
    assert len(rows) == 1


@pytest.mark.asyncio
async def test_register_crash_likely_harmless(
    async_client: AsyncClient, admin_token: str,
) -> None:
    wid, tid = await _make_workspace_and_target(
        async_client, admin_token, "f-crash-harm",
    )
    create = await async_client.post(
        "/vr/fuzz/campaigns", headers=_auth(admin_token),
        json={
            "target_id": tid, "workspace_id": wid, "name": "c-harm",
            "engine_id": "libfuzzer", "strategy_id": "coverage_guided",
        },
    )
    cid = create.json()["data"]["id"]

    crash = await async_client.post(
        "/vr/fuzz/crashes", headers=_auth(admin_token),
        json={
            "campaign_id": cid,
            "stack_hash": "11111111",
            "crash_type": "out-of-memory",
            "crash_signature": "fuzzer OOM at 4GB",
        },
    )
    assert crash.status_code == 201
    assert crash.json()["data"]["triage_verdict"] == "likely_harmless"


@pytest.mark.asyncio
async def test_list_campaigns_filtered_by_target(
    async_client: AsyncClient, admin_token: str,
) -> None:
    wid, tid = await _make_workspace_and_target(
        async_client, admin_token, "f-list",
    )
    for name in ("c1", "c2", "c3"):
        resp = await async_client.post(
            "/vr/fuzz/campaigns", headers=_auth(admin_token),
            json={
                "target_id": tid, "workspace_id": wid, "name": name,
                "engine_id": "afl++_qemu", "strategy_id": "mutational",
            },
        )
        assert resp.status_code == 201, resp.text

    listing = await async_client.get(
        "/vr/fuzz/campaigns", headers=_auth(admin_token),
        params={"target_id": tid},
    )
    assert listing.status_code == 200
    rows = listing.json()["data"]
    assert len(rows) == 3
    names = {r["name"] for r in rows}
    assert names == {"c1", "c2", "c3"}


@pytest.mark.asyncio
async def test_create_campaign_unknown_target_returns_404(
    async_client: AsyncClient, admin_token: str,
) -> None:
    wid, _tid = await _make_workspace_and_target(
        async_client, admin_token, "f-unkn-tgt",
    )
    resp = await async_client.post(
        "/vr/fuzz/campaigns", headers=_auth(admin_token),
        json={
            "target_id": "bogus", "workspace_id": wid, "name": "x",
            "engine_id": "afl++_qemu", "strategy_id": "mutational",
        },
    )
    assert resp.status_code == 404
    assert "target" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_404_on_unknown_resource(
    async_client: AsyncClient, admin_token: str,
) -> None:
    for path in (
        "/vr/fuzz/campaigns/nonexistent",
        "/vr/fuzz/crashes/nonexistent",
    ):
        resp = await async_client.get(path, headers=_auth(admin_token))
        assert resp.status_code == 404, f"{path} returned {resp.status_code}"
