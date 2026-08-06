"""Regression tests for issue #55 slice covering the vulnerability router.

Findings covered:
    55-3.5: list endpoints paginate in Python -> push ORDER BY / LIMIT /
            OFFSET into the SQL query.
    55-3.8: bulk_update_findings accepts any workflow_state -> validate
            transitions against the graph declared in api_router.

Fixtures rely on ``tests/api/conftest.py``: ``async_client``,
``operator_token``, ``admin_token``, and ``seeded_system``. Findings are
seeded here (not via the shared ``seeded_findings`` fixture) because the
shared fixture uses the legacy uppercase criticality vocabulary
(``CRITICAL``/``HIGH``/``MEDIUM``) that does not exercise the ordered
severity CASE map introduced by 55-3.5.
"""
from __future__ import annotations

import pytest
import pytest_asyncio
from httpx import AsyncClient

from aila.modules.vulnerability.tools._scoring_constants import CRITICALITY_KEYS
from aila.platform.contracts._common import utc_now
from aila.storage.database import async_session_scope

# ---------------------------------------------------------------------------
# Seed helpers (proper CRITICALITY_KEYS vocabulary, not the legacy uppercase)
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture
async def seeded_findings_ordered(test_db, seeded_system):
    """Seed 10 LatestFindingRecord rows across the four criticality tiers.

    Rows are inserted intentionally out of severity order so the SQL
    ORDER BY (55-3.5) has real work to do. Two rows sit in each tier
    except ``Immediate`` (four rows) so pagination with ``page_size=3``
    crosses tier boundaries and exposes any off-by-one in the offset
    path. Every row lives on the same host + system_id so team-scope
    behaviour is unaffected.
    """
    from aila.modules.vulnerability.db_models import LatestFindingRecord

    # (cve_suffix, package, criticality, score, is_kev)
    specs = [
        ("0010", "libcurl",    "Moderate",  4.5,  False),
        ("0011", "openssl",    "Immediate", 9.8,  True),
        ("0012", "nginx",      "Planned",   2.1,  False),
        ("0013", "openssh",    "High",      7.3,  False),
        ("0014", "kernel",     "Immediate", 9.5,  False),
        ("0015", "glibc",      "High",      7.9,  True),
        ("0016", "python",     "Moderate",  5.0,  False),
        ("0017", "systemd",    "Immediate", 9.1,  False),
        ("0018", "bash",       "Planned",   1.7,  False),
        ("0019", "sudo",       "Immediate", 9.4,  True),
    ]

    records: list[LatestFindingRecord] = []
    for suffix, pkg, criticality, score, is_kev in specs:
        records.append(
            LatestFindingRecord(
                system_id=seeded_system.id,
                system_name=seeded_system.name,
                host=seeded_system.host,
                cve_id=f"CVE-2025-{suffix}",
                package_name=pkg,
                criticality=criticality,
                score=score,
                is_kev=is_kev,
                current_workflow_state="new",
                nvd_url=f"https://nvd.nist.gov/vuln/detail/CVE-2025-{suffix}",
                last_scanned_at=utc_now(),
                created_at=utc_now(),
            )
        )

    async with async_session_scope() as session:
        for r in records:
            session.add(r)
        await session.commit()
        for r in records:
            await session.refresh(r)
    return records


@pytest_asyncio.fixture
async def seeded_verified_finding(test_db, seeded_system):
    """Seed a single finding already in ``verified`` state.

    Used by the transition-validation test to prove that ``verified ->
    new`` (not on the graph) is rejected while ``verified -> closed``
    (on the graph) succeeds.
    """
    from aila.modules.vulnerability.db_models import LatestFindingRecord

    record = LatestFindingRecord(
        system_id=seeded_system.id,
        system_name=seeded_system.name,
        host=seeded_system.host,
        cve_id="CVE-2025-9000",
        package_name="verified-pkg",
        criticality="High",
        score=8.0,
        is_kev=False,
        current_workflow_state="verified",
        nvd_url="https://nvd.nist.gov/vuln/detail/CVE-2025-9000",
        last_scanned_at=utc_now(),
        created_at=utc_now(),
    )
    async with async_session_scope() as session:
        session.add(record)
        await session.commit()
        await session.refresh(record)
    return record


# ---------------------------------------------------------------------------
# 55-3.5: SQL pagination
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_list_findings_returns_bounded_page_in_severity_order(
    async_client: AsyncClient,
    operator_token: str,
    seeded_findings_ordered,
) -> None:
    """First page: bounded to ``page_size`` rows, ordered by CRITICALITY_KEYS.

    The prior implementation loaded every row and sliced in Python. With
    SQL pushdown the response envelope MUST report the full ``total`` while
    the ``items`` array carries only the requested page. Ordering follows
    the CRITICALITY_KEYS rank map (Immediate first, then High, Moderate,
    Planned) with is_kev DESC as the tie-breaker inside a tier.
    """
    resp = await async_client.get(
        "/vulnerability/findings",
        params={"sort_by": "severity", "order": "asc", "page": 1, "page_size": 3},
        headers={"Authorization": f"Bearer {operator_token}"},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()["data"]

    assert body["total"] == 10, "seeded 10 findings should reappear in total"
    assert body["page"] == 1
    assert body["page_size"] == 3
    assert body["pages"] == 4, "ceil(10 / 3) == 4"
    assert len(body["items"]) == 3, "page must be bounded to page_size"

    severities = [item["severity"] for item in body["items"]]
    # All three highest-ranked rows are ``Immediate`` (four in the seed set),
    # so the page must not leak a lower tier ahead of them.
    assert severities == ["Immediate", "Immediate", "Immediate"], severities

    # KEV tie-break inside the Immediate tier: is_kev=True rows lead.
    # Seed has two KEV+Immediate rows (openssl, sudo) so both MUST land on
    # the first page even though four Immediate rows exist.
    first_page_kev_true = [item for item in body["items"] if item["is_kev"] is True]
    assert len(first_page_kev_true) == 2, (
        f"KEV rows should lead within the tier: {body['items']!r}"
    )


@pytest.mark.asyncio
async def test_list_findings_offset_returns_disjoint_page(
    async_client: AsyncClient,
    operator_token: str,
    seeded_findings_ordered,
) -> None:
    """Offset (page=2) must return the next slice, no overlap with page=1.

    With Python-side slicing an off-by-one on offset would silently repeat
    rows. Pushing offset into SQL only helps if the tie-breaker in the
    ORDER BY is stable across pages; the ``id ASC`` fallback proves this.
    """
    common_params = {
        "sort_by": "severity",
        "order": "asc",
        "page_size": 3,
    }

    page_one = await async_client.get(
        "/vulnerability/findings",
        params={**common_params, "page": 1},
        headers={"Authorization": f"Bearer {operator_token}"},
    )
    page_two = await async_client.get(
        "/vulnerability/findings",
        params={**common_params, "page": 2},
        headers={"Authorization": f"Bearer {operator_token}"},
    )
    assert page_one.status_code == 200, page_one.text
    assert page_two.status_code == 200, page_two.text

    ids_one = [item["id"] for item in page_one.json()["data"]["items"]]
    ids_two = [item["id"] for item in page_two.json()["data"]["items"]]

    assert len(ids_one) == 3
    assert len(ids_two) == 3
    assert set(ids_one).isdisjoint(ids_two), (
        f"page 2 leaked page 1 rows: {ids_one=} {ids_two=}"
    )

    # Page 2 sits at the tier boundary: the fourth Immediate + first two
    # High rows. That is the observable contract 55-3.5 promises when the
    # sort is honoured inside the DB.
    severities_two = [item["severity"] for item in page_two.json()["data"]["items"]]
    assert severities_two == ["Immediate", "High", "High"], severities_two


# ---------------------------------------------------------------------------
# 55-3.8: workflow-transition validation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_bulk_update_rejects_invalid_workflow_transition(
    async_client: AsyncClient,
    operator_token: str,
    seeded_verified_finding,
) -> None:
    """``verified -> new`` is off the graph and MUST 422 with a code payload.

    The DB CHECK constraint only enforces the value set; without the
    graph guard the rewind would land silently and destroy audit trail.
    """
    resp = await async_client.patch(
        "/vulnerability/findings/bulk",
        json={
            "finding_ids": [seeded_verified_finding.id],
            "workflow_state": "new",
        },
        headers={"Authorization": f"Bearer {operator_token}"},
    )
    assert resp.status_code == 422, resp.text
    detail = resp.json()["detail"]
    assert isinstance(detail, dict), f"structured error expected, got: {detail!r}"
    assert detail["code"] == "transition_not_allowed"
    assert detail["current_state"] == "verified"
    assert detail["target_state"] == "new"
    assert detail["finding_id"] == seeded_verified_finding.id


@pytest.mark.asyncio
async def test_bulk_update_accepts_valid_workflow_transition(
    async_client: AsyncClient,
    operator_token: str,
    seeded_verified_finding,
) -> None:
    """``verified -> closed`` IS on the graph and MUST succeed.

    Complements the negative test: proves the graph is not vacuously
    strict. Also checks the row's state actually flipped in the DB, so
    the audit-adjacent update path did not regress alongside the guard.
    """
    from sqlmodel import select

    from aila.modules.vulnerability.db_models import LatestFindingRecord

    resp = await async_client.patch(
        "/vulnerability/findings/bulk",
        json={
            "finding_ids": [seeded_verified_finding.id],
            "workflow_state": "closed",
        },
        headers={"Authorization": f"Bearer {operator_token}"},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()["data"]
    assert body["status"] == "updated"
    assert body["count"] == 1

    # Verify the DB actually flipped (guards against the write being
    # short-circuited by the transition preflight).
    async with async_session_scope() as session:
        row = (await session.exec(
            select(LatestFindingRecord).where(
                LatestFindingRecord.id == seeded_verified_finding.id,
            )
        )).first()
    assert row is not None
    assert row.current_workflow_state == "closed"


@pytest.mark.asyncio
async def test_transition_graph_covers_every_declared_state() -> None:
    """Structural guard: every state in the CHECK constraint appears in the graph.

    The DB CHECK constraint (db_models/findings.py) enumerates
    new/investigating/mitigated/verified/closed. If someone adds a new
    state to the constraint without updating the graph, transitions
    involving that state would silently fall through to
    ``allowed=frozenset()`` and reject everything. This test catches the
    drift at import time -- no HTTP surface needed.
    """
    from aila.modules.vulnerability.api_router import _ALLOWED_WORKFLOW_TRANSITIONS

    declared_states = {"new", "investigating", "mitigated", "verified", "closed"}
    assert set(_ALLOWED_WORKFLOW_TRANSITIONS.keys()) == declared_states, (
        f"graph missing states from the CHECK constraint: "
        f"{declared_states - set(_ALLOWED_WORKFLOW_TRANSITIONS.keys())}"
    )
    # And every target must itself be a declared state (no typos).
    for src, targets in _ALLOWED_WORKFLOW_TRANSITIONS.items():
        stray = targets - declared_states
        assert not stray, f"graph edge from {src!r} references undeclared state(s): {stray!r}"

    # Sanity checks drawn from the design (DESIGN_module_correctness.md 3.8):
    assert "new" not in _ALLOWED_WORKFLOW_TRANSITIONS["verified"], (
        "verified must never rewind to new"
    )
    assert _ALLOWED_WORKFLOW_TRANSITIONS["closed"] == frozenset({"investigating"}), (
        "closed reopens only via investigating"
    )


def test_criticality_keys_source_of_truth() -> None:
    """Import-only guard: the scoring vocabulary is the one the router uses.

    If ``CRITICALITY_KEYS`` drifts, the SQL CASE map in list_findings drifts
    with it, so this pins the two sides together.
    """
    assert CRITICALITY_KEYS == ("Immediate", "High", "Moderate", "Planned")
