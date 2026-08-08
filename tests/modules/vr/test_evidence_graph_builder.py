"""Offline unit tests for the VR evidence-graph snapshot builder.

The `get_evidence_graph` endpoint used to emit only three node kinds
(investigation, branch, outcome). Mid-flight investigations with a few
live branches and no outcomes yet produced a snapshot that carried no
reasoning content -- issue #17 ("evidence graph is not working and
displayed", "does not have any meaningful information that you could be
interested in").

The builder now surfaces hypotheses (extracted from per-branch
``case_state_json``) and linked findings so the graph reflects the
actual state of an investigation. These tests exercise the pure
builder against in-memory fake rows -- no live DB, no network.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from aila.modules.vr.services.evidence_graph import build_evidence_graph_snapshot


@dataclass
class _FakeBranch:
    id: str
    status: str = "active"
    persona_voice: str = "halvar"
    strategy_family: str | None = None
    promoted: bool = False
    case_state_json: str = "{}"


@dataclass
class _FakeOutcome:
    id: str
    branch_id: str
    outcome_kind: str = "assessment_report"
    dispatch_status: str = "pending"
    dispatch_target: str | None = None
    confidence: str = "strong"


def _by_kind(snapshot: Any, kind: str) -> list[Any]:
    return [n for n in snapshot.nodes if n.kind == kind]


def _edges_of_kind(snapshot: Any, kind: str) -> list[Any]:
    return [e for e in snapshot.edges if e.kind == kind]


def test_empty_investigation_still_carries_root_node() -> None:
    """An investigation with no branches, no outcomes, no findings still
    gets one investigation root node -- the graph is never zero nodes."""
    snap = build_evidence_graph_snapshot(
        investigation_id="inv-empty",
        inv_status="created",
        inv_linked_finding_ids_json="[]",
        branches=[],
        outcomes=[],
    )
    assert snap.investigation_id == "inv-empty"
    assert snap.layout == "concentric"
    assert len(snap.nodes) == 1
    assert snap.nodes[0].kind == "investigation"
    assert snap.nodes[0].state == "created"
    assert snap.edges == []


def test_hypotheses_are_extracted_from_branch_case_state() -> None:
    """The core fix: hypotheses stored in branch case_state_json become
    nodes with branch->hypothesis edges. Prior implementation ignored
    case_state_json entirely -- the mid-flight investigation defect."""
    # Two branches, three distinct hypothesis ids. h1 is live on
    # branch A and rejected on branch B (=> mixed). h2 is only live
    # on A. h3 is only rejected on B.
    case_a = json.dumps({
        "hypotheses": [
            {"id": "h1", "claim": "parse_header overflow at src/http.c:412"},
            {"id": "h2", "claim": "signed int truncation on length field"},
        ],
    })
    case_b = json.dumps({
        "rejected": [
            {"id": "h1", "claim": "parse_header overflow", "reason": "guard covers case"},
            {"id": "h3", "claim": "double-free in cleanup"},
        ],
    })
    branches = [
        _FakeBranch(id="branch-a", status="active", case_state_json=case_a),
        _FakeBranch(id="branch-b", status="active", case_state_json=case_b),
    ]

    snap = build_evidence_graph_snapshot(
        investigation_id="inv-hypo",
        inv_status="running",
        inv_linked_finding_ids_json=None,
        branches=branches,
        outcomes=[],
    )

    hyp = _by_kind(snap, "hypothesis")
    assert {n.id for n in hyp} == {
        "hypothesis:h1", "hypothesis:h2", "hypothesis:h3",
    }

    by_id = {n.id: n for n in hyp}
    assert by_id["hypothesis:h1"].state == "mixed"
    assert by_id["hypothesis:h2"].state == "live"
    assert by_id["hypothesis:h3"].state == "rejected"

    # Labels carry the claim snippet so the graph reads meaningfully.
    assert "parse_header" in by_id["hypothesis:h1"].label
    assert "signed int" in by_id["hypothesis:h2"].label

    # Attributes cross-list the branches carrying each partition.
    assert by_id["hypothesis:h1"].attributes["live_in_branches"] == ["branch-a"]
    assert by_id["hypothesis:h1"].attributes["rejected_in_branches"] == ["branch-b"]

    raises = _edges_of_kind(snap, "raises")
    rejects = _edges_of_kind(snap, "rejects")
    assert {(e.source, e.target) for e in raises} == {
        ("branch:branch-a", "hypothesis:h1"),
        ("branch:branch-a", "hypothesis:h2"),
    }
    assert {(e.source, e.target) for e in rejects} == {
        ("branch:branch-b", "hypothesis:h1"),
        ("branch:branch-b", "hypothesis:h3"),
    }


def test_findings_are_wired_to_producing_outcome_when_dispatched() -> None:
    """Findings from linked_finding_ids_json get their own outermost
    nodes. When an outcome dispatched to that finding
    (dispatch_target='vr_finding:<id>'), the edge runs outcome ->
    finding; otherwise it falls back to investigation -> finding."""
    branches = [_FakeBranch(id="branch-a", status="promoted", promoted=True)]
    outcomes = [
        _FakeOutcome(
            id="outcome-1",
            branch_id="branch-a",
            outcome_kind="direct_finding",
            dispatch_status="dispatched",
            dispatch_target="vr_finding:F-42",
        ),
    ]

    snap = build_evidence_graph_snapshot(
        investigation_id="inv-fin",
        inv_status="completed",
        # Two findings: F-42 (produced by outcome-1) and F-99 (linked
        # to the investigation without an intermediate outcome row).
        inv_linked_finding_ids_json=json.dumps(["F-42", "F-99"]),
        branches=branches,
        outcomes=outcomes,
    )

    finding_ids = {n.id for n in _by_kind(snap, "finding")}
    assert finding_ids == {"finding:F-42", "finding:F-99"}

    produced_finding = _edges_of_kind(snap, "produced_finding")
    linked = _edges_of_kind(snap, "linked")
    assert {(e.source, e.target) for e in produced_finding} == {
        ("outcome:outcome-1", "finding:F-42"),
    }
    assert {(e.source, e.target) for e in linked} == {
        ("inv:inv-fin", "finding:F-99"),
    }


def test_full_snapshot_carries_meaningful_content_for_active_investigation() -> None:
    """Regression guard for issue #17: an active investigation with
    branches and hypotheses (but no terminal outcomes yet) MUST NOT
    produce a barren snapshot. Before the fix, no hypothesis nodes were
    emitted at all so the graph collapsed to (1 root + N branches)."""
    case_a = json.dumps({
        "hypotheses": [
            {"id": "h1", "claim": "buffer overflow in parse_header"},
            {"id": "h2", "claim": "off-by-one in loop bound"},
        ],
    })
    case_b = json.dumps({
        "hypotheses": [
            {"id": "h3", "claim": "TOCTOU on config read"},
        ],
        "resolved": [
            {"id": "h1", "claim": "buffer overflow", "note": "confirmed"},
        ],
    })
    branches = [
        _FakeBranch(id="a", status="active", case_state_json=case_a),
        _FakeBranch(id="b", status="active", case_state_json=case_b),
    ]

    snap = build_evidence_graph_snapshot(
        investigation_id="inv-active",
        inv_status="running",
        inv_linked_finding_ids_json=None,
        branches=branches,
        outcomes=[],  # deliberately empty: pre-terminal investigation
    )

    counts = {
        "investigation": len(_by_kind(snap, "investigation")),
        "branch": len(_by_kind(snap, "branch")),
        "hypothesis": len(_by_kind(snap, "hypothesis")),
        "outcome": len(_by_kind(snap, "outcome")),
        "finding": len(_by_kind(snap, "finding")),
    }
    # Meaningful content: hypothesis vocabulary is present even without
    # any terminal outcomes.
    assert counts == {
        "investigation": 1,
        "branch": 2,
        "hypothesis": 3,
        "outcome": 0,
        "finding": 0,
    }
    # Edges: 2 spawned (inv->branch) + 2 raises (a->h1, a->h2) + 1
    # raises (b->h3) + 1 resolves (b->h1).
    assert len(_edges_of_kind(snap, "spawned")) == 2
    assert len(_edges_of_kind(snap, "raises")) == 3
    assert len(_edges_of_kind(snap, "resolves")) == 1


def test_malformed_case_state_json_does_not_crash_the_builder() -> None:
    """A branch with corrupted case_state_json is skipped gracefully;
    the rest of the snapshot must still assemble."""
    branches = [
        _FakeBranch(id="a", case_state_json="not-json"),
        _FakeBranch(id="b", case_state_json=json.dumps({
            "hypotheses": [{"id": "h9", "claim": "guarded path"}],
        })),
    ]

    snap = build_evidence_graph_snapshot(
        investigation_id="inv-bad",
        inv_status="running",
        inv_linked_finding_ids_json=None,
        branches=branches,
        outcomes=[],
    )

    # Branch nodes still emitted for both.
    assert {n.id for n in _by_kind(snap, "branch")} == {"branch:a", "branch:b"}
    # h9 from the intact branch survives.
    assert {n.id for n in _by_kind(snap, "hypothesis")} == {"hypothesis:h9"}


def test_outcome_without_branch_falls_back_to_investigation_source() -> None:
    """Existing behaviour preserved: an outcome with no branch_id is
    wired directly to the investigation root."""
    outcomes = [
        _FakeOutcome(
            id="orphan",
            branch_id="",  # empty -- pre-branching outcome
            outcome_kind="audit_memo",
        ),
    ]
    snap = build_evidence_graph_snapshot(
        investigation_id="inv-orph",
        inv_status="running",
        inv_linked_finding_ids_json=None,
        branches=[],
        outcomes=outcomes,
    )
    produced = _edges_of_kind(snap, "produced")
    assert produced[0].source == "inv:inv-orph"
    assert produced[0].target == "outcome:orphan"


def test_grid_layout_places_kinds_on_distinct_rows() -> None:
    """The grid layout separates each node kind onto its own row so a
    dense investigation reads left-to-right."""
    case = json.dumps({"hypotheses": [{"id": "h1", "claim": "x"}]})
    branches = [_FakeBranch(id="b1", case_state_json=case)]
    outcomes = [_FakeOutcome(id="o1", branch_id="b1")]
    snap = build_evidence_graph_snapshot(
        investigation_id="inv-grid",
        inv_status="running",
        inv_linked_finding_ids_json=json.dumps(["F1"]),
        branches=branches,
        outcomes=outcomes,
        layout="grid",
    )
    row_by_kind = {n.kind: n.y for n in snap.nodes}
    # Row order: investigation (0) < branch (200) < hypothesis (320) <
    # outcome (440) < finding (580).
    assert row_by_kind["investigation"] == 0.0
    assert row_by_kind["branch"] < row_by_kind["hypothesis"]
    assert row_by_kind["hypothesis"] < row_by_kind["outcome"]
    assert row_by_kind["outcome"] < row_by_kind["finding"]


def test_observables_become_evidence_nodes_with_support_refute_links() -> None:
    """MCP tool readings in case_state.observables become evidence nodes,
    attributed to the observing branch via found_by, and linked to a
    hypothesis only when the hypothesis text names the reading's target:
    supports for a live claim, refutes for a rejected reason. Scratchpad
    keys (leading underscore) are skipped, and the rejection reason is
    surfaced on the hypothesis node."""
    case = json.dumps({
        "hypotheses": [
            {"id": "h1",
             "claim": "heap overflow in mov_read_senc via unchecked count",
             "why_plausible": "mov_read_senc reads count without a bound"},
        ],
        "rejected": [
            {"id": "h2",
             "claim": "overflow in mov_read_saiz",
             "reason": "mov_read_saiz validates the size before use; disproved"},
        ],
        "observables": {
            "audit_mcp.read_function.source.mov_read_senc": "static int mov_read_senc(){}",
            "audit_mcp.read_function.source.mov_read_saiz": "static int mov_read_saiz(){}",
            "_directive.phase_mission": "scratchpad key -- must be skipped",
        },
    })
    branches = [_FakeBranch(id="b1", persona_voice="halvar", case_state_json=case)]
    snap = build_evidence_graph_snapshot(
        investigation_id="inv-ev",
        inv_status="running",
        inv_linked_finding_ids_json="[]",
        branches=branches,
        outcomes=[],
    )

    ev_ids = {n.id for n in _by_kind(snap, "evidence")}
    assert ev_ids == {
        "evidence:audit_mcp.read_function.source.mov_read_senc",
        "evidence:audit_mcp.read_function.source.mov_read_saiz",
    }
    senc = next(n for n in _by_kind(snap, "evidence") if n.id.endswith("mov_read_senc"))
    assert senc.attributes["tool"] == "read_function"
    assert senc.attributes["target"] == "mov_read_senc"
    assert senc.attributes["personas"] == ["halvar"]

    found = _edges_of_kind(snap, "found_by")
    assert any(e.source == senc.id and e.target == "branch:b1" for e in found)

    supports = _edges_of_kind(snap, "supports")
    assert any(
        e.source == senc.id and e.target == "hypothesis:h1" for e in supports
    )

    saiz = next(n for n in _by_kind(snap, "evidence") if n.id.endswith("mov_read_saiz"))
    refutes = _edges_of_kind(snap, "refutes")
    assert any(
        e.source == saiz.id and e.target == "hypothesis:h2" for e in refutes
    )

    h2 = next(n for n in _by_kind(snap, "hypothesis") if n.id == "hypothesis:h2")
    assert "validates the size" in h2.attributes["rejection_reason"]
