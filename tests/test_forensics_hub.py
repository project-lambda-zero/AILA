"""Forensics dispatch-hub: evidence-driven lane activation + evidence board (RFC-13 Phase 6)."""
from __future__ import annotations

from aila.modules.forensics.workflow.definitions_hub import (
    FORENSICS_HUB_PHASES,
    FORENSICS_INVESTIGATE_HUB,
    record_evidence,
)
from aila.platform.services.ledger import LedgerService
from aila.platform.workflows.phase_graph import DISPATCH_STATE, make_dispatch_router


def test_hub_has_dispatch_lane_and_tail_states() -> None:
    states = FORENSICS_INVESTIGATE_HUB.states
    assert DISPATCH_STATE in states
    for name in ("disk", "memory", "network", "log", "binary"):
        assert name in states
    for name in ("deep_analysis", "promotion", "resolution", "writeup"):
        assert name in states
    assert FORENSICS_INVESTIGATE_HUB.definition_id == "forensics.investigate.hub"


async def test_disk_image_activates_disk_lane(test_db) -> None:
    del test_db
    inv = "inv-fx-disk"
    await record_evidence(inv, "intake", "disk_image", "/ev/img.E01", "case-1")
    router = make_dispatch_router(FORENSICS_HUB_PHASES)
    result = await router({"investigation_id": inv, "_dispatch_visited": []}, None)
    assert result.next_state == "disk"


async def test_pcap_activates_network_lane(test_db) -> None:
    del test_db
    inv = "inv-fx-pcap"
    await record_evidence(inv, "intake", "pcap", "/ev/capture.pcap", "case-2")
    router = make_dispatch_router(FORENSICS_HUB_PHASES)
    # Disk/memory lanes have no matching evidence, so the hub skips them and
    # activates the network lane.
    result = await router(
        {"investigation_id": inv, "_dispatch_visited": ["disk", "memory"]}, None,
    )
    assert result.next_state == "network"


async def test_evidence_board_records_provenance(test_db) -> None:
    del test_db
    inv = "inv-fx-board"
    entry_id = await record_evidence(
        inv, "intake", "memory_dump", "/ev/mem.raw", "case-3",
    )
    rows = await LedgerService().read_general(inv, kinds=["discovery"])
    assert len(rows) == 1
    payload = rows[0]["payload"]
    assert rows[0]["id"] == entry_id
    assert payload["evidence_type"] == "memory_dump"
    assert payload["path"] == "/ev/mem.raw"
    assert payload["source"] == "case-3"
    # Re-recording the same path is idempotent (no double-post).
    await record_evidence(inv, "intake", "memory_dump", "/ev/mem.raw", "case-3")
    rows_again = await LedgerService().read_general(inv, kinds=["discovery"])
    assert len(rows_again) == 1


async def test_no_matching_evidence_falls_through_to_tail(test_db) -> None:
    del test_db
    inv = "inv-fx-tail"
    # No evidence discovered: every lane condition is false, so the hub
    # activates the first unconditional tail stage.
    router = make_dispatch_router(FORENSICS_HUB_PHASES)
    result = await router({"investigation_id": inv, "_dispatch_visited": []}, None)
    assert result.next_state == "deep_analysis"
