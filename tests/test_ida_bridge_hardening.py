"""Bridge + adapter hardening: dead-worker fail-fast, per-call dedup,
xref-pagination hint.

Three independent fixes against observed failure modes on the masson
investigation:

(B) Bridge fail-fast on dead arbiter. ida-headless can leave the
    IDA worker subprocess permanently down (crash counts hit cap;
    arbiter refuses to respawn). Every request returns
    ``status: pending`` with stale ``heartbeat_age_s`` and
    ``worker_phase: exiting_idle``. The auto-poll loop used to
    burn 240s per call before surfacing a generic timeout. The
    bridge now matches that shape on first response (and on each
    retry payload) and short-circuits with a structured error
    naming the symptom and the operator action.

(C) XREF pagination hint. Observable preview is capped at
    ``MAX_LIST_PREVIEW=20``. The old format silently dropped rows
    beyond the cap with a bare ``... and N more`` line; agents had
    no actionable way to fetch the suppressed rows. The adapter
    now emits a hint naming the offset / limit shape for the
    follow-up call, AND stamps ``payload.pagination_hint`` so
    consumers can branch on it programmatically.

(D) Per-call dedup. Sibling branches frequently issue identical
    ``xrefs_to`` / ``decompile`` / ``capa_scan`` calls within a
    short window. The bridge caches ready payloads by
    ``sha256(action, normalized_kwargs)`` for ``IDA_HEADLESS_DEDUP_TTL_S``
    seconds (default 300) and replays cached results without
    re-dispatching to the MCP server.
"""
from __future__ import annotations

import time

import pytest

from aila.platform.mcp.adapters._shared import MAX_LIST_PREVIEW, AdapterContext
from aila.platform.mcp.adapters.ida_headless import _xref_view_result
from aila.platform.mcp.bridges.ida_headless import IDABridgeTool


class TestDeadWorkerDetection:
    """``_looks_like_dead_worker`` matches only the full signature."""

    def _payload(
        self,
        *,
        status: str = "pending",
        phase: str = "exiting_idle",
        hb_age: float | int | None = 75000,
    ) -> dict:
        out: dict = {"status": status, "worker_phase": phase}
        if hb_age is not None:
            out["heartbeat_age_s"] = hb_age
        return out

    def test_matches_canonical_dead_arbiter_shape(self) -> None:
        # status=pending + worker_phase=exiting_idle + hb_age >= 600
        # matches the live failure mode observed on masson.
        assert IDABridgeTool._looks_like_dead_worker(self._payload())

    def test_pending_alone_does_not_trip(self) -> None:
        # A genuinely slow but live worker (recent heartbeat, normal
        # phase) must NOT be flagged. Otherwise the bridge would
        # convert every transient ``pending`` into a hard error and
        # never give the actual auto-poll loop a chance to recover.
        assert not IDABridgeTool._looks_like_dead_worker(
            self._payload(phase="processing", hb_age=2),
        )
        assert not IDABridgeTool._looks_like_dead_worker(
            self._payload(phase="idle", hb_age=5),
        )

    def test_ready_status_never_flagged(self) -> None:
        assert not IDABridgeTool._looks_like_dead_worker(
            self._payload(status="ready"),
        )

    def test_stale_heartbeat_alone_is_not_enough(self) -> None:
        # Heartbeat could be stale because the worker just finished a
        # long synchronous IDA call and hasn't ticked the heartbeat
        # yet. Without the matching ``exiting_idle`` phase the bridge
        # must keep retrying.
        assert not IDABridgeTool._looks_like_dead_worker(
            self._payload(phase="processing"),
        )

    def test_under_threshold_not_flagged(self) -> None:
        # Default threshold is 600s; 60s of staleness is normal.
        assert not IDABridgeTool._looks_like_dead_worker(
            self._payload(hb_age=60),
        )

    def test_non_string_phase_rejected(self) -> None:
        assert not IDABridgeTool._looks_like_dead_worker({
            "status": "pending", "worker_phase": None, "heartbeat_age_s": 75000,
        })

    def test_non_numeric_heartbeat_rejected(self) -> None:
        assert not IDABridgeTool._looks_like_dead_worker({
            "status": "pending",
            "worker_phase": "exiting_idle",
            "heartbeat_age_s": "not-a-number",
        })

    def test_crashed_phase_alias(self) -> None:
        # ``crashed`` is the other observed dead-arbiter phase.
        assert IDABridgeTool._looks_like_dead_worker(self._payload(phase="crashed"))

    def test_empty_string_phase_alias(self) -> None:
        # Some old responses come back with worker_phase="" when the
        # arbiter never ticked. Treated as dead.
        assert IDABridgeTool._looks_like_dead_worker(self._payload(phase=""))

    def test_error_message_names_symptom_and_action(self) -> None:
        bridge = IDABridgeTool()
        err = bridge._dead_worker_error("xrefs_to", {
            "binary_id": "b_abc123",
            "heartbeat_age_s": 75123,
            "queue_depth": 4521,
            "worker_phase": "exiting_idle",
        })
        assert err["status"] == "error"
        msg = err["error"]
        # Names what's broken.
        assert "IDA worker is not alive" in msg
        # Names the diagnostic numbers.
        assert "b_abc123" in msg
        assert "75123" in msg or "75000" in msg or "heartbeat_age_s" in msg
        # Names the operator action.
        assert "restart ida-headless" in msg
        assert "crash_counts" in msg
        # Structured payload field for programmatic consumers.
        assert err["dead_worker_diagnostic"]["sha"] == "b_abc123"
        assert err["dead_worker_diagnostic"]["action"] == "xrefs_to"


class TestDedupCache:
    """Per-call dedup of ready payloads by sha256(action, kwargs)."""

    def test_fingerprint_stable_across_kwarg_order(self) -> None:
        bridge = IDABridgeTool()
        fp1 = bridge._dedup_fingerprint("xrefs_to", {"a": 1, "b": 2})
        fp2 = bridge._dedup_fingerprint("xrefs_to", {"b": 2, "a": 1})
        assert fp1 == fp2

    def test_fingerprint_diverges_on_kwargs(self) -> None:
        bridge = IDABridgeTool()
        fp1 = bridge._dedup_fingerprint("xrefs_to", {"binary_id": "b1"})
        fp2 = bridge._dedup_fingerprint("xrefs_to", {"binary_id": "b2"})
        assert fp1 != fp2

    def test_fingerprint_diverges_on_action(self) -> None:
        bridge = IDABridgeTool()
        fp1 = bridge._dedup_fingerprint("xrefs_to", {"binary_id": "b1"})
        fp2 = bridge._dedup_fingerprint("xrefs_from", {"binary_id": "b1"})
        assert fp1 != fp2

    def test_store_and_lookup_round_trip(self) -> None:
        bridge = IDABridgeTool()
        fp = bridge._dedup_fingerprint("xrefs_to", {"binary_id": "b1"})
        payload = {"status": "ready", "xrefs": [{"addr": "0x1"}]}
        bridge._dedup_store(fp, payload)
        cached = bridge._dedup_lookup(fp)
        assert cached == payload

    def test_lookup_miss_returns_none(self) -> None:
        bridge = IDABridgeTool()
        assert bridge._dedup_lookup("never-stored") is None

    def test_zero_ttl_disables_cache(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("IDA_HEADLESS_DEDUP_TTL_S", "0")
        bridge = IDABridgeTool()
        fp = bridge._dedup_fingerprint("xrefs_to", {"binary_id": "b1"})
        bridge._dedup_store(fp, {"status": "ready"})
        # store() with ttl=0 short-circuits; lookup returns None.
        assert bridge._dedup_lookup(fp) is None

    def test_expired_entry_evicted_on_lookup(self) -> None:
        bridge = IDABridgeTool()
        bridge._dedup_ttl_s = 0.01
        fp = bridge._dedup_fingerprint("xrefs_to", {"binary_id": "b1"})
        bridge._dedup_store(fp, {"status": "ready"})
        time.sleep(0.05)
        assert bridge._dedup_lookup(fp) is None
        # Eviction on read: the entry is also gone from the cache dict.
        assert fp not in bridge._dedup_cache

    def test_dedup_actions_includes_canonical_read_tools(self) -> None:
        bridge = IDABridgeTool()
        # Read-only graph queries every sibling branch issues.
        for action in (
            "xrefs_to", "xrefs_from", "decompile",
            "find_api_call_sites", "callers_of",
            "build_call_tree", "call_graph", "list_strings",
            "imports", "exports",
        ):
            assert action in bridge._dedup_actions, action

    def test_dedup_actions_excludes_state_mutators(self) -> None:
        bridge = IDABridgeTool()
        for action in (
            "open_binary", "upload", "patch_assemble", "poll_analysis",
        ):
            assert action not in bridge._dedup_actions, action


class TestXrefPaginationHint:
    """Adapter surfaces the suppressed-row count + the follow-up call."""

    def _ctx(self) -> AdapterContext:
        return AdapterContext(
            mcp_server_id="ida_headless",
            tool_name="xrefs_to",
            investigation_id="inv-1",
            branch_id="br-1",
            call_id="call-abc-123",
            args={"binary_id": "b_d22c", "address_or_name": "0x401000"},
        )

    def test_no_hint_when_under_cap(self) -> None:
        refs = [{"function_name": f"sub_{i}", "function_address": f"0x{i:x}"} for i in range(5)]
        result = _xref_view_result(
            {"binary_id": "b_d22c", "xrefs": refs},
            self._ctx(),
            target="0x401000",
            list_keys=("xrefs",),
            target_field="target",
            obs_suffix="xrefs_to",
            summary_noun="xref(s) to",
        )
        assert "pagination_hint" not in result.payload
        for obs in result.observables_delta.values():
            assert "more row" not in obs
            assert "suppressed" not in obs

    def test_hint_surfaced_when_over_cap(self) -> None:
        # 47 xrefs, cap=20 -> 27 suppressed.
        n = MAX_LIST_PREVIEW + 27
        refs = [
            {"function_name": f"sub_{i}", "function_address": f"0x{i:x}"}
            for i in range(n)
        ]
        result = _xref_view_result(
            {"binary_id": "b_d22c", "xrefs": refs},
            self._ctx(),
            target="0x401000",
            list_keys=("xrefs",),
            target_field="target",
            obs_suffix="xrefs_to",
            summary_noun="xref(s) to",
        )
        # Payload pagination_hint structure is correct.
        ph = result.payload["pagination_hint"]
        assert ph["shown"] == MAX_LIST_PREVIEW
        assert ph["total"] == n
        assert ph["suppressed"] == 27
        assert ph["next_offset"] == MAX_LIST_PREVIEW
        assert ph["call_id"] == "call-abc-123"
        # Full xref list still on the payload (no trimming).
        assert len(result.payload["xrefs"]) == n
        # Observable text names the suppressed count + the offset.
        obs_value = next(iter(result.observables_delta.values()))
        assert "27 more row" in obs_value
        assert "offset=20" in obs_value
        assert "call-abc-123" in obs_value
        assert f"cap={MAX_LIST_PREVIEW}" in obs_value

    def test_full_payload_preserved_when_hint_emitted(self) -> None:
        # Regression: the trimming logic only affects the observable
        # preview; the canonical payload's xrefs array must carry
        # EVERY row so downstream consumers (UI, dispatch, exports)
        # see the complete result.
        n = MAX_LIST_PREVIEW * 3
        refs = [
            {"function_name": f"sub_{i}", "function_address": f"0x{i:x}"}
            for i in range(n)
        ]
        result = _xref_view_result(
            {"binary_id": "b_d22c", "xrefs": refs},
            self._ctx(),
            target="0x401000",
            list_keys=("xrefs",),
            target_field="target",
            obs_suffix="xrefs_to",
            summary_noun="xref(s) to",
        )
        assert len(result.payload["xrefs"]) == n
        assert result.payload["total"] == n
        # Summary line carries the real total, not the trimmed count.
        assert str(n) in result.summary

    def test_empty_xrefs_renders_none_marker(self) -> None:
        result = _xref_view_result(
            {"binary_id": "b_d22c", "xrefs": []},
            self._ctx(),
            target="0x401000",
            list_keys=("xrefs",),
            target_field="target",
            obs_suffix="xrefs_to",
            summary_noun="xref(s) to",
        )
        assert "pagination_hint" not in result.payload
        obs = next(iter(result.observables_delta.values()))
        assert "(none)" in obs
