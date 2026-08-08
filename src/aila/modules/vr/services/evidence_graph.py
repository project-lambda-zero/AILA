"""Evidence-graph snapshot builder for a single VR investigation.

The endpoint ``GET /vr/investigations/{id}/evidence-graph`` (defined in
``aila.modules.vr.api_router``) loads investigation / branch / outcome
rows and delegates node-and-edge assembly to
:func:`build_evidence_graph_snapshot` in this module.

The prior implementation emitted only three node kinds (investigation,
branch, outcome). Outcomes only exist once a branch reaches a terminal
state, so an active investigation with a few live branches and no
outcomes yet produced a snapshot that carried no reasoning content --
just a persona map. The real hypothesis vocabulary (``h1``, ``h2``, ...)
lives inside each branch's ``case_state_json`` and was never surfaced.
Findings (``VRInvestigationRecord.linked_finding_ids_json``) never
appeared either.

This builder emits five node kinds -- investigation | branch |
hypothesis | outcome | finding -- and eight edge kinds so the graph
reflects the actual evidence and reasoning state of an investigation.
"""
from __future__ import annotations

import json
import logging
import math
from typing import Any

from aila.platform.contracts.evidence_graph import (
    EvidenceGraphEdge,
    EvidenceGraphNode,
    EvidenceGraphSnapshot,
)

__all__ = ["build_evidence_graph_snapshot"]

_log = logging.getLogger(__name__)


def _parse_case_state(raw: str | None) -> dict[str, Any]:
    """Return the JSON dict stored in a branch's case_state_json cell."""
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
    except (TypeError, ValueError) as exc:
        _log.warning("case_state_json parse failed: %s", exc)
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _parse_id_list(raw: str | None) -> list[str]:
    """Return the list stored in an investigation's linked_*_ids_json cell."""
    if not raw:
        return []
    try:
        parsed = json.loads(raw)
    except (TypeError, ValueError) as exc:
        _log.warning("linked-id list JSON parse failed: %s", exc)
        return []
    if not isinstance(parsed, list):
        return []
    return [str(x) for x in parsed if x]


def _hypothesis_state(
    hid: str,
    live: dict[str, list[str]],
    rejected: dict[str, list[str]],
    resolved: dict[str, list[str]],
) -> str:
    """Return the aggregate state for a hypothesis across all branches.

    Mirrors the precedence used by ``list_investigation_hypotheses``:
    two or more distinct branch-side states -> ``mixed``; otherwise
    rejected > resolved > live in specificity.
    """
    distinct = (
        (1 if live.get(hid) else 0)
        + (1 if rejected.get(hid) else 0)
        + (1 if resolved.get(hid) else 0)
    )
    if distinct >= 2:
        return "mixed"
    if rejected.get(hid):
        return "rejected"
    if resolved.get(hid):
        return "resolved"
    return "live"


def build_evidence_graph_snapshot(
    *,
    investigation_id: str,
    inv_status: str,
    inv_linked_finding_ids_json: str | None,
    branches: list[Any],
    outcomes: list[Any],
    layout: str = "concentric",
) -> EvidenceGraphSnapshot:
    """Assemble a rich evidence-graph snapshot for one investigation.

    Node kinds emitted:

    * ``investigation`` -- one root node at the origin.
    * ``branch`` -- one per ``VRInvestigationBranchRecord`` on the
      inner ring; edge ``investigation --spawned--> branch``.
    * ``hypothesis`` -- one per distinct hypothesis id across all
      branches' ``case_state_json.hypotheses/rejected/resolved``.
      Aggregate state (live | rejected | resolved | mixed) mirrors
      the ``/investigations/{id}/hypotheses`` projection. Edges
      ``branch --raises|rejects|resolves--> hypothesis`` are emitted
      per branch-side state.
    * ``outcome`` -- one per ``VRInvestigationOutcomeRecord`` on the
      outer ring; edge ``branch --produced--> outcome`` (falls back
      to ``investigation --produced--> outcome`` when the outcome
      has no branch_id).
    * ``finding`` -- one per id in the investigation's
      ``linked_finding_ids_json``. Edge ``outcome
      --produced_finding--> finding`` when a dispatched outcome
      references the finding via ``dispatch_target='vr_finding:<id>'``;
      otherwise a fallback ``investigation --linked--> finding``.

    Pure function: takes DB rows and returns the snapshot; testable
    without a live database.
    """
    nodes: list[EvidenceGraphNode] = []
    edges: list[EvidenceGraphEdge] = []

    root_id = f"inv:{investigation_id}"
    nodes.append(
        EvidenceGraphNode(
            id=root_id,
            kind="investigation",
            label=f"Investigation {investigation_id[:8]}",
            state=inv_status,
            x=0.0,
            y=0.0,
        ),
    )

    # --- branches --------------------------------------------------- inner ring
    radius_branch = 220.0
    n_branches = max(len(branches), 1)
    for i, b in enumerate(branches):
        if layout == "grid":
            x = (i % 4) * 200 - 300
            y = 200.0
        else:
            angle = (2 * math.pi * i / n_branches) - math.pi / 2
            x = radius_branch * math.cos(angle)
            y = radius_branch * math.sin(angle)
        bid = f"branch:{b.id}"
        nodes.append(
            EvidenceGraphNode(
                id=bid,
                kind="branch",
                label=f"branch \u00b7 {b.status}",
                state=b.status,
                x=x,
                y=y,
                attributes={
                    "persona_voice": getattr(b, "persona_voice", "") or "",
                    "strategy_family": getattr(b, "strategy_family", "") or "",
                    "promoted": bool(getattr(b, "promoted", False)),
                },
            ),
        )
        edges.append(
            EvidenceGraphEdge(
                source=root_id,
                target=bid,
                kind="spawned",
            ),
        )

    # --- hypotheses ---------------------------------------- mid ring (new)
    # Aggregate hypothesis id -> branch id lists across live / rejected /
    # resolved partitions so a single hypothesis node collapses siblings.
    live_branches: dict[str, list[str]] = {}
    rejected_branches: dict[str, list[str]] = {}
    resolved_branches: dict[str, list[str]] = {}
    claims: dict[str, str] = {}
    why_plausible: dict[str, str] = {}
    reasons: dict[str, str] = {}

    for b in branches:
        state = _parse_case_state(getattr(b, "case_state_json", "") or "")
        for h in state.get("hypotheses", []) or []:
            if not isinstance(h, dict):
                continue
            hid = h.get("id")
            if not hid:
                continue
            live_branches.setdefault(str(hid), []).append(b.id)
            claims.setdefault(str(hid), str(h.get("claim") or ""))
            if h.get("why_plausible"):
                why_plausible.setdefault(str(hid), str(h.get("why_plausible")))
        for h in state.get("rejected", []) or []:
            if not isinstance(h, dict):
                continue
            hid = h.get("id")
            if not hid:
                continue
            rejected_branches.setdefault(str(hid), []).append(b.id)
            claims.setdefault(str(hid), str(h.get("claim") or ""))
            # RejectedHypothesis carries the disproof rationale in ``reason``;
            # it is the "rejected because of these calls" text the operator
            # wants surfaced on the node and matched against tool readings.
            if h.get("reason"):
                reasons.setdefault(str(hid), str(h.get("reason")))
        for h in state.get("resolved", []) or []:
            if not isinstance(h, dict):
                continue
            hid = h.get("id")
            if not hid:
                continue
            resolved_branches.setdefault(str(hid), []).append(b.id)
            claims.setdefault(str(hid), str(h.get("claim") or ""))

    hyp_ids = sorted(
        set(live_branches) | set(rejected_branches) | set(resolved_branches),
    )
    radius_hyp = 310.0
    n_hyp = max(len(hyp_ids), 1)
    for i, hid in enumerate(hyp_ids):
        hstate = _hypothesis_state(
            hid, live_branches, rejected_branches, resolved_branches,
        )
        # Offset by half a slot so hypothesis rays don't collide with
        # branch rays in the concentric layout.
        angle = (2 * math.pi * i / n_hyp) - math.pi / 2 + math.pi / n_hyp
        if layout == "grid":
            x = (i % 6) * 180 - 450
            y = 320.0
        else:
            x = radius_hyp * math.cos(angle)
            y = radius_hyp * math.sin(angle)
        node_id = f"hypothesis:{hid}"
        first_line = (claims.get(hid) or "").strip().splitlines()
        claim_snip = first_line[0][:80] if first_line else ""
        label = f"{hid}: {claim_snip}" if claim_snip else str(hid)
        nodes.append(
            EvidenceGraphNode(
                id=node_id,
                kind="hypothesis",
                label=label,
                state=hstate,
                x=x,
                y=y,
                attributes={
                    "live_in_branches": list(live_branches.get(hid, [])),
                    "rejected_in_branches": list(rejected_branches.get(hid, [])),
                    "resolved_in_branches": list(resolved_branches.get(hid, [])),
                    "claim": claims.get(hid, ""),
                    "why_plausible": why_plausible.get(hid, ""),
                    "rejection_reason": reasons.get(hid, ""),
                },
            ),
        )
        for src_bid in live_branches.get(hid, []):
            edges.append(EvidenceGraphEdge(
                source=f"branch:{src_bid}", target=node_id, kind="raises",
            ))
        for src_bid in rejected_branches.get(hid, []):
            edges.append(EvidenceGraphEdge(
                source=f"branch:{src_bid}", target=node_id, kind="rejects",
            ))
        for src_bid in resolved_branches.get(hid, []):
            edges.append(EvidenceGraphEdge(
                source=f"branch:{src_bid}", target=node_id, kind="resolves",
            ))

    # --- evidence (MCP tool readings) --------------------------- new ring
    # Each branch's case_state.observables holds the MCP tool readings the
    # personas gathered, keyed "<server>.<tool>.<selector>.<target>" (e.g.
    # "audit_mcp.read_function.source.ff_hevc_decode_nal_vps"). Agent
    # scratchpad / directive keys start with "_" and are skipped. Dedupe by
    # key so one reading collapses across branches; attribute which
    # branches (personas) observed it via a ``found_by`` edge. A reading is
    # linked to a hypothesis ONLY when the hypothesis text names the
    # reading's target: ``supports`` when a live/resolved claim or
    # why_plausible cites it, ``refutes`` when a rejected hypothesis's
    # reason cites it. No text match leaves the reading as an unlinked
    # evidence node -- we never invent a relation the reasoning did not
    # assert, and we never drop a reading: every tool observation the
    # personas made is surfaced. Any thinning is the display layer's job
    # (visible, operator-controllable), never a silent cap here.
    ev_branches: dict[str, list[str]] = {}
    ev_personas: dict[str, set[str]] = {}
    for b in branches:
        state = _parse_case_state(getattr(b, "case_state_json", "") or "")
        obs = state.get("observables")
        if not isinstance(obs, dict):
            continue
        persona = getattr(b, "persona_voice", "") or ""
        for k in obs:
            if not isinstance(k, str) or k.startswith("_") or "." not in k:
                continue
            ev_branches.setdefault(k, []).append(b.id)
            ev_personas.setdefault(k, set()).add(persona)

    def _parse_ev_key(key: str) -> tuple[str, str, str]:
        """(server, tool, target) from a "server.tool.selector.target" key."""
        parts = key.split(".", 3)
        server = parts[0] if parts else ""
        tool = parts[1] if len(parts) > 1 else ""
        target = parts[3] if len(parts) > 3 else (parts[2] if len(parts) > 2 else "")
        target = target.split("=", 1)[-1]  # semantic_search.query=... -> query
        if "/" in target and ":" in target:  # path:line-range -> path
            target = target.split(":", 1)[0]
        return server, tool, target.strip()

    ev_keys = sorted(ev_branches)
    radius_ev = 470.0
    n_ev = max(len(ev_keys), 1)
    for i, key in enumerate(ev_keys):
        server, tool, target = _parse_ev_key(key)
        if layout == "grid":
            x = (i % 6) * 180 - 450
            y = 560.0
        else:
            angle = (2 * math.pi * i / n_ev) - math.pi / 2 + math.pi / (2 * n_ev)
            x = radius_ev * math.cos(angle)
            y = radius_ev * math.sin(angle)
        node_id = f"evidence:{key}"
        base = target.rsplit("/", 1)[-1]
        label = (f"{tool}: {base}" if tool else base)[:80] or key[:80]
        obs_bids = list(dict.fromkeys(ev_branches.get(key, [])))
        nodes.append(
            EvidenceGraphNode(
                id=node_id,
                kind="evidence",
                label=label,
                state="",
                x=x,
                y=y,
                attributes={
                    "server": server,
                    "tool": tool,
                    "target": target,
                    # The full, untruncated tool output is fetched on click
                    # via GET /investigations/{id}/observable?key=... -- the
                    # snapshot carries only the key, never a preview, so the
                    # graph payload stays lean and no output is pre-trimmed.
                    "observable_key": key,
                    "observed_by_branches": obs_bids,
                    "personas": sorted(p for p in ev_personas.get(key, set()) if p),
                },
            ),
        )
        # Attribution: which branch(es) made this MCP call.
        for bid in obs_bids:
            edges.append(EvidenceGraphEdge(
                source=node_id, target=f"branch:{bid}", kind="found_by",
            ))
        # Honest linkage: match the reading's target token against the
        # hypothesis's own text. Candidate tokens = full target + basename
        # (>=5 chars each to drop noise like "ps.c").
        cands = {target.lower()}
        if "/" in target:
            cands.add(target.rsplit("/", 1)[-1].lower())
        cands = {c for c in cands if len(c) >= 5}
        if cands:
            for hid in hyp_ids:
                if live_branches.get(hid) or resolved_branches.get(hid):
                    blob = (claims.get(hid, "") + " " + why_plausible.get(hid, "")).lower()
                    if any(c in blob for c in cands):
                        edges.append(EvidenceGraphEdge(
                            source=node_id, target=f"hypothesis:{hid}",
                            kind="supports",
                        ))
                if rejected_branches.get(hid):
                    rblob = reasons.get(hid, "").lower()
                    if any(c in rblob for c in cands):
                        edges.append(EvidenceGraphEdge(
                            source=node_id, target=f"hypothesis:{hid}",
                            kind="refutes",
                        ))

    # --- outcomes --------------------------------------------------- outer ring
    radius_outcome = 400.0
    n_outcomes = max(len(outcomes), 1)
    outcome_finding_to_node: dict[str, str] = {}
    for i, o in enumerate(outcomes):
        if layout == "grid":
            x = (i % 4) * 200 - 300
            y = 440.0
        elif layout == "radial":
            angle = (2 * math.pi * i / n_outcomes) - math.pi / 2
            x = radius_outcome * math.cos(angle)
            y = radius_outcome * math.sin(angle)
        else:
            angle = (2 * math.pi * i / n_outcomes) + math.pi / 6
            x = radius_outcome * math.cos(angle)
            y = radius_outcome * math.sin(angle)
        oid = f"outcome:{o.id}"
        nodes.append(
            EvidenceGraphNode(
                id=oid,
                kind="outcome",
                label=str(getattr(o, "outcome_kind", "")),
                state=str(getattr(o, "dispatch_status", "")),
                x=x,
                y=y,
                attributes={
                    "confidence": getattr(o, "confidence", None),
                    "branch_id": getattr(o, "branch_id", None),
                    "dispatch_target": getattr(o, "dispatch_target", None),
                },
            ),
        )
        b_id = getattr(o, "branch_id", None)
        source_id = f"branch:{b_id}" if b_id else root_id
        edges.append(
            EvidenceGraphEdge(source=source_id, target=oid, kind="produced"),
        )
        dt = getattr(o, "dispatch_target", None) or ""
        if isinstance(dt, str) and dt.startswith("vr_finding:"):
            outcome_finding_to_node[dt.removeprefix("vr_finding:")] = oid

    # --- findings ----------------------------------------- outermost ring (new)
    finding_ids = _parse_id_list(inv_linked_finding_ids_json)
    radius_finding = 520.0
    n_findings = max(len(finding_ids), 1)
    for i, fid in enumerate(finding_ids):
        if layout == "grid":
            x = (i % 4) * 200 - 300
            y = 580.0
        else:
            angle = (2 * math.pi * i / n_findings) - math.pi / 2 + math.pi / (2 * n_findings)
            x = radius_finding * math.cos(angle)
            y = radius_finding * math.sin(angle)
        node_id = f"finding:{fid}"
        nodes.append(
            EvidenceGraphNode(
                id=node_id,
                kind="finding",
                label=f"finding {fid[:8]}",
                state="",
                x=x,
                y=y,
                attributes={"finding_id": fid},
            ),
        )
        upstream_outcome = outcome_finding_to_node.get(fid)
        if upstream_outcome:
            edges.append(EvidenceGraphEdge(
                source=upstream_outcome, target=node_id, kind="produced_finding",
            ))
        else:
            edges.append(EvidenceGraphEdge(
                source=root_id, target=node_id, kind="linked",
            ))

    return EvidenceGraphSnapshot(
        investigation_id=investigation_id,
        layout=layout,
        nodes=nodes,
        edges=edges,
    )
