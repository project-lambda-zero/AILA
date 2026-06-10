import { useMemo, useState } from "react";
import { useParams } from "react-router";

import { AilaBadge } from "@/components/aila/AilaBadge";
import { AilaCard } from "@/components/aila/AilaCard";
import { LoadingSkeleton } from "@/components/aila/LoadingSkeleton";

import { outcomeKindLabel } from "../components/OutcomeKindBadge";
import {
  EvidenceGraph,
  type GraphEdgeInput,
  type GraphNodeInput,
} from "../components/EvidenceGraph";
import {
  useEvidenceGraph,
  useInvestigation,
  useInvestigationBranches,
  useInvestigationOutcomes,
} from "../queries";

/** EvidenceGraphPage — 08_FRONTEND_UX.md §1.9.
 *
 *  Backend has no project-evidence-graph endpoint yet, so we synthesise
 *  a graph from existing investigation data:
 *
 *    Branches  → hypothesis nodes (state = branch.status)
 *    Outcomes  → evidence | advisory nodes (kind by outcome_kind)
 *    Branches' parent_branch_id → derived_from edges
 *    Outcomes' branch_id → supports/refutes edges
 *
 *  Once the backend ships a real graph (with proper crash + exploit
 *  + obligation nodes from §1.9), this page swaps the data source. */
export function EvidenceGraphPage() {
  const { investigationId = "" } = useParams<{ investigationId: string }>();
  const { data: inv, isLoading } = useInvestigation(investigationId);
  const { data: branchesResult } = useInvestigationBranches(investigationId);
  const { data: outcomesResult } = useInvestigationOutcomes(investigationId);
  const [selected, setSelected] = useState<GraphNodeInput | null>(null);

  const branches = useMemo(
    () => branchesResult?.data ?? [],
    [branchesResult],
  );
  const outcomes = useMemo(
    () => outcomesResult?.data ?? [],
    [outcomesResult],
  );
  const { data: snapshotResult } = useEvidenceGraph(investigationId);
  // Map server node id (`branch:xxx` / `outcome:xxx` / `inv:xxx`) onto
  // the client node id space (`branch-xxx` / `outcome-xxx`). Keep
  // both keys so either id format resolves.
  const serverPositions = useMemo(() => {
    const m = new Map<string, { x: number; y: number }>();
    const snap = snapshotResult?.data;
    if (!snap) return m;
    for (const n of snap.nodes) {
      m.set(n.id, { x: n.x, y: n.y });
      // colon → dash translation for the client synthesis id space
      m.set(n.id.replace(":", "-"), { x: n.x, y: n.y });
    }
    return m;
  }, [snapshotResult]);


  const { nodes, edges } = useMemo(() => {
    const ns: GraphNodeInput[] = [];
    const es: GraphEdgeInput[] = [];

    for (const b of branches) {
      // Map branch.status → hypothesis state per the spec vocabulary
      const stateMap: Record<string, string> = {
        active: "open",
        paused: "open",
        merged: "confirmed",
        promoted: "confirmed",
        abandoned: "refuted",
      };
      ns.push({
        id: `branch-${b.id}`,
        kind: "hypothesis",
        label: `${b.persona_voice ?? "branch"}${b.fork_at_turn != null ? ` @t${b.fork_at_turn}` : ""}`,
        state: stateMap[b.status] ?? "open",
        meta: { branch: b },
      });
      if (b.parent_branch_id) {
        es.push({
          id: `e-${b.id}-parent`,
          source: `branch-${b.parent_branch_id}`,
          target: `branch-${b.id}`,
          kind: "derived_from",
        });
      }
    }

    for (const o of outcomes) {
      const kind =
        o.outcome_kind === "patch_assessment_report" ||
        o.outcome_kind === "direct_finding" ||
        o.outcome_kind === "audit_memo"
          ? "advisory"
          : o.outcome_kind === "crash_triage_report"
            ? "crash"
            : "evidence";
      ns.push({
        id: `outcome-${o.id}`,
        kind: kind as "advisory" | "crash" | "evidence",
        label: outcomeKindLabel(o.outcome_kind),
        state: o.dispatch_status,
        meta: { outcome: o },
      });
      es.push({
        id: `e-${o.id}-branch`,
        source: `outcome-${o.id}`,
        target: `branch-${o.branch_id}`,
        kind: o.confidence === "exact" || o.confidence === "strong" ? "supports" : "supports",
      });
    }

    return { nodes: ns, edges: es };
  }, [branches, outcomes]);

  if (isLoading) return <LoadingSkeleton size="lg" width="full" />;
  if (!inv) {
    return (
      <AilaCard className="border-border-danger" techBorder glow><p className="text-sm text-text-danger">Investigation not found.</p></AilaCard>
    );
  }

  return (
    <div className="space-y-3">
      {/* sr-only section heading bridges PageShell h1 → rail card h3s for screen readers. */}
      <h2 className="sr-only">Evidence graph</h2>

      <ServerSnapshotStatus investigationId={investigationId} />


      <div className="grid grid-cols-1 lg:grid-cols-rail gap-3">
        <EvidenceGraph
          nodes={nodes}
          edges={edges}
          serverPositions={serverPositions}
          height={620}
          onNodeClick={(node, event) => {
            // Cmd/Ctrl-click → open the node's dedicated page in a new
            // tab per §3.6 / §1.9. Each node kind has its own target URL.
            if (event.metaKey || event.ctrlKey) {
              const url = openUrlForNode(node);
              if (url) window.open(url, "_blank", "noopener");
              return;
            }
            setSelected(node);
          }}
        />

        {/* Right rail: selected node detail */}
        <aside className="space-y-2">
          <AilaCard  techBorder glow><h2 className="text-xs font-semibold uppercase tracking-wide text-text-muted mb-2">
            Selection
          </h2>
          {selected ? (
            <div className="text-xs space-y-2">
              <div className="flex items-center gap-1 flex-wrap">
                <AilaBadge severity="info" size="sm">
                  {selected.kind}
                </AilaBadge>
                {selected.state && (
                  <AilaBadge severity="info" size="sm">
                    {selected.state}
                  </AilaBadge>
                )}
              </div>
              <p className="font-mono text-foreground break-all">
                {selected.label}
              </p>
              <p className="text-3xs text-text-muted font-mono break-all">
                id: {selected.id}
              </p>
              {selected.meta && (
                <pre className="text-3xs font-mono text-text-muted whitespace-pre-wrap max-h-60 overflow-y-auto">
                  {JSON.stringify(selected.meta, null, 2)}
                </pre>
              )}
              {(() => {
                const url = openUrlForNode(selected);
                if (!url) return null;
                return (
                  <a
                    href={url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-3xs text-accent hover:underline mt-1 inline-block"
                  >
                    open {selected.kind} page in new tab →
                  </a>
                );
              })()}
              {selected.kind === "obligation" && (
                <div className="mt-2 border border-dashed border-border-default rounded p-2 bg-surface/40">
                  <AilaBadge severity="info" size="sm">operator-only</AilaBadge>
                  <p className="text-3xs text-text-muted mt-1">
                    "Manually close" — backend pending.
                  </p>
                </div>
              )}
            </div>
          ) : (
            <p className="text-xs text-text-muted">
              Click a node to inspect its payload.
            </p>
          )}</AilaCard>

          <AilaCard  techBorder glow><h2 className="text-xs font-semibold uppercase tracking-wide text-text-muted mb-2">
            Counts
          </h2>
          <dl className="text-xs grid grid-cols-2 gap-1 font-mono">
            <dt className="text-text-muted">hypotheses</dt>
            <dd className="text-foreground text-right">
              {nodes.filter((n) => n.kind === "hypothesis").length}
            </dd>
            <dt className="text-text-muted">evidence</dt>
            <dd className="text-foreground text-right">
              {nodes.filter((n) => n.kind === "evidence").length}
            </dd>
            <dt className="text-text-muted">crashes</dt>
            <dd className="text-foreground text-right">
              {nodes.filter((n) => n.kind === "crash").length}
            </dd>
            <dt className="text-text-muted">exploits</dt>
            <dd className="text-foreground text-right">
              {nodes.filter((n) => n.kind === "exploit").length}
            </dd>
            <dt className="text-text-muted">advisories</dt>
            <dd className="text-foreground text-right">
              {nodes.filter((n) => n.kind === "advisory").length}
            </dd>
            <dt className="text-text-muted">obligations</dt>
            <dd className="text-foreground text-right">
              {nodes.filter((n) => n.kind === "obligation").length}
            </dd>
          </dl></AilaCard>
        </aside>
      </div>
    </div>
  );
}

/** Per-node-kind navigation target for Cmd-click (08_FRONTEND_UX.md §3.6).
 *  Synthesised graph: nodes carry meta with the source row (branch /
 *  outcome) so we navigate accordingly. */
function openUrlForNode(node: GraphNodeInput): string | null {
  const meta = node.meta as Record<string, unknown> | undefined;
  if (node.kind === "hypothesis") {
    const branch = meta?.branch as { investigation_id?: string } | undefined;
    if (branch?.investigation_id) {
      return `/vr/investigations/${branch.investigation_id}/tree`;
    }
  }
  if (node.kind === "crash") {
    const o = meta?.outcome as { id?: string } | undefined;
    // Outcomes don't carry crash_id directly — fall back to a generic
    // fuzz crashes list; once a crash → outcome mapping ships, this
    // resolves to /vr/fuzz/crashes/:id.
    if (o?.id) return `/vr/fuzz/campaigns`;
  }
  if (node.kind === "advisory") {
    const o = meta?.outcome as { id?: string } | undefined;
    if (o?.id) return `/vr/disclosures`;
  }
  if (node.kind === "exploit") {
    return `/vr/fuzz/campaigns`;
  }
  return null;
}

/** Status card surfacing the backend evidence-graph endpoint
 *  (08_FRONTEND_UX.md §1.9). When the snapshot is present the
 *  EvidenceGraph below uses the server-computed x/y positions
 *  directly — the client-side concentric/grid/radial layouts only
 *  apply when the snapshot is unavailable. */
function ServerSnapshotStatus({
  investigationId,
}: {
  investigationId: string;
}) {
  const { data, isLoading, error } = useEvidenceGraph(investigationId);
  const ready = !!data && !error;
  return (
    <AilaCard className="border-dashed" techBorder glow><div className="flex items-center justify-between gap-2 flex-wrap">
      <div>
        <AilaBadge severity={error ? "high" : ready ? "low" : "info"} size="sm">
          {error
            ? "server snapshot unavailable — using client layout"
            : isLoading
              ? "loading server snapshot…"
              : "server layout in use"}
        </AilaBadge>
        {data && (
          <span className="text-3xs text-text-muted ml-2 font-mono">
            layout={data.data.layout} · {data.data.nodes.length} nodes ·{" "}
            {data.data.edges.length} edges
          </span>
        )}
      </div>
      <p className="text-3xs text-text-muted">
        Coordinates come from the backend so they stay stable across
        operators + sessions. The picker below only matters when the
        backend snapshot isn't available.
      </p>
    </div></AilaCard>
  );
}
