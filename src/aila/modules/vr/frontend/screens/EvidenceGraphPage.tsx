import { useMemo, useState } from "react";
import { useParams } from "react-router";

import { AilaBadge } from "@/components/aila/AilaBadge";
import { AilaCard } from "@/components/aila/AilaCard";
import { WindowPanel } from "@/components/aila/WindowPanel";
import { LoadingSkeleton } from "@/components/aila/LoadingSkeleton";

import { outcomeKindLabel } from "../components/OutcomeKindBadge";
import {
  EvidenceGraph,
  type GraphEdgeInput,
  type GraphNodeInput,
} from "../components/EvidenceGraph";
import { PanelBoundary } from "../components/PanelBoundary";
import {
  useEvidenceGraph,
  useInvestigation,
  useInvestigationBranches,
  useInvestigationOutcomes,
  useObservable,
} from "../queries";
import { formatBranchDisplayName } from "../branchDisplay";

/** EvidenceGraphPage -- 08_FRONTEND_UX.md \u00a71.9.
 *
 *  Data model: the backend `/investigations/{id}/evidence-graph`
 *  endpoint is authoritative -- it walks each branch's
 *  `case_state_json` to surface the actual hypothesis vocabulary
 *  (h1, h2, ...) plus branches, outcomes, and linked findings, all
 *  with server-computed x/y positions. This page renders the
 *  snapshot nodes+edges directly (issue #17 -- prior implementation
 *  only rendered a persona map derived from branch/outcome rows and
 *  never surfaced the hypothesis content that lives inside branch
 *  state, so the graph carried no reasoning information).
 *
 *  A minimal client-side synthesis is retained as a fallback when the
 *  server snapshot is unavailable (offline, error, or a still-empty
 *  investigation): investigation root + one node per branch + one
 *  node per outcome. It stays intentionally simple; the server is
 *  where the real assembly logic lives. */
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

  // When an evidence node is selected, load its full, untruncated tool
  // output on demand (the snapshot carries only the observable key).
  const selectedObservableKey =
    selected?.kind === "evidence"
      ? (((selected.meta as Record<string, unknown> | undefined)
          ?.observable_key as string | undefined) ?? null)
      : null;
  const { data: observableResult, isLoading: observableLoading } =
    useObservable(investigationId, selectedObservableKey);

  // Preferred data path: use the server snapshot's nodes and edges
  // directly. Fall back to a local synthesis (branches + outcomes
  // only, minus hypotheses) if the endpoint is unavailable so the
  // page still shows something and the selection panel still works.
  const { nodes, edges, serverPositions } = useMemo(() => {
    const snap = snapshotResult?.data;
    if (snap && snap.nodes.length > 0) {
      const branchById = new Map(branches.map((b) => [b.id, b] as const));
      const outcomeById = new Map(outcomes.map((o) => [o.id, o] as const));
      const ns: GraphNodeInput[] = snap.nodes.map((n) => {
        // Meta hydration: for branch/outcome nodes attach the full
        // summary row so openUrlForNode + the selection panel still
        // work. Hypotheses / findings / investigation carry their
        // server attributes verbatim.
        let meta: Record<string, unknown> | undefined;
        if (n.kind === "branch") {
          const bid = n.id.replace(/^branch:/, "");
          const b = branchById.get(bid);
          meta = { ...(n.attributes ?? {}), ...(b ? { branch: b } : {}) };
        } else if (n.kind === "outcome") {
          const oid = n.id.replace(/^outcome:/, "");
          const o = outcomeById.get(oid);
          if (o) {
            meta = { ...(n.attributes ?? {}), outcome: o, humanLabel: outcomeKindLabel(o.outcome_kind) };
          } else {
            meta = { ...(n.attributes ?? {}) };
          }
        } else {
          meta = { ...(n.attributes ?? {}) };
        }
        return {
          id: n.id,
          kind: n.kind as GraphNodeInput["kind"],
          label:
            n.kind === "branch"
              ? branchById.get(n.id.replace(/^branch:/, ""))
                ? `${formatBranchDisplayName(branchById.get(n.id.replace(/^branch:/, ""))!)}`
                : n.label
              : n.kind === "outcome"
                ? outcomeById.get(n.id.replace(/^outcome:/, ""))
                  ? outcomeKindLabel(outcomeById.get(n.id.replace(/^outcome:/, ""))!.outcome_kind)
                  : n.label
                : n.label,
          state: n.state || undefined,
          meta,
        };
      });
      const es: GraphEdgeInput[] = snap.edges.map((e, i) => ({
        id: `e${i}-${e.source}-${e.target}-${e.kind}`,
        source: e.source,
        target: e.target,
        kind: e.kind as GraphEdgeInput["kind"],
      }));
      const positions = new Map<string, { x: number; y: number }>();
      for (const n of snap.nodes) positions.set(n.id, { x: n.x, y: n.y });
      return { nodes: ns, edges: es, serverPositions: positions };
    }

    // Fallback synthesis when snapshot is unavailable. Deliberately
    // minimal -- just enough for the page to render something useful.
    const ns: GraphNodeInput[] = [];
    const es: GraphEdgeInput[] = [];
    for (const b of branches) {
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
        label: `${formatBranchDisplayName(b)}${b.fork_at_turn != null ? ` @t${b.fork_at_turn}` : ""}`,
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
        kind: "supports",
      });
    }
    return { nodes: ns, edges: es, serverPositions: new Map() };
  }, [snapshotResult, branches, outcomes]);

  if (isLoading) return <LoadingSkeleton size="lg" width="full" />;
  if (!inv) {
    return (
      <AilaCard className="border-critical" techBorder glow><p className="text-sm text-critical">Investigation not found.</p></AilaCard>
    );
  }

  return (
    <div className="space-y-3">
      {/* sr-only section heading bridges PageShell h1 → rail card h3s for screen readers. */}
      <h2 className="sr-only">Evidence graph</h2>

      <ServerSnapshotStatus investigationId={investigationId} />


      <div className="grid grid-cols-1 lg:grid-cols-rail gap-3">
        <PanelBoundary
          label="Evidence graph"
          invalidateKeyPrefix={["vr", "evidence-graph", investigationId]}
        >
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
        </PanelBoundary>

        {/* Right rail: selected node detail */}
        <aside className="space-y-2">
          <WindowPanel title="selection" tone="muted">
          <h2 className="sr-only">Selection</h2>
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
              {selected.kind === "evidence" && selectedObservableKey && (
                <div className="mt-1">
                  <p className="text-3xs uppercase tracking-wide text-text-muted mb-1">
                    full tool output
                  </p>
                  {observableLoading ? (
                    <p className="text-3xs text-text-muted">loading...</p>
                  ) : observableResult?.data ? (
                    <pre className="text-3xs font-mono text-foreground whitespace-pre-wrap max-h-96 overflow-y-auto border border-border rounded p-2 bg-surface/40">
                      {typeof observableResult.data.value === "string"
                        ? observableResult.data.value
                        : JSON.stringify(observableResult.data.value, null, 2)}
                    </pre>
                  ) : (
                    <p className="text-3xs text-text-muted">
                      no output found for this reading
                    </p>
                  )}
                </div>
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
                <div className="mt-2 border border-dashed border-border rounded p-2 bg-surface/40">
                  <AilaBadge severity="info" size="sm">operator-only</AilaBadge>
                  <p className="text-3xs text-text-muted mt-1">
                    "Manually close" -- backend pending.
                  </p>
                </div>
              )}
            </div>
          ) : (
            <p className="text-xs text-text-muted">
              Click a node to inspect its payload.
            </p>
          )}</WindowPanel>

          <WindowPanel title="counts" tone="muted">
          <h2 className="sr-only">Counts</h2>
          <dl className="text-xs grid grid-cols-2 gap-1 font-mono">
            <dt className="text-text-muted">branches</dt>
            <dd className="text-foreground text-right">
              {nodes.filter((n) => n.kind === "branch").length}
            </dd>
            <dt className="text-text-muted">hypotheses</dt>
            <dd className="text-foreground text-right">
              {nodes.filter((n) => n.kind === "hypothesis").length}
            </dd>
            <dt className="text-text-muted">outcomes</dt>
            <dd className="text-foreground text-right">
              {nodes.filter((n) => n.kind === "outcome").length}
            </dd>
            <dt className="text-text-muted">findings</dt>
            <dd className="text-foreground text-right">
              {nodes.filter((n) => n.kind === "finding").length}
            </dd>
            <dt className="text-text-muted">crashes</dt>
            <dd className="text-foreground text-right">
              {nodes.filter((n) => n.kind === "crash").length}
            </dd>
            <dt className="text-text-muted">advisories</dt>
            <dd className="text-foreground text-right">
              {nodes.filter((n) => n.kind === "advisory").length}
            </dd>
            <dt className="text-text-muted">obligations</dt>
            <dd className="text-foreground text-right">
              {nodes.filter((n) => n.kind === "obligation").length}
            </dd>
          </dl></WindowPanel>
        </aside>
      </div>
    </div>
  );
}

/** Per-node-kind navigation target for Cmd-click (08_FRONTEND_UX.md \u00a73.6).
 *  Server snapshot nodes carry meta with the source row (branch /
 *  outcome) so we navigate accordingly. */
function openUrlForNode(node: GraphNodeInput): string | null {
  const meta = node.meta as Record<string, unknown> | undefined;
  if (node.kind === "branch") {
    const branch = meta?.branch as { investigation_id?: string; id?: string } | undefined;
    if (branch?.investigation_id) {
      return `/vr/investigations/${branch.investigation_id}/tree`;
    }
  }
  if (node.kind === "hypothesis") {
    // Deep-link to the branch tree so operators can inspect the
    // hypothesis in the case-state timeline. When the hypothesis is
    // live/rejected/resolved on a specific branch, hop through it.
    const branch = meta?.branch as { investigation_id?: string } | undefined;
    if (branch?.investigation_id) {
      return `/vr/investigations/${branch.investigation_id}/tree`;
    }
    const liveIn = meta?.live_in_branches as string[] | undefined;
    if (liveIn && liveIn.length > 0) {
      // Hypothesis node id format: `hypothesis:<hid>`; the branch
      // graph is per-investigation and reachable from the surrounding
      // route (`params.investigationId`), but we can't read params
      // here; fall through to null and let the sidebar link stay hidden.
      return null;
    }
  }
  if (node.kind === "outcome") {
    const o = meta?.outcome as { id?: string; outcome_kind?: string } | undefined;
    if (o?.outcome_kind === "crash_triage_report") return `/vr/fuzz/campaigns`;
    if (o?.outcome_kind === "direct_finding" || o?.outcome_kind === "patch_assessment_report") {
      return `/vr/disclosures`;
    }
  }
  if (node.kind === "finding") {
    const fid = (meta?.finding_id as string | undefined) || node.id.replace(/^finding:/, "");
    if (fid) return `/vr/findings/${encodeURIComponent(fid)}`;
  }
  if (node.kind === "crash") {
    const o = meta?.outcome as { id?: string } | undefined;
    // Outcomes don't carry crash_id directly -- fall back to a generic
    // fuzz crashes list; once a crash \u2192 outcome mapping ships, this
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
 *  (08_FRONTEND_UX.md \u00a71.9). The server is authoritative for BOTH
 *  content (branches, hypotheses, outcomes, findings, edges) and
 *  layout coordinates. The local synthesis fallback (branches +
 *  outcomes only) kicks in when the endpoint is unavailable. */
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
            ? "server snapshot unavailable -- using local fallback"
            : isLoading
              ? "loading server snapshot\u2026"
              : "server snapshot in use"}
        </AilaBadge>
        {data && (
          <span className="text-3xs text-text-muted ml-2 font-mono">
            layout={data.data.layout} \u00b7 {data.data.nodes.length} nodes \u00b7{" "}
            {data.data.edges.length} edges
          </span>
        )}
      </div>
      <p className="text-3xs text-text-muted">
        Content and coordinates both come from the backend so the
        graph reads the same across operators + sessions. The local
        fallback shows branches and outcomes only.
      </p>
    </div></AilaCard>
  );
}
