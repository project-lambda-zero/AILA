import { useMemo, useState, type ReactNode } from "react";
import { useParams } from "react-router";

import { WindowPanel } from "@/components/aila/WindowPanel";
import { LoadingSkeleton } from "@/components/aila/LoadingSkeleton";
import { SectionHeader, MonoBadge } from "@/components/aila/mock";

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

  if (isLoading) {
    return (
      <div className="flex flex-col" style={{ gap: 14 }}>
        <SectionHeader icon="\u25c8" title="Evidence graph" />
        <div style={{ padding: 12 }}>
          <LoadingSkeleton size="lg" width="full" />
        </div>
      </div>
    );
  }
  if (!inv) {
    return (
      <div className="flex flex-col" style={{ gap: 14 }}>
        <SectionHeader icon="\u25c8" title="Evidence graph" />
        <WindowPanel title="not found" tone="accent">
          <p
            className="font-mono"
            style={{
              padding: 34,
              textAlign: "center",
              fontSize: 11.5,
              letterSpacing: "0.04em",
              color: "var(--accent)",
            }}
          >
            investigation not found.
          </p>
        </WindowPanel>
      </div>
    );
  }

  return (
    <div className="flex flex-col" style={{ gap: 14 }}>
      {/* sr-only section heading bridges PageShell h1 → rail card h3s for screen readers. */}
      <h2 className="sr-only">Evidence graph</h2>
      <SectionHeader icon="\u25c8" title="Evidence graph" />

      <div className="grid grid-cols-1 lg:grid-cols-rail gap-3">
        <PanelBoundary
          label="Evidence graph"
          invalidateKeyPrefix={["vr", "evidence-graph", investigationId]}
        >
          <WindowPanel title="evidence graph" tone="accent" flush>
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
          </WindowPanel>
        </PanelBoundary>

        {/* Right rail: snapshot status + selection brief + counts */}
        <aside className="flex flex-col" style={{ gap: 8 }}>
          <ServerSnapshotStatus investigationId={investigationId} />

          <WindowPanel title="selection" tone="muted">
            <h3 className="sr-only">Selection</h3>
            {selected ? (
              <div className="flex flex-col" style={{ gap: 2 }}>
                <BriefRow label="kind">
                  <MonoBadge tone="info">{selected.kind}</MonoBadge>
                </BriefRow>
                {selected.state ? (
                  <BriefRow label="state">
                    <MonoBadge tone="ok">{selected.state}</MonoBadge>
                  </BriefRow>
                ) : null}
                <BriefRow label="target">
                  <span
                    className="font-mono"
                    style={{ overflowWrap: "anywhere" }}
                  >
                    {selected.label}
                  </span>
                </BriefRow>
                <BriefRow label="id">
                  <span
                    className="font-mono"
                    style={{
                      fontSize: 10,
                      color: "var(--text-muted)",
                      overflowWrap: "anywhere",
                    }}
                  >
                    {selected.id}
                  </span>
                </BriefRow>
                {selected.meta ? (
                  <BriefRow label="meta">
                    <pre
                      className="font-mono"
                      style={{
                        margin: 0,
                        padding: 8,
                        fontSize: 9.5,
                        lineHeight: 1.5,
                        color: "var(--text-muted)",
                        background: "var(--surface-sunk)",
                        border: "1px solid var(--border-soft)",
                        borderRadius: 3,
                        maxHeight: 220,
                        overflow: "auto",
                        whiteSpace: "pre-wrap",
                        overflowWrap: "anywhere",
                      }}
                    >
                      {JSON.stringify(selected.meta, null, 2)}
                    </pre>
                  </BriefRow>
                ) : null}
                {selected.kind === "evidence" && selectedObservableKey ? (
                  <BriefRow label="full tool output">
                    {observableLoading ? (
                      <span
                        className="font-mono"
                        style={{
                          fontSize: 10,
                          color: "var(--text-muted)",
                          letterSpacing: "0.04em",
                        }}
                      >
                        loading\u2026
                      </span>
                    ) : observableResult?.data ? (
                      <pre
                        className="font-mono"
                        style={{
                          margin: 0,
                          padding: 8,
                          fontSize: 10,
                          lineHeight: 1.5,
                          color: "var(--text-primary)",
                          background: "var(--surface-sunk)",
                          border: "1px solid var(--border-soft)",
                          borderRadius: 3,
                          maxHeight: 320,
                          overflow: "auto",
                          whiteSpace: "pre-wrap",
                          overflowWrap: "anywhere",
                        }}
                      >
                        {typeof observableResult.data.value === "string"
                          ? observableResult.data.value
                          : JSON.stringify(observableResult.data.value, null, 2)}
                      </pre>
                    ) : (
                      <span
                        className="font-mono"
                        style={{
                          fontSize: 10,
                          color: "var(--text-muted)",
                          letterSpacing: "0.04em",
                        }}
                      >
                        no output found for this reading.
                      </span>
                    )}
                  </BriefRow>
                ) : null}
                {(() => {
                  const url = openUrlForNode(selected);
                  if (!url) return null;
                  return (
                    <a
                      href={url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="font-mono uppercase"
                      style={{
                        marginTop: 8,
                        fontSize: 10,
                        letterSpacing: "0.08em",
                        color: "var(--accent)",
                      }}
                    >
                      open {selected.kind} page in new tab \u2192
                    </a>
                  );
                })()}
                {selected.kind === "obligation" ? (
                  <div
                    style={{
                      marginTop: 10,
                      padding: 10,
                      border: "1px dashed var(--border-soft)",
                      borderRadius: 3,
                      background: "var(--surface-sunk)",
                      display: "flex",
                      flexDirection: "column",
                      gap: 6,
                    }}
                  >
                    <MonoBadge tone="info">operator-only</MonoBadge>
                    <p
                      className="font-mono"
                      style={{
                        margin: 0,
                        fontSize: 10,
                        color: "var(--text-muted)",
                        letterSpacing: "0.04em",
                      }}
                    >
                      "manually close" -- backend pending.
                    </p>
                  </div>
                ) : null}
              </div>
            ) : (
              <p
                className="font-mono"
                style={{
                  margin: 0,
                  padding: 12,
                  fontSize: 10.5,
                  color: "var(--text-muted)",
                  letterSpacing: "0.04em",
                }}
              >
                click a node to inspect its payload.
              </p>
            )}
          </WindowPanel>

          <WindowPanel title="counts" tone="muted">
            <h3 className="sr-only">Counts</h3>
            <dl
              className="font-mono"
              style={{
                margin: 0,
                display: "grid",
                gridTemplateColumns: "1fr auto",
                rowGap: 4,
                columnGap: 12,
                fontSize: 10.5,
                letterSpacing: "0.04em",
              }}
            >
              {([
                ["branches", "branch"],
                ["hypotheses", "hypothesis"],
                ["outcomes", "outcome"],
                ["findings", "finding"],
                ["crashes", "crash"],
                ["advisories", "advisory"],
                ["obligations", "obligation"],
              ] as const).map(([label, kind]) => (
                <div key={label} style={{ display: "contents" }}>
                  <dt style={{ color: "var(--text-muted)" }}>{label}</dt>
                  <dd
                    style={{
                      margin: 0,
                      textAlign: "right",
                      color: "var(--text-primary)",
                    }}
                  >
                    {nodes.filter((n) => n.kind === kind).length}
                  </dd>
                </div>
              ))}
            </dl>
          </WindowPanel>
        </aside>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// BriefRow -- uppercase mono label above the mono value, border-bottom rule.
// Matches ProjectDetailPage's brief pattern.
// ---------------------------------------------------------------------------
function BriefRow({
  label,
  children,
}: {
  label: ReactNode;
  children: ReactNode;
}) {
  return (
    <div
      style={{
        display: "flex",
        flexDirection: "column",
        gap: 3,
        padding: "8px 0",
        borderBottom: "1px solid var(--border-faint)",
      }}
    >
      <span
        className="font-mono uppercase"
        style={{
          fontSize: 9,
          letterSpacing: "0.14em",
          color: "var(--text-faint)",
        }}
      >
        {label}
      </span>
      <span
        className="font-mono"
        style={{
          fontSize: 11,
          color: "var(--text-primary)",
          minHeight: 14,
          overflowWrap: "anywhere",
        }}
      >
        {children}
      </span>
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
  const panelTone: "info" | "warn" | "muted" = error
    ? "warn"
    : ready
      ? "info"
      : "muted";
  const badgeTone = error ? "warn" : ready ? "ok" : "info";
  const badgeLabel = error
    ? "unavailable"
    : isLoading
      ? "loading"
      : ready
        ? "ready"
        : "idle";
  const meta = data?.data;
  return (
    <WindowPanel title="snapshot" tone={panelTone}>
      <h3 className="sr-only">Server snapshot status</h3>
      <div className="flex flex-col" style={{ gap: 8 }}>
        <div className="flex items-center" style={{ gap: 6, flexWrap: "wrap" }}>
          <MonoBadge tone={badgeTone}>{badgeLabel}</MonoBadge>
          {meta ? (
            <span
              className="font-mono"
              style={{
                fontSize: 9.5,
                letterSpacing: "0.06em",
                color: "var(--text-faint)",
              }}
            >
              layout={meta.layout} \u00b7 {meta.nodes.length} nodes \u00b7 {meta.edges.length} edges
            </span>
          ) : null}
        </div>
        <p
          className="font-mono"
          style={{
            margin: 0,
            fontSize: 9.5,
            lineHeight: 1.5,
            letterSpacing: "0.04em",
            color: "var(--text-muted)",
          }}
        >
          {error
            ? "server snapshot unavailable -- rendering local fallback (branches + outcomes only)."
            : "content + coordinates come from the backend so the graph reads the same across operators and sessions."}
        </p>
      </div>
    </WindowPanel>
  );
}
