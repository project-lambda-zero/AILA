import { useMemo, useState } from "react";
import { useParams } from "react-router";

import { AilaBadge } from "@/components/aila/AilaBadge";
import { AilaCard } from "@/components/aila/AilaCard";
import { LoadingSkeleton } from "@/components/aila/LoadingSkeleton";

import {
  EvidenceGraph,
  type GraphEdgeInput,
  type GraphNodeInput,
} from "../components/EvidenceGraph";
import {
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
        label: o.outcome_kind,
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
      <AilaCard className="border-border-danger">
        <p className="text-sm text-text-danger">Investigation not found.</p>
      </AilaCard>
    );
  }

  return (
    <div className="space-y-3">
      <div>
        <h1 className="text-xl font-bold font-mono text-foreground truncate">
          Evidence graph
        </h1>
        <p className="text-xs text-text-muted mt-1 font-mono">
          {inv.title}
        </p>
      </div>

      <AilaCard className="border-dashed">
        <AilaBadge severity="info" size="sm">
          synthesised view
        </AilaBadge>
        <p className="text-[10px] text-text-muted mt-1">
          Spec §1.9 wants a real project-level evidence graph with hypothesis
          + evidence + obligation + crash + exploit + advisory nodes from
          the reasoning engine. Backend graph endpoint is pending — this
          view derives a graph from branches (as hypotheses) + outcomes
          (as evidence / crash / advisory by outcome_kind).
        </p>
      </AilaCard>

      <div className="grid grid-cols-1 lg:grid-cols-[1fr_280px] gap-3">
        <EvidenceGraph
          nodes={nodes}
          edges={edges}
          height={620}
          onNodeClick={setSelected}
        />

        {/* Right rail: selected node detail */}
        <aside className="space-y-2">
          <AilaCard>
            <h3 className="text-xs font-semibold uppercase tracking-wide text-text-muted mb-2">
              Selection
            </h3>
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
                <p className="text-[10px] text-text-muted font-mono break-all">
                  id: {selected.id}
                </p>
                {selected.meta && (
                  <pre className="text-[10px] font-mono text-text-muted whitespace-pre-wrap max-h-60 overflow-y-auto">
                    {JSON.stringify(selected.meta, null, 2)}
                  </pre>
                )}
              </div>
            ) : (
              <p className="text-xs text-text-muted">
                Click a node to inspect its payload.
              </p>
            )}
          </AilaCard>

          <AilaCard>
            <h3 className="text-xs font-semibold uppercase tracking-wide text-text-muted mb-2">
              Counts
            </h3>
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
            </dl>
          </AilaCard>
        </aside>
      </div>
    </div>
  );
}
