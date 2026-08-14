import { useMemo } from "react";
import { Link } from "react-router";
import { GitBranch } from "@phosphor-icons/react/dist/csr/GitBranch";
import { FolderOpen } from "@phosphor-icons/react/dist/csr/FolderOpen";
import { CaretRight } from "@phosphor-icons/react/dist/csr/CaretRight";

import { AilaBadge } from "@/components/aila/AilaBadge";
import { AilaCard } from "@/components/aila/AilaCard";

import {
  useForensicsProject,
  useProjectInvestigations,
} from "../queries";
import type { AgentStep, InvestigationDetail, InvestigationSummary } from "../types";

interface ConnectedPanelProps {
  projectId: string;
  investigation: InvestigationDetail;
}

const STATUS_SEVERITY: Record<
  string,
  Parameters<typeof AilaBadge>[0]["severity"]
> = {
  created: "info",
  queued: "info",
  running: "medium",
  analyzing: "medium",
  completed: "low",
  failed: "critical",
  exhausted: "high",
  cancelled: "high",
};

/**
 * Walk parent_investigation_id upward through the project's investigation
 * list to build the ancestor chain (oldest first). Bounded to 8 hops so a
 * cycle in the data cannot loop forever.
 */
function computeAncestors(
  current: InvestigationSummary,
  byId: Map<string, InvestigationSummary>,
): InvestigationSummary[] {
  const chain: InvestigationSummary[] = [];
  const seen = new Set<string>([current.id]);
  let cursor = current.parent_investigation_id ?? null;
  let hops = 0;
  while (cursor && !seen.has(cursor) && hops < 8) {
    const parent = byId.get(cursor);
    if (!parent) break;
    chain.unshift(parent);
    seen.add(parent.id);
    cursor = parent.parent_investigation_id ?? null;
    hops += 1;
  }
  return chain;
}

/** Collect unique artifact + investigation ids surfaced by the case model
 *  attached to reasoning steps. Kept strictly to the shape declared by
 *  AgentProvenance / NormalizedArtifact -- no speculative fields. */
function collectStepReferences(steps: AgentStep[]): {
  artifactIds: string[];
  investigationIds: string[];
} {
  const artifacts = new Set<string>();
  const investigations = new Set<string>();
  for (const s of steps) {
    const prov = s.provenance;
    if (prov?.primary_artifact) artifacts.add(prov.primary_artifact);
    for (const a of prov?.corroboration ?? []) {
      if (typeof a === "string" && a) artifacts.add(a);
    }
    // observables is loose Record<string, unknown>; accept a source_investigation_id
    // ONLY when it appears verbatim as a string field (never invent).
    const obs = s.observables ?? null;
    if (obs && typeof obs === "object") {
      const src = (obs as Record<string, unknown>).source_investigation_id;
      if (typeof src === "string" && src) investigations.add(src);
    }
  }
  return {
    artifactIds: Array.from(artifacts),
    investigationIds: Array.from(investigations),
  };
}

interface LineageRowProps {
  projectId: string;
  inv: InvestigationSummary;
  depth: number;
  self: boolean;
}

function LineageRow({ projectId, inv, depth, self }: LineageRowProps) {
  const severity = STATUS_SEVERITY[inv.status] ?? "neutral";
  const label = inv.question.length > 90
    ? `${inv.question.slice(0, 88)}\u2026`
    : inv.question;
  const inner = (
    <div className="flex items-center gap-2 min-w-0">
      <AilaBadge severity={severity} size="sm">
        {inv.status}
      </AilaBadge>
      <span className="text-xs font-mono text-text-muted shrink-0">
        {inv.id.slice(0, 8)}
      </span>
      <span
        className={`text-xs truncate ${self ? "text-foreground font-medium" : "text-foreground"}`}
        title={inv.question}
      >
        {label}
      </span>
      {self && (
        <AilaBadge severity="info" size="sm">
          this
        </AilaBadge>
      )}
    </div>
  );

  return (
    <li
      className="flex items-center gap-1"
      style={{ paddingLeft: `${depth * 1.25}rem` }}
    >
      {depth > 0 && (
        <CaretRight
          className="h-3 w-3 text-text-muted shrink-0"
          aria-hidden="true"
        />
      )}
      {self ? (
        <span className="flex-1 min-w-0">{inner}</span>
      ) : (
        <Link
          to={`/forensics/projects/${projectId}/investigations/${inv.id}`}
          className="flex-1 min-w-0 py-0.5 px-1 rounded hover:bg-surface-secondary focus:outline focus:outline-2 focus:outline-accent"
        >
          {inner}
        </Link>
      )}
    </li>
  );
}

/**
 * ConnectedPanel -- surfaces cross-links carried by the InvestigationDetail
 * contract:
 *
 *   - project           (project_id -> ProjectSummary)
 *   - lineage           (parent_investigation_id ancestor chain +
 *                        direct children where parent_investigation_id === this.id)
 *   - referenced        artifact ids surfaced by AgentProvenance rows on the
 *                        reasoning steps
 *
 * Every link is guarded by the presence of the underlying id in the data.
 * When the investigation has no parent + no children, the lineage section
 * shows a neutral "single attempt" note (no fabricated relationships).
 */
export function ConnectedPanel({ projectId, investigation }: ConnectedPanelProps) {
  const { data: project } = useForensicsProject(projectId);
  const { data: siblings } = useProjectInvestigations(projectId);

  const { ancestors, children, byId } = useMemo(() => {
    const list = siblings ?? [];
    const idx = new Map<string, InvestigationSummary>();
    for (const inv of list) idx.set(inv.id, inv);
    const anc = computeAncestors(investigation, idx);
    const kids = list.filter(
      (i) => i.parent_investigation_id === investigation.id && i.id !== investigation.id,
    );
    return { ancestors: anc, children: kids, byId: idx };
  }, [investigation, siblings]);

  const { artifactIds, investigationIds } = useMemo(
    () => collectStepReferences(investigation.steps ?? []),
    [investigation.steps],
  );

  // Cross-referenced investigations resolved back to their summary (drop any
  // that isn't in the project's own list so we don't render dead links).
  const relatedInvestigations = investigationIds
    .filter((id) => id !== investigation.id && byId.has(id))
    .map((id) => byId.get(id)!)
    .slice(0, 12);

  const hasLineage = ancestors.length > 0 || children.length > 0;

  return (
    <AilaCard padding="md" className="space-y-4" techBorder glow>
      <div className="flex items-center gap-2">
        <GitBranch className="h-4 w-4 text-text-muted" aria-hidden="true" />
        <h2 className="text-sm font-semibold text-foreground">Connected</h2>
      </div>

      {/* Project link */}
      <div className="flex items-start gap-3">
        <FolderOpen
          className="h-4 w-4 text-text-muted mt-0.5"
          aria-hidden="true"
        />
        <div className="min-w-0 flex-1">
          <p className="text-xs text-text-muted">Project</p>
          <Link
            to={`/forensics/projects/${projectId}`}
            className="text-sm font-medium text-accent hover:underline focus:outline focus:outline-2 focus:outline-accent"
          >
            {project?.name ?? projectId}
          </Link>
          {project && (
            <p className="text-3xs font-mono text-text-muted">
              {project.investigation_count} investigation(s) {"\u00b7"}{" "}
              {project.evidence_count} evidence {"\u00b7"}{" "}
              {project.artifact_count} artifact(s)
            </p>
          )}
        </div>
      </div>

      {/* Lineage tree */}
      <div className="space-y-2">
        <div className="flex items-baseline gap-2">
          <h3 className="text-xs font-mono uppercase tracking-wider text-text-muted">
            Lineage
          </h3>
          <span className="text-3xs font-mono text-text-muted">
            {ancestors.length} ancestor(s) {"\u00b7"} {children.length} rerun(s)
          </span>
        </div>
        {!hasLineage ? (
          <p className="font-mono text-xs text-text-muted">
            Single attempt {"\u2014"} no parent or rerun chain recorded.
          </p>
        ) : (
          <ul className="space-y-0.5">
            {ancestors.map((inv, i) => (
              <LineageRow
                key={inv.id}
                projectId={projectId}
                inv={inv}
                depth={i}
                self={false}
              />
            ))}
            <LineageRow
              projectId={projectId}
              inv={investigation}
              depth={ancestors.length}
              self
            />
            {children.map((inv) => (
              <LineageRow
                key={inv.id}
                projectId={projectId}
                inv={inv}
                depth={ancestors.length + 1}
                self={false}
              />
            ))}
          </ul>
        )}
      </div>

      {/* Related investigations surfaced by step observables */}
      {relatedInvestigations.length > 0 && (
        <div className="space-y-2">
          <h3 className="text-xs font-mono uppercase tracking-wider text-text-muted">
            Referenced investigations
          </h3>
          <ul className="flex flex-wrap gap-1.5">
            {relatedInvestigations.map((inv) => (
              <li key={inv.id}>
                <Link
                  to={`/forensics/projects/${projectId}/investigations/${inv.id}`}
                  className="inline-flex items-center gap-1 px-2 py-1 rounded border border-border bg-surface hover:bg-surface-secondary transition-colors focus:outline focus:outline-2 focus:outline-accent"
                  title={inv.question}
                >
                  <AilaBadge
                    severity={STATUS_SEVERITY[inv.status] ?? "neutral"}
                    size="sm"
                  >
                    {inv.status}
                  </AilaBadge>
                  <span className="text-xs font-mono text-accent">
                    {inv.id.slice(0, 8)}
                  </span>
                </Link>
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* Referenced artifacts (id-only; the project's artifact explorer
          resolves each id when the operator jumps into the project). */}
      <div className="space-y-2">
        <div className="flex items-baseline gap-2">
          <h3 className="text-xs font-mono uppercase tracking-wider text-text-muted">
            Referenced artifacts
          </h3>
          <span className="text-3xs font-mono text-text-muted">
            {artifactIds.length} id(s)
          </span>
        </div>
        {artifactIds.length === 0 ? (
          <p className="font-mono text-xs text-text-muted">
            No artifact ids surfaced by the reasoning provenance yet.
          </p>
        ) : (
          <ul className="flex flex-wrap gap-1">
            {artifactIds.slice(0, 24).map((id) => (
              <li key={id}>
                <span
                  className="inline-block px-1.5 py-0.5 rounded border border-border bg-surface text-3xs font-mono text-text-muted"
                  title={id}
                >
                  {id.slice(0, 10)}
                </span>
              </li>
            ))}
            {artifactIds.length > 24 && (
              <li className="text-3xs font-mono text-text-muted self-center">
                {"\u2026"} {artifactIds.length - 24} more
              </li>
            )}
          </ul>
        )}
      </div>
    </AilaCard>
  );
}
