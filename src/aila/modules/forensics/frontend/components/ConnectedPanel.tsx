import { useMemo } from "react";
import { Link } from "react-router";
import { FolderOpen } from "@phosphor-icons/react/dist/csr/FolderOpen";
import { CaretRight } from "@phosphor-icons/react/dist/csr/CaretRight";

import { WindowPanel } from "@/components/aila/WindowPanel";
import { MonoBadge } from "@/components/aila/mock";

import {
  useForensicsProject,
  useProjectInvestigations,
} from "../queries";
import type {
  AgentStep,
  InvestigationDetail,
  InvestigationSummary,
} from "../types";

interface ConnectedPanelProps {
  projectId: string;
  investigation: InvestigationDetail;
}

// Status -> mock semantic tone (info/medium/ok/critical/high).
const STATUS_TONE: Record<string, string> = {
  created: "info",
  queued: "info",
  running: "medium",
  analyzing: "medium",
  completed: "ok",
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
  const tone = STATUS_TONE[inv.status] ?? "muted";
  const label =
    inv.question.length > 90 ? `${inv.question.slice(0, 88)}\u2026` : inv.question;
  const inner = (
    <div className="flex items-center min-w-0" style={{ gap: 8 }}>
      <MonoBadge tone={tone}>{inv.status}</MonoBadge>
      <span
        className="font-mono shrink-0"
        style={{ fontSize: 10.5, color: "var(--text-faint)" }}
      >
        {inv.id.slice(0, 8)}
      </span>
      <span
        className="font-mono truncate"
        style={{
          fontSize: 11,
          color: "var(--text-primary)",
          fontWeight: self ? 500 : 400,
        }}
        title={inv.question}
      >
        {label}
      </span>
      {self && <MonoBadge tone="info">this</MonoBadge>}
    </div>
  );

  return (
    <li
      className="flex items-center"
      style={{ gap: 4, paddingLeft: depth * 20 }}
    >
      {depth > 0 && (
        <CaretRight
          className="shrink-0"
          aria-hidden="true"
          style={{
            width: 12,
            height: 12,
            color: "var(--text-faint)",
          }}
        />
      )}
      {self ? (
        <span className="flex-1 min-w-0">{inner}</span>
      ) : (
        <Link
          to={`/forensics/projects/${projectId}/investigations/${inv.id}`}
          className="flex-1 min-w-0"
          style={{
            padding: "3px 4px",
            borderRadius: 3,
            textDecoration: "none",
          }}
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
export function ConnectedPanel({
  projectId,
  investigation,
}: ConnectedPanelProps) {
  const { data: project } = useForensicsProject(projectId);
  const { data: siblings } = useProjectInvestigations(projectId);

  const { ancestors, children, byId } = useMemo(() => {
    const list = siblings ?? [];
    const idx = new Map<string, InvestigationSummary>();
    for (const inv of list) idx.set(inv.id, inv);
    const anc = computeAncestors(investigation, idx);
    const kids = list.filter(
      (i) =>
        i.parent_investigation_id === investigation.id && i.id !== investigation.id,
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

  const sectionLabelStyle: React.CSSProperties = {
    fontSize: 9,
    letterSpacing: "0.14em",
    color: "var(--text-faint)",
  };

  return (
    <WindowPanel title="connected" status="forensics ; cross-references">
      <div className="space-y-4">
        {/* Project link */}
        <div className="flex items-start" style={{ gap: 10 }}>
          <FolderOpen
            aria-hidden="true"
            style={{
              width: 16,
              height: 16,
              marginTop: 2,
              color: "var(--text-faint)",
              flex: "0 0 auto",
            }}
          />
          <div className="min-w-0 flex-1">
            <p className="font-mono uppercase" style={sectionLabelStyle}>
              Project
            </p>
            <Link
              to={`/forensics/projects/${projectId}`}
              className="font-mono"
              style={{
                fontSize: 12,
                color: "var(--accent)",
                textDecoration: "none",
              }}
            >
              {project?.name ?? projectId}
            </Link>
            {project && (
              <p
                className="font-mono"
                style={{
                  fontSize: 9.5,
                  color: "var(--text-faint)",
                  marginTop: 2,
                }}
              >
                {project.investigation_count} investigation(s) {"\u00b7"}{" "}
                {project.evidence_count} evidence {"\u00b7"}{" "}
                {project.artifact_count} artifact(s)
              </p>
            )}
          </div>
        </div>

        {/* Lineage tree */}
        <div className="space-y-2">
          <div className="flex items-baseline" style={{ gap: 8 }}>
            <h3 className="font-mono uppercase" style={sectionLabelStyle}>
              Lineage
            </h3>
            <span
              className="font-mono"
              style={{ fontSize: 9.5, color: "var(--text-faint)" }}
            >
              {ancestors.length} ancestor(s) {"\u00b7"} {children.length} rerun(s)
            </span>
          </div>
          {!hasLineage ? (
            <p
              className="font-mono"
              style={{ fontSize: 11, color: "var(--text-muted)" }}
            >
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
            <h3 className="font-mono uppercase" style={sectionLabelStyle}>
              Referenced investigations
            </h3>
            <ul className="flex flex-wrap" style={{ gap: 6 }}>
              {relatedInvestigations.map((inv) => (
                <li key={inv.id}>
                  <Link
                    to={`/forensics/projects/${projectId}/investigations/${inv.id}`}
                    className="inline-flex items-center"
                    title={inv.question}
                    style={{
                      gap: 6,
                      padding: "3px 8px",
                      border: "1px solid var(--border-soft)",
                      background: "var(--surface-card)",
                      borderRadius: 3,
                      textDecoration: "none",
                    }}
                  >
                    <MonoBadge tone={STATUS_TONE[inv.status] ?? "muted"}>
                      {inv.status}
                    </MonoBadge>
                    <span
                      className="font-mono"
                      style={{ fontSize: 10.5, color: "var(--accent)" }}
                    >
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
          <div className="flex items-baseline" style={{ gap: 8 }}>
            <h3 className="font-mono uppercase" style={sectionLabelStyle}>
              Referenced artifacts
            </h3>
            <span
              className="font-mono"
              style={{ fontSize: 9.5, color: "var(--text-faint)" }}
            >
              {artifactIds.length} id(s)
            </span>
          </div>
          {artifactIds.length === 0 ? (
            <p
              className="font-mono"
              style={{ fontSize: 11, color: "var(--text-muted)" }}
            >
              No artifact ids surfaced by the reasoning provenance yet.
            </p>
          ) : (
            <ul className="flex flex-wrap" style={{ gap: 4 }}>
              {artifactIds.slice(0, 24).map((id) => (
                <li key={id}>
                  <span
                    className="inline-block font-mono"
                    style={{
                      padding: "2px 6px",
                      border: "1px solid var(--border-faint)",
                      background: "var(--surface-card)",
                      borderRadius: 2,
                      fontSize: 9.5,
                      color: "var(--text-faint)",
                    }}
                    title={id}
                  >
                    {id.slice(0, 10)}
                  </span>
                </li>
              ))}
              {artifactIds.length > 24 && (
                <li
                  className="font-mono self-center"
                  style={{ fontSize: 9.5, color: "var(--text-faint)" }}
                >
                  {"\u2026"} {artifactIds.length - 24} more
                </li>
              )}
            </ul>
          )}
        </div>
      </div>
    </WindowPanel>
  );
}
