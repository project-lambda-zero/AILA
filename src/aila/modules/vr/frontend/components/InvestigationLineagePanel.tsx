/**
 * InvestigationLineagePanel -- shows an investigation's ancestry and its
 * variant-hunt descendants as a small xyflow graph.
 *
 * Data source (client-side derivation, no lineage endpoint):
 *   - `parent_investigation_id` on VRInvestigationSummary -> parent node
 *   - a client-side filter of the full investigations list keyed by
 *     `parent_investigation_id === current.id` -> child nodes
 *
 * If neither exists, the panel hides itself so standalone investigations
 * don't render an empty container. Each node deep-links to that
 * investigation's detail page. Reuses @xyflow/react (already a vr dep
 * via BranchTreePage); no new dependencies.
 */
import { useMemo } from "react";
import { Link } from "react-router";
import {
  Background,
  Controls,
  type Edge,
  type Node,
  ReactFlow,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { ArrowsOutLineVertical } from "@phosphor-icons/react/dist/csr/ArrowsOutLineVertical";

import { AilaBadge } from "@/components/aila/AilaBadge";
import { WindowPanel } from "@/components/aila/WindowPanel";

import { useInvestigation, useInvestigations } from "../queries";
import type {
  InvestigationKind,
  InvestigationStatus,
  VRInvestigationSummary,
} from "../types";

// ─── Palette ────────────────────────────────────────────────────────────
// Match InvestigationDetailPage's STATUS_META intent -- lifecycle hue,
// not danger ramp -- but keep the local subset small (parent/self/child).
const STATUS_FILL: Record<string, string> = {
  running: "var(--color-medium)",
  completed: "var(--color-mint)",
  paused: "var(--color-amber)",
  failed: "var(--color-accent)",
  abandoned: "var(--color-text-faint)",
  stalled: "var(--color-lavender)",
  created: "var(--color-text-muted)",
};
const STATUS_BORDER: Record<string, string> = {
  running: "color-mix(in srgb, var(--color-medium) 68%, var(--surface-sunk))",
  completed: "color-mix(in srgb, var(--color-mint) 68%, var(--surface-sunk))",
  paused: "color-mix(in srgb, var(--color-amber) 68%, var(--surface-sunk))",
  failed: "var(--color-accent-deep)",
  abandoned: "color-mix(in srgb, var(--color-text-faint) 78%, var(--surface-sunk))",
  stalled: "color-mix(in srgb, var(--color-lavender) 68%, var(--surface-sunk))",
  created: "color-mix(in srgb, var(--color-text-muted) 60%, var(--surface-sunk))",
};

const KIND_LABEL: Record<InvestigationKind, string> = {
  discovery: "discovery",
  variant_hunt: "variant hunt",
  triage: "triage",
  n_day: "n-day",
  audit: "audit",
};

const COL_X_GAP = 320;
const ROW_Y_GAP = 96;

interface NodeInput {
  inv: VRInvestigationSummary | { id: string; title: string | null };
  isSelf: boolean;
  role: "parent" | "self" | "child";
  col: number;
  row: number;
}

function nodeStyle(role: "parent" | "self" | "child", status?: string | null) {
  const hasStatus = Boolean(status && STATUS_FILL[status]);
  const fill = hasStatus ? STATUS_FILL[status as string] : "var(--color-elevated)";
  const border = hasStatus ? STATUS_BORDER[status as string] : "var(--color-border-bright)";
  const text = hasStatus ? "var(--text-on-accent)" : "var(--color-text)";
  return {
    background: fill,
    color: text,
    border: `${role === "self" ? 3 : 2}px solid ${role === "self" ? "var(--color-accent)" : border}`,
    borderRadius: 4,
    width: 260,
    padding: 8,
  };
}

function buildLineageGraph(
  self: VRInvestigationSummary,
  parent: VRInvestigationSummary | undefined,
  children: VRInvestigationSummary[],
): { nodes: Node[]; edges: Edge[] } {
  const columns: NodeInput[] = [];
  if (parent) {
    columns.push({ inv: parent, isSelf: false, role: "parent", col: 0, row: 0 });
  }
  columns.push({ inv: self, isSelf: true, role: "self", col: parent ? 1 : 0, row: 0 });
  children.forEach((c, i) => {
    columns.push({
      inv: c,
      isSelf: false,
      role: "child",
      col: parent ? 2 : 1,
      row: i,
    });
  });

  // Vertically centre parent relative to the child column so a single
  // parent doesn't stick to the top.
  const childCount = children.length;
  const centerY = childCount > 1 ? ((childCount - 1) * ROW_Y_GAP) / 2 : 0;

  const nodes: Node[] = columns.map((c) => {
    const full = c.inv as VRInvestigationSummary;
    const y =
      c.role === "self" || c.role === "parent" ? centerY : c.row * ROW_Y_GAP;
    return {
      id: c.inv.id,
      type: "default",
      position: { x: c.col * COL_X_GAP, y },
      data: {
        label: (
          <Link
            to={`/vr/investigations/${c.inv.id}`}
            className="no-theme-link block text-left no-underline focus:outline focus:outline-2"
            style={{ color: "inherit" }}
            aria-label={`Open ${c.role === "self" ? "current" : c.role} investigation: ${full.title ?? c.inv.id}`}
            // Prevent xyflow from swallowing the click when the label
            // sits inside a "default" node.
            onClick={(e) => e.stopPropagation()}
          >
            <div style={{ fontSize: 11, opacity: 0.85, fontFamily: "monospace" }}>
              {c.role.toUpperCase()}
              {full.kind ? ` · ${KIND_LABEL[full.kind]}` : ""}
            </div>
            <div
              style={{
                fontSize: 12,
                fontWeight: 600,
                marginTop: 2,
                overflow: "hidden",
                textOverflow: "ellipsis",
                whiteSpace: "nowrap",
              }}
            >
              {full.title ?? c.inv.id}
            </div>
            <div style={{ fontSize: 10, opacity: 0.8, marginTop: 2 }}>
              {full.status ?? "unknown"}
              {typeof full.branch_count === "number"
                ? ` · ${full.branch_count} br`
                : ""}
              {typeof full.outcome_count === "number"
                ? ` · ${full.outcome_count} out`
                : ""}
            </div>
          </Link>
        ),
      },
      style: nodeStyle(c.role, full.status ?? null),
      draggable: false,
      selectable: true,
    };
  });

  const edges: Edge[] = [];
  if (parent) {
    edges.push({
      id: `parent:${parent.id}->${self.id}`,
      source: parent.id,
      target: self.id,
      type: "smoothstep",
      label: "spawned",
      labelStyle: { fontSize: 10, fill: "var(--color-text-muted)" },
      style: { stroke: "var(--color-border-bright)", strokeWidth: 1.5 },
    });
  }
  for (const c of children) {
    edges.push({
      id: `child:${self.id}->${c.id}`,
      source: self.id,
      target: c.id,
      type: "smoothstep",
      label: c.kind === "variant_hunt" ? "variant hunt" : "spawned",
      labelStyle: { fontSize: 10, fill: "var(--color-text-muted)" },
      style: { stroke: "var(--color-border-bright)", strokeWidth: 1.5 },
    });
  }
  return { nodes, edges };
}

export function InvestigationLineagePanel({
  investigation,
}: {
  investigation: VRInvestigationSummary;
}) {
  // Fetch the parent lazily -- one HTTP request only when the field is
  // set. Placement: useQuery calls need to be unconditional so the
  // enabled flag on `useInvestigation` gates the fetch itself.
  const parentQuery = useInvestigation(investigation.parent_investigation_id ?? "");

  // Children come from the general investigations list (already-cached
  // by useInvestigations if the operator has visited the list) filtered
  // by parent_investigation_id. Cheap; page-size 200 mirrors
  // useInvestigationsForTarget's ceiling.
  const listQuery = useInvestigations({ limit: 200 });

  const children = useMemo(() => {
    const rows: VRInvestigationSummary[] = listQuery.data?.data ?? [];
    return rows
      .filter((row) => row.parent_investigation_id === investigation.id)
      .sort((a, b) => (a.created_at ?? "").localeCompare(b.created_at ?? ""));
  }, [listQuery.data, investigation.id]);

  const hasParent = !!investigation.parent_investigation_id;
  const hasChildren = children.length > 0;

  const parentInv = parentQuery.data;
  const { nodes, edges } = useMemo(
    () => buildLineageGraph(investigation, parentInv, children),
    [investigation, parentInv, children],
  );

  const parentLoading =
    hasParent && (parentQuery.isLoading || parentQuery.isFetching) && !parentInv;

  // Hide the whole card for standalone investigations. Placed AFTER
  // every hook so a switch from lineage-present -> standalone doesn't
  // trip React's Rules of Hooks.
  if (!hasParent && !hasChildren) return null;

  return (
    <WindowPanel
      title="lineage"
      tone="info"
      actions={
        <div className="flex items-center gap-2">
          {hasParent && (
            <AilaBadge severity="info" size="sm">
              parent
            </AilaBadge>
          )}
          {hasChildren && (
            <AilaBadge severity="low" size="sm">
              {children.length} child{children.length === 1 ? "" : "ren"}
            </AilaBadge>
          )}
          <span className="inline-flex items-center gap-1 text-3xs font-mono text-text-muted">
            <ArrowsOutLineVertical weight="regular" size={11} />
            click any node to open
          </span>
        </div>
      }
    >
      <h2 className="sr-only">Lineage</h2>
      <p className="text-3xs text-text-muted mb-2 font-mono">
        Derived from parent_investigation_id + reverse lookup. Each node
        deep-links to that investigation's detail page.
        {parentLoading ? " Resolving parent…" : ""}
      </p>
      <div
        style={{ width: "100%", height: Math.max(260, children.length * 96 + 120) }}
      >
        <ReactFlow
          nodes={nodes}
          edges={edges}
          fitView
          fitViewOptions={{ padding: 0.2 }}
          nodesDraggable={false}
          nodesConnectable={false}
          elementsSelectable
          panOnDrag
          proOptions={{ hideAttribution: true }}
          aria-label="Investigation lineage graph"
        >
          <Background gap={20} size={1} color="var(--color-border)" />
          <Controls showInteractive={false} />
        </ReactFlow>
      </div>
      {/* Flat text fallback for screen readers -- xyflow nodes aren't in
          the natural tab order, so we expose the same relationships as a
          list below the visualisation. */}
      <ul className="sr-only">
        {parentInv && (
          <li>
            Parent investigation:{" "}
            <Link to={`/vr/investigations/${parentInv.id}`}>
              {parentInv.title ?? parentInv.id}
            </Link>
          </li>
        )}
        {children.map((c) => (
          <li key={c.id}>
            Child investigation ({KIND_LABEL[c.kind]}):{" "}
            <Link to={`/vr/investigations/${c.id}`}>
              {c.title ?? c.id}
            </Link>
          </li>
        ))}
      </ul>
    </WindowPanel>
  );
}

// Suppress noUnused: keep the InvestigationStatus type referenced so
// the palette maps stay honest even though we index by string above.
export type _StatusReference = InvestigationStatus;
