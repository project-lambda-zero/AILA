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

import { WindowPanel } from "@/components/aila/WindowPanel";
import { MonoBadge } from "@/components/aila/mock";

import { useInvestigation, useInvestigations } from "../queries";
import type {
  InvestigationKind,
  InvestigationStatus,
  VRInvestigationSummary,
} from "../types";

// ─── Palette ────────────────────────────────────────────────────────────
// Match the mock-token status meta from vr-persona-contract.md: lifecycle
// hue, not a danger ramp. running→status-info, completed→status-ok,
// paused→status-warn, failed→accent, abandoned→text-faint,
// stalled→status-info, created→text-muted.
const STATUS_FILL: Record<string, string> = {
  running: "var(--status-info)",
  completed: "var(--status-ok)",
  paused: "var(--status-warn)",
  failed: "var(--accent)",
  abandoned: "var(--text-faint)",
  stalled: "var(--status-info)",
  created: "var(--text-muted)",
};
const STATUS_BORDER: Record<string, string> = {
  running: "var(--status-info)",
  completed: "var(--status-ok)",
  paused: "var(--status-warn)",
  failed: "var(--accent)",
  abandoned: "var(--text-faint)",
  stalled: "var(--status-info)",
  created: "var(--text-muted)",
};
const STATUS_TEXT: Record<string, string> = {
  running: "var(--text-on-accent)",
  completed: "var(--text-on-accent)",
  paused: "var(--text-on-accent)",
  failed: "var(--text-on-accent)",
  abandoned: "var(--text-primary)",
  stalled: "var(--text-on-accent)",
  created: "var(--text-primary)",
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
  const fill = hasStatus
    ? `color-mix(in srgb, ${STATUS_FILL[status as string]} 22%, var(--surface-sunk))`
    : "var(--surface-sunk)";
  const border = hasStatus ? STATUS_BORDER[status as string] : "var(--border-soft)";
  const text = hasStatus ? STATUS_TEXT[status as string] : "var(--text-primary)";
  return {
    background: fill,
    color: text,
    border: `${role === "self" ? 2 : 1}px solid ${
      role === "self" ? "var(--accent)" : border
    }`,
    borderRadius: 3,
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
            className="no-theme-link"
            style={{
              display: "block",
              textAlign: "left",
              textDecoration: "none",
              color: "inherit",
            }}
            aria-label={`Open ${c.role === "self" ? "current" : c.role} investigation: ${full.title ?? c.inv.id}`}
            onClick={(e) => e.stopPropagation()}
          >
            <div
              style={{
                fontSize: 9,
                textTransform: "uppercase",
                letterSpacing: "0.12em",
                fontFamily: "var(--font-mono)",
                opacity: 0.85,
              }}
            >
              {c.role}
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
                fontFamily: "var(--font-mono)",
              }}
            >
              {full.title ?? c.inv.id}
            </div>
            <div
              style={{
                fontSize: 9.5,
                opacity: 0.85,
                marginTop: 3,
                fontFamily: "var(--font-mono)",
                letterSpacing: "0.06em",
              }}
            >
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
      labelStyle: {
        fontSize: 9,
        fill: "var(--text-muted)",
        fontFamily: "var(--font-mono)",
      },
      style: { stroke: "var(--border-soft)", strokeWidth: 1.25 },
    });
  }
  for (const c of children) {
    edges.push({
      id: `child:${self.id}->${c.id}`,
      source: self.id,
      target: c.id,
      type: "smoothstep",
      label: c.kind === "variant_hunt" ? "variant hunt" : "spawned",
      labelStyle: {
        fontSize: 9,
        fill: "var(--text-muted)",
        fontFamily: "var(--font-mono)",
      },
      style: { stroke: "var(--border-soft)", strokeWidth: 1.25 },
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
      tone="muted"
      actions={
        <div className="flex items-center" style={{ gap: 6 }}>
          {hasParent && <MonoBadge tone="info">parent</MonoBadge>}
          {hasChildren && (
            <MonoBadge tone="ok">
              {children.length} child{children.length === 1 ? "" : "ren"}
            </MonoBadge>
          )}
          <span
            className="inline-flex items-center font-mono"
            style={{
              gap: 4,
              fontSize: 9,
              color: "var(--text-faint)",
              letterSpacing: "0.06em",
            }}
          >
            <ArrowsOutLineVertical weight="regular" size={10} />
            click any node to open
          </span>
        </div>
      }
    >
      <h2 className="sr-only">Lineage</h2>
      <div style={{ padding: 10 }}>
        <p
          className="font-mono"
          style={{
            marginBottom: 8,
            fontSize: 9.5,
            color: "var(--text-faint)",
            letterSpacing: "0.05em",
          }}
        >
          derived from parent_investigation_id + reverse lookup. each node
          deep-links to that investigation's detail page.
          {parentLoading ? " resolving parent…" : ""}
        </p>
        <div
          style={{
            width: "100%",
            height: Math.max(260, children.length * 96 + 120),
            border: "1px solid var(--border-soft)",
            background: "var(--surface-sunk)",
          }}
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
            <Background gap={20} size={1} color="var(--border-faint)" />
            <Controls showInteractive={false} />
          </ReactFlow>
        </div>
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
