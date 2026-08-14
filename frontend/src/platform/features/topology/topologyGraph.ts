/**
 * topologyGraph.ts -- pure builders that turn the /topology payload into
 * xyflow nodes/edges for the Topology console (issue #212).
 *
 * Kept separate from React components so the layout math stays testable
 * and re-runs cheap (memoised at the call site). Mirrors the radar
 * builders in spirit but the console has richer overlay semantics:
 *
 *   overlays.severityHeat  -- when off, nodes render neutral (no heat).
 *   overlays.staleOnly     -- when on, fresh nodes dim; stale pop.
 *   overlays.groupBySubnet -- xyflow parent groups per subnet_prefix.
 *
 * Node colour palette per spec (#212):
 *   critical -> #ff5f87 (accent hot-pink)
 *   high     -> soft-pink   (--color-high)
 *   medium   -> lavender    (--color-medium)
 *   low      -> mint        (--color-low)
 */
import type { Edge, Node } from "@xyflow/react";

import type {
  SeverityCounts,
  SubnetGroup,
  TopologyEdge,
  TopologyNode,
} from "@platform/features/radar/types";

// ---------------------------------------------------------------------------
// Severity palette
// ---------------------------------------------------------------------------

const SEVERITY_FILL: Record<Severity, string> = {
  critical: "#ff5f87",
  high: "var(--color-high)",
  medium: "var(--color-medium)",
  low: "var(--color-low)",
  none: "var(--color-border)",
};

export type Severity = "critical" | "high" | "medium" | "low" | "none";

export function dominantSeverity(counts: SeverityCounts | null): Severity {
  if (!counts) return "none";
  if (counts.critical > 0) return "critical";
  if (counts.high > 0) return "high";
  if (counts.medium > 0) return "medium";
  if (counts.low > 0) return "low";
  return "none";
}

// ---------------------------------------------------------------------------
// Overlay knobs
// ---------------------------------------------------------------------------

export interface TopologyOverlays {
  /** Colour nodes by dominant severity. Off -> neutral surface fill. */
  severityHeat: boolean;
  /** Dim non-stale nodes to spotlight the stale ones. */
  staleOnly: boolean;
  /** Cluster nodes inside dashed subnet frames. */
  groupBySubnet: boolean;
}

export const DEFAULT_OVERLAYS: TopologyOverlays = {
  severityHeat: true,
  staleOnly: false,
  groupBySubnet: false,
};

// ---------------------------------------------------------------------------
// Data attached to each xyflow node -- consumed by TopologyGraphNode.
// ---------------------------------------------------------------------------

export interface TopologyNodeData extends Record<string, unknown> {
  node: TopologyNode;
  fill: string;
  severity: Severity;
  faded: boolean;
}

// ---------------------------------------------------------------------------
// Layout -- a plain grid, subnet-scoped when grouping is on.
// ---------------------------------------------------------------------------

const COLS = 6;
const CELL_W = 180;
const CELL_H = 150;
const GROUP_PAD_X = 24;
const GROUP_PAD_TOP = 44;
const GROUP_GAP = 40;

function cellPosition(index: number, offsetX = 0, offsetY = 0) {
  const col = index % COLS;
  const row = Math.floor(index / COLS);
  return { x: offsetX + col * CELL_W, y: offsetY + row * CELL_H };
}

// ---------------------------------------------------------------------------
// Node/edge builders
// ---------------------------------------------------------------------------

export function buildNodes(
  nodes: TopologyNode[],
  overlays: TopologyOverlays,
  focusedSubnet: string | null,
): Node<TopologyNodeData>[] {
  const out: Node<TopologyNodeData>[] = [];

  const nodeToData = (n: TopologyNode): TopologyNodeData => {
    const sev = dominantSeverity(n.severity_counts);
    const fill = overlays.severityHeat ? SEVERITY_FILL[sev] : "var(--color-surface)";
    const staleFade = overlays.staleOnly && !n.is_stale;
    const subnetFade =
      focusedSubnet !== null && (n.subnet ?? "unresolved") !== focusedSubnet;
    return { node: n, fill, severity: sev, faded: staleFade || subnetFade };
  };

  if (!overlays.groupBySubnet) {
    nodes.forEach((n, i) => {
      out.push({
        id: String(n.id),
        type: "topologyNode",
        position: cellPosition(i, 40, 40),
        data: nodeToData(n),
      });
    });
    return out;
  }

  // Subnet grouping -- one parent group per prefix.
  const bySubnet = new Map<string, TopologyNode[]>();
  for (const n of nodes) {
    const key = n.subnet ?? "unresolved";
    const arr = bySubnet.get(key) ?? [];
    arr.push(n);
    bySubnet.set(key, arr);
  }

  let groupY = 20;
  for (const [subnet, subnetNodes] of Array.from(bySubnet.entries()).sort(
    (a, b) => a[0].localeCompare(b[0]),
  )) {
    const cols = Math.min(subnetNodes.length, COLS);
    const rows = Math.ceil(subnetNodes.length / COLS);
    const width = cols * CELL_W + GROUP_PAD_X * 2;
    const height = rows * CELL_H + GROUP_PAD_TOP + GROUP_PAD_X;
    const groupId = `subnet:${subnet}`;

    out.push({
      id: groupId,
      type: "group",
      position: { x: 20, y: groupY },
      // Cast: group nodes intentionally hold a subset of data; the graph
      // filters on `type === "topologyNode"` before touching TopologyNodeData.
      data: { subnet } as unknown as TopologyNodeData,
      style: {
        width,
        height,
        background: "color-mix(in srgb, var(--color-surface) 40%, transparent)",
        border: "1px dashed var(--color-border)",
        borderRadius: 4,
      },
      selectable: false,
      draggable: false,
    });

    subnetNodes.forEach((n, i) => {
      out.push({
        id: String(n.id),
        type: "topologyNode",
        position: cellPosition(i, GROUP_PAD_X, GROUP_PAD_TOP),
        parentId: groupId,
        extent: "parent",
        data: nodeToData(n),
      });
    });

    groupY += height + GROUP_GAP;
  }

  return out;
}

export function buildEdges(
  apiEdges: TopologyEdge[],
  visibleIds: Set<string>,
  focusedSubnet: string | null,
  nodesById: Map<string, TopologyNode>,
): Edge[] {
  return apiEdges
    .filter(
      (e) =>
        visibleIds.has(String(e.source_system_id)) &&
        visibleIds.has(String(e.dest_system_id)),
    )
    .map((e) => {
      const src = nodesById.get(String(e.source_system_id));
      const dst = nodesById.get(String(e.dest_system_id));
      const focusHit =
        focusedSubnet === null ||
        (src?.subnet ?? "unresolved") === focusedSubnet ||
        (dst?.subnet ?? "unresolved") === focusedSubnet;
      const stroke = e.is_stale
        ? "var(--color-border)"
        : "color-mix(in srgb, var(--color-accent) 70%, transparent)";
      return {
        id: `e-${e.source_system_id}-${e.dest_system_id}-${e.dest_port}-${e.protocol}`,
        source: String(e.source_system_id),
        target: String(e.dest_system_id),
        label: `${e.dest_port}/${e.protocol}`,
        labelStyle: {
          fill: "var(--color-text-muted)",
          fontFamily: "var(--font-mono, ui-monospace, monospace)",
          fontSize: 10,
        },
        labelBgStyle: { fill: "var(--color-base)", fillOpacity: 0.75 },
        labelBgPadding: [4, 2] as [number, number],
        style: {
          stroke,
          strokeWidth: 1.25,
          strokeDasharray: e.is_stale ? "4 4" : undefined,
          opacity: focusHit ? 1 : 0.15,
        },
        data: { edge: e },
      } satisfies Edge;
    });
}

// ---------------------------------------------------------------------------
// Uptime humaniser -- used by the detail sheet.
// ---------------------------------------------------------------------------

export function humaniseUptime(seconds: number | null | undefined): string {
  if (seconds == null || Number.isNaN(seconds) || seconds < 0) return "--";
  const d = Math.floor(seconds / 86400);
  const h = Math.floor((seconds % 86400) / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  const parts: string[] = [];
  if (d > 0) parts.push(`${d}d`);
  if (h > 0) parts.push(`${h}h`);
  if (m > 0 || parts.length === 0) parts.push(`${m}m`);
  return parts.join(" ");
}
