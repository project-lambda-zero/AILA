/**
 * topologyUtils.ts — Transform API topology data to ReactFlow nodes/edges.
 *
 * Applies color-by mode to determine node fill color.
 * Pure functions — no React, no side effects.
 *
 * Per D-03 (Phase 144): client-side filtering, no additional API calls.
 */
import type { Node, Edge } from "@xyflow/react";

import type { ColorByMode, RadarFilter, TopologyEdge, TopologyNode } from "./types";

// ---------------------------------------------------------------------------
// Color utilities
// ---------------------------------------------------------------------------

/** Severity → CSS variable color. */
const SEVERITY_COLORS: Record<string, string> = {
  critical: "var(--color-critical)",
  high: "var(--color-high)",
  medium: "var(--color-medium)",
  low: "var(--color-low)",
  none: "var(--color-border)",
};

/** Determine dominant severity for a node's severity_counts. */
export function dominantSeverity(
  counts: { critical: number; high: number; medium: number; low: number } | null,
): string {
  if (!counts) return "none";
  if (counts.critical > 0) return "critical";
  if (counts.high > 0) return "high";
  if (counts.medium > 0) return "medium";
  if (counts.low > 0) return "low";
  return "none";
}

/** Map service count to a color (green gradient by density). */
function serviceColor(serviceCount: number): string {
  if (serviceCount === 0) return "var(--color-border)";
  if (serviceCount < 3) return "var(--color-low)";
  if (serviceCount < 7) return "var(--color-medium)";
  return "var(--color-mint, #059669)";
}

/** Derive fill color from a topology node based on the active colorByMode. */
export function nodeColor(node: TopologyNode, mode: ColorByMode): string {
  switch (mode) {
    case "vulnerabilities":
      return SEVERITY_COLORS[dominantSeverity(node.severity_counts)] ?? SEVERITY_COLORS.none;
    case "services":
      return serviceColor(node.services.length);
    case "distro": {
      const distros: Record<string, string> = {
        ubuntu: "var(--color-lavender, #7c3aed)",
        debian: "var(--color-lavender, #7c3aed)",
        centos: "var(--color-mint, #059669)",
        rhel: "var(--color-mint, #059669)",
        fedora: "var(--color-peach, #92400e)",
        alpine: "var(--color-accent)",
      };
      const lc = node.distro.toLowerCase();
      for (const [key, color] of Object.entries(distros)) {
        if (lc.includes(key)) return color;
      }
      return "var(--color-border)";
    }
    case "connectivity":
      return node.is_stale ? "var(--color-critical)" : "var(--color-mint, #059669)";
    default:
      return "var(--color-border)";
  }
}

// ---------------------------------------------------------------------------
// Filter
// ---------------------------------------------------------------------------

/** Apply RadarFilter to topology nodes — pure client-side filtering. */
export function filterNodes(nodes: TopologyNode[], filter: RadarFilter): TopologyNode[] {
  let result = nodes;

  if (filter.search.trim()) {
    const q = filter.search.trim().toLowerCase();
    result = result.filter(
      (n) =>
        n.name.toLowerCase().includes(q) ||
        n.host.toLowerCase().includes(q),
    );
  }

  if (filter.severities.length > 0) {
    result = result.filter((n) => {
      const sev = dominantSeverity(n.severity_counts);
      return filter.severities.includes(sev);
    });
  }

  return result;
}

// ---------------------------------------------------------------------------
// Layout
// ---------------------------------------------------------------------------

/** Simple grid layout: place nodes in rows of 5 with 200px spacing. */
function gridPosition(index: number): { x: number; y: number } {
  const cols = 5;
  const col = index % cols;
  const row = Math.floor(index / cols);
  return { x: col * 200 + 50, y: row * 180 + 50 };
}

// ---------------------------------------------------------------------------
// ReactFlow node/edge builders
// ---------------------------------------------------------------------------

/** Build ReactFlow node array from filtered topology nodes. */
export function buildFlowNodes(
  nodes: TopologyNode[],
  mode: ColorByMode,
  subnetGrouping: boolean,
): Node[] {
  // Build subnet → group node ID mapping when grouping is enabled
  const subnetGroupIds = new Map<string, string>();
  if (subnetGrouping) {
    const subnets = Array.from(new Set(nodes.map((n) => n.subnet ?? "unresolved")));
    subnets.forEach((subnet, i) => {
      subnetGroupIds.set(subnet, `subnet-group-${i}`);
    });
  }

  const flowNodes: Node[] = [];

  // Emit group nodes first — ReactFlow requires parent before child
  if (subnetGrouping) {
    const subnetMap = new Map<string, TopologyNode[]>();
    for (const node of nodes) {
      const key = node.subnet ?? "unresolved";
      const arr = subnetMap.get(key) ?? [];
      arr.push(node);
      subnetMap.set(key, arr);
    }

    let groupY = 0;
    for (const [subnet, subnetNodes] of subnetMap.entries()) {
      const groupId = subnetGroupIds.get(subnet) ?? `group-${subnet}`;
      const cols = 5;
      const rows = Math.ceil(subnetNodes.length / cols);
      const width = Math.min(subnetNodes.length, cols) * 200 + 60;
      const height = rows * 180 + 60;

      flowNodes.push({
        id: groupId,
        type: "group",
        position: { x: 20, y: groupY },
        data: { label: subnet },
        style: {
          width,
          height,
          backgroundColor: "rgba(255,255,255,0.02)",
          border: "1px dashed var(--color-border)",
          borderRadius: "8px",
        },
      });
      groupY += height + 40;
    }
  }

  // Emit actual system nodes
  const subnetIndexes = new Map<string, number>();
  nodes.forEach((node, globalIndex) => {
    const subnet = node.subnet ?? "unresolved";
    const localIndex = subnetIndexes.get(subnet) ?? 0;
    subnetIndexes.set(subnet, localIndex + 1);

    const pos = subnetGrouping ? gridPosition(localIndex) : gridPosition(globalIndex);
    const groupId = subnetGrouping ? subnetGroupIds.get(subnet) : undefined;

    flowNodes.push({
      id: String(node.id),
      type: "radarNode",
      position: pos,
      parentId: groupId,
      extent: groupId ? "parent" : undefined,
      data: {
        node,
        fillColor: nodeColor(node, mode),
        dominantSeverity: dominantSeverity(node.severity_counts),
      },
    });
  });

  return flowNodes;
}

/** Build ReactFlow edge array from topology edges, filtered to visible nodes. */
export function buildFlowEdges(
  apiEdges: TopologyEdge[],
  visibleNodeIds: Set<string>,
): Edge[] {
  return apiEdges
    .filter(
      (e) =>
        visibleNodeIds.has(String(e.source_system_id)) &&
        visibleNodeIds.has(String(e.dest_system_id)),
    )
    .map((e) => ({
      id: `edge-${e.source_system_id}-${e.dest_system_id}-${e.dest_port}`,
      source: String(e.source_system_id),
      target: String(e.dest_system_id),
      label: `${e.dest_port}/${e.protocol}`,
      animated: !e.is_stale,
      style: {
        stroke: e.is_stale ? "var(--color-border)" : "var(--color-accent)",
        strokeWidth: 1.5,
        strokeDasharray: e.is_stale ? "4 4" : undefined,
      },
      // Hide label on edge by default; shown in tooltip via data
      labelStyle: { display: "none" as const },
      data: { edge: e },
    }));
}
