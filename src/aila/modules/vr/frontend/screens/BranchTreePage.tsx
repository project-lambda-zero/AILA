import { useMemo } from "react";
import { useParams } from "react-router";

import {
  Background,
  Controls,
  type Edge,
  type Node,
  ReactFlow,
} from "@xyflow/react";

import "@xyflow/react/dist/style.css";

import { AilaBadge } from "@/components/aila/AilaBadge";
import { AilaCard } from "@/components/aila/AilaCard";
import { LoadingSkeleton } from "@/components/aila/LoadingSkeleton";

import {
  useInvestigation,
  useInvestigationBranches,
} from "../queries";
import type { BranchStatus, VRBranchSummary } from "../types";
import { formatBranchDisplayName } from "../branchDisplay";
import { useUpdatePageHeader } from "@/components/aila/PageHeaderContext";

// Colour-code branches by status. Aligns with the AilaBadge palette so
// the tree + list views look consistent.
const STATUS_COLORS: Record<BranchStatus, string> = {
  active: "#10b981",        // emerald -- running
  paused: "#f59e0b",        // amber -- paused
  merged: "#6366f1",        // indigo -- merged in
  promoted: "#22c55e",      // green -- promoted to outcome
  completed: "#3b82f6",     // blue -- completed
  abandoned: "#ef4444",     // red -- abandoned
};

const STATUS_BORDER: Record<BranchStatus, string> = {
  active: "#059669",
  paused: "#d97706",
  merged: "#4338ca",
  promoted: "#15803d",
  completed: "#1d4ed8",
  abandoned: "#b91c1c",
};

// Spacing between strategy-family clusters + within a cluster.
const STRATEGY_X_GAP = 320;
const BRANCH_Y_GAP = 96;
const CLUSTER_HEADER_Y = -48;

interface ClusteredBranch extends VRBranchSummary {
  cluster: string;
}

/** Group branches by strategy_family; '__no_strategy__' for legacy nulls. */
function clusterBranches(branches: VRBranchSummary[]): ClusteredBranch[] {
  return branches.map((b) => ({
    ...b,
    cluster: b.strategy_family ?? "__no_strategy__",
  }));
}

/** Build react-flow nodes laid out as one column per strategy family,
 * branches stacked vertically inside each column. */
function layoutNodes(clustered: ClusteredBranch[]): Node[] {
  const columns = new Map<string, ClusteredBranch[]>();
  for (const b of clustered) {
    const col = columns.get(b.cluster) ?? [];
    col.push(b);
    columns.set(b.cluster, col);
  }
  const orderedClusters = Array.from(columns.keys()).sort((a, b) => {
    // legacy bucket goes first so it sits on the left
    if (a === "__no_strategy__") return -1;
    if (b === "__no_strategy__") return 1;
    return a.localeCompare(b);
  });

  const nodes: Node[] = [];

  orderedClusters.forEach((cluster, colIdx) => {
    const x = colIdx * STRATEGY_X_GAP;
    const branches = columns.get(cluster) ?? [];

    // Cluster header (label node, non-interactive)
    nodes.push({
      id: `__cluster__:${cluster}`,
      type: "default",
      position: { x, y: CLUSTER_HEADER_Y },
      data: {
        label: cluster === "__no_strategy__" ? "(no strategy)" : cluster,
      },
      style: {
        background: "transparent",
        border: "none",
        color: "#94a3b8",
        fontSize: 11,
        fontFamily: "monospace",
        width: 240,
      },
      draggable: false,
      selectable: false,
    });

    branches.forEach((b, rowIdx) => {
      const colour = STATUS_COLORS[b.status] ?? "#64748b";
      const border = STATUS_BORDER[b.status] ?? "#475569";
      nodes.push({
        id: b.id,
        type: "default",
        position: { x, y: rowIdx * BRANCH_Y_GAP },
        data: {
          label: (
            <div style={{ textAlign: "left", color: "white", fontSize: 11 }}>
              <div style={{ fontWeight: 600 }}>
                {formatBranchDisplayName(b)}
                {b.fork_at_turn != null ? ` @t${b.fork_at_turn}` : ""}
              </div>
              <div style={{ opacity: 0.8 }}>
                {b.status} · turns:{b.turn_count}
              </div>
              <div style={{ opacity: 0.65, fontSize: 10 }}>
                ${b.branch_cost_usd.toFixed(2)}
              </div>
            </div>
          ),
        },
        style: {
          background: colour,
          color: "white",
          border: `2px solid ${border}`,
          borderRadius: 6,
          width: 240,
          padding: 8,
        },
      });
    });
  });

  return nodes;
}

/** Build edges: parent → child for forks, plus merge edges. */
function buildEdges(branches: VRBranchSummary[]): Edge[] {
  const ids = new Set(branches.map((b) => b.id));
  const edges: Edge[] = [];

  for (const b of branches) {
    if (b.parent_branch_id && ids.has(b.parent_branch_id)) {
      edges.push({
        id: `fork:${b.parent_branch_id}->${b.id}`,
        source: b.parent_branch_id,
        target: b.id,
        type: "smoothstep",
        label: "fork",
        labelStyle: { fontSize: 10, fill: "#64748b" },
        style: { stroke: "#64748b", strokeWidth: 1.5 },
      });
    }
    if (b.merged_into_branch_id && ids.has(b.merged_into_branch_id)) {
      edges.push({
        id: `merge:${b.id}->${b.merged_into_branch_id}`,
        source: b.id,
        target: b.merged_into_branch_id,
        type: "smoothstep",
        animated: true,
        label: "merge",
        labelStyle: { fontSize: 10, fill: "#6366f1" },
        style: { stroke: "#6366f1", strokeDasharray: "4 4" },
      });
    }
  }

  return edges;
}

export function BranchTreePage() {
  const { investigationId } = useParams<{ investigationId: string }>();
  const invId = investigationId ?? "";

  const { data: inv, isLoading: invLoading } = useInvestigation(invId);
  const { data: branchesData, isLoading: branchesLoading } =
    useInvestigationBranches(invId);
  const branches = branchesData?.data ?? [];

  useUpdatePageHeader({
    title: inv ? `Branch tree: ${inv.title}` : undefined,
    subtitle: branches.length ? `${branches.length} branch${branches.length === 1 ? '' : 'es'} across ${new Set(branches.map((b) => b.strategy_family ?? '__no_strategy__')).size} strategy famil${new Set(branches.map((b) => b.strategy_family ?? '__no_strategy__')).size === 1 ? 'y' : 'ies'}` : undefined,
    status: null,
  });

  const { nodes, edges } = useMemo(() => {
    const clustered = clusterBranches(branches);
    return {
      nodes: layoutNodes(clustered),
      edges: buildEdges(branches),
    };
  }, [branches]);

  if (invLoading || branchesLoading) {
    return <LoadingSkeleton size="lg" width="full" />;
  }

  if (!inv) {
    return (
      <AilaCard className="border-border-danger" techBorder glow><p className="text-sm text-text-danger">
        Investigation {invId} not found.
      </p></AilaCard>
    );
  }

  // Count by status for the header summary
  const statusCounts = branches.reduce<Record<string, number>>((acc, b) => {
    acc[b.status] = (acc[b.status] ?? 0) + 1;
    return acc;
  }, {});
  const strategyCount = new Set(
    branches.map((b) => b.strategy_family ?? "__no_strategy__"),
  ).size;

  return (
    <div className="space-y-4">

      <AilaCard  techBorder glow><div className="flex flex-wrap gap-2">
        {(
          ["active", "paused", "merged", "promoted", "abandoned"] as BranchStatus[]
        ).map((s) => {
          const n = statusCounts[s] ?? 0;
          return (
            <AilaBadge
              key={s}
              severity={
                s === "active"
                  ? "low"
                  : s === "paused"
                    ? "medium"
                    : s === "abandoned"
                      ? "high"
                      : "info"
              }
              size="sm"
            >
              {s}:{n}
            </AilaBadge>
          );
        })}
      </div></AilaCard>

      <AilaCard className="p-0 overflow-hidden" techBorder glow><div style={{ width: "100%", height: 600 }}>
        <ReactFlow
          nodes={nodes}
          edges={edges}
          fitView
          nodesDraggable
          nodesConnectable={false}
          elementsSelectable
          proOptions={{ hideAttribution: true }}
        >
          <Background gap={20} size={1} color="#1e293b" />
          <Controls showInteractive={false} />
        </ReactFlow>
      </div></AilaCard>

      {branches.length === 0 && (
        <AilaCard  techBorder glow><p className="text-sm text-text-muted text-center py-4">
          No branches yet. Create the primary branch via the investigation
          workflow or POST /vr/investigations/{`{id}`}/strategy-branches.
        </p></AilaCard>
      )}
    </div>
  );
}
