import { useMemo, useState } from "react";
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
  useAbandonBranch,
  useForkBranch,
  usePauseBranch,
  usePromoteBranch,
  useResumeBranch,
  useSpawnStrategyBranch,
} from "../mutations";
import {
  useInvestigation,
  useInvestigationBranches,
} from "../queries";
import type { BranchStatus, PersonaVoice, VRBranchSummary } from "../types";
import { formatBranchDisplayName } from "../branchDisplay";
import { PanelBoundary } from "../components/PanelBoundary";
import { useUpdatePageHeader } from "@/components/aila/PageHeaderContext";

/** Persona-voice values operators can attach to a spawn / fork.
 *  Mirrors PersonaVoice in contracts/enums.py (core roles only —
 *  specialists are on-demand and belong on a dedicated spawn UI). */
const PERSONA_VOICES: readonly PersonaVoice[] = [
  "halvar", "maddie", "yuki", "renzo", "noor", "wei",
];

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

      <PanelBoundary
        label="Branch tree"
        invalidateKeyPrefix={["vr", "investigation-branches", invId]}
      >
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
      </PanelBoundary>

      {branches.length === 0 && (
        <AilaCard  techBorder glow><p className="text-sm text-text-muted text-center py-4">
          No branches yet. Create the primary branch via the investigation
          workflow, or spawn one below.
        </p></AilaCard>
      )}

      <AilaCard techBorder glow>
        <h2 className="text-sm font-semibold text-foreground mb-2">
          Spawn strategy branch
        </h2>
        <p className="text-3xs text-text-muted mb-3">
          POST /vr/investigations/{`{id}`}/strategy-branches — creates a new
          branch tagged with a strategy_family. Leave parent empty for a
          genuinely-parallel strategy; pick a parent to inherit its
          case_state.
        </p>
        <StrategyBranchSpawnForm invId={invId} branches={branches} />
      </AilaCard>

      {branches.length > 0 && (
        <AilaCard techBorder glow>
          <h2 className="text-sm font-semibold text-foreground mb-2">
            Branch operations
          </h2>
          <p className="text-3xs text-text-muted mb-3">
            Per-branch fork / promote / abandon / pause / resume. Merge (two
            branches into a new one) is not surfaced here — pick a merge
            target from the dedicated merge dialog when available.
          </p>
          <BranchOpsTable invId={invId} branches={branches} />
        </AilaCard>
      )}
    </div>
  );
}

// ─── Strategy branch spawn form ─────────────────────────────────────────
function StrategyBranchSpawnForm({
  invId,
  branches,
}: {
  invId: string;
  branches: VRBranchSummary[];
}) {
  const [strategyFamily, setStrategyFamily] = useState("");
  const [personaVoice, setPersonaVoice] = useState<PersonaVoice | "">("");
  const [rationale, setRationale] = useState("");
  const [parentBranchId, setParentBranchId] = useState<string>("");
  const spawnMut = useSpawnStrategyBranch(invId);

  const disabled = spawnMut.isPending || strategyFamily.trim().length === 0;

  return (
    <form
      className="space-y-2"
      onSubmit={(e) => {
        e.preventDefault();
        if (disabled) return;
        spawnMut.mutate(
          {
            strategy_family: strategyFamily.trim(),
            persona_voice: personaVoice === "" ? null : personaVoice,
            rationale: rationale.trim(),
            parent_branch_id: parentBranchId === "" ? null : parentBranchId,
          },
          {
            onSuccess: () => {
              setStrategyFamily("");
              setRationale("");
            },
          },
        );
      }}
    >
      <div className="grid gap-2 md:grid-cols-3">
        <label className="text-xs">
          <span className="block text-3xs text-text-muted uppercase tracking-wide mb-0.5">
            Strategy family (required)
          </span>
          <input
            type="text"
            value={strategyFamily}
            onChange={(e) => setStrategyFamily(e.target.value)}
            placeholder="e.g. taint-first, memory-corruption"
            maxLength={128}
            className="w-full text-xs font-mono px-2 py-1 rounded bg-surface border border-border-default focus:border-accent focus:outline-none"
          />
        </label>
        <label className="text-xs">
          <span className="block text-3xs text-text-muted uppercase tracking-wide mb-0.5">
            Persona voice
          </span>
          <select
            value={personaVoice}
            onChange={(e) => setPersonaVoice(e.target.value as PersonaVoice | "")}
            className="w-full text-xs px-2 py-1 rounded bg-surface border border-border-default"
          >
            <option value="">(none)</option>
            {PERSONA_VOICES.map((v) => (
              <option key={v} value={v}>{v}</option>
            ))}
          </select>
        </label>
        <label className="text-xs">
          <span className="block text-3xs text-text-muted uppercase tracking-wide mb-0.5">
            Parent branch (optional — inherits case_state)
          </span>
          <select
            value={parentBranchId}
            onChange={(e) => setParentBranchId(e.target.value)}
            className="w-full text-xs font-mono px-2 py-1 rounded bg-surface border border-border-default"
          >
            <option value="">(fresh — no parent)</option>
            {branches.map((b) => (
              <option key={b.id} value={b.id}>
                {formatBranchDisplayName(b)} · {b.status}
              </option>
            ))}
          </select>
        </label>
      </div>
      <textarea
        value={rationale}
        onChange={(e) => setRationale(e.target.value)}
        placeholder="Rationale (optional) — why this strategy is worth exploring"
        rows={2}
        maxLength={2048}
        className="w-full text-xs font-mono p-2 rounded bg-surface border border-border-default focus:border-accent focus:outline-none"
      />
      <div className="flex justify-end">
        <button
          type="submit"
          disabled={disabled}
          className="text-xs px-3 py-1 rounded bg-accent text-white disabled:opacity-50 disabled:cursor-not-allowed"
        >
          {spawnMut.isPending ? "Spawning…" : "Spawn branch"}
        </button>
      </div>
    </form>
  );
}

// ─── Per-branch ops table ───────────────────────────────────────────────
function BranchOpsTable({
  invId,
  branches,
}: {
  invId: string;
  branches: VRBranchSummary[];
}) {
  const forkMut = useForkBranch(invId);
  const promoteMut = usePromoteBranch(invId);
  const abandonMut = useAbandonBranch(invId);
  const pauseMut = usePauseBranch(invId);
  const resumeMut = useResumeBranch(invId);

  return (
    <div className="overflow-x-auto">
      <table className="w-full text-xs">
        <caption className="sr-only">Investigation branches with status and actions</caption>
        <thead>
          <tr className="border-b border-border-default text-left text-text-muted">
            <th className="px-2 py-1 font-semibold">Branch</th>
            <th className="px-2 py-1 font-semibold">Status</th>
            <th className="px-2 py-1 font-semibold">Turns</th>
            <th className="px-2 py-1 font-semibold text-right">Actions</th>
          </tr>
        </thead>
        <tbody>
          {branches.map((b) => {
            const active = b.status === "active";
            const paused = b.status === "paused";
            return (
              <tr
                key={b.id}
                className="border-b border-border-default last:border-b-0 align-top"
              >
                <td className="px-2 py-2 font-mono">
                  <div className="text-foreground">{formatBranchDisplayName(b)}</div>
                  <div className="text-3xs text-text-muted">
                    {b.strategy_family ?? "(no strategy)"}
                    {b.persona_voice ? ` · ${b.persona_voice}` : ""}
                  </div>
                </td>
                <td className="px-2 py-2">
                  <AilaBadge
                    severity={
                      active
                        ? "low"
                        : paused
                          ? "medium"
                          : b.status === "abandoned"
                            ? "high"
                            : "info"
                    }
                    size="sm"
                  >
                    {b.status}
                  </AilaBadge>
                </td>
                <td className="px-2 py-2 font-mono">{b.turn_count}</td>
                <td className="px-2 py-2">
                  <div className="flex gap-1 flex-wrap justify-end">
                    <BranchOpButton
                      label="Fork"
                      title="Fork this branch into a new child (prompts for a fork reason)"
                      disabled={forkMut.isPending || !active}
                      onClick={() => {
                        const reason = window.prompt(
                          `Fork reason for branch ${formatBranchDisplayName(b)}?`,
                          "",
                        );
                        if (reason == null) return;
                        forkMut.mutate({
                          branchId: b.id,
                          body: { reason },
                        });
                      }}
                    />
                    <BranchOpButton
                      label="Promote"
                      title="Promote to authoritative — sibling ACTIVE branches → ABANDONED"
                      variant="accent"
                      disabled={promoteMut.isPending || !active}
                      onClick={() => {
                        if (!window.confirm(
                          `Promote branch ${formatBranchDisplayName(b)} to authoritative?\n\n` +
                          `Sibling ACTIVE branches will be ABANDONED.`,
                        )) return;
                        const reason = window.prompt(
                          "Promotion reason (optional)?",
                          "",
                        ) ?? "";
                        promoteMut.mutate({ branchId: b.id, body: { reason } });
                      }}
                    />
                    {paused ? (
                      <BranchOpButton
                        label="Resume"
                        title="Resume a PAUSED branch (status PAUSED → ACTIVE)"
                        disabled={resumeMut.isPending}
                        onClick={() => {
                          const reason = window.prompt("Resume reason (optional)?", "") ?? "";
                          resumeMut.mutate({ branchId: b.id, body: { reason } });
                        }}
                      />
                    ) : (
                      <BranchOpButton
                        label="Pause"
                        title="Pause an ACTIVE branch (status ACTIVE → PAUSED)"
                        disabled={pauseMut.isPending || !active}
                        onClick={() => {
                          const reason = window.prompt("Pause reason (optional)?", "") ?? "";
                          pauseMut.mutate({ branchId: b.id, body: { reason } });
                        }}
                      />
                    )}
                    <BranchOpButton
                      label="Abandon"
                      title="Close a branch without promotion"
                      variant="danger"
                      disabled={abandonMut.isPending || (!active && !paused)}
                      onClick={() => {
                        if (!window.confirm(
                          `Abandon branch ${formatBranchDisplayName(b)}?`,
                        )) return;
                        const reason = window.prompt(
                          "Abandon reason (optional)?",
                          "",
                        ) ?? "";
                        abandonMut.mutate({ branchId: b.id, body: { reason } });
                      }}
                    />
                  </div>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

function BranchOpButton({
  label,
  title,
  onClick,
  disabled,
  variant,
}: {
  label: string;
  title: string;
  onClick: () => void;
  disabled?: boolean;
  variant?: "accent" | "danger";
}) {
  const base =
    "text-3xs font-mono px-2 py-0.5 rounded border transition-colors disabled:opacity-40 disabled:cursor-not-allowed";
  const style =
    variant === "accent"
      ? "bg-accent text-white border-accent hover:bg-accent/90"
      : variant === "danger"
        ? "bg-surface border-border-danger text-text-danger hover:bg-surface-hover"
        : "bg-surface border-border-default hover:bg-surface-hover";
  return (
    <button
      type="button"
      title={title}
      disabled={disabled}
      onClick={onClick}
      className={`${base} ${style}`}
    >
      {label}
    </button>
  );
}
