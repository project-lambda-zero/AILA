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

import { WindowPanel } from "@/components/aila/WindowPanel";
import { SectionHeader, MonoBadge } from "@/components/aila/mock";

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
import { personaMeta } from "../components/personaMeta";

/** Persona-voice values operators can attach to a spawn / fork. Mirrors
 *  PersonaVoice in contracts/enums.py (core roles only -- specialists are
 *  on-demand and belong on a dedicated spawn UI). */
const PERSONA_VOICES: readonly PersonaVoice[] = [
  "halvar", "maddie", "yuki", "renzo", "noor", "wei",
];

// Branch node fill per status -- mock tokens.
const STATUS_COLORS: Record<BranchStatus, string> = {
  active: "var(--status-ok)",
  paused: "var(--status-warn)",
  merged: "var(--status-info)",
  promoted: "var(--status-ok)",
  completed: "var(--status-info)",
  abandoned: "var(--text-faint)",
};

const STATUS_BORDER: Record<BranchStatus, string> = {
  active: "color-mix(in srgb, var(--status-ok) 68%, var(--surface-sunk))",
  paused: "color-mix(in srgb, var(--status-warn) 68%, var(--surface-sunk))",
  merged: "color-mix(in srgb, var(--status-info) 68%, var(--surface-sunk))",
  promoted: "color-mix(in srgb, var(--status-ok) 68%, var(--surface-sunk))",
  completed: "color-mix(in srgb, var(--status-info) 68%, var(--surface-sunk))",
  abandoned: "color-mix(in srgb, var(--text-faint) 78%, var(--surface-sunk))",
};

const BRANCH_STATUS_TONE: Record<BranchStatus, string> = {
  active: "ok",
  paused: "warn",
  merged: "info",
  promoted: "ok",
  completed: "info",
  abandoned: "muted",
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
    if (a === "__no_strategy__") return -1;
    if (b === "__no_strategy__") return 1;
    return a.localeCompare(b);
  });

  const nodes: Node[] = [];

  orderedClusters.forEach((cluster, colIdx) => {
    const x = colIdx * STRATEGY_X_GAP;
    const branches = columns.get(cluster) ?? [];

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
        color: "var(--text-faint)",
        fontSize: 11,
        fontFamily: "var(--font-mono)",
        width: 240,
      },
      draggable: false,
      selectable: false,
    });

    branches.forEach((b, rowIdx) => {
      const colour = STATUS_COLORS[b.status] ?? "var(--text-faint)";
      const border =
        STATUS_BORDER[b.status] ??
        "color-mix(in srgb, var(--text-faint) 60%, var(--surface-sunk))";
      nodes.push({
        id: b.id,
        type: "default",
        position: { x, y: rowIdx * BRANCH_Y_GAP },
        data: {
          label: (
            <div
              style={{
                textAlign: "left",
                color: "var(--text-on-accent)",
                fontSize: 11,
                fontFamily: "var(--font-mono)",
              }}
            >
              <div style={{ fontWeight: 600 }}>
                {formatBranchDisplayName(b)}
                {b.fork_at_turn != null ? ` @t${b.fork_at_turn}` : ""}
              </div>
              <div style={{ opacity: 0.85 }}>
                {b.status} · turns:{b.turn_count}
              </div>
              <div style={{ opacity: 0.7, fontSize: 10 }}>
                ${b.branch_cost_usd.toFixed(2)}
              </div>
            </div>
          ),
        },
        style: {
          background: colour,
          color: "var(--text-on-accent)",
          border: `2px solid ${border}`,
          borderRadius: 4,
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
        labelStyle: { fontSize: 10, fill: "var(--text-faint)" },
        style: { stroke: "var(--border)", strokeWidth: 1.5 },
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
        labelStyle: { fontSize: 10, fill: "var(--status-info)" },
        style: { stroke: "var(--status-info)", strokeDasharray: "4 4" },
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

  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [showSpawn, setShowSpawn] = useState(false);

  const { nodes, edges } = useMemo(() => {
    const clustered = clusterBranches(branches);
    return {
      nodes: layoutNodes(clustered),
      edges: buildEdges(branches),
    };
  }, [branches]);

  const selected = useMemo(
    () => branches.find((b) => b.id === selectedId) ?? branches[0],
    [branches, selectedId],
  );

  if (invLoading || branchesLoading) {
    return (
      <div className="flex flex-col" style={{ gap: 14 }}>
        <SectionHeader icon="⌥" title="Branch Tree" />
        <WindowPanel title="loading" tone="muted">
          <p
            className="font-mono"
            style={{ fontSize: 11, color: "var(--text-muted)" }}
          >
            loading branches…
          </p>
        </WindowPanel>
      </div>
    );
  }

  if (!inv) {
    return (
      <div className="flex flex-col" style={{ gap: 14 }}>
        <SectionHeader icon="⌥" title="Branch Tree" />
        <WindowPanel title="not found" tone="warn">
          <p
            className="font-mono"
            style={{ fontSize: 11, color: "var(--accent)" }}
          >
            investigation {invId} not found.
          </p>
        </WindowPanel>
      </div>
    );
  }

  const statusCounts = branches.reduce<Record<string, number>>((acc, b) => {
    acc[b.status] = (acc[b.status] ?? 0) + 1;
    return acc;
  }, {});

  return (
    <div className="flex flex-col" style={{ gap: 14 }}>
      <SectionHeader
        icon="⌥"
        title="Branch Tree"
        actions={
          <div className="flex items-center" style={{ gap: 8 }}>
            <span
              className="font-mono uppercase"
              style={{
                fontSize: 9,
                letterSpacing: "0.12em",
                color: "var(--text-faint)",
              }}
              title={inv.title}
            >
              {inv.title.length > 42 ? inv.title.slice(0, 40) + "…" : inv.title}
            </span>
            <button
              type="button"
              onClick={() => setShowSpawn((v) => !v)}
              className="font-mono uppercase"
              style={{
                height: 26,
                padding: "0 11px",
                fontSize: 9.5,
                letterSpacing: "0.08em",
                borderRadius: 3,
                border: `1px solid ${showSpawn ? "var(--accent)" : "var(--border-soft)"}`,
                background: showSpawn
                  ? "color-mix(in srgb, var(--accent) 11%, transparent)"
                  : "transparent",
                color: showSpawn ? "var(--accent)" : "var(--text-primary)",
                cursor: "pointer",
              }}
            >
              spawn strategy branch
            </button>
          </div>
        }
      />

      {/* status counts strip */}
      <WindowPanel title="branch states" tone="info">
        <div className="flex flex-wrap items-center" style={{ gap: 8 }}>
          {(
            [
              "active",
              "paused",
              "merged",
              "promoted",
              "completed",
              "abandoned",
            ] as BranchStatus[]
          ).map((s) => (
            <MonoBadge key={s} tone={BRANCH_STATUS_TONE[s]}>
              {s}: {statusCounts[s] ?? 0}
            </MonoBadge>
          ))}
          <span style={{ flex: 1 }} />
          <span
            className="font-mono"
            style={{ fontSize: 10, color: "var(--text-muted)" }}
          >
            {branches.length} branch{branches.length === 1 ? "" : "es"}
          </span>
        </div>
      </WindowPanel>

      {showSpawn && (
        <WindowPanel title="spawn strategy branch" tone="muted">
          <StrategyBranchSpawnForm invId={invId} branches={branches} />
        </WindowPanel>
      )}

      {/* main tree + right rail */}
      <div
        className="grid"
        style={{ gridTemplateColumns: "1fr 340px", gap: 14 }}
      >
        <PanelBoundary
          label="Branch tree"
          invalidateKeyPrefix={["vr", "investigation-branches", invId]}
        >
          <WindowPanel
            title="tree"
            tone="accent"
            flush
            status={
              branches.length === 0
                ? "no branches yet -- spawn one via the strategy form"
                : undefined
            }
          >
            <div style={{ width: "100%", height: 600 }}>
              <ReactFlow
                nodes={nodes}
                edges={edges}
                fitView
                nodesDraggable
                nodesConnectable={false}
                elementsSelectable
                proOptions={{ hideAttribution: true }}
                onNodeClick={(_, n) => {
                  if (!n.id.startsWith("__cluster__:")) setSelectedId(n.id);
                }}
              >
                <Background gap={20} size={1} color="var(--border)" />
                <Controls showInteractive={false} />
              </ReactFlow>
            </div>
          </WindowPanel>
        </PanelBoundary>

        <SelectedBranchRail invId={invId} branch={selected} />
      </div>

      {/* legend */}
      <WindowPanel title="legend" tone="muted">
        <div
          className="grid"
          style={{
            gridTemplateColumns: "repeat(6, minmax(0, 1fr))",
            gap: 12,
          }}
        >
          {(
            [
              "active",
              "paused",
              "merged",
              "promoted",
              "completed",
              "abandoned",
            ] as BranchStatus[]
          ).map((s) => (
            <div key={s} className="flex items-center" style={{ gap: 8 }}>
              <span
                aria-hidden
                style={{
                  width: 12,
                  height: 12,
                  background: STATUS_COLORS[s],
                  border: `1px solid ${STATUS_BORDER[s]}`,
                  borderRadius: 2,
                  flex: "0 0 auto",
                }}
              />
              <span
                className="font-mono uppercase"
                style={{
                  fontSize: 9,
                  letterSpacing: "0.1em",
                  color: "var(--text-muted)",
                }}
              >
                {s}
              </span>
            </div>
          ))}
        </div>
      </WindowPanel>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Selected branch rail -- persona tile + brief rows + op buttons.
// ---------------------------------------------------------------------------
function SelectedBranchRail({
  invId,
  branch,
}: {
  invId: string;
  branch: VRBranchSummary | undefined;
}) {
  const forkMut = useForkBranch(invId);
  const promoteMut = usePromoteBranch(invId);
  const abandonMut = useAbandonBranch(invId);
  const pauseMut = usePauseBranch(invId);
  const resumeMut = useResumeBranch(invId);

  if (!branch) {
    return (
      <WindowPanel title="selected branch" tone="muted">
        <p
          className="font-mono"
          style={{ fontSize: 11, color: "var(--text-muted)" }}
        >
          no branch selected. click a node in the tree.
        </p>
      </WindowPanel>
    );
  }

  const pm = personaMeta(branch.persona_voice);
  const active = branch.status === "active";
  const paused = branch.status === "paused";

  const opsPending =
    forkMut.isPending ||
    promoteMut.isPending ||
    abandonMut.isPending ||
    pauseMut.isPending ||
    resumeMut.isPending;

  return (
    <WindowPanel title="selected branch" tone="info">
      <div className="flex flex-col" style={{ gap: 12 }}>
        <div className="flex items-center" style={{ gap: 10 }}>
          <span
            aria-hidden
            className="flex items-center justify-center font-mono uppercase"
            style={{
              width: 22,
              height: 22,
              flex: "0 0 auto",
              fontSize: 11,
              color: pm.hue,
              background: `color-mix(in srgb, ${pm.hue} 18%, transparent)`,
              border: `1px solid color-mix(in srgb, ${pm.hue} 40%, transparent)`,
              borderRadius: 3,
            }}
          >
            {pm.initial}
          </span>
          <div className="flex flex-col" style={{ minWidth: 0, gap: 2 }}>
            <span
              className="font-mono"
              style={{
                fontSize: 12,
                color: "var(--text-primary)",
                fontWeight: 600,
                lineHeight: 1.2,
              }}
              title={formatBranchDisplayName(branch)}
            >
              {formatBranchDisplayName(branch)}
            </span>
            <span
              className="font-mono uppercase"
              style={{
                fontSize: 8.5,
                letterSpacing: "0.1em",
                color: "var(--text-faint)",
              }}
            >
              {branch.strategy_family ?? "(no strategy)"}
            </span>
          </div>
        </div>

        <BriefRows
          rows={[
            {
              label: "status",
              value: (
                <MonoBadge tone={BRANCH_STATUS_TONE[branch.status]}>
                  {branch.status}
                </MonoBadge>
              ),
            },
            {
              label: "fork at",
              value:
                branch.fork_at_turn != null ? (
                  <span>t{branch.fork_at_turn}</span>
                ) : (
                  <span style={{ color: "var(--text-faint)" }}>root</span>
                ),
            },
            { label: "turns", value: <span>{branch.turn_count}</span> },
            {
              label: "cost",
              value: <span>${branch.branch_cost_usd.toFixed(2)}</span>,
            },
            {
              label: "persona",
              value: (
                <span style={{ color: pm.hue }}>
                  {branch.persona_voice ?? "\u2014"}
                </span>
              ),
            },
          ]}
        />

        <div className="flex flex-wrap" style={{ gap: 6 }}>
          <OpButton
            label="fork"
            disabled={opsPending || !active}
            onClick={() => {
              const reason = window.prompt(
                `Fork reason for branch ${formatBranchDisplayName(branch)}?`,
                "",
              );
              if (reason == null) return;
              forkMut.mutate({ branchId: branch.id, body: { reason } });
            }}
          />
          {paused ? (
            <OpButton
              label="resume"
              disabled={opsPending}
              onClick={() => {
                const reason =
                  window.prompt("Resume reason (optional)?", "") ?? "";
                resumeMut.mutate({ branchId: branch.id, body: { reason } });
              }}
            />
          ) : (
            <OpButton
              label="pause"
              disabled={opsPending || !active}
              onClick={() => {
                const reason =
                  window.prompt("Pause reason (optional)?", "") ?? "";
                pauseMut.mutate({ branchId: branch.id, body: { reason } });
              }}
            />
          )}
          <OpButton
            label="promote"
            variant="accent"
            disabled={opsPending || !active}
            onClick={() => {
              if (
                !window.confirm(
                  `Promote branch ${formatBranchDisplayName(branch)}?\n\n` +
                    `Sibling ACTIVE branches will be ABANDONED.`,
                )
              )
                return;
              const reason =
                window.prompt("Promotion reason (optional)?", "") ?? "";
              promoteMut.mutate({ branchId: branch.id, body: { reason } });
            }}
          />
          <OpButton
            label="abandon"
            variant="danger"
            disabled={opsPending || (!active && !paused)}
            onClick={() => {
              if (
                !window.confirm(
                  `Abandon branch ${formatBranchDisplayName(branch)}?`,
                )
              )
                return;
              const reason =
                window.prompt("Abandon reason (optional)?", "") ?? "";
              abandonMut.mutate({ branchId: branch.id, body: { reason } });
            }}
          />
        </div>
      </div>
    </WindowPanel>
  );
}

// ---------------------------------------------------------------------------
// Strategy branch spawn form -- mono inputs, mock button.
// ---------------------------------------------------------------------------
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
      className="flex flex-col"
      style={{ gap: 10 }}
    >
      <p
        className="font-mono"
        style={{ fontSize: 10, color: "var(--text-muted)", lineHeight: 1.5 }}
      >
        POST /vr/investigations/{"{id}"}/strategy-branches — leave parent empty
        for a genuinely parallel strategy; pick a parent to inherit its
        case_state.
      </p>
      <div
        className="grid"
        style={{
          gridTemplateColumns: "repeat(3, minmax(0, 1fr))",
          gap: 10,
        }}
      >
        <FormField label="strategy family (required)">
          <MonoInput
            type="text"
            value={strategyFamily}
            onChange={(e) => setStrategyFamily(e.target.value)}
            placeholder="e.g. taint-first, memory-corruption"
            maxLength={128}
          />
        </FormField>
        <FormField label="persona voice">
          <MonoSelect
            value={personaVoice}
            onChange={(e) =>
              setPersonaVoice(e.target.value as PersonaVoice | "")
            }
          >
            <option value="">(none)</option>
            {PERSONA_VOICES.map((v) => (
              <option key={v} value={v}>
                {v}
              </option>
            ))}
          </MonoSelect>
        </FormField>
        <FormField label="parent branch (optional -- inherits case_state)">
          <MonoSelect
            value={parentBranchId}
            onChange={(e) => setParentBranchId(e.target.value)}
          >
            <option value="">(fresh — no parent)</option>
            {branches.map((b) => (
              <option key={b.id} value={b.id}>
                {formatBranchDisplayName(b)} · {b.status}
              </option>
            ))}
          </MonoSelect>
        </FormField>
      </div>
      <FormField label="rationale (optional)">
        <textarea
          value={rationale}
          onChange={(e) => setRationale(e.target.value)}
          placeholder="why this strategy is worth exploring"
          rows={2}
          maxLength={2048}
          className="font-mono"
          style={{
            width: "100%",
            padding: "6px 8px",
            fontSize: 11,
            color: "var(--text-primary)",
            background: "var(--surface-sunk)",
            border: "1px solid var(--border-soft)",
            borderRadius: 2,
            outline: "none",
            resize: "vertical",
          }}
        />
      </FormField>
      <div className="flex justify-end">
        <button
          type="submit"
          disabled={disabled}
          className="font-mono uppercase"
          style={{
            height: 26,
            padding: "0 12px",
            fontSize: 9.5,
            letterSpacing: "0.08em",
            borderRadius: 3,
            border: "1px solid var(--accent)",
            background: disabled ? "transparent" : "var(--accent)",
            color: disabled ? "var(--text-faint)" : "var(--text-on-accent)",
            cursor: disabled ? "not-allowed" : "pointer",
          }}
        >
          {spawnMut.isPending ? "spawning…" : "spawn branch"}
        </button>
      </div>
    </form>
  );
}

// ---------------------------------------------------------------------------
// Shared mock primitives (kept local so this screen doesn't force a
// public re-export from the mock kit).
// ---------------------------------------------------------------------------
function BriefRows({
  rows,
}: {
  rows: { label: string; value: React.ReactNode }[];
}) {
  return (
    <div className="flex flex-col">
      {rows.map((r, i) => (
        <div
          key={r.label}
          className="grid items-center"
          style={{
            gridTemplateColumns: "76px 1fr",
            gap: 10,
            padding: "5px 0",
            borderTop: i === 0 ? "none" : "1px solid var(--border-faint)",
          }}
        >
          <span
            className="font-mono uppercase"
            style={{
              fontSize: 9,
              letterSpacing: "0.12em",
              color: "var(--text-faint)",
            }}
          >
            {r.label}
          </span>
          <span
            className="font-mono"
            style={{
              fontSize: 11,
              color: "var(--text-primary)",
              minWidth: 0,
            }}
          >
            {r.value}
          </span>
        </div>
      ))}
    </div>
  );
}

function OpButton({
  label,
  onClick,
  disabled,
  variant,
}: {
  label: string;
  onClick: () => void;
  disabled?: boolean;
  variant?: "accent" | "danger";
}) {
  const accent = variant === "accent";
  const danger = variant === "danger";
  return (
    <button
      type="button"
      disabled={disabled}
      onClick={onClick}
      className="font-mono uppercase"
      style={{
        height: 22,
        padding: "0 9px",
        fontSize: 9,
        letterSpacing: "0.1em",
        borderRadius: 2,
        border: `1px solid ${
          disabled
            ? "var(--border-soft)"
            : accent
              ? "var(--accent)"
              : danger
                ? "var(--accent)"
                : "var(--border-soft)"
        }`,
        background: disabled
          ? "transparent"
          : accent
            ? "var(--accent)"
            : "transparent",
        color: disabled
          ? "var(--text-faint)"
          : accent
            ? "var(--text-on-accent)"
            : danger
              ? "var(--accent)"
              : "var(--text-primary)",
        cursor: disabled ? "not-allowed" : "pointer",
      }}
    >
      {label}
    </button>
  );
}

function FormField({
  label,
  children,
}: {
  label: string;
  children: React.ReactNode;
}) {
  return (
    <label className="flex flex-col" style={{ gap: 4 }}>
      <span
        className="font-mono uppercase"
        style={{
          fontSize: 9,
          letterSpacing: "0.12em",
          color: "var(--text-faint)",
        }}
      >
        {label}
      </span>
      {children}
    </label>
  );
}

function MonoInput(
  props: React.InputHTMLAttributes<HTMLInputElement>,
) {
  const { style, className, ...rest } = props;
  return (
    <input
      {...rest}
      className={`font-mono ${className ?? ""}`}
      style={{
        width: "100%",
        padding: "5px 8px",
        fontSize: 11,
        color: "var(--text-primary)",
        background: "var(--surface-sunk)",
        border: "1px solid var(--border-soft)",
        borderRadius: 2,
        outline: "none",
        ...style,
      }}
    />
  );
}

function MonoSelect(
  props: React.SelectHTMLAttributes<HTMLSelectElement> & {
    children: React.ReactNode;
  },
) {
  const { style, className, children, ...rest } = props;
  return (
    <select
      {...rest}
      className={`font-mono ${className ?? ""}`}
      style={{
        width: "100%",
        padding: "5px 8px",
        fontSize: 11,
        color: "var(--text-primary)",
        background: "var(--surface-sunk)",
        border: "1px solid var(--border-soft)",
        borderRadius: 2,
        outline: "none",
        ...style,
      }}
    >
      {children}
    </select>
  );
}
