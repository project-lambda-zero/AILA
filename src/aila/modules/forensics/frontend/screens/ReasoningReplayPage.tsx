import { useEffect, useMemo, useState } from "react";
import { useNavigate, useParams } from "react-router";

import { GitBranch } from "@phosphor-icons/react/dist/csr/GitBranch";

import { AilaBadge } from "@/components/aila/AilaBadge";
import { AilaCard } from "@/components/aila/AilaCard";
import { EmptyState } from "@/components/aila/EmptyState";
import { LoadingSkeleton } from "@/components/aila/LoadingSkeleton";
import { useUpdatePageHeader } from "@/components/aila/PageHeaderContext";

import { PanelBoundary } from "../components/PanelBoundary";
import { SnapshotListSkeleton } from "../components/skeletons";
import {
  useInvestigationDetail,
  useReasoningGraphDiff,
  useReasoningGraphs,
} from "../queries";
import type {
  ReasoningGraphEdge,
  ReasoningGraphNode,
  ReasoningGraphSnapshot,
} from "../types";

function formatTs(ts: string | null): string {
  if (!ts) return "-";
  try {
    return new Date(ts).toLocaleString();
  } catch {
    return ts;
  }
}

function NodeRow({ node }: { node: ReasoningGraphNode }) {
  return (
    <li className="flex items-baseline gap-2 font-mono text-xs">
      <span className="text-text-muted uppercase tracking-wide shrink-0" style={{ minWidth: "9rem" }}>
        {node.kind}
      </span>
      <span className="text-text-muted shrink-0" style={{ minWidth: "10rem" }}>
        {node.id}
      </span>
      <span className="text-foreground break-all">{node.label}</span>
    </li>
  );
}

function EdgeRow({ edge }: { edge: ReasoningGraphEdge }) {
  return (
    <li className="flex items-baseline gap-2 font-mono text-xs">
      <span className="text-text-muted uppercase tracking-wide shrink-0" style={{ minWidth: "9rem" }}>
        {edge.kind}
      </span>
      <span className="text-foreground break-all">
        {edge.source} <span className="text-text-muted">-&gt;</span> {edge.target}
      </span>
    </li>
  );
}

interface DiffPanelProps {
  projectId: string;
  investigationId: string;
  fromStep: number | null;
  toStep: number | null;
}

function DiffPanel({ projectId, investigationId, fromStep, toStep }: DiffPanelProps) {
  const { data, isLoading, isError, error } = useReasoningGraphDiff(
    projectId,
    investigationId,
    fromStep,
    toStep,
  );

  if (fromStep === null || toStep === null) {
    return (
      <AilaCard className="border-border" techBorder glow>
        <p className="text-xs text-text-muted">
          Pick a from-step and a to-step above to see the diff.
        </p>
      </AilaCard>
    );
  }
  if (isLoading) return <LoadingSkeleton size="md" width="full" />;
  if (isError || !data) {
    return (
      <AilaCard className="border-border-danger" techBorder glow>
        <p className="text-sm text-text-danger">
          Failed to load diff{error instanceof Error ? `: ${error.message}` : "."}
        </p>
      </AilaCard>
    );
  }

  const { diff } = data;
  const addedN = diff.added_nodes.length;
  const removedN = diff.removed_nodes.length;
  const addedE = diff.added_edges.length;
  const removedE = diff.removed_edges.length;

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap gap-2 items-center text-xs text-text-muted font-mono">
        <span>
          step {diff.from_step} <span className="text-foreground">-&gt;</span> step {diff.to_step}
        </span>
        <AilaBadge severity="low" size="sm">+{addedN} nodes</AilaBadge>
        <AilaBadge severity="high" size="sm">-{removedN} nodes</AilaBadge>
        <AilaBadge severity="low" size="sm">+{addedE} edges</AilaBadge>
        <AilaBadge severity="high" size="sm">-{removedE} edges</AilaBadge>
      </div>

      <div className="grid gap-3 md:grid-cols-2">
        <AilaCard className="border-emerald-700/40 bg-emerald-950/10" techBorder glow>
          <div className="space-y-2">
            <p className="text-xs font-mono uppercase tracking-wide text-emerald-300">
              Added nodes ({addedN})
            </p>
            {addedN === 0 ? (
              <p className="text-xs text-text-muted">None.</p>
            ) : (
              <ul className="space-y-1">
                {diff.added_nodes.map((n) => (
                  <NodeRow key={`add-n-${n.id}`} node={n} />
                ))}
              </ul>
            )}
          </div>
        </AilaCard>
        <AilaCard className="border-rose-700/40 bg-rose-950/10" techBorder glow>
          <div className="space-y-2">
            <p className="text-xs font-mono uppercase tracking-wide text-rose-300">
              Removed nodes ({removedN})
            </p>
            {removedN === 0 ? (
              <p className="text-xs text-text-muted">None.</p>
            ) : (
              <ul className="space-y-1">
                {diff.removed_nodes.map((n) => (
                  <NodeRow key={`rem-n-${n.id}`} node={n} />
                ))}
              </ul>
            )}
          </div>
        </AilaCard>
        <AilaCard className="border-emerald-700/40 bg-emerald-950/10" techBorder glow>
          <div className="space-y-2">
            <p className="text-xs font-mono uppercase tracking-wide text-emerald-300">
              Added edges ({addedE})
            </p>
            {addedE === 0 ? (
              <p className="text-xs text-text-muted">None.</p>
            ) : (
              <ul className="space-y-1">
                {diff.added_edges.map((e, i) => (
                  <EdgeRow key={`add-e-${i}-${e.source}-${e.target}`} edge={e} />
                ))}
              </ul>
            )}
          </div>
        </AilaCard>
        <AilaCard className="border-rose-700/40 bg-rose-950/10" techBorder glow>
          <div className="space-y-2">
            <p className="text-xs font-mono uppercase tracking-wide text-rose-300">
              Removed edges ({removedE})
            </p>
            {removedE === 0 ? (
              <p className="text-xs text-text-muted">None.</p>
            ) : (
              <ul className="space-y-1">
                {diff.removed_edges.map((e, i) => (
                  <EdgeRow key={`rem-e-${i}-${e.source}-${e.target}`} edge={e} />
                ))}
              </ul>
            )}
          </div>
        </AilaCard>
      </div>
    </div>
  );
}

interface SnapshotDetailProps {
  snapshot: ReasoningGraphSnapshot;
}

function SnapshotDetail({ snapshot }: SnapshotDetailProps) {
  const nodeCount = snapshot.graph.nodes.length;
  const edgeCount = snapshot.graph.edges.length;
  return (
    <AilaCard className="border-border" techBorder glow>
      <div className="space-y-2">
        <div className="flex flex-wrap items-baseline gap-3">
          <p className="text-sm font-mono text-foreground">
            step {snapshot.step_number}
          </p>
          <p className="text-xs font-mono text-text-muted">
            {snapshot.strategy_family}
          </p>
          <p className="text-xs text-text-muted">
            {formatTs(snapshot.created_at)}
          </p>
          <AilaBadge severity="info" size="sm">
            {nodeCount} nodes
          </AilaBadge>
          <AilaBadge severity="info" size="sm">
            {edgeCount} edges
          </AilaBadge>
        </div>
        <p className="text-xs text-text-muted font-mono break-all">
          snapshot {snapshot.id}
        </p>
      </div>
    </AilaCard>
  );
}

export function ReasoningReplayPage() {
  const { projectId, investigationId } = useParams<{
    projectId: string;
    investigationId: string;
  }>();
  const navigate = useNavigate();

  const { data: investigation } = useInvestigationDetail(
    projectId ?? "",
    investigationId ?? "",
  );
  const {
    data: snapshots,
    isLoading,
    isError,
  } = useReasoningGraphs(projectId ?? "", investigationId ?? "");

  useUpdatePageHeader({
    title: "Reasoning Replay",
    subtitle: investigation
      ? `Investigation ${investigationId?.slice(0, 8) ?? ""}`
      : undefined,
  });

  const sorted = useMemo(
    () => (snapshots ? [...snapshots].sort((a, b) => a.step_number - b.step_number) : []),
    [snapshots],
  );

  const [selectedStep, setSelectedStep] = useState<number | null>(null);
  const [fromStep, setFromStep] = useState<number | null>(null);
  const [toStep, setToStep] = useState<number | null>(null);

  // Seed selections once snapshots arrive. Default: focus the latest step,
  // diff between first and last.
  useEffect(() => {
    if (sorted.length === 0) return;
    const first = sorted[0].step_number;
    const last = sorted[sorted.length - 1].step_number;
    setSelectedStep((prev) => (prev === null ? last : prev));
    setFromStep((prev) => (prev === null ? first : prev));
    setToStep((prev) => (prev === null ? last : prev));
  }, [sorted]);

  if (!projectId || !investigationId) {
    return (
      <AilaCard className="border-border-danger" techBorder glow>
        <p className="text-sm text-text-danger">Invalid replay URL.</p>
      </AilaCard>
    );
  }

  if (isLoading) return <SnapshotListSkeleton count={8} />;

  if (isError) {
    return (
      <AilaCard className="border-border-danger" techBorder glow>
        <p className="text-sm text-text-danger">
          Failed to load reasoning-graph snapshots.
        </p>
      </AilaCard>
    );
  }

  if (sorted.length === 0) {
    return (
      <div className="space-y-4">
        <button
          type="button"
          onClick={() =>
            navigate(`/forensics/projects/${projectId}/investigations/${investigationId}`)
          }
          className="flex items-center gap-1 text-xs text-text-muted hover:text-foreground transition-colors"
        >
          {"\u2190"} Back to investigation
        </button>
        <EmptyState
          icon={<GitBranch className="h-10 w-10" />}
          title="No reasoning-graph snapshots recorded."
          description="The reasoning engine writes one snapshot per turn. If the investigation has not started, or the engine did not emit graphs on this run, this list stays empty."
          action={{
            label: "Back to investigation",
            onClick: () =>
              navigate(`/forensics/projects/${projectId}/investigations/${investigationId}`),
          }}
        />
      </div>
    );
  }

  const selectedSnapshot =
    selectedStep === null
      ? null
      : sorted.find((s) => s.step_number === selectedStep) ?? null;

  const minStep = sorted[0].step_number;
  const maxStep = sorted[sorted.length - 1].step_number;

  const handleFromChange = (value: number) => {
    const clamped = Math.max(minStep, Math.min(maxStep, value));
    setFromStep(clamped);
    if (toStep !== null && clamped > toStep) {
      setToStep(clamped);
    }
  };

  const handleToChange = (value: number) => {
    const clamped = Math.max(minStep, Math.min(maxStep, value));
    setToStep(clamped);
    if (fromStep !== null && clamped < fromStep) {
      setFromStep(clamped);
    }
  };

  return (
    <div className="space-y-4">
      <button
        type="button"
        onClick={() =>
          navigate(`/forensics/projects/${projectId}/investigations/${investigationId}`)
        }
        className="flex items-center gap-1 text-xs text-text-muted hover:text-foreground transition-colors"
      >
        {"\u2190"} Back to investigation
      </button>

      {/* Timeline */}
      <AilaCard className="border-border" techBorder glow>
        <div className="space-y-2">
          <p className="text-xs font-mono uppercase tracking-wide text-text-muted">
            Snapshots ({sorted.length})
          </p>
          <ul className="space-y-1 overflow-y-auto" style={{ maxHeight: "18rem" }}>
            {sorted.map((snap) => {
              const isSelected = snap.step_number === selectedStep;
              return (
                <li key={snap.id}>
                  <button
                    type="button"
                    onClick={() => setSelectedStep(snap.step_number)}
                    className={`w-full text-left px-2 py-1 rounded-md border transition-colors font-mono text-xs flex items-center gap-3 flex-wrap ${
                      isSelected
                        ? "border-border-accent bg-accent/10 text-foreground"
                        : "border-border bg-surface hover:bg-surface-secondary text-text-muted hover:text-foreground"
                    }`}
                  >
                    <span className="shrink-0" style={{ minWidth: "4rem" }}>
                      step {snap.step_number}
                    </span>
                    <span className="shrink-0" style={{ minWidth: "10rem" }}>
                      {snap.strategy_family}
                    </span>
                    <span className="shrink-0">{formatTs(snap.created_at)}</span>
                    <span className="ml-auto shrink-0">
                      {snap.graph.nodes.length}n / {snap.graph.edges.length}e
                    </span>
                  </button>
                </li>
              );
            })}
          </ul>
        </div>
      </AilaCard>

      {/* Selected snapshot */}
      {selectedSnapshot && <SnapshotDetail snapshot={selectedSnapshot} />}

      {/* Range controls */}
      <AilaCard className="border-border" techBorder glow>
        <div className="space-y-3">
          <p className="text-xs font-mono uppercase tracking-wide text-text-muted">
            Diff range (step {minStep} .. step {maxStep})
          </p>
          <div className="grid gap-3 md:grid-cols-2">
            <div className="space-y-1">
              <label className="text-xs text-text-muted font-mono flex items-baseline justify-between gap-2">
                <span>from step</span>
                <span className="text-foreground">{fromStep ?? "-"}</span>
              </label>
              <input
                type="range"
                min={minStep}
                max={maxStep}
                step={1}
                value={fromStep ?? minStep}
                onChange={(e) => handleFromChange(Number(e.target.value))}
                className="w-full"
              />
              <select
                className="w-full bg-surface border border-border rounded-md px-2 py-1 text-xs font-mono text-foreground"
                value={fromStep ?? ""}
                onChange={(e) => handleFromChange(Number(e.target.value))}
              >
                {sorted.map((snap) => (
                  <option key={`from-${snap.id}`} value={snap.step_number}>
                    step {snap.step_number} -- {snap.strategy_family}
                  </option>
                ))}
              </select>
            </div>
            <div className="space-y-1">
              <label className="text-xs text-text-muted font-mono flex items-baseline justify-between gap-2">
                <span>to step</span>
                <span className="text-foreground">{toStep ?? "-"}</span>
              </label>
              <input
                type="range"
                min={minStep}
                max={maxStep}
                step={1}
                value={toStep ?? maxStep}
                onChange={(e) => handleToChange(Number(e.target.value))}
                className="w-full"
              />
              <select
                className="w-full bg-surface border border-border rounded-md px-2 py-1 text-xs font-mono text-foreground"
                value={toStep ?? ""}
                onChange={(e) => handleToChange(Number(e.target.value))}
              >
                {sorted.map((snap) => (
                  <option key={`to-${snap.id}`} value={snap.step_number}>
                    step {snap.step_number} -- {snap.strategy_family}
                  </option>
                ))}
              </select>
            </div>
          </div>
        </div>
      </AilaCard>

      {/* Diff */}
      <PanelBoundary label="Reasoning graph diff">
        <DiffPanel
          projectId={projectId}
          investigationId={investigationId}
          fromStep={fromStep}
          toStep={toStep}
        />
      </PanelBoundary>
    </div>
  );
}
