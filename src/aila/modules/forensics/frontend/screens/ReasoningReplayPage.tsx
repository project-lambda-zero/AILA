import { useEffect, useMemo, useState } from "react";
import { useNavigate, useParams } from "react-router";

import { GitBranch } from "@phosphor-icons/react/dist/csr/GitBranch";

import { AilaBadge } from "@/components/aila/AilaBadge";
import { EmptyState } from "@/components/aila/EmptyState";
import { LoadingSkeleton } from "@/components/aila/LoadingSkeleton";
import { PixelIcon } from "@/components/aila/PixelIcon";
import { WindowPanel } from "@/components/aila/WindowPanel";
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
      <span className="text-muted-foreground uppercase tracking-cyber-sm shrink-0" style={{ minWidth: "9rem" }}>
        {node.kind}
      </span>
      <span className="text-muted-foreground shrink-0" style={{ minWidth: "10rem" }}>
        {node.id}
      </span>
      <span className="text-foreground break-all">{node.label}</span>
    </li>
  );
}

function EdgeRow({ edge }: { edge: ReasoningGraphEdge }) {
  return (
    <li className="flex items-baseline gap-2 font-mono text-xs">
      <span className="text-muted-foreground uppercase tracking-cyber-sm shrink-0" style={{ minWidth: "9rem" }}>
        {edge.kind}
      </span>
      <span className="text-foreground break-all">
        {edge.source} <PixelIcon name="arrow" size={12} className="inline-block align-middle text-muted-foreground" /> {edge.target}
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
      <WindowPanel title="graph diff" tone="muted" status="reasoning ; select a range">
        <p className="text-xs text-text-muted">
          Pick a from-step and a to-step above to see the diff.
        </p>
      </WindowPanel>
    );
  }
  if (isLoading) return <LoadingSkeleton size="md" width="full" />;
  if (isError || !data) {
    return (
      <WindowPanel title="graph diff" tone="warn" status="reasoning ; diff unavailable">
        <p className="text-sm text-critical">
          Failed to load diff{error instanceof Error ? `: ${error.message}` : "."}
        </p>
      </WindowPanel>
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
        <span className="inline-flex items-center gap-1">
          step {diff.from_step} <PixelIcon name="arrow" size={12} className="text-foreground" /> step {diff.to_step}
        </span>
        <AilaBadge severity="low" size="sm">+{addedN} nodes</AilaBadge>
        <AilaBadge severity="high" size="sm">-{removedN} nodes</AilaBadge>
        <AilaBadge severity="low" size="sm">+{addedE} edges</AilaBadge>
        <AilaBadge severity="high" size="sm">-{removedE} edges</AilaBadge>
      </div>

      <div className="grid gap-3 md:grid-cols-2">
        <WindowPanel title={`added nodes (${addedN})`} tone="ok">
          {addedN === 0 ? (
            <p className="text-xs text-text-muted">None.</p>
          ) : (
            <ul className="space-y-1">
              {diff.added_nodes.map((n) => (
                <NodeRow key={`add-n-${n.id}`} node={n} />
              ))}
            </ul>
          )}
        </WindowPanel>
        <WindowPanel title={`removed nodes (${removedN})`} tone="warn">
          {removedN === 0 ? (
            <p className="text-xs text-text-muted">None.</p>
          ) : (
            <ul className="space-y-1">
              {diff.removed_nodes.map((n) => (
                <NodeRow key={`rem-n-${n.id}`} node={n} />
              ))}
            </ul>
          )}
        </WindowPanel>
        <WindowPanel title={`added edges (${addedE})`} tone="ok">
          {addedE === 0 ? (
            <p className="text-xs text-text-muted">None.</p>
          ) : (
            <ul className="space-y-1">
              {diff.added_edges.map((e, i) => (
                <EdgeRow key={`add-e-${i}-${e.source}-${e.target}`} edge={e} />
              ))}
            </ul>
          )}
        </WindowPanel>
        <WindowPanel title={`removed edges (${removedE})`} tone="warn">
          {removedE === 0 ? (
            <p className="text-xs text-text-muted">None.</p>
          ) : (
            <ul className="space-y-1">
              {diff.removed_edges.map((e, i) => (
                <EdgeRow key={`rem-e-${i}-${e.source}-${e.target}`} edge={e} />
              ))}
            </ul>
          )}
        </WindowPanel>
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
    <WindowPanel
      title={`step ${snapshot.step_number} -- ${snapshot.strategy_family}`}
      status={`snapshot ; ${snapshot.id}`}
    >
      <div className="flex flex-wrap items-baseline gap-3">
        <p className="text-xs text-text-muted font-mono">
          {formatTs(snapshot.created_at)}
        </p>
        <AilaBadge severity="info" size="sm">
          {nodeCount} nodes
        </AilaBadge>
        <AilaBadge severity="info" size="sm">
          {edgeCount} edges
        </AilaBadge>
      </div>
    </WindowPanel>
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
      <WindowPanel title="reasoning replay" tone="warn" status="reasoning ; invalid replay url">
        <p className="text-sm text-critical">Invalid replay URL.</p>
      </WindowPanel>
    );
  }

  if (isLoading) return <SnapshotListSkeleton count={8} />;

  if (isError) {
    return (
      <WindowPanel title="reasoning replay" tone="warn" status="reasoning ; snapshots unavailable">
        <p className="text-sm text-critical">
          Failed to load reasoning-graph snapshots.
        </p>
      </WindowPanel>
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
          className="flex items-center gap-1 font-mono text-xs uppercase tracking-cyber-sm text-text-muted hover:text-foreground transition-colors"
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
      <WindowPanel title={`snapshots (${sorted.length})`} status="reasoning ; one snapshot per turn">
        <div className="space-y-2">
          <ul className="space-y-1 overflow-y-auto" style={{ maxHeight: "18rem" }}>
            {sorted.map((snap) => {
              const isSelected = snap.step_number === selectedStep;
              return (
                <li key={snap.id}>
                  <button
                    type="button"
                    onClick={() => setSelectedStep(snap.step_number)}
                    className={`w-full text-left px-2 py-1 rounded-[3px] border transition-colors font-mono text-xs flex items-center gap-3 flex-wrap ${
                      isSelected
                        ? "border-accent bg-accent/10 text-foreground"
                        : "border-border bg-surface hover:bg-elevated text-text-muted hover:text-foreground"
                    }`}
                  >
                    <PixelIcon name="cycle" size={12} className="shrink-0" style={isSelected ? { color: "var(--color-accent)" } : undefined} />
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
      </WindowPanel>

      {/* Selected snapshot */}
      {selectedSnapshot && <SnapshotDetail snapshot={selectedSnapshot} />}

      {/* Range controls */}
      <WindowPanel title={`diff range (step ${minStep} .. step ${maxStep})`}>
        <div className="space-y-3">
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
      </WindowPanel>

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
