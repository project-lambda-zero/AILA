import { useEffect, useMemo, useState } from "react";
import { useNavigate, useParams } from "react-router";

import { GitBranch } from "@phosphor-icons/react/dist/csr/GitBranch";

import { LoadingSkeleton } from "@/components/aila/LoadingSkeleton";
import { PixelIcon } from "@/components/aila/PixelIcon";
import { WindowPanel } from "@/components/aila/WindowPanel";
import { MonoBadge, SectionHeader } from "@/components/aila/mock";
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

const CHROME_BTN: React.CSSProperties = {
  height: 26,
  padding: "0 10px",
  fontSize: 9.5,
  letterSpacing: "0.08em",
  color: "var(--text-muted)",
  background: "transparent",
  border: "1px solid var(--border-soft)",
  borderRadius: 3,
  cursor: "pointer",
};

const SELECT_BASE: React.CSSProperties = {
  width: "100%",
  height: 28,
  padding: "0 10px",
  fontSize: 11,
  background: "var(--surface-sunk)",
  border: "1px solid var(--border-soft)",
  color: "var(--text-primary)",
  borderRadius: 3,
};

function NodeRow({ node }: { node: ReasoningGraphNode }) {
  return (
    <li
      className="flex items-baseline font-mono"
      style={{ gap: 8, fontSize: 10.5, padding: "3px 0" }}
    >
      <span
        className="uppercase shrink-0"
        style={{
          minWidth: 120,
          letterSpacing: "0.1em",
          color: "var(--text-faint)",
        }}
      >
        {node.kind}
      </span>
      <span
        className="shrink-0"
        style={{ minWidth: 140, color: "var(--text-faint)" }}
      >
        {node.id}
      </span>
      <span className="break-all" style={{ color: "var(--text-primary)" }}>
        {node.label}
      </span>
    </li>
  );
}

function EdgeRow({ edge }: { edge: ReasoningGraphEdge }) {
  return (
    <li
      className="flex items-baseline font-mono"
      style={{ gap: 8, fontSize: 10.5, padding: "3px 0" }}
    >
      <span
        className="uppercase shrink-0"
        style={{
          minWidth: 120,
          letterSpacing: "0.1em",
          color: "var(--text-faint)",
        }}
      >
        {edge.kind}
      </span>
      <span className="break-all" style={{ color: "var(--text-primary)" }}>
        {edge.source}{" "}
        <PixelIcon
          name="arrow"
          size={12}
          className="inline-block align-middle"
          style={{ color: "var(--text-faint)" }}
        />{" "}
        {edge.target}
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

function DiffPanel({
  projectId,
  investigationId,
  fromStep,
  toStep,
}: DiffPanelProps) {
  const { data, isLoading, isError, error } = useReasoningGraphDiff(
    projectId,
    investigationId,
    fromStep,
    toStep,
  );

  if (fromStep === null || toStep === null) {
    return (
      <WindowPanel
        title="graph diff"
        tone="muted"
        status="reasoning ; select a range"
      >
        <p
          className="font-mono"
          style={{ fontSize: 11, color: "var(--text-muted)" }}
        >
          Pick a from-step and a to-step above to see the diff.
        </p>
      </WindowPanel>
    );
  }
  if (isLoading) return <LoadingSkeleton size="md" width="full" />;
  if (isError || !data) {
    return (
      <WindowPanel
        title="graph diff"
        tone="warn"
        status="reasoning ; diff unavailable"
      >
        <p
          className="font-mono"
          style={{ fontSize: 11, color: "var(--accent)" }}
        >
          Failed to load diff
          {error instanceof Error ? `: ${error.message}` : "."}
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
      <div
        className="flex flex-wrap items-center font-mono"
        style={{ gap: 8, fontSize: 10.5, color: "var(--text-muted)" }}
      >
        <span className="inline-flex items-center" style={{ gap: 4 }}>
          step {diff.from_step}{" "}
          <PixelIcon
            name="arrow"
            size={12}
            style={{ color: "var(--text-primary)" }}
          />{" "}
          step {diff.to_step}
        </span>
        <MonoBadge tone="ok">+{addedN} nodes</MonoBadge>
        <MonoBadge tone="high">-{removedN} nodes</MonoBadge>
        <MonoBadge tone="ok">+{addedE} edges</MonoBadge>
        <MonoBadge tone="high">-{removedE} edges</MonoBadge>
      </div>

      <div className="grid gap-3 md:grid-cols-2">
        <WindowPanel title={`added nodes (${addedN})`} tone="ok">
          {addedN === 0 ? (
            <p
              className="font-mono"
              style={{ fontSize: 11, color: "var(--text-muted)" }}
            >
              None.
            </p>
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
            <p
              className="font-mono"
              style={{ fontSize: 11, color: "var(--text-muted)" }}
            >
              None.
            </p>
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
            <p
              className="font-mono"
              style={{ fontSize: 11, color: "var(--text-muted)" }}
            >
              None.
            </p>
          ) : (
            <ul className="space-y-1">
              {diff.added_edges.map((e, i) => (
                <EdgeRow
                  key={`add-e-${i}-${e.source}-${e.target}`}
                  edge={e}
                />
              ))}
            </ul>
          )}
        </WindowPanel>
        <WindowPanel title={`removed edges (${removedE})`} tone="warn">
          {removedE === 0 ? (
            <p
              className="font-mono"
              style={{ fontSize: 11, color: "var(--text-muted)" }}
            >
              None.
            </p>
          ) : (
            <ul className="space-y-1">
              {diff.removed_edges.map((e, i) => (
                <EdgeRow
                  key={`rem-e-${i}-${e.source}-${e.target}`}
                  edge={e}
                />
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
      title={`step ${snapshot.step_number} \u2014 ${snapshot.strategy_family}`}
      status={`snapshot ; ${snapshot.id}`}
    >
      <div
        className="flex flex-wrap items-baseline"
        style={{ gap: 10 }}
      >
        <p
          className="font-mono"
          style={{ fontSize: 10.5, color: "var(--text-faint)" }}
        >
          {formatTs(snapshot.created_at)}
        </p>
        <MonoBadge tone="info">{nodeCount} nodes</MonoBadge>
        <MonoBadge tone="info">{edgeCount} edges</MonoBadge>
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
    () =>
      snapshots
        ? [...snapshots].sort((a, b) => a.step_number - b.step_number)
        : [],
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
      <WindowPanel
        title="reasoning replay"
        tone="warn"
        status="reasoning ; invalid replay url"
      >
        <p
          className="font-mono"
          style={{ fontSize: 11, color: "var(--accent)" }}
        >
          Invalid replay URL.
        </p>
      </WindowPanel>
    );
  }

  if (isLoading) return <SnapshotListSkeleton count={8} />;

  if (isError) {
    return (
      <WindowPanel
        title="reasoning replay"
        tone="warn"
        status="reasoning ; snapshots unavailable"
      >
        <p
          className="font-mono"
          style={{ fontSize: 11, color: "var(--accent)" }}
        >
          Failed to load reasoning-graph snapshots.
        </p>
      </WindowPanel>
    );
  }

  if (sorted.length === 0) {
    return (
      <div className="space-y-4">
        <SectionHeader
          icon={<PixelIcon name="branch" />}
          title="reasoning replay"
          actions={
            <button
              type="button"
              onClick={() =>
                navigate(
                  `/forensics/projects/${projectId}/investigations/${investigationId}`,
                )
              }
              className="font-mono uppercase"
              style={CHROME_BTN}
            >
              {"\u2190"} back to investigation
            </button>
          }
        />
        <WindowPanel
          title="no snapshots"
          tone="muted"
          status="reasoning ; empty replay"
        >
          <div
            className="flex flex-col items-center"
            style={{ gap: 12, padding: "24px 0" }}
          >
            <GitBranch
              aria-hidden="true"
              className="h-10 w-10"
              style={{ color: "var(--text-faint)" }}
            />
            <p
              className="font-mono"
              style={{
                fontSize: 11,
                color: "var(--text-muted)",
                textAlign: "center",
                maxWidth: 480,
                lineHeight: 1.55,
              }}
            >
              No reasoning-graph snapshots recorded. The reasoning engine
              writes one snapshot per turn. If the investigation has not
              started, or the engine did not emit graphs on this run, this
              list stays empty.
            </p>
            <button
              type="button"
              onClick={() =>
                navigate(
                  `/forensics/projects/${projectId}/investigations/${investigationId}`,
                )
              }
              className="font-mono uppercase"
              style={CHROME_BTN}
            >
              back to investigation
            </button>
          </div>
        </WindowPanel>
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
      <SectionHeader
        icon={<PixelIcon name="branch" />}
        title="reasoning replay"
        actions={
          <button
            type="button"
            onClick={() =>
              navigate(
                `/forensics/projects/${projectId}/investigations/${investigationId}`,
              )
            }
            className="font-mono uppercase"
            style={CHROME_BTN}
          >
            {"\u2190"} back to investigation
          </button>
        }
      />

      {/* Timeline */}
      <WindowPanel
        title={`snapshots (${sorted.length})`}
        status="reasoning ; one snapshot per turn"
      >
        <ul
          className="space-y-1 overflow-y-auto"
          style={{ maxHeight: "18rem" }}
        >
          {sorted.map((snap) => {
            const isSelected = snap.step_number === selectedStep;
            return (
              <li key={snap.id}>
                <button
                  type="button"
                  onClick={() => setSelectedStep(snap.step_number)}
                  className="w-full text-left font-mono flex items-center flex-wrap"
                  style={{
                    gap: 12,
                    padding: "6px 10px",
                    borderRadius: 3,
                    fontSize: 10.5,
                    color: isSelected
                      ? "var(--text-primary)"
                      : "var(--text-muted)",
                    background: isSelected
                      ? "color-mix(in srgb, var(--accent) 12%, transparent)"
                      : "var(--surface-card)",
                    border: `1px solid ${
                      isSelected ? "var(--accent)" : "var(--border-soft)"
                    }`,
                    cursor: "pointer",
                  }}
                >
                  <PixelIcon
                    name="cycle"
                    size={12}
                    className="shrink-0"
                    style={
                      isSelected
                        ? { color: "var(--accent)" }
                        : { color: "var(--text-faint)" }
                    }
                  />
                  <span className="shrink-0" style={{ minWidth: 64 }}>
                    step {snap.step_number}
                  </span>
                  <span className="shrink-0" style={{ minWidth: 160 }}>
                    {snap.strategy_family}
                  </span>
                  <span className="shrink-0">
                    {formatTs(snap.created_at)}
                  </span>
                  <span
                    className="ml-auto shrink-0"
                    style={{ color: "var(--text-faint)" }}
                  >
                    {snap.graph.nodes.length}n / {snap.graph.edges.length}e
                  </span>
                </button>
              </li>
            );
          })}
        </ul>
      </WindowPanel>

      {/* Selected snapshot */}
      {selectedSnapshot && <SnapshotDetail snapshot={selectedSnapshot} />}

      {/* Range controls */}
      <WindowPanel
        title={`diff range (step ${minStep} .. step ${maxStep})`}
        status="reasoning ; from / to selection"
      >
        <div className="grid gap-4 md:grid-cols-2">
          <div className="space-y-2">
            <label
              className="font-mono flex items-baseline justify-between"
              style={{
                gap: 8,
                fontSize: 10,
                letterSpacing: "0.08em",
                color: "var(--text-faint)",
              }}
            >
              <span className="uppercase">from step</span>
              <span style={{ color: "var(--text-primary)" }}>
                {fromStep ?? "-"}
              </span>
            </label>
            <input
              type="range"
              min={minStep}
              max={maxStep}
              step={1}
              value={fromStep ?? minStep}
              onChange={(e) => handleFromChange(Number(e.target.value))}
              className="w-full"
              style={{ accentColor: "var(--accent)" }}
            />
            <select
              value={fromStep ?? ""}
              onChange={(e) => handleFromChange(Number(e.target.value))}
              className="font-mono"
              style={SELECT_BASE}
            >
              {sorted.map((snap) => (
                <option key={`from-${snap.id}`} value={snap.step_number}>
                  step {snap.step_number} -- {snap.strategy_family}
                </option>
              ))}
            </select>
          </div>
          <div className="space-y-2">
            <label
              className="font-mono flex items-baseline justify-between"
              style={{
                gap: 8,
                fontSize: 10,
                letterSpacing: "0.08em",
                color: "var(--text-faint)",
              }}
            >
              <span className="uppercase">to step</span>
              <span style={{ color: "var(--text-primary)" }}>
                {toStep ?? "-"}
              </span>
            </label>
            <input
              type="range"
              min={minStep}
              max={maxStep}
              step={1}
              value={toStep ?? maxStep}
              onChange={(e) => handleToChange(Number(e.target.value))}
              className="w-full"
              style={{ accentColor: "var(--accent)" }}
            />
            <select
              value={toStep ?? ""}
              onChange={(e) => handleToChange(Number(e.target.value))}
              className="font-mono"
              style={SELECT_BASE}
            >
              {sorted.map((snap) => (
                <option key={`to-${snap.id}`} value={snap.step_number}>
                  step {snap.step_number} -- {snap.strategy_family}
                </option>
              ))}
            </select>
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
