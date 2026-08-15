/**
 * WorkflowInspectorPage -- Admin Workflow Inspector at /admin/workflows.
 *
 * Rebuilt to the AILA mock language: SectionHeader + FilterChip filter row +
 * split (left: run selector as DataGrid; right: WindowPanel('cursor') mono kv
 * + WindowPanel('transitions', flush) DataGrid). No shadcn Sheet / Tabs /
 * Select / Card. All chrome via WindowPanel + DataGrid + MonoBadge.
 */

import { useState, useMemo, useCallback, type CSSProperties } from "react";
import { useQuery } from "@tanstack/react-query";
import { GitBranch } from "@phosphor-icons/react/dist/csr/GitBranch";

import {
  SectionHeader,
  DataGrid,
  MonoBadge,
  FilterChip,
} from "@/components/aila/mock";
import { WindowPanel } from "@/components/aila/WindowPanel";
import { LoadingSkeletonGroup } from "@/components/aila/LoadingSkeleton";
import type { TransitionView } from "@platform/features/tasks/transitions";

import {
  fetchWorkflowRunTransition,
  fetchWorkflowRunTransitions,
  fetchWorkflowRuns,
} from "./workflow-inspector-api";
import type { WorkflowRunView } from "./workflow-inspector-types";

// ---------------------------------------------------------------------------
// Shared mock button + input primitives
// ---------------------------------------------------------------------------

const ACTION_BTN: CSSProperties = {
  height: 26,
  padding: "0 10px",
  fontSize: 9.5,
  letterSpacing: "0.08em",
  borderRadius: 3,
  cursor: "pointer",
  color: "var(--text-primary)",
  background: "var(--surface-sunk)",
  border: "1px solid var(--border-soft)",
};

const INPUT_STYLE: CSSProperties = {
  height: 28,
  padding: "0 10px",
  fontSize: 11,
  color: "var(--text-primary)",
  background: "var(--surface-sunk)",
  border: "1px solid var(--border-soft)",
  borderRadius: 3,
  outline: "none",
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const STATE_TONE: Record<string, string> = {
  __succeeded__: "ok",
  __failed__: "critical",
  __crashed__: "critical",
  on_failure: "warn",
};

function stateTone(state: string): string {
  return STATE_TONE[state] ?? "accent";
}

function formatRelativeTime(iso: string): string {
  const now = Date.now();
  const then = new Date(iso).getTime();
  const diffMs = now - then;
  if (diffMs < 0) return "just now";
  const diffSec = Math.floor(diffMs / 1000);
  if (diffSec < 60) return `${diffSec}s ago`;
  const diffMin = Math.floor(diffSec / 60);
  if (diffMin < 60) return `${diffMin}m ago`;
  const diffHr = Math.floor(diffMin / 60);
  if (diffHr < 24) return `${diffHr}h ago`;
  return `${Math.floor(diffHr / 24)}d ago`;
}

// ---------------------------------------------------------------------------
// Copy button (inline, mock-styled)
// ---------------------------------------------------------------------------

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);

  function handleCopy(e: React.MouseEvent) {
    e.stopPropagation();
    void navigator.clipboard.writeText(text).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    });
  }

  return (
    <button
      type="button"
      onClick={handleCopy}
      className="font-mono uppercase"
      title="Copy"
      aria-label="Copy value"
      style={{
        height: 18,
        padding: "0 6px",
        fontSize: 8.5,
        letterSpacing: "0.1em",
        borderRadius: 2,
        cursor: "pointer",
        color: copied ? "var(--status-ok)" : "var(--text-faint)",
        background: "transparent",
        border: "1px solid var(--border-faint)",
      }}
    >
      {copied ? "ok" : "copy"}
    </button>
  );
}

// ---------------------------------------------------------------------------
// Cursor + transitions panel (right column)
// ---------------------------------------------------------------------------

function KvRow({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div
      className="flex items-start"
      style={{
        gap: 10,
        padding: "6px 0",
        borderBottom: "1px solid var(--border-faint)",
      }}
    >
      <span
        className="font-mono uppercase"
        style={{
          flex: "0 0 110px",
          fontSize: 9.5,
          letterSpacing: "0.12em",
          color: "var(--text-muted)",
        }}
      >
        {label}
      </span>
      <span
        className="font-mono"
        style={{
          flex: 1,
          minWidth: 0,
          fontSize: 11,
          color: "var(--text-primary)",
          wordBreak: "break-all",
        }}
      >
        {children}
      </span>
    </div>
  );
}

function StateMachineSketch({ rows }: { rows: TransitionView[] }) {
  const edges = useMemo(() => {
    const seen = new Set<string>();
    const ordered: { from: string; to: string; count: number }[] = [];
    const counts = new Map<string, number>();
    for (const r of rows) {
      if (r.from_state === null) continue;
      const key = `${r.from_state}\u2192${r.to_state}`;
      counts.set(key, (counts.get(key) ?? 0) + 1);
      if (!seen.has(key)) {
        seen.add(key);
        ordered.push({ from: r.from_state, to: r.to_state, count: 0 });
      }
    }
    for (const edge of ordered) {
      edge.count = counts.get(`${edge.from}\u2192${edge.to}`) ?? 0;
    }
    return ordered;
  }, [rows]);

  if (edges.length === 0) return null;

  return (
    <WindowPanel title={`edges \u00b7 ${edges.length}`} tone="muted">
      <ul
        className="flex flex-col"
        style={{
          gap: 4,
          margin: 0,
          padding: 0,
          listStyle: "none",
          fontSize: 10.5,
        }}
      >
        {edges.map((e) => (
          <li
            key={`${e.from}\u2192${e.to}`}
            className="flex items-center font-mono"
            style={{ gap: 8, color: "var(--text-primary)" }}
          >
            <span style={{ opacity: 0.85 }}>{e.from}</span>
            <span style={{ color: "var(--text-muted)" }}>{"\u2192"}</span>
            <span>{e.to}</span>
            {e.count > 1 && (
              <span style={{ color: "var(--text-faint)" }}>
                {"\u00d7"}
                {e.count}
              </span>
            )}
          </li>
        ))}
      </ul>
    </WindowPanel>
  );
}

interface TransitionDetailProps {
  row: TransitionView;
  onClose: () => void;
}

function TransitionDetail({ row, onClose }: TransitionDetailProps) {
  const query = useQuery({
    queryKey: ["workflow-run-transition", row.run_id, row.seq],
    queryFn: () => fetchWorkflowRunTransition(row.run_id, row.seq),
    enabled: row !== null,
    staleTime: 30_000,
    initialData: row,
  });

  const view = query.data ?? row;

  return (
    <WindowPanel
      title={`transition seq #${view.seq}`}
      tone={stateTone(view.to_state) === "critical" ? "warn" : "info"}
      actions={
        <button
          type="button"
          className="font-mono uppercase"
          onClick={onClose}
          style={{ ...ACTION_BTN, height: 22, fontSize: 9 }}
        >
          close
        </button>
      }
    >
      {query.isError && (
        <div
          className="font-mono"
          style={{
            border:
              "1px solid color-mix(in srgb, var(--status-warn) 40%, transparent)",
            background:
              "color-mix(in srgb, var(--status-warn) 10%, transparent)",
            color: "var(--status-warn)",
            padding: "6px 10px",
            fontSize: 10.5,
            borderRadius: 3,
            marginBottom: 8,
          }}
        >
          Failed to fetch transition: {(query.error as Error).message}
        </div>
      )}
      <div className="flex flex-col">
        <KvRow label="event">
          <MonoBadge tone={stateTone(view.to_state)}>{view.event}</MonoBadge>
        </KvRow>
        <KvRow label="from_state">
          {view.from_state ?? (
            <span style={{ color: "var(--text-faint)" }}>(initial)</span>
          )}
        </KvRow>
        <KvRow label="to_state">
          <MonoBadge tone={stateTone(view.to_state)}>{view.to_state}</MonoBadge>
        </KvRow>
        <KvRow label="duration_ms">
          <span className="tabular-nums">{view.duration_ms ?? "--"}</span>
        </KvRow>
        <KvRow label="happened_at">{view.happened_at}</KvRow>
        <KvRow label="task_id">
          {view.task_id ?? (
            <span style={{ color: "var(--text-faint)" }}>(none)</span>
          )}
        </KvRow>
      </div>

      {view.error_class !== null && (
        <div style={{ marginTop: 10 }}>
          <div
            className="font-mono uppercase"
            style={{
              fontSize: 9,
              letterSpacing: "0.14em",
              color: "var(--status-warn)",
              marginBottom: 4,
            }}
          >
            error
          </div>
          <div
            className="font-mono"
            style={{
              padding: 8,
              fontSize: 10.5,
              color: "var(--status-warn)",
              background:
                "color-mix(in srgb, var(--status-warn) 8%, transparent)",
              border:
                "1px solid color-mix(in srgb, var(--status-warn) 32%, transparent)",
              borderRadius: 3,
            }}
          >
            <div style={{ fontWeight: 500 }}>{view.error_class}</div>
            {view.error_message !== null &&
              view.error_message !== view.error_class && (
                <pre
                  className="font-mono"
                  style={{
                    margin: "6px 0 0",
                    maxHeight: 240,
                    overflow: "auto",
                    whiteSpace: "pre-wrap",
                    wordBreak: "break-word",
                    fontSize: 10,
                  }}
                >
                  {view.error_message}
                </pre>
              )}
          </div>
        </div>
      )}
    </WindowPanel>
  );
}

interface RunDetailPanelProps {
  run: WorkflowRunView;
}

function RunDetailPanel({ run }: RunDetailPanelProps) {
  const {
    data: transitions,
    isLoading,
    isError,
  } = useQuery({
    queryKey: ["workflow-run-transitions", run.run_id],
    queryFn: () => fetchWorkflowRunTransitions(run.run_id),
    staleTime: 15_000,
  });

  const [selectedTransition, setSelectedTransition] =
    useState<TransitionView | null>(null);

  const rows = transitions ?? [];

  return (
    <div className="flex flex-col" style={{ gap: 12, minWidth: 0 }}>
      <WindowPanel title="cursor" tone={stateTone(run.current_state) === "critical" ? "warn" : "accent"}>
        <div className="flex flex-col">
          <KvRow label="run_id">
            <span className="inline-flex items-center" style={{ gap: 6 }}>
              <span style={{ wordBreak: "break-all" }}>{run.run_id}</span>
              <CopyButton text={run.run_id} />
            </span>
          </KvRow>
          <KvRow label="definition">{run.definition_id}</KvRow>
          <KvRow label="current_state">
            <MonoBadge tone={stateTone(run.current_state)}>
              {run.current_state}
            </MonoBadge>
          </KvRow>
          <KvRow label="retries">
            <span className="tabular-nums">{run.retries_in_state}</span>
          </KvRow>
          <KvRow label="version">
            <span className="tabular-nums">{run.version}</span>
          </KvRow>
          <KvRow label="updated_at">{formatRelativeTime(run.updated_at)}</KvRow>
        </div>
      </WindowPanel>

      <StateMachineSketch rows={rows} />

      <WindowPanel title={`transitions \u00b7 ${rows.length}`} flush>
        {isLoading ? (
          <div style={{ padding: 16 }}>
            <LoadingSkeletonGroup lines={5} />
          </div>
        ) : isError ? (
          <div
            className="font-mono"
            style={{
              padding: 16,
              color: "var(--status-warn)",
              fontSize: 11,
            }}
          >
            Failed to load transitions.
          </div>
        ) : (
          <DataGrid<TransitionView>
            columns={[
              { label: "SEQ", width: "60px", align: "right" },
              { label: "EVENT", width: "1fr" },
              { label: "FROM", width: "1.2fr" },
              { label: "TO", width: "1.2fr" },
              { label: "MS", width: "60px", align: "right" },
              { label: "WHEN", width: "160px" },
            ]}
            rows={rows}
            getKey={(r) => r.seq}
            onRowClick={(r) => setSelectedTransition(r)}
            empty={
              <div
                className="font-mono"
                style={{
                  padding: 24,
                  textAlign: "center",
                  fontSize: 11,
                  color: "var(--text-muted)",
                }}
              >
                no transitions recorded for this run.
              </div>
            }
            renderCells={(r) => [
              <span
                key="seq"
                className="font-mono tabular-nums"
                style={{ color: "var(--text-primary)", fontSize: 11 }}
              >
                {r.seq}
              </span>,
              <span
                key="ev"
                className="font-mono truncate"
                style={{ color: "var(--text-primary)", fontSize: 11 }}
              >
                {r.event}
              </span>,
              <span
                key="from"
                className="font-mono truncate"
                style={{ color: "var(--text-muted)", fontSize: 11 }}
              >
                {r.from_state ?? "(initial)"}
              </span>,
              <MonoBadge key="to" tone={stateTone(r.to_state)}>
                {r.to_state}
              </MonoBadge>,
              <span
                key="ms"
                className="font-mono tabular-nums"
                style={{ color: "var(--text-muted)", fontSize: 11 }}
              >
                {r.duration_ms ?? "--"}
              </span>,
              <span
                key="ha"
                className="font-mono"
                style={{
                  color: "var(--text-muted)",
                  fontSize: 10.5,
                  whiteSpace: "nowrap",
                }}
                title={r.happened_at}
              >
                {formatRelativeTime(r.happened_at)}
              </span>,
            ]}
          />
        )}
      </WindowPanel>

      {selectedTransition && (
        <TransitionDetail
          row={selectedTransition}
          onClose={() => setSelectedTransition(null)}
        />
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Filter bar
// ---------------------------------------------------------------------------

interface FiltersState {
  definition_id: string;
  current_state: string;
}

interface FilterBarProps {
  runs: WorkflowRunView[];
  filters: FiltersState;
  onFiltersChange: (filters: FiltersState) => void;
  autoRefresh: boolean;
  onAutoRefreshChange: (enabled: boolean) => void;
  onRefresh: () => void;
  isLoading: boolean;
}

function FilterBar({
  runs,
  filters,
  onFiltersChange,
  autoRefresh,
  onAutoRefreshChange,
  onRefresh,
  isLoading,
}: FilterBarProps) {
  const definitionIds = useMemo(() => {
    const seen = new Set<string>();
    for (const run of runs) seen.add(run.definition_id);
    return [...seen].sort();
  }, [runs]);

  return (
    <div className="flex items-center flex-wrap" style={{ gap: 8 }}>
      <select
        aria-label="Filter by definition"
        value={filters.definition_id}
        onChange={(e) =>
          onFiltersChange({ ...filters, definition_id: e.target.value })
        }
        className="font-mono"
        style={{ ...INPUT_STYLE, width: 220 }}
      >
        <option value="">All definitions</option>
        {definitionIds.map((id) => (
          <option key={id} value={id}>
            {id}
          </option>
        ))}
      </select>

      <input
        type="text"
        placeholder="filter by state…"
        aria-label="Filter by current state"
        value={filters.current_state}
        onChange={(e) =>
          onFiltersChange({ ...filters, current_state: e.target.value })
        }
        className="font-mono"
        style={{ ...INPUT_STYLE, width: 180 }}
      />

      <FilterChip
        active={autoRefresh}
        onClick={() => onAutoRefreshChange(!autoRefresh)}
      >
        {autoRefresh ? "auto-refresh on" : "auto-refresh off"}
      </FilterChip>

      <button
        type="button"
        className="font-mono uppercase"
        onClick={onRefresh}
        disabled={isLoading}
        style={{
          ...ACTION_BTN,
          opacity: isLoading ? 0.6 : 1,
        }}
      >
        {isLoading ? "refreshing" : "refresh"}
      </button>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Run list panel (left column)
// ---------------------------------------------------------------------------

interface RunListProps {
  runs: WorkflowRunView[];
  selectedRunId: string | null;
  onSelectRun: (runId: string) => void;
  isLoading: boolean;
  isError: boolean;
}

function RunList({
  runs,
  selectedRunId,
  onSelectRun,
  isLoading,
  isError,
}: RunListProps) {
  if (isLoading) {
    return (
      <div style={{ padding: 16 }}>
        <LoadingSkeletonGroup lines={6} />
      </div>
    );
  }

  if (isError) {
    return (
      <div
        className="font-mono"
        style={{
          padding: 16,
          color: "var(--status-warn)",
          fontSize: 11,
        }}
      >
        Failed to load workflow runs. Check backend connectivity.
      </div>
    );
  }

  return (
    <DataGrid<WorkflowRunView>
      columns={[
        { label: "RUN", width: "110px" },
        { label: "DEFINITION", width: "1fr" },
        { label: "STATE", width: "170px" },
        { label: "RTY", width: "44px", align: "right" },
        { label: "V", width: "36px", align: "right" },
        { label: "UPDATED", width: "90px", align: "right" },
      ]}
      rows={runs}
      getKey={(r) => r.run_id}
      onRowClick={(r) => onSelectRun(r.run_id)}
      empty={
        <div
          className="font-mono"
          style={{
            padding: 24,
            textAlign: "center",
            fontSize: 11,
            color: "var(--text-muted)",
          }}
        >
          no workflow runs match the filters.
        </div>
      }
      renderCells={(r) => {
        const isSelected = r.run_id === selectedRunId;
        return [
          <span
            key="id"
            className="font-mono truncate"
            title={r.run_id}
            style={{
              color: isSelected ? "var(--accent)" : "var(--text-primary)",
              fontSize: 10.5,
            }}
          >
            {r.run_id.slice(0, 8)}
            {"\u2026"}
          </span>,
          <span
            key="def"
            className="font-mono truncate"
            style={{ color: "var(--text-primary)", fontSize: 11 }}
          >
            {r.definition_id}
          </span>,
          <MonoBadge key="st" tone={stateTone(r.current_state)}>
            {r.current_state}
          </MonoBadge>,
          <span
            key="rty"
            className="font-mono tabular-nums"
            style={{ color: "var(--text-muted)", fontSize: 11 }}
          >
            {r.retries_in_state}
          </span>,
          <span
            key="v"
            className="font-mono tabular-nums"
            style={{ color: "var(--text-muted)", fontSize: 11 }}
          >
            {r.version}
          </span>,
          <span
            key="upd"
            className="font-mono"
            style={{
              color: "var(--text-muted)",
              fontSize: 10.5,
              whiteSpace: "nowrap",
            }}
          >
            {formatRelativeTime(r.updated_at)}
          </span>,
        ];
      }}
    />
  );
}

// ---------------------------------------------------------------------------
// Page root
// ---------------------------------------------------------------------------

export function WorkflowInspectorPage() {
  const [filters, setFilters] = useState<FiltersState>({
    definition_id: "",
    current_state: "",
  });
  const [autoRefresh, setAutoRefresh] = useState(false);
  const [selectedRunId, setSelectedRunId] = useState<string | null>(null);

  const apiParams = useMemo(
    () => ({
      definition_id: filters.definition_id || undefined,
      current_state: filters.current_state || undefined,
    }),
    [filters],
  );

  const {
    data: runs,
    isLoading: runsLoading,
    isError: runsError,
    refetch: refetchRuns,
  } = useQuery({
    queryKey: ["workflow-runs", apiParams],
    queryFn: () => fetchWorkflowRuns(apiParams),
    refetchInterval: autoRefresh ? 30_000 : false,
    staleTime: 10_000,
  });

  const allRuns = runs ?? [];

  const selectedRun = useMemo(
    () => allRuns.find((r) => r.run_id === selectedRunId) ?? null,
    [allRuns, selectedRunId],
  );

  const handleRefresh = useCallback(() => {
    void refetchRuns();
  }, [refetchRuns]);

  return (
    <div
      className="flex flex-col"
      style={{ gap: 16, padding: 20, minHeight: "100%" }}
    >
      <SectionHeader
        icon={
          <GitBranch
            size={16}
            weight="duotone"
            style={{ color: "var(--text-on-accent)" }}
            aria-hidden="true"
          />
        }
        title="workflow inspector"
      />

      <FilterBar
        runs={allRuns}
        filters={filters}
        onFiltersChange={setFilters}
        autoRefresh={autoRefresh}
        onAutoRefreshChange={setAutoRefresh}
        onRefresh={handleRefresh}
        isLoading={runsLoading}
      />

      <div
        className="grid"
        style={{
          gridTemplateColumns: "1fr 460px",
          gap: 16,
          minHeight: 0,
        }}
      >
        <WindowPanel title={`runs \u00b7 ${allRuns.length}`} flush>
          <RunList
            runs={allRuns}
            selectedRunId={selectedRunId}
            onSelectRun={setSelectedRunId}
            isLoading={runsLoading}
            isError={runsError}
          />
        </WindowPanel>

        {selectedRun === null ? (
          <WindowPanel title="cursor" tone="muted">
            <div
              className="flex flex-col items-center justify-center"
              style={{ gap: 8, padding: "36px 12px", textAlign: "center" }}
            >
              <span aria-hidden="true" style={{ color: "var(--text-faint)" }}>
                <GitBranch size={28} weight="duotone" />
              </span>
              <span
                className="font-mono"
                style={{ color: "var(--text-primary)", fontSize: 12 }}
              >
                Select a run
              </span>
              <span
                className="font-mono"
                style={{
                  color: "var(--text-muted)",
                  fontSize: 10.5,
                  maxWidth: 260,
                }}
              >
                Click a row to inspect its cursor and the recorded transitions.
              </span>
            </div>
          </WindowPanel>
        ) : (
          <RunDetailPanel run={selectedRun} />
        )}
      </div>
    </div>
  );
}
