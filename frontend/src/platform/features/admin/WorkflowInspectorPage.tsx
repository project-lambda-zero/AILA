/**
 * WorkflowInspectorPage — Admin Workflow Inspector at /admin/workflows.
 *
 * Requires admin role at the route level (defense-in-depth).
 * Backend endpoints also independently enforce admin role.
 *
 * Layout:
 * - Filter bar: definition_id dropdown + current_state text + auto-refresh toggle
 * - Run table: columns for run_id, definition_id, current_state, retries, version, updated_at
 * - Right panel (row click): run metadata + TransitionTimeline from tasks/
 *
 * State badge colors (from CONTEXT.md Part 10):
 * - __succeeded__ → green  (oklch 72% 0.18 150)
 * - __failed__    → text-destructive
 * - on_failure    → amber  (oklch 78% 0.18 80)
 * - other         → text-accent
 */

import { useState, useMemo } from "react";
import { useQuery } from "@tanstack/react-query";
import { GitBranch } from "@phosphor-icons/react/dist/csr/GitBranch";
import { ArrowClockwise } from "@phosphor-icons/react/dist/csr/ArrowClockwise";
import { Copy } from "@phosphor-icons/react/dist/csr/Copy";
import { Check } from "@phosphor-icons/react/dist/csr/Check";

import { AilaCard } from "@/components/aila/AilaCard";
import { LoadingSkeletonGroup } from "@/components/aila/LoadingSkeleton";
import { EmptyState } from "@/components/aila/EmptyState";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { TransitionTimeline } from "@platform/features/tasks/TransitionTimeline";

import { fetchWorkflowRunTransitions, fetchWorkflowRuns } from "./workflow-inspector-api";
import type { WorkflowRunView } from "./workflow-inspector-types";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** State badge colour class per CONTEXT.md Part 10. */
function stateBadgeClass(state: string): string {
  if (state === "__succeeded__") return "text-[oklch(72%_0.18_150)]"; // green
  if (state === "__failed__") return "text-destructive";
  if (state === "on_failure") return "text-[oklch(78%_0.18_80)]"; // amber
  return "text-accent";
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

/** Truncate a run_id UUID for display in the table (first 8 chars + ellipsis). */
function truncateRunId(runId: string): string {
  return runId.length > 12 ? `${runId.slice(0, 8)}…` : runId;
}

// ---------------------------------------------------------------------------
// CopyButton — copies text to clipboard, shows brief checkmark
// ---------------------------------------------------------------------------

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);

  function handleCopy(e: React.MouseEvent): void {
    e.stopPropagation();
    void navigator.clipboard.writeText(text).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    });
  }

  return (
    <button
      type="button"
      role="button"
      onClick={handleCopy}
      className="ml-1 shrink-0 opacity-50 hover:opacity-100 transition-opacity"
      title="Copy run_id"
      aria-label="Copy run_id"
    >
      {copied ? (
        <Check className="h-3 w-3 text-[oklch(72%_0.18_150)]" />
      ) : (
        <Copy className="h-3 w-3" />
      )}
    </button>
  );
}

// ---------------------------------------------------------------------------
// RunTable
// ---------------------------------------------------------------------------

interface RunTableProps {
  runs: WorkflowRunView[];
  selectedRunId: string | null;
  onSelectRun: (runId: string) => void;
  isLoading: boolean;
  isError: boolean;
}

function RunTable({
  runs,
  selectedRunId,
  onSelectRun,
  isLoading,
  isError,
}: RunTableProps) {
  if (isLoading) {
    return <LoadingSkeletonGroup lines={6} />;
  }

  if (isError) {
    return (
      <div className="rounded-[4px] border border-destructive bg-destructive/10 px-3 py-2 font-mono text-xs text-destructive">
        Failed to load workflow runs. Check backend connectivity.
      </div>
    );
  }

  if (runs.length === 0) {
    return (
      <p className="font-mono text-xs text-muted-foreground py-4 text-center">
        No workflow runs found.
      </p>
    );
  }

  return (
    <div className="overflow-x-auto rounded-[4px] border border-border">
      <table className="w-full font-mono text-xs">
        <thead>
          <tr className="border-b border-border bg-elevated">
            <th className="text-left px-3 py-2 text-muted-foreground font-semibold whitespace-nowrap">
              Run ID
            </th>
            <th className="text-left px-3 py-2 text-muted-foreground font-semibold whitespace-nowrap">
              Definition
            </th>
            <th className="text-left px-3 py-2 text-muted-foreground font-semibold whitespace-nowrap">
              State
            </th>
            <th className="text-right px-3 py-2 text-muted-foreground font-semibold whitespace-nowrap">
              Retries
            </th>
            <th className="text-right px-3 py-2 text-muted-foreground font-semibold whitespace-nowrap">
              Version
            </th>
            <th className="text-right px-3 py-2 text-muted-foreground font-semibold whitespace-nowrap">
              Updated
            </th>
          </tr>
        </thead>
        <tbody>
          {runs.map((run) => {
            const isSelected = run.run_id === selectedRunId;
            return (
              <tr
                key={run.run_id}
                onClick={(e) => {
                  const target = e.target as HTMLElement;
                  // Row-click trap: ignore clicks on buttons/icons inside the row
                  if (
                    target !== e.currentTarget &&
                    target.closest('[role="button"], button')
                  ) {
                    return;
                  }
                  onSelectRun(run.run_id);
                }}
                className={[
                  "border-b border-border last:border-0 cursor-pointer transition-colors",
                  isSelected
                    ? "bg-accent/10 border-accent/30"
                    : "hover:bg-elevated",
                ].join(" ")}
              >
                <td className="px-3 py-2 whitespace-nowrap">
                  <div className="flex items-center gap-1">
                    <span
                      className="text-foreground"
                      title={run.run_id}
                    >
                      {truncateRunId(run.run_id)}
                    </span>
                    <CopyButton text={run.run_id} />
                  </div>
                </td>
                <td className="px-3 py-2 whitespace-nowrap text-foreground">
                  {run.definition_id}
                </td>
                <td className="px-3 py-2 whitespace-nowrap">
                  <span className={`font-semibold ${stateBadgeClass(run.current_state)}`}>
                    {run.current_state}
                  </span>
                </td>
                <td className="px-3 py-2 text-right text-muted-foreground tabular-nums">
                  {run.retries_in_state}
                </td>
                <td className="px-3 py-2 text-right text-muted-foreground tabular-nums">
                  {run.version}
                </td>
                <td className="px-3 py-2 text-right text-muted-foreground whitespace-nowrap">
                  {formatRelativeTime(run.updated_at)}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

// ---------------------------------------------------------------------------
// RunDetailPanel
// ---------------------------------------------------------------------------

interface RunDetailPanelProps {
  run: WorkflowRunView;
}

function RunDetailPanel({ run }: RunDetailPanelProps) {
  const { data: transitions, isLoading, isError } = useQuery({
    queryKey: ["workflow-run-transitions", run.run_id],
    queryFn: () => fetchWorkflowRunTransitions(run.run_id),
    staleTime: 15_000,
  });

  return (
    <AilaCard variant="elevated" padding="md" className="flex flex-col gap-4" techBorder glow>{/* Run metadata header */}
    <div className="flex flex-col gap-2">
      <div className="flex items-center gap-2">
        <span className="font-mono text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
          Run ID
        </span>
        <div className="flex items-center gap-1">
          <span className="font-mono text-xs text-foreground break-all">
            {run.run_id}
          </span>
          <CopyButton text={run.run_id} />
        </div>
      </div>
    
      <div className="grid grid-cols-2 gap-x-4 gap-y-1 font-mono text-[11px]">
        <div>
          <span className="text-muted-foreground">Definition: </span>
          <span className="text-foreground">{run.definition_id}</span>
        </div>
        <div>
          <span className="text-muted-foreground">Version: </span>
          <span className="text-foreground tabular-nums">{run.version}</span>
        </div>
        <div>
          <span className="text-muted-foreground">State: </span>
          <span className={`font-semibold ${stateBadgeClass(run.current_state)}`}>
            {run.current_state}
          </span>
        </div>
        <div>
          <span className="text-muted-foreground">Updated: </span>
          <span className="text-foreground">{formatRelativeTime(run.updated_at)}</span>
        </div>
      </div>
    </div>
    
    {/* Transition timeline — reused from tasks/ (not duplicated) */}
    <TransitionTimeline
      rows={transitions ?? []}
      isLoading={isLoading}
      isError={isError}
    /></AilaCard>
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
  // Populate definition_id dropdown from distinct values in the current run list
  const definitionIds = useMemo(() => {
    const seen = new Set<string>();
    for (const run of runs) {
      seen.add(run.definition_id);
    }
    return [...seen].sort();
  }, [runs]);

  return (
    <div className="flex flex-wrap items-center gap-3">
      {/* Definition ID dropdown */}
      <Select
        value={filters.definition_id || "__all__"}
        onValueChange={(val) => {
          const selected = val ?? "__all__";
          onFiltersChange({
            ...filters,
            definition_id: selected === "__all__" ? "" : selected,
          });
        }}
      >
        <SelectTrigger className="touch-target font-mono text-xs h-8 w-[220px]">
          <SelectValue placeholder="All definitions" />
        </SelectTrigger>
        <SelectContent>
          <SelectItem value="__all__">All definitions</SelectItem>
          {definitionIds.map((id) => (
            <SelectItem key={id} value={id}>
              {id}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>

      {/* State text filter */}
      <Input
        type="text"
        placeholder="Filter by state…"
        value={filters.current_state}
        onChange={(e) => {
          onFiltersChange({ ...filters, current_state: e.target.value });
        }}
        className="touch-target font-mono text-xs h-8 w-[180px]"
        aria-label="Filter by current state"
      />

      {/* Auto-refresh toggle */}
      <button
        type="button"
        onClick={() => onAutoRefreshChange(!autoRefresh)}
        className={[
          "touch-target flex items-center gap-1.5 px-2.5 py-1 rounded-[4px] border font-mono text-[11px] transition-colors",
          autoRefresh
            ? "border-accent/60 bg-accent/10 text-accent"
            : "border-border text-muted-foreground hover:border-border hover:text-foreground",
        ].join(" ")}
        title={autoRefresh ? "Auto-refresh on (30s) — click to disable" : "Enable auto-refresh (30s)"}
      >
        <ArrowClockwise className={`h-3 w-3 ${autoRefresh ? "animate-spin" : ""}`} style={autoRefresh ? { animationDuration: "3s" } : undefined} />
        Auto-refresh
      </button>

      {/* Manual refresh */}
      <Button
        size="sm"
        variant="ghost"
        className="touch-target h-8 w-8 p-0"
        onClick={onRefresh}
        disabled={isLoading}
        aria-label="Refresh now"
        title="Refresh now"
      >
        <ArrowClockwise className="h-3.5 w-3.5" />
      </Button>
    </div>
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

  // API params — only pass non-empty strings
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

  // Resolve the selected run from the list for the detail panel
  const selectedRun = useMemo(
    () => allRuns.find((r) => r.run_id === selectedRunId) ?? null,
    [allRuns, selectedRunId],
  );

  return (
    <div className="flex flex-col gap-6 p-4 lg:p-6 h-full">
      {/* Page header */}

      {/* Filter bar */}
      <FilterBar
        runs={allRuns}
        filters={filters}
        onFiltersChange={setFilters}
        autoRefresh={autoRefresh}
        onAutoRefreshChange={setAutoRefresh}
        onRefresh={() => void refetchRuns()}
        isLoading={runsLoading}
      />

      {/* Two-column split: run table + detail panel */}
      <div className="grid grid-cols-1 lg:grid-cols-[1fr_420px] gap-4 min-h-0 flex-1">
        {/* Left: run table */}
        <AilaCard variant="default" padding="md" className="overflow-hidden min-w-0" techBorder glow><div className="flex flex-col gap-3 h-full">
          <div className="flex items-center justify-between gap-2">
            <h2 className="font-mono text-sm font-semibold text-foreground">
              Runs
              {allRuns.length > 0 && (
                <span className="ml-2 text-muted-foreground font-normal">
                  ({allRuns.length})
                </span>
              )}
            </h2>
          </div>
          <div className="overflow-auto min-h-0 flex-1">
            <RunTable
              runs={allRuns}
              selectedRunId={selectedRunId}
              onSelectRun={setSelectedRunId}
              isLoading={runsLoading}
              isError={runsError}
            />
          </div>
        </div></AilaCard>

        {/* Right: run detail + transition timeline */}
        <div className="min-w-0">
          {selectedRun === null ? (
            <EmptyState
              icon={<GitBranch className="h-10 w-10" />}
              title="Select a run"
              description="Click a row to view its state transition history."
            />
          ) : (
            <RunDetailPanel run={selectedRun} />
          )}
        </div>
      </div>
    </div>
  );
}
