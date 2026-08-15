/**
 * WorkflowInspectorPage -- Admin Workflow Inspector at /admin/workflows.
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
import type { TransitionView } from "@platform/features/tasks/transitions";
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from "@/components/ui/sheet";
import {
  Tabs,
  TabsContent,
  TabsList,
  TabsTrigger,
} from "@/components/ui/tabs";
import { ActivityTimeline } from "@platform/features/activity/ActivityTimeline";

import {
  fetchWorkflowRunTransition,
  fetchWorkflowRunTransitions,
  fetchWorkflowRuns,
} from "./workflow-inspector-api";
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
// CopyButton -- copies text to clipboard, shows brief checkmark
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
      <table aria-label="Workflow states" className="w-full font-mono text-xs border-collapse [&_th]:border [&_th]:border-border [&_th]:uppercase [&_th]:tracking-wider [&_td]:border [&_td]:border-border">
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

  const [selectedTransition, setSelectedTransition] =
    useState<TransitionView | null>(null);

  return (
    <AilaCard variant="elevated" padding="md" className="flex flex-col gap-4">{/* Run metadata header */}
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

    {/* State machine sketch -- text-only ordered edge list derived from the
       observed transitions. Mermaid is intentionally NOT rendered because
       it is not a workspace dependency; the ordered list is the durable
       readable form of the same information. */}
    {(transitions?.length ?? 0) > 0 && (
      <StateMachineSketch rows={transitions ?? []} />
    )}

    {/* Transitions + Activity -- the transitions tab is the durable view the
       inspector has always shown; the activity tab reuses the shared
       ActivityTimeline (GET /audit/events?run_id=<id>) so the same panel
       exposes both the state-machine trace and the audit trail without
       duplicating the admin AuditLogsPage. */}
    <Tabs defaultValue="transitions">
      <TabsList variant="line">
        <TabsTrigger value="transitions">Transitions</TabsTrigger>
        <TabsTrigger value="activity">Activity</TabsTrigger>
      </TabsList>
      <TabsContent value="transitions">
        <TransitionTimeline
          rows={transitions ?? []}
          isLoading={isLoading}
          isError={isError}
          onRowSelect={setSelectedTransition}
        />
      </TabsContent>
      <TabsContent value="activity">
        <ActivityTimeline runId={run.run_id} label="Workflow Run" />
      </TabsContent>
    </Tabs>

    {/* Drill-down drawer for a single transition */}
    <TransitionDetailSheet
      row={selectedTransition}
      onClose={() => setSelectedTransition(null)}
    /></AilaCard>
  );
}

// ---------------------------------------------------------------------------
// StateMachineSketch -- ordered edge list derived from observed transitions.
// (Mermaid render is intentionally omitted; no workspace dep.)
// ---------------------------------------------------------------------------

function StateMachineSketch({ rows }: { rows: TransitionView[] }) {
  const edges = useMemo(() => {
    const seen = new Set<string>();
    const ordered: { from: string; to: string; count: number }[] = [];
    const counts = new Map<string, number>();
    for (const r of rows) {
      if (r.from_state === null) continue;
      const key = `${r.from_state}→${r.to_state}`;
      counts.set(key, (counts.get(key) ?? 0) + 1);
      if (!seen.has(key)) {
        seen.add(key);
        ordered.push({ from: r.from_state, to: r.to_state, count: 0 });
      }
    }
    for (const edge of ordered) {
      edge.count = counts.get(`${edge.from}→${edge.to}`) ?? 0;
    }
    return ordered;
  }, [rows]);

  if (edges.length === 0) return null;

  return (
    <div className="rounded-[2px] border border-border bg-elevated/30 p-2">
      <p className="font-mono text-[10px] font-semibold uppercase tracking-wider text-muted-foreground mb-1">
        Observed edges ({edges.length})
      </p>
      <ul className="flex flex-col gap-0.5 font-mono text-[10px]">
        {edges.map((e) => (
          <li key={`${e.from}→${e.to}`} className="flex items-center gap-2">
            <span className="text-foreground opacity-80">{e.from}</span>
            <span className="text-muted-foreground">→</span>
            <span className="text-foreground">{e.to}</span>
            {e.count > 1 && (
              <span className="text-muted-foreground opacity-60">×{e.count}</span>
            )}
          </li>
        ))}
      </ul>
    </div>
  );
}

// ---------------------------------------------------------------------------
// TransitionDetailSheet -- drill-down drawer for a single transition
// ---------------------------------------------------------------------------

interface TransitionDetailSheetProps {
  row: TransitionView | null;
  onClose: () => void;
}

function TransitionDetailSheet({ row, onClose }: TransitionDetailSheetProps) {
  // Refetch the authoritative row via /transitions/{seq} so the drawer shows
  // the server-side canonical data (not a snapshot from the list). The list
  // row is the seed for the drawer; the query is the source of truth once
  // opened.
  const query = useQuery({
    queryKey: [
      "workflow-run-transition",
      row?.run_id ?? "",
      row?.seq ?? -1,
    ],
    queryFn: () => fetchWorkflowRunTransition(row!.run_id, row!.seq),
    enabled: row !== null,
    staleTime: 30_000,
    initialData: row ?? undefined,
  });

  const view = query.data ?? row;

  return (
    <Sheet
      open={row !== null}
      onOpenChange={(open) => {
        if (!open) onClose();
      }}
    >
      <SheetContent side="right" className="w-full sm:max-w-lg p-4 sm:p-6">
        <SheetHeader className="flex flex-col gap-1">
          <SheetTitle className="font-mono text-sm">
            Transition seq #{view?.seq ?? "--"}
          </SheetTitle>
          <SheetDescription className="font-mono text-[11px]">
            run {view?.run_id ?? ""}
          </SheetDescription>
        </SheetHeader>

        {view === undefined && (
          <p className="font-mono text-xs text-muted-foreground">Loading…</p>
        )}

        {query.isError && (
          <div className="rounded-[4px] border border-destructive bg-destructive/10 px-3 py-2 font-mono text-[11px] text-destructive">
            Failed to fetch transition:{" "}
            {(query.error as Error).message}
          </div>
        )}

        {view !== undefined && view !== null && (
          <div className="flex flex-col gap-3 overflow-y-auto">
            <div className="grid grid-cols-[max-content_1fr] gap-x-3 gap-y-1 font-mono text-[11px]">
              <span className="text-muted-foreground">event</span>
              <span className={`font-semibold ${stateBadgeClass(view.to_state)}`}>
                {view.event}
              </span>

              <span className="text-muted-foreground">from_state</span>
              <span className="text-foreground">
                {view.from_state ?? <span className="opacity-60">(initial)</span>}
              </span>

              <span className="text-muted-foreground">to_state</span>
              <span className={`font-semibold ${stateBadgeClass(view.to_state)}`}>
                {view.to_state}
              </span>

              <span className="text-muted-foreground">duration_ms</span>
              <span className="text-foreground tabular-nums">
                {view.duration_ms ?? "--"}
              </span>

              <span className="text-muted-foreground">happened_at</span>
              <span className="text-foreground">{view.happened_at}</span>

              <span className="text-muted-foreground">task_id</span>
              <span className="text-foreground break-all">
                {view.task_id ?? <span className="opacity-60">(none)</span>}
              </span>
            </div>

            {view.error_class !== null && (
              <div className="rounded-[2px] border border-destructive/40 bg-destructive/5 p-2">
                <p className="font-mono text-[10px] font-semibold uppercase tracking-wider text-destructive mb-1">
                  Error
                </p>
                <p className="font-mono text-[11px] text-destructive">
                  {view.error_class}
                </p>
                {view.error_message !== null &&
                  view.error_message !== view.error_class && (
                    <pre className="mt-1 max-h-64 overflow-auto font-mono text-[10px] text-destructive whitespace-pre-wrap break-words">
{view.error_message}
                    </pre>
                  )}
              </div>
            )}
          </div>
        )}
      </SheetContent>
    </Sheet>
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
        title={autoRefresh ? "Auto-refresh on (30s) -- click to disable" : "Enable auto-refresh (30s)"}
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

  // API params -- only pass non-empty strings
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
        <AilaCard variant="default" padding="md" className="overflow-hidden min-w-0"><div className="flex flex-col gap-3 h-full">
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
