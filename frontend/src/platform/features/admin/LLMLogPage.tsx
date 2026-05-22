/**
 * LLMLogPage -- admin-only interaction log for LLM calls (Plan 176e P2).
 *
 * Shows one row per persisted LLMCostRecord with the columns operators care
 * about during a demo: timestamp, model, task_type, tokens, cost, duration,
 * status, run_id. Clicking a row opens a side panel with the truncated
 * prompt/response previews; the full payloads are never fetched into the
 * client because the backend intentionally stores only the previews.
 *
 * Filter state is driven by the shared JqlFilterBar so the same syntax used
 * on AuditLogsPage applies here -- one filter UI for operators to learn.
 */
import { useCallback, useMemo, useState } from "react";
import { useNavigate } from "react-router";
import { useQuery } from "@tanstack/react-query";
import { type ColumnDef } from "@tanstack/react-table";
import {
  Robot,
  Coins,
  ArrowClockwise,
  ArrowSquareOut,
  X as XIcon,
} from "@phosphor-icons/react";

import { AilaCard } from "@/components/aila/AilaCard";
import { AilaTable } from "@/components/aila/AilaTable";
import { AilaBadge } from "@/components/aila/AilaBadge";
import { LoadingSkeletonGroup } from "@/components/aila/LoadingSkeleton";
import { EmptyState } from "@/components/aila/EmptyState";
import { Button } from "@/components/ui/button";
import {
  JqlFilterBar,
  filtersToQueryParams,
  type JqlFieldSpec,
  type JqlFilter,
} from "@/components/filters/JqlFilterBar";
import { authorizedRequestJson } from "@platform/api/http";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface LLMLogEntry {
  id: string;
  timestamp: string;
  model: string;
  task_type: string;
  input_tokens: number;
  output_tokens: number;
  cost_usd: number;
  duration_ms: number | null;
  status: string;
  run_id: string;
  user_id: string | null;
  team_id: string | null;
  prompt_preview: string | null;
  response_preview: string | null;
}

interface LLMLogResponse {
  items: LLMLogEntry[];
  total: number;
  limit: number;
  offset: number;
  total_cost_usd: number;
}

interface Envelope<T> {
  data: T;
  error: string | null;
  meta: Record<string, unknown>;
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const FIELDS: JqlFieldSpec[] = [
  { key: "model", label: "Model", operators: [":"] },
  { key: "task_type", label: "Task Type", operators: [":"] },
  { key: "status", label: "Status", operators: [":"] },
  { key: "user", label: "User", operators: [":"] },
  { key: "team_id", label: "Team", operators: [":"] },
  { key: "from_date", label: "From", operators: [":"] },
  { key: "to_date", label: "To", operators: [":"] },
  { key: "cost", label: "Cost", operators: [">", "<"] },
  { key: "search", label: "Search", operators: [":"] },
];

const PAGE_SIZE = 50;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function buildLogPath(filters: JqlFilter[], offset: number): string {
  const params = new URLSearchParams();
  params.set("limit", String(PAGE_SIZE));
  params.set("offset", String(offset));
  const backendParams = filtersToQueryParams(filters);
  for (const [k, v] of Object.entries(backendParams)) {
    // Map `min_cost` / `max_cost` aliases used by JqlFilterBar directly into
    // the backend's accepted keys. Everything else passes through as-is.
    params.set(k, v);
  }
  return `/admin/llm-log?${params.toString()}`;
}

function formatTimestamp(value: string): string {
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) return value;
  return parsed.toLocaleString();
}

function formatCost(value: number): string {
  return `$${value.toFixed(4)}`;
}

function formatDuration(ms: number | null): string {
  if (ms === null || ms === undefined) return "—";
  if (ms < 1000) return `${ms}ms`;
  return `${(ms / 1000).toFixed(2)}s`;
}

function statusSeverity(
  status: string,
): "info" | "critical" | "medium" | "neutral" {
  const s = status.toLowerCase();
  if (s === "ok" || s === "completed") return "info";
  if (s === "error" || s === "failed") return "critical";
  if (s === "timeout" || s === "retry") return "medium";
  return "neutral";
}

// ---------------------------------------------------------------------------
// Column builder
// ---------------------------------------------------------------------------

function buildColumns(
  onSelect: (entry: LLMLogEntry) => void,
  onOpenRun: (runId: string) => void,
): ColumnDef<LLMLogEntry>[] {
  return [
    {
      id: "timestamp",
      header: "Timestamp",
      accessorKey: "timestamp",
      cell: ({ getValue }) => (
        <span className="font-mono text-xs text-text-muted whitespace-nowrap">
          {formatTimestamp(String(getValue()))}
        </span>
      ),
    },
    {
      id: "model",
      header: "Model",
      accessorKey: "model",
      cell: ({ getValue }) => (
        <span className="font-mono text-xs text-text">{String(getValue())}</span>
      ),
    },
    {
      id: "task_type",
      header: "Task",
      accessorKey: "task_type",
      cell: ({ getValue }) => (
        <span className="font-mono text-xs text-text-muted">
          {String(getValue()) || "—"}
        </span>
      ),
    },
    {
      id: "tokens",
      header: "Tokens",
      accessorFn: (row) => row.input_tokens + row.output_tokens,
      cell: ({ row }) => (
        <span className="font-mono text-xs text-text tabular-nums">
          {row.original.input_tokens}
          <span className="text-text-muted">/</span>
          {row.original.output_tokens}
        </span>
      ),
    },
    {
      id: "cost",
      header: "Cost",
      accessorKey: "cost_usd",
      cell: ({ getValue }) => (
        <span className="font-mono text-xs text-text tabular-nums">
          {formatCost(Number(getValue()))}
        </span>
      ),
    },
    {
      id: "duration",
      header: "Duration",
      accessorKey: "duration_ms",
      cell: ({ getValue }) => (
        <span className="font-mono text-xs text-text-muted tabular-nums">
          {formatDuration(getValue() as number | null)}
        </span>
      ),
    },
    {
      id: "status",
      header: "Status",
      accessorKey: "status",
      cell: ({ getValue }) => {
        const s = String(getValue());
        return (
          <AilaBadge severity={statusSeverity(s)} size="sm">
            {s}
          </AilaBadge>
        );
      },
    },
    {
      id: "run_id",
      header: "Run",
      accessorKey: "run_id",
      cell: ({ getValue }) => {
        const rid = String(getValue());
        return (
          <Button
            type="button"
            size="sm"
            variant="ghost"
            className="h-6 px-1.5 gap-1 font-mono text-[10px] text-accent"
            onClick={(event) => {
              event.stopPropagation();
              onOpenRun(rid);
            }}
            aria-label={`Open run ${rid}`}
          >
            {rid.slice(0, 8)}…
            <ArrowSquareOut className="h-3 w-3" />
          </Button>
        );
      },
    },
    {
      id: "details",
      header: "",
      cell: ({ row }) => (
        <Button
          type="button"
          size="sm"
          variant="outline"
          className="h-6 px-2 font-mono text-[10px]"
          onClick={() => onSelect(row.original)}
        >
          View
        </Button>
      ),
    },
  ];
}

// ---------------------------------------------------------------------------
// Detail panel
// ---------------------------------------------------------------------------

interface DetailPanelProps {
  entry: LLMLogEntry;
  onClose: () => void;
}

function DetailPanel({ entry, onClose }: DetailPanelProps) {
  return (
    <AilaCard variant="elevated" padding="md" className="relative" techBorder glow><div className="flex items-start justify-between gap-2 mb-3">
      <div>
        <h3 className="font-mono text-sm font-semibold text-text">
          {entry.model}
          <span className="text-text-muted"> · {entry.task_type || "—"}</span>
        </h3>
        <p className="font-mono text-[10px] text-text-muted mt-1">
          {formatTimestamp(entry.timestamp)} · {formatCost(entry.cost_usd)} ·{" "}
          {entry.input_tokens + entry.output_tokens} tokens ·{" "}
          {formatDuration(entry.duration_ms)}
        </p>
      </div>
      <Button
        type="button"
        size="sm"
        variant="ghost"
        className="h-7 w-7 p-0"
        onClick={onClose}
        aria-label="Close detail panel"
      >
        <XIcon className="h-4 w-4" />
      </Button>
    </div>
    <div className="flex flex-col gap-3">
      <div>
        <p className="font-mono text-[10px] uppercase tracking-wider text-text-muted mb-1">
          Prompt Preview
        </p>
        <pre
          className="font-mono text-xs text-text whitespace-pre-wrap break-all bg-surface border border-border rounded-[4px] p-2 max-h-[240px] overflow-auto"
        >
          {entry.prompt_preview ?? "(not captured)"}
        </pre>
      </div>
      <div>
        <p className="font-mono text-[10px] uppercase tracking-wider text-text-muted mb-1">
          Response Preview
        </p>
        <pre
          className="font-mono text-xs text-text whitespace-pre-wrap break-all bg-surface border border-border rounded-[4px] p-2 max-h-[240px] overflow-auto"
        >
          {entry.response_preview ?? "(not captured)"}
        </pre>
      </div>
    </div></AilaCard>
  );
}

// ---------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------

export function LLMLogPage() {
  const navigate = useNavigate();
  const [filters, setFilters] = useState<JqlFilter[]>([]);
  const [offset, setOffset] = useState(0);
  const [selected, setSelected] = useState<LLMLogEntry | null>(null);

  const logQuery = useQuery({
    queryKey: ["admin", "llm-log", filters, offset],
    queryFn: () =>
      authorizedRequestJson<Envelope<LLMLogResponse>>(
        buildLogPath(filters, offset),
      ),
  });

  const data = logQuery.data?.data;
  const items = useMemo(() => data?.items ?? [], [data]);
  const totalCost = data?.total_cost_usd ?? 0;
  const total = data?.total ?? 0;

  const handleFiltersChange = useCallback((next: JqlFilter[]) => {
    setFilters(next);
    setOffset(0);
  }, []);

  const handleOpenRun = useCallback(
    (runId: string) => {
      navigate(`/console/${runId}`);
    },
    [navigate],
  );

  const columns = useMemo(
    () => buildColumns(setSelected, handleOpenRun),
    [handleOpenRun],
  );

  return (
    <div className="flex flex-col gap-6 p-4 lg:p-6">
      <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="font-mono text-xl font-semibold text-text flex items-center gap-2">
            <Robot className="h-5 w-5 text-accent" />
            LLM Interaction Log
          </h1>
          <p className="font-mono text-sm text-text-muted mt-0.5">
            Per-call record of every LLM request. Admin-only. Previews are
            truncated on write -- full payloads are never stored here.
          </p>
        </div>
        <div className="flex items-center gap-3">
          <AilaCard variant="elevated" padding="md" techBorder glow><p className="font-mono text-[10px] uppercase tracking-wider text-text-muted flex items-center gap-1">
            <Coins className="h-3 w-3" /> Total Cost
          </p>
          <p className="font-mono text-lg font-semibold text-text tabular-nums">
            {formatCost(totalCost)}
          </p>
          <p className="font-mono text-[10px] text-text-muted">
            {total} call{total === 1 ? "" : "s"} matching filters
          </p></AilaCard>
        </div>
      </div>

      <JqlFilterBar
        fields={FIELDS}
        onChange={handleFiltersChange}
        placeholder="Filter (e.g. model:gpt-4o, cost>0.5, search:scan)"
      />

      {logQuery.isError && (
        <div className="rounded-[4px] border border-destructive bg-destructive/10 px-4 py-3 font-mono text-sm text-destructive">
          Failed to load LLM log: {(logQuery.error as Error).message}
        </div>
      )}

      {logQuery.isLoading && (
        <AilaCard variant="default" padding="md" techBorder glow><LoadingSkeletonGroup lines={8} /></AilaCard>
      )}

      {!logQuery.isLoading && !logQuery.isError && items.length === 0 && (
        <EmptyState
          icon={<Robot className="h-10 w-10" />}
          title="No LLM calls recorded"
          description="No calls matched the current filters. Clear filters or widen the date range."
          action={{ label: "Clear Filters", onClick: () => handleFiltersChange([]) }}
        />
      )}

      {!logQuery.isLoading && items.length > 0 && (
        <div className="flex flex-col gap-4">
          <div className="flex items-center justify-between">
            <h2 className="font-mono text-sm font-semibold text-text">Calls</h2>
            <Button
              size="sm"
              variant="outline"
              className="gap-1.5"
              onClick={() => logQuery.refetch()}
              disabled={logQuery.isFetching}
            >
              <ArrowClockwise
                className={`h-3.5 w-3.5 ${logQuery.isFetching ? "animate-spin" : ""}`}
              />
              Refresh
            </Button>
          </div>

          <AilaTable
            data={items}
            columns={columns}
            pageSize={25}
            enableSorting
            enableFiltering={false}
          >
            <AilaTable.Header />
            <AilaTable.Body emptyState="No calls match the current filter." />
            <AilaTable.Pagination pageSizeOptions={[10, 25, 50, 100]} />
          </AilaTable>

          {total > PAGE_SIZE && (
            <div className="flex items-center justify-between">
              <span className="font-mono text-xs text-text-muted">
                {offset + 1}-{Math.min(offset + items.length, total)} of {total}
              </span>
              <div className="flex gap-2">
                <Button
                  size="sm"
                  variant="outline"
                  disabled={offset === 0 || logQuery.isFetching}
                  onClick={() => setOffset(Math.max(0, offset - PAGE_SIZE))}
                >
                  Previous
                </Button>
                <Button
                  size="sm"
                  variant="outline"
                  disabled={offset + PAGE_SIZE >= total || logQuery.isFetching}
                  onClick={() => setOffset(offset + PAGE_SIZE)}
                >
                  Next
                </Button>
              </div>
            </div>
          )}

          {selected && (
            <DetailPanel entry={selected} onClose={() => setSelected(null)} />
          )}
        </div>
      )}
    </div>
  );
}

export default LLMLogPage;
