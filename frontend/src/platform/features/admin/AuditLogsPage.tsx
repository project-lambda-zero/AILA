/**
 * AuditLogsPage — admin audit trail with filterable AilaTable and CSV/JSON export.
 *
 * ADM-01: Filterable, sortable audit log table with server-side filtering
 * (run_id, stage, action, status, user_id, since, until) and client-side
 * sort/pagination via AilaTable. Exports current page as CSV or JSON.
 *
 * Fetches up to 250 events per server request (backend max). AilaTable
 * handles local sort/filter/pagination within the fetched set.
 */
import { useState, useCallback, useMemo } from "react";
import { useQuery } from "@tanstack/react-query";
import { type ColumnDef } from "@tanstack/react-table";
import { Download, ArrowClockwise, ClipboardText, X as XIcon } from "@phosphor-icons/react";

import { AilaCard } from "@/components/aila/AilaCard";
import { AilaTable } from "@/components/aila/AilaTable";
import { AilaBadge } from "@/components/aila/AilaBadge";
import { LoadingSkeletonGroup } from "@/components/aila/LoadingSkeleton";
import { EmptyState } from "@/components/aila/EmptyState";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { authorizedRequestJson } from "@platform/api/http";
import {
  JqlFilterBar,
  filtersToQueryParams,
  type JqlFieldSpec,
  type JqlFilter,
} from "@/components/filters/JqlFilterBar";
import { AuditDetailRenderer } from "./AuditDetailRenderer";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface AuditEvent {
  id: number | null;
  run_id: string;
  stage: string;
  action: string;
  status: string;
  target: string;
  user_id: string;
  details: Record<string, unknown>;
  created_at: string | null;
}

interface AuditListResponse {
  total: number;
  page: number;
  page_size: number;
  pages: number;
  items: AuditEvent[];
}

interface AuditFilters {
  runId: string;
  stage: string;
  action: string;
  status: string;
  userId: string;
  since: string;
  until: string;
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const EMPTY_FILTERS: AuditFilters = {
  runId: "",
  stage: "",
  action: "",
  status: "",
  userId: "",
  since: "",
  until: "",
};

const SERVER_PAGE_SIZE = 250; // backend max

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

function buildAuditPath(filters: AuditFilters): string {
  const params = new URLSearchParams();
  if (filters.runId) params.set("run_id", filters.runId);
  if (filters.stage) params.set("stage", filters.stage);
  if (filters.action) params.set("action", filters.action);
  if (filters.status) params.set("status", filters.status);
  if (filters.userId) params.set("user_id", filters.userId);
  if (filters.since) params.set("since", filters.since);
  if (filters.until) params.set("until", filters.until);
  params.set("page", "1");
  params.set("page_size", String(SERVER_PAGE_SIZE));
  const qs = params.toString();
  return qs ? `/audit/events?${qs}` : "/audit/events";
}

// JQL filter bar field specs -- names match the `AuditFilters` query keys so
// `jqlToAuditFilters()` can translate one to the other without a lookup table.
const AUDIT_JQL_FIELDS: JqlFieldSpec[] = [
  { key: "run_id", label: "Run ID", operators: [":"] },
  { key: "stage", label: "Stage", operators: [":"] },
  { key: "action", label: "Action", operators: [":"] },
  { key: "status", label: "Status", operators: [":"] },
  { key: "user_id", label: "User", operators: [":"] },
  { key: "since", label: "Since", operators: [":"] },
  { key: "until", label: "Until", operators: [":"] },
  { key: "search", label: "Search", operators: [":"] },
];

/** Translate JQL filter chips into the legacy AuditFilters shape. */
function jqlToAuditFilters(filters: JqlFilter[]): AuditFilters {
  const backend = filtersToQueryParams(filters);
  return {
    runId: backend.run_id ?? "",
    stage: backend.stage ?? "",
    action: backend.action ?? "",
    status: backend.status ?? "",
    userId: backend.user_id ?? "",
    since: backend.since ?? "",
    until: backend.until ?? "",
  };
}

function formatTimestamp(value: string | null): string {
  if (!value) return "—";
  return new Date(value).toLocaleString();
}

function auditStatusSeverity(
  status: string,
): "info" | "critical" | "medium" | "neutral" {
  const s = status.toLowerCase();
  if (s === "completed") return "info";
  if (s === "failed") return "critical";
  if (s === "running") return "medium";
  return "neutral";
}

// ---------------------------------------------------------------------------
// Export helpers
// ---------------------------------------------------------------------------

function escapeCsvCell(value: string): string {
  if (value.includes(",") || value.includes('"') || value.includes("\n")) {
    return `"${value.replace(/"/g, '""')}"`;
  }
  return value;
}

function exportAsCsv(items: AuditEvent[]): void {
  const headers = ["run_id", "stage", "action", "status", "user_id", "target", "created_at"];
  const rows = items.map((item) =>
    [
      item.run_id,
      item.stage,
      item.action,
      item.status,
      item.user_id,
      item.target ?? "",
      item.created_at ?? "",
    ]
      .map(escapeCsvCell)
      .join(","),
  );
  const csv = [headers.join(","), ...rows].join("\n");
  triggerDownload(new Blob([csv], { type: "text/csv" }), "audit-logs.csv");
}

function exportAsJson(items: AuditEvent[]): void {
  const json = JSON.stringify(items, null, 2);
  triggerDownload(
    new Blob([json], { type: "application/json" }),
    "audit-logs.json",
  );
}

function triggerDownload(blob: Blob, filename: string): void {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

// ---------------------------------------------------------------------------
// Column definitions
// ---------------------------------------------------------------------------

const AUDIT_COLUMNS: ColumnDef<AuditEvent>[] = [
  {
    id: "run_id",
    header: "Run ID",
    accessorKey: "run_id",
    cell: ({ getValue }) => (
      <span className="font-mono text-xs text-text-muted truncate max-w-[120px] block" title={String(getValue())}>
        {String(getValue()).slice(0, 8)}…
      </span>
    ),
  },
  {
    id: "stage",
    header: "Stage",
    accessorKey: "stage",
    cell: ({ getValue }) => (
      <span className="font-mono text-xs text-text">{String(getValue())}</span>
    ),
  },
  {
    id: "action",
    header: "Action",
    accessorKey: "action",
    cell: ({ getValue }) => (
      <span className="font-mono text-xs text-text">{String(getValue())}</span>
    ),
  },
  {
    id: "status",
    header: "Status",
    accessorKey: "status",
    cell: ({ getValue }) => {
      const s = String(getValue());
      return (
        <AilaBadge severity={auditStatusSeverity(s)} size="sm">
          {s}
        </AilaBadge>
      );
    },
  },
  {
    id: "user_id",
    header: "User",
    accessorKey: "user_id",
    cell: ({ getValue }) => (
      <span className="font-mono text-xs text-text">{String(getValue())}</span>
    ),
  },
  {
    id: "target",
    header: "Target",
    accessorKey: "target",
    cell: ({ getValue }) => {
      const v = String(getValue() ?? "");
      return (
        <span className="font-mono text-xs text-text-muted">{v || "—"}</span>
      );
    },
  },
  {
    id: "created_at",
    header: "Timestamp",
    accessorKey: "created_at",
    cell: ({ getValue }) => (
      <span className="font-mono text-xs text-text-muted whitespace-nowrap">
        {formatTimestamp(getValue() as string | null)}
      </span>
    ),
  },
];

/**
 * Extend AUDIT_COLUMNS with a final "Details" column that opens the
 * AuditDetailRenderer panel for the clicked event. Defined as a builder so
 * the onSelect callback is closure-captured cleanly.
 */
function AUDIT_COLUMNS_WITH_DETAILS(
  onSelect: (event: AuditEvent) => void,
): ColumnDef<AuditEvent>[] {
  return [
    ...AUDIT_COLUMNS,
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
// Filter form
// ---------------------------------------------------------------------------

interface FilterFormProps {
  draft: AuditFilters;
  onDraftChange: (patch: Partial<AuditFilters>) => void;
  onApply: () => void;
  onClear: () => void;
  isFetching: boolean;
}

function FilterForm({
  draft,
  onDraftChange,
  onApply,
  onClear,
  isFetching,
}: FilterFormProps) {
  return (
    <AilaCard variant="elevated" padding="md">
      <h2 className="font-mono text-sm font-semibold text-text mb-3">
        Filters
      </h2>
      <form
        className="flex flex-col gap-4"
        onSubmit={(e) => {
          e.preventDefault();
          onApply();
        }}
      >
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3">
          <div className="flex flex-col gap-1">
            <label className="font-mono text-xs text-text-muted" htmlFor="af-run-id">
              Run ID
            </label>
            <Input
              id="af-run-id"
              value={draft.runId}
              onChange={(e) => onDraftChange({ runId: e.target.value })}
              placeholder="50b5b278-1b3d-…"
              className="font-mono text-xs"
            />
          </div>

          <div className="flex flex-col gap-1">
            <label className="font-mono text-xs text-text-muted" htmlFor="af-stage">
              Stage
            </label>
            <Input
              id="af-stage"
              value={draft.stage}
              onChange={(e) => onDraftChange({ stage: e.target.value })}
              placeholder="task,report_lookup"
              className="font-mono text-xs"
            />
          </div>

          <div className="flex flex-col gap-1">
            <label className="font-mono text-xs text-text-muted" htmlFor="af-action">
              Action
            </label>
            <Input
              id="af-action"
              value={draft.action}
              onChange={(e) => onDraftChange({ action: e.target.value })}
              placeholder="scan.start"
              className="font-mono text-xs"
            />
          </div>

          <div className="flex flex-col gap-1">
            <label className="font-mono text-xs text-text-muted" htmlFor="af-status">
              Status
            </label>
            <Input
              id="af-status"
              value={draft.status}
              onChange={(e) => onDraftChange({ status: e.target.value })}
              placeholder="completed,failed"
              className="font-mono text-xs"
            />
          </div>

          <div className="flex flex-col gap-1">
            <label className="font-mono text-xs text-text-muted" htmlFor="af-user">
              User ID
            </label>
            <Input
              id="af-user"
              value={draft.userId}
              onChange={(e) => onDraftChange({ userId: e.target.value })}
              placeholder="system"
              className="font-mono text-xs"
            />
          </div>
        </div>

        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
          <div className="flex flex-col gap-1">
            <label className="font-mono text-xs text-text-muted" htmlFor="af-since">
              Since (ISO 8601)
            </label>
            <Input
              id="af-since"
              type="datetime-local"
              value={draft.since}
              onChange={(e) => onDraftChange({ since: e.target.value })}
              className="font-mono text-xs"
            />
          </div>

          <div className="flex flex-col gap-1">
            <label className="font-mono text-xs text-text-muted" htmlFor="af-until">
              Until (ISO 8601)
            </label>
            <Input
              id="af-until"
              type="datetime-local"
              value={draft.until}
              onChange={(e) => onDraftChange({ until: e.target.value })}
              className="font-mono text-xs"
            />
          </div>
        </div>

        <div className="flex gap-2">
          <Button type="submit" size="sm" disabled={isFetching}>
            {isFetching ? "Loading…" : "Apply Filters"}
          </Button>
          <Button
            type="button"
            size="sm"
            variant="outline"
            onClick={onClear}
          >
            Clear
          </Button>
        </div>
      </form>
    </AilaCard>
  );
}

// ---------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------

export function AuditLogsPage() {
  const [draftFilters, setDraftFilters] = useState<AuditFilters>(EMPTY_FILTERS);
  const [activeFilters, setActiveFilters] = useState<AuditFilters>(EMPTY_FILTERS);
  const [useJql, setUseJql] = useState(true);
  const [selectedEvent, setSelectedEvent] = useState<AuditEvent | null>(null);

  const auditQuery = useQuery({
    queryKey: ["platform", "audit-events", activeFilters],
    queryFn: () =>
      authorizedRequestJson<AuditListResponse>(buildAuditPath(activeFilters)),
  });

  const items = useMemo(() => auditQuery.data?.items ?? [], [auditQuery.data]);

  const applyFilters = useCallback(() => {
    setActiveFilters({ ...draftFilters });
  }, [draftFilters]);

  const clearFilters = useCallback(() => {
    setDraftFilters(EMPTY_FILTERS);
    setActiveFilters(EMPTY_FILTERS);
  }, []);

  const handleJqlChange = useCallback((filters: JqlFilter[]) => {
    setActiveFilters(jqlToAuditFilters(filters));
  }, []);

  const hasDateRange = activeFilters.since || activeFilters.until;
  const dateRangeLabel = hasDateRange
    ? [activeFilters.since, activeFilters.until].filter(Boolean).join(" → ")
    : "All time";

  return (
    <div className="flex flex-col gap-6 p-4 lg:p-6">
      {/* Page header */}
      <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="font-mono text-xl font-semibold text-text flex items-center gap-2">
            <ClipboardText className="h-5 w-5 text-accent" />
            Audit Logs
          </h1>
          <p className="font-mono text-sm text-text-muted mt-0.5">
            Immutable platform audit trail. Filters use AND-across-fields,
            comma-OR within a field.
          </p>
        </div>

        {items.length > 0 && (
          <div className="flex gap-2">
            <Button
              size="sm"
              variant="outline"
              className="gap-1.5"
              onClick={() => exportAsCsv(items)}
            >
              <Download className="h-4 w-4" />
              Export CSV
            </Button>
            <Button
              size="sm"
              variant="outline"
              className="gap-1.5"
              onClick={() => exportAsJson(items)}
            >
              <Download className="h-4 w-4" />
              Export JSON
            </Button>
          </div>
        )}
      </div>

      {/* Filter bar -- JQL chip input is default; legacy form available as fallback */}
      <div className="flex flex-col gap-2">
        <div className="flex items-center justify-between">
          <h2 className="font-mono text-xs text-text-muted uppercase tracking-wider">
            Filters
          </h2>
          <Button
            type="button"
            size="sm"
            variant="ghost"
            className="h-6 px-2 font-mono text-[10px] text-text-muted"
            onClick={() => setUseJql((v) => !v)}
          >
            {useJql ? "Use form" : "Use filter bar"}
          </Button>
        </div>
        {useJql ? (
          <JqlFilterBar
            fields={AUDIT_JQL_FIELDS}
            onChange={handleJqlChange}
            placeholder="Filter (e.g. stage:ssh, status:failed, search:web01)"
          />
        ) : (
          <FilterForm
            draft={draftFilters}
            onDraftChange={(patch) =>
              setDraftFilters((prev) => ({ ...prev, ...patch }))
            }
            onApply={applyFilters}
            onClear={clearFilters}
            isFetching={auditQuery.isFetching}
          />
        )}
      </div>

      {/* Metric cards */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
        <AilaCard variant="elevated" padding="md">
          <p className="font-mono text-xs uppercase tracking-wider text-text-muted">
            Total Events
          </p>
          <p className="font-mono text-2xl font-semibold text-text mt-1">
            {auditQuery.data?.total ?? "—"}
          </p>
          <p className="font-mono text-xs text-text-muted mt-0.5">
            Matching active filters
          </p>
        </AilaCard>

        <AilaCard variant="elevated" padding="md">
          <p className="font-mono text-xs uppercase tracking-wider text-text-muted">
            Loaded Events
          </p>
          <p className="font-mono text-2xl font-semibold text-text mt-1">
            {items.length}
          </p>
          <p className="font-mono text-xs text-text-muted mt-0.5">
            This page (max {SERVER_PAGE_SIZE})
          </p>
        </AilaCard>

        <AilaCard variant="elevated" padding="md">
          <p className="font-mono text-xs uppercase tracking-wider text-text-muted">
            Date Range
          </p>
          <p className="font-mono text-sm font-semibold text-text mt-1 truncate" title={dateRangeLabel}>
            {dateRangeLabel}
          </p>
          <p className="font-mono text-xs text-text-muted mt-0.5">
            Active filter range
          </p>
        </AilaCard>
      </div>

      {/* Error banner */}
      {auditQuery.isError && (
        <div className="rounded-[4px] border border-destructive bg-destructive/10 px-4 py-3 font-mono text-sm text-destructive">
          Failed to load audit events:{" "}
          {(auditQuery.error as Error).message}
        </div>
      )}

      {/* Loading skeleton */}
      {auditQuery.isLoading && (
        <AilaCard variant="default" padding="md">
          <LoadingSkeletonGroup lines={8} />
        </AilaCard>
      )}

      {/* Empty state */}
      {!auditQuery.isLoading && !auditQuery.isError && items.length === 0 && (
        <EmptyState
          icon={<ClipboardText className="h-10 w-10" />}
          title="No audit events"
          description="No events matched the current filters. Try clearing the filters or adjusting the date range."
          action={{ label: "Clear Filters", onClick: clearFilters }}
        />
      )}

      {/* Audit table */}
      {!auditQuery.isLoading && items.length > 0 && (
        <div>
          <div className="flex items-center justify-between mb-2">
            <h2 className="font-mono text-sm font-semibold text-text">
              Audit Trail
            </h2>
            <Button
              size="sm"
              variant="outline"
              className="gap-1.5"
              onClick={() => auditQuery.refetch()}
              disabled={auditQuery.isFetching}
            >
              <ArrowClockwise
                className={`h-3.5 w-3.5 ${auditQuery.isFetching ? "animate-spin" : ""}`}
              />
              Refresh
            </Button>
          </div>

          <AilaTable
            data={items}
            columns={AUDIT_COLUMNS_WITH_DETAILS(setSelectedEvent)}
            pageSize={25}
            enableSorting
            enableFiltering={false}
          >
            <AilaTable.Header />
            <AilaTable.Body
              emptyState="No events match the current table filter."
            />
            <AilaTable.Pagination pageSizeOptions={[10, 25, 50, 100]} />
          </AilaTable>

          <p className="font-mono text-xs text-text-muted mt-2">
            Showing first {items.length} of {auditQuery.data?.total ?? items.length} total events.
            {(auditQuery.data?.total ?? 0) > SERVER_PAGE_SIZE &&
              " Narrow the filters to see more."}
          </p>

          {selectedEvent && (
            <AilaCard variant="elevated" padding="md" className="mt-4 relative">
              <div className="flex items-start justify-between gap-2 mb-3">
                <div>
                  <h3 className="font-mono text-sm font-semibold text-text">
                    {selectedEvent.stage} · {selectedEvent.action}
                    <AilaBadge
                      severity={auditStatusSeverity(selectedEvent.status)}
                      size="sm"
                      className="ml-2"
                    >
                      {selectedEvent.status}
                    </AilaBadge>
                  </h3>
                  <p className="font-mono text-[10px] text-text-muted mt-1">
                    {formatTimestamp(selectedEvent.created_at)} · user {selectedEvent.user_id} ·
                    run {selectedEvent.run_id}
                  </p>
                </div>
                <Button
                  type="button"
                  size="sm"
                  variant="ghost"
                  className="h-7 w-7 p-0"
                  onClick={() => setSelectedEvent(null)}
                  aria-label="Close audit details"
                >
                  <XIcon className="h-4 w-4" />
                </Button>
              </div>
              <AuditDetailRenderer details={selectedEvent.details} />
            </AilaCard>
          )}
        </div>
      )}
    </div>
  );
}
