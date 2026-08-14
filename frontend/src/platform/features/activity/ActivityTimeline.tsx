/**
 * ActivityTimeline -- reusable per-run audit trail view.
 *
 * Renders the /audit/events?run_id=<id> stream chronologically (action,
 * stage, status, user, time) with a compact action/status filter and a
 * graceful empty state. Presentation-only: fetching is owned by
 * `useActivity`. Intentionally NOT a replacement for the admin
 * AuditLogsPage -- that page owns the global log, JQL filters, and export.
 *
 * A11y: the region is labelled ("Activity for run <id>"), the filter
 * inputs carry visible labels, and the event list uses role="list" so
 * screen readers announce the count.
 */
import { useMemo, useState } from "react";

import { AilaBadge } from "@/components/aila/AilaBadge";
import { EmptyState } from "@/components/aila/EmptyState";
import { LoadingSkeletonGroup } from "@/components/aila/LoadingSkeleton";
import { Input } from "@/components/ui/input";

import type { ActivityEvent, ActivityFilters } from "./api";
import { useActivity } from "./useActivity";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface ActivityTimelineProps {
  /** Run this timeline is scoped to. Empty string disables fetching. */
  runId: string;
  /**
   * Optional filter overrides that pin the query to a subset (e.g. only
   * status=failed for a "recent failures" panel). User-typed filters in
   * the compact filter row merge on top of these.
   */
  initialFilters?: ActivityFilters;
  /** Skip fetching until the parent surface becomes visible. */
  disabled?: boolean;
  /** Refetch every 5 s -- for running entities. */
  live?: boolean;
  /** Hide the compact action/status filter row. */
  hideFilters?: boolean;
  /**
   * Cap the number of rows rendered from the resolved page (backend already
   * pages by 50 by default; this is a display cap for tight side panels).
   */
  maxRows?: number;
  /** Accessible label suffix, e.g. "Scan Run" -> "Activity for Scan Run …". */
  label?: string;
  className?: string;
}

// ---------------------------------------------------------------------------
// Row
// ---------------------------------------------------------------------------

type BadgeSeverity = "info" | "critical" | "medium" | "neutral";

const STATUS_SEVERITY: Record<string, BadgeSeverity> = {
  completed: "info",
  succeeded: "info",
  success: "info",
  failed: "critical",
  error: "critical",
  running: "medium",
  in_progress: "medium",
  started: "medium",
};

function ActivityRow({ row }: { row: ActivityEvent }) {
  const severity: BadgeSeverity =
    STATUS_SEVERITY[row.status.toLowerCase()] ?? "neutral";
  const when = row.created_at ? new Date(row.created_at).toLocaleString() : "--";
  return (
    <li className="border-l-2 border-accent/40 pl-3 py-1.5" role="listitem">
      <div className="flex items-center gap-2 font-mono text-xs">
        <AilaBadge severity={severity} size="sm">
          {row.status || "?"}
        </AilaBadge>
        <span className="font-semibold text-text break-all">{row.action}</span>
        {row.stage ? (
          <span className="text-text-muted opacity-70">· {row.stage}</span>
        ) : null}
      </div>
      <div className="flex flex-wrap items-center gap-x-3 gap-y-0.5 pl-1 pt-0.5 font-mono text-[10px] text-text-muted">
        <span>{when}</span>
        {row.user_id ? <span>by {row.user_id}</span> : null}
        {row.target ? (
          <span className="break-all">target {row.target}</span>
        ) : null}
      </div>
    </li>
  );
}

// ---------------------------------------------------------------------------
// Timeline
// ---------------------------------------------------------------------------

export function ActivityTimeline({
  runId,
  initialFilters,
  disabled,
  live,
  hideFilters,
  maxRows,
  label,
  className,
}: ActivityTimelineProps) {
  const [actionFilter, setActionFilter] = useState("");
  const [statusFilter, setStatusFilter] = useState("");

  const query = useActivity(runId, {
    ...initialFilters,
    action: actionFilter.trim() || initialFilters?.action,
    status: statusFilter.trim() || initialFilters?.status,
    disabled,
    live,
  });

  const rows = useMemo(() => {
    const items = query.data?.items ?? [];
    return maxRows && maxRows > 0 ? items.slice(0, maxRows) : items;
  }, [query.data, maxRows]);

  const regionLabel = `Activity for ${label ?? "run"} ${runId || "(none)"}`;

  return (
    <section
      className={`flex flex-col gap-3 ${className ?? ""}`}
      aria-label={regionLabel}
    >
      <div className="flex items-center justify-between gap-2">
        <h3 className="font-mono text-xs font-semibold uppercase tracking-wider text-text-muted">
          Activity
        </h3>
        {query.data ? (
          <span
            className="font-mono text-[10px] text-text-muted tabular-nums"
            aria-live="polite"
          >
            {query.data.total} event{query.data.total === 1 ? "" : "s"}
          </span>
        ) : null}
      </div>

      {!hideFilters && (
        <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
          <label className="flex flex-col gap-1 font-mono text-[10px] uppercase tracking-wider text-text-muted">
            <span>Action</span>
            <Input
              value={actionFilter}
              onChange={(e) => setActionFilter(e.target.value)}
              placeholder="scan.start,ssh.execute"
              className="h-8 font-mono text-xs"
              aria-label="Filter activity by action"
            />
          </label>
          <label className="flex flex-col gap-1 font-mono text-[10px] uppercase tracking-wider text-text-muted">
            <span>Status</span>
            <Input
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              placeholder="completed,failed"
              className="h-8 font-mono text-xs"
              aria-label="Filter activity by status"
            />
          </label>
        </div>
      )}

      {!runId ? (
        <p className="font-mono text-xs text-text-muted">
          No run selected -- select an entity to view its activity.
        </p>
      ) : query.isLoading ? (
        <LoadingSkeletonGroup lines={4} />
      ) : query.isError ? (
        <div
          role="alert"
          className="rounded-[2px] border border-destructive bg-destructive/10 px-3 py-2 font-mono text-xs text-destructive"
        >
          {(query.error as Error).message}
        </div>
      ) : rows.length === 0 ? (
        <EmptyState
          title="No activity yet"
          description="No audit events have been recorded for this run. Live actions will appear here."
        />
      ) : (
        <ol
          role="list"
          className="flex flex-col gap-1 max-h-80 overflow-y-auto"
        >
          {rows.map((row, index) => (
            <ActivityRow key={row.id ?? `${row.created_at}-${index}`} row={row} />
          ))}
        </ol>
      )}
    </section>
  );
}
