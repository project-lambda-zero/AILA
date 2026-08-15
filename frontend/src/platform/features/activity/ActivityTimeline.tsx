/**
 * ActivityTimeline -- reusable per-run audit trail view.
 *
 * Renders the /audit/events?run_id=<id> stream chronologically (action,
 * stage, status, user, time) with a compact action/status filter and a
 * graceful empty state. Presentation-only: fetching is owned by
 * `useActivity`. Intentionally NOT a replacement for the admin
 * AuditLogsPage -- that page owns the global log, JQL filters, and export.
 *
 * Rebuilt to the mock kit: MonoBadge for status chips, raw mono <input>
 * pair for the filter row, inline mock empty/error states.
 *
 * A11y: the region is labelled ("Activity for run <id>"), the filter
 * inputs carry visible labels, and the event list uses role="list" so
 * screen readers announce the count.
 */
import { useMemo, useState, type CSSProperties } from "react";

import { LoadingSkeletonGroup } from "@/components/aila/LoadingSkeleton";
import { MonoBadge } from "@/components/aila/mock";

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
  /** Accessible label suffix, e.g. "Scan Run" -> "Activity for Scan Run ...". */
  label?: string;
  className?: string;
}

// ---------------------------------------------------------------------------
// Row
// ---------------------------------------------------------------------------

/**
 * Status token -> mock kit tone. Neutral / unknown statuses fall back to
 * `muted` so they read as faint metadata rather than an alarming colour.
 */
const STATUS_TONE: Record<string, string> = {
  completed: "ok",
  succeeded: "ok",
  success: "ok",
  failed: "critical",
  error: "critical",
  running: "info",
  in_progress: "info",
  started: "info",
};

const INPUT_STYLE: CSSProperties = {
  height: 28,
  fontSize: 11,
  padding: "0 10px",
  background: "var(--surface-sunk)",
  color: "var(--text-primary)",
  border: "1px solid var(--border-soft)",
  borderRadius: 3,
  outline: "none",
  fontFamily: "var(--font-mono)",
  width: "100%",
};

const FILTER_LABEL_STYLE: CSSProperties = {
  fontSize: 9,
  letterSpacing: "0.14em",
  textTransform: "uppercase",
  color: "var(--text-faint)",
  fontFamily: "var(--font-mono)",
};

function ActivityRow({ row }: { row: ActivityEvent }) {
  const tone = STATUS_TONE[row.status.toLowerCase()] ?? "muted";
  const when = row.created_at ? new Date(row.created_at).toLocaleString() : "--";
  return (
    <li
      role="listitem"
      className="font-mono"
      style={{
        padding: "8px 10px",
        borderLeft: "2px solid color-mix(in srgb, var(--accent) 45%, transparent)",
        background: "var(--surface-card)",
      }}
    >
      <div className="flex items-center" style={{ gap: 8, fontSize: 11 }}>
        <MonoBadge tone={tone}>{row.status || "?"}</MonoBadge>
        <span
          className="break-all"
          style={{ color: "var(--text-primary)", fontWeight: 500 }}
        >
          {row.action}
        </span>
        {row.stage ? (
          <span style={{ color: "var(--text-muted)", opacity: 0.75 }}>
            {"\u00b7"} {row.stage}
          </span>
        ) : null}
      </div>
      <div
        className="flex flex-wrap items-center"
        style={{
          columnGap: 12,
          rowGap: 2,
          paddingLeft: 2,
          paddingTop: 3,
          fontSize: 9.5,
          color: "var(--text-muted)",
          letterSpacing: "0.02em",
        }}
      >
        <span>{when}</span>
        {row.user_id ? <span>by {row.user_id}</span> : null}
        {row.target ? <span className="break-all">target {row.target}</span> : null}
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
      className={`flex flex-col ${className ?? ""}`}
      style={{ gap: 12 }}
      aria-label={regionLabel}
    >
      <div className="flex items-center justify-between" style={{ gap: 8 }}>
        <h3
          className="font-mono uppercase"
          style={{
            fontSize: 10,
            letterSpacing: "0.14em",
            color: "var(--text-faint)",
            fontWeight: 600,
            margin: 0,
          }}
        >
          Activity
        </h3>
        {query.data ? (
          <span
            className="font-mono tabular-nums"
            style={{ fontSize: 9.5, color: "var(--text-faint)" }}
            aria-live="polite"
          >
            {query.data.total} event{query.data.total === 1 ? "" : "s"}
          </span>
        ) : null}
      </div>

      {!hideFilters && (
        <div className="grid grid-cols-1 sm:grid-cols-2" style={{ gap: 8 }}>
          <label className="flex flex-col" style={{ gap: 4 }}>
            <span style={FILTER_LABEL_STYLE}>Action</span>
            <input
              type="text"
              value={actionFilter}
              onChange={(e) => setActionFilter(e.target.value)}
              placeholder="scan.start,ssh.execute"
              style={INPUT_STYLE}
              aria-label="Filter activity by action"
            />
          </label>
          <label className="flex flex-col" style={{ gap: 4 }}>
            <span style={FILTER_LABEL_STYLE}>Status</span>
            <input
              type="text"
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              placeholder="completed,failed"
              style={INPUT_STYLE}
              aria-label="Filter activity by status"
            />
          </label>
        </div>
      )}

      {!runId ? (
        <p
          className="font-mono"
          style={{ fontSize: 11, color: "var(--text-muted)", margin: 0 }}
        >
          No run selected -- select an entity to view its activity.
        </p>
      ) : query.isLoading ? (
        <LoadingSkeletonGroup lines={4} />
      ) : query.isError ? (
        <div
          role="alert"
          className="font-mono"
          style={{
            padding: "8px 12px",
            borderRadius: 3,
            border: "1px solid color-mix(in srgb, var(--accent) 45%, transparent)",
            background: "color-mix(in srgb, var(--accent) 8%, transparent)",
            color: "var(--accent)",
            fontSize: 11,
          }}
        >
          {(query.error as Error).message}
        </div>
      ) : rows.length === 0 ? (
        <div
          className="flex flex-col items-center justify-center"
          style={{
            gap: 6,
            padding: 24,
            textAlign: "center",
            minHeight: 96,
          }}
        >
          <div
            className="font-mono uppercase"
            style={{
              fontSize: 11,
              letterSpacing: "0.14em",
              color: "var(--text-primary)",
            }}
          >
            No activity yet
          </div>
          <div
            className="font-mono"
            style={{ fontSize: 10.5, color: "var(--text-muted)", maxWidth: 380 }}
          >
            No audit events have been recorded for this run. Live actions will
            appear here.
          </div>
        </div>
      ) : (
        <ol
          role="list"
          className="flex flex-col"
          style={{ gap: 4, maxHeight: 320, overflowY: "auto", listStyle: "none", padding: 0, margin: 0 }}
        >
          {rows.map((row, index) => (
            <ActivityRow key={row.id ?? `${row.created_at}-${index}`} row={row} />
          ))}
        </ol>
      )}
    </section>
  );
}
