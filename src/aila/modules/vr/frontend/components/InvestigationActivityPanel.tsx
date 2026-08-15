/**
 * InvestigationActivityPanel -- audit-trail view scoped to one
 * investigation's workflow run.
 *
 * Data source: GET /audit/events?run_id=<id>&action=&status=&page_size=50
 * (see aila/api/routers/audit.py). The response shape is a paginated
 * `AuditListResponse` with items `{ id, run_id, stage, action, status,
 * target, user_id, details, created_at }`. Team-scoped server-side; the
 * team check is transparent to the client.
 *
 * VRInvestigationSummary does not yet expose a distinct `task_id`
 * column, so we use `investigation.id` as the run_id. Backends that
 * key audit events under a different run identifier will simply
 * return zero rows -- handled as an empty state, never as an error.
 */
import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Funnel } from "@phosphor-icons/react/dist/csr/Funnel";
import { ArrowClockwise } from "@phosphor-icons/react/dist/csr/ArrowClockwise";

import { authorizedRequestJson } from "@platform/api/http";

import { AilaBadge } from "@/components/aila/AilaBadge";
import { WindowPanel } from "@/components/aila/WindowPanel";
import { LoadingSkeletonGroup } from "@/components/aila/LoadingSkeleton";

// Local wire types. Kept private -- the shell defines the same shape
// under `frontend/src/platform/features/admin/AuditLogsPage.tsx` but
// modules must not import from the shell (@aila/vr-frontend is a
// standalone package). Fields mirror `AuditEventResponse` /
// `PaginatedResponse[AuditEventResponse]` on the backend and MUST
// stay in sync when either side moves.
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

function statusSeverity(
  status: string,
): "critical" | "high" | "medium" | "low" | "info" | "neutral" {
  const s = status.toLowerCase();
  if (s === "failed" || s === "error") return "critical";
  if (s === "warning" || s === "skipped") return "medium";
  if (s === "completed" || s === "succeeded" || s === "ok") return "low";
  if (s === "running" || s === "started") return "info";
  return "neutral";
}

function formatTs(value: string | null): string {
  if (!value) return "--";
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return value;
  return d.toLocaleString();
}

export function InvestigationActivityPanel({
  investigationId,
  hasTaskId = true,
}: {
  investigationId: string;
  /** When the caller can prove the entity has no task/run identifier
   *  (e.g. an investigation that never enqueued), pass false so the
   *  panel skips the fetch and shows a clear "no run id" empty state
   *  instead of a noisy 0-row spinner. */
  hasTaskId?: boolean;
}) {
  const [actionFilter, setActionFilter] = useState("");
  const [statusFilter, setStatusFilter] = useState("");

  // Auto-refresh cadence matches useInvestigation's live poll -- the
  // audit trail is append-only, so 5s cadence is enough to catch new
  // stage transitions without hammering the endpoint. Query is disabled
  // when no run id is available so we don't fire pointless requests.
  const query = useQuery({
    queryKey: [
      "vr",
      "investigation-audit",
      investigationId,
      actionFilter,
      statusFilter,
    ],
    queryFn: async () => {
      const params = new URLSearchParams({ page: "1", page_size: "50" });
      params.set("run_id", investigationId);
      if (actionFilter.trim()) params.set("action", actionFilter.trim());
      if (statusFilter.trim()) params.set("status", statusFilter.trim());
      return await authorizedRequestJson<AuditListResponse>(
        `/audit/events?${params.toString()}`,
      );
    },
    enabled: hasTaskId && !!investigationId,
    refetchInterval: 5000,
    // The audit endpoint is a strict read from Postgres; when it 500s
    // (rare) we surface the empty state rather than the panel-boundary
    // error UI, because the operator has nothing to act on.
    retry: 1,
  });

  const items = useMemo(() => {
    const raw = query.data?.items ?? [];
    // API returns newest-first (`ORDER BY created_at DESC`); the panel
    // reads better chronologically (oldest at top, newest at bottom)
    // so we reverse in place.
    return [...raw].sort((a, b) =>
      (a.created_at ?? "").localeCompare(b.created_at ?? ""),
    );
  }, [query.data]);

  const totalReported = query.data?.total ?? 0;
  const shown = items.length;

  return (
    <WindowPanel
      title="activity"
      tone="info"
      actions={
        <div className="flex items-center gap-2">
          {hasTaskId && (
            <span className="text-3xs font-mono text-text-muted tabular-nums">
              {shown} shown{totalReported > shown ? ` / ${totalReported}` : ""}
            </span>
          )}
          <button
            type="button"
            onClick={() => query.refetch()}
            className="inline-flex items-center gap-1 px-2 py-0.5 text-3xs font-mono rounded border border-border text-text-muted hover:border-accent hover:text-foreground transition-colors"
            disabled={query.isFetching || !hasTaskId}
            aria-label="Refresh activity log"
            title="Refresh audit trail"
          >
            <ArrowClockwise
              weight="bold"
              size={11}
              className={query.isFetching ? "animate-spin motion-reduce:animate-none" : undefined}
            />
            refresh
          </button>
        </div>
      }
    >
      <h2 className="sr-only">Activity</h2>

      {hasTaskId && (
        <div className="flex items-center gap-2 mb-3 flex-wrap text-xs">
          <span className="inline-flex items-center gap-1 text-text-muted font-mono uppercase tracking-wide text-3xs">
            <Funnel weight="fill" size={11} />
            filter
          </span>
          <label className="inline-flex items-center gap-1 text-3xs">
            <span className="text-text-muted font-mono">action</span>
            <input
              type="text"
              value={actionFilter}
              onChange={(e) => setActionFilter(e.target.value)}
              placeholder="scan.start,ssh.execute"
              aria-label="Filter activity events by action (comma-separated)"
              className="w-40 text-2xs font-mono px-2 py-0.5 rounded bg-elevated border border-border focus:border-accent focus:outline-none"
            />
          </label>
          <label className="inline-flex items-center gap-1 text-3xs">
            <span className="text-text-muted font-mono">status</span>
            <input
              type="text"
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              placeholder="completed,failed"
              aria-label="Filter activity events by status (comma-separated)"
              className="w-36 text-2xs font-mono px-2 py-0.5 rounded bg-elevated border border-border focus:border-accent focus:outline-none"
            />
          </label>
          {(actionFilter || statusFilter) && (
            <button
              type="button"
              onClick={() => {
                setActionFilter("");
                setStatusFilter("");
              }}
              className="text-3xs font-mono text-text-muted hover:text-foreground"
            >
              clear
            </button>
          )}
        </div>
      )}

      {!hasTaskId ? (
        <p className="text-xs text-text-muted">
          No workflow run bound yet. The audit trail populates once the
          investigation dispatches a worker task.
        </p>
      ) : query.isLoading ? (
        <LoadingSkeletonGroup lines={4} />
      ) : query.isError ? (
        <p className="text-xs text-critical font-mono">
          Failed to load audit trail. Retry above.
        </p>
      ) : items.length === 0 ? (
        <p className="text-xs text-text-muted">
          {actionFilter || statusFilter
            ? "No events match the current filters."
            : "No audit events recorded for this run yet."}
        </p>
      ) : (
        <ol
          className="space-y-1.5 scroll-virtual-row"
          aria-label="Investigation audit trail (oldest first)"
        >
          {items.map((ev) => (
            <li
              key={`${ev.id ?? ""}:${ev.created_at ?? ""}:${ev.action}`}
              className="flex items-start gap-2 rounded-md border border-border/60 bg-elevated/40 p-2 hover:border-accent/40 transition-colors"
            >
              <AilaBadge severity={statusSeverity(ev.status)} size="sm">
                {ev.status || "--"}
              </AilaBadge>
              <div className="min-w-0 flex-1">
                <div className="flex items-baseline gap-2 flex-wrap">
                  <span className="text-xs font-mono text-foreground truncate">
                    {ev.action || "(no action)"}
                  </span>
                  {ev.stage && (
                    <span className="text-3xs font-mono text-text-muted">
                      stage:{ev.stage}
                    </span>
                  )}
                  {ev.target && (
                    <span
                      className="text-3xs font-mono text-text-muted truncate"
                      title={ev.target}
                    >
                      target:{ev.target}
                    </span>
                  )}
                </div>
                <div className="text-3xs font-mono text-text-muted mt-0.5 flex items-center gap-3 flex-wrap">
                  <span>{formatTs(ev.created_at)}</span>
                  <span>user:{ev.user_id || "system"}</span>
                </div>
              </div>
            </li>
          ))}
        </ol>
      )}
    </WindowPanel>
  );
}
