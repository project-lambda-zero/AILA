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
import { useMemo, useState, type CSSProperties } from "react";
import { useQuery } from "@tanstack/react-query";
import { Funnel } from "@phosphor-icons/react/dist/csr/Funnel";
import { ArrowClockwise } from "@phosphor-icons/react/dist/csr/ArrowClockwise";

import { authorizedRequestJson } from "@platform/api/http";

import { MonoBadge } from "@/components/aila/mock";
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

type Severity = "critical" | "high" | "medium" | "low" | "info" | "neutral";

function statusSeverity(status: string): Severity {
  const s = status.toLowerCase();
  if (s === "failed" || s === "error") return "critical";
  if (s === "warning" || s === "skipped") return "medium";
  if (s === "completed" || s === "succeeded" || s === "ok") return "low";
  if (s === "running" || s === "started") return "info";
  return "neutral";
}

// Severity -> MonoBadge tone. low -> ok, neutral -> muted; the rest are
// pass-through onto the mock kit's tone keys.
const SEVERITY_TONE: Record<Severity, string> = {
  critical: "critical",
  high: "high",
  medium: "medium",
  low: "ok",
  info: "info",
  neutral: "muted",
};

function formatTs(value: string | null): string {
  if (!value) return "--";
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return value;
  return d.toLocaleString();
}

// Mock text-input control, matching the CTRL shape used across VR rebuilds.
const CTRL: CSSProperties = {
  height: 24,
  padding: "0 8px",
  fontSize: 10,
  letterSpacing: "0.06em",
  background: "var(--surface-sunk)",
  color: "var(--text-primary)",
  border: "1px solid var(--border-soft)",
  borderRadius: 3,
  fontFamily: "var(--font-mono)",
};

// Mock ghost button -- matches the header-action idiom used across VR
// wave-1 rebuilds (see ProjectDetailPage, LiveRunPanel).
const GHOST_BTN: CSSProperties = {
  height: 24,
  padding: "0 8px",
  fontSize: 10,
  letterSpacing: "0.08em",
  background: "var(--surface-sunk)",
  color: "var(--text-primary)",
  border: "1px solid var(--border-soft)",
  borderRadius: 3,
  cursor: "pointer",
  display: "inline-flex",
  alignItems: "center",
  gap: 4,
  fontFamily: "var(--font-mono)",
  textTransform: "uppercase",
};

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

  const clearFilters = () => {
    setActionFilter("");
    setStatusFilter("");
  };

  const headerActions = (
    <div className="flex items-center" style={{ gap: 8 }}>
      {hasTaskId ? (
        <span
          className="font-mono tabular-nums"
          style={{
            fontSize: 10,
            letterSpacing: "0.08em",
            color: "var(--text-muted)",
          }}
        >
          {shown} shown{totalReported > shown ? ` / ${totalReported}` : ""}
        </span>
      ) : null}
      <button
        type="button"
        onClick={() => query.refetch()}
        style={GHOST_BTN}
        disabled={query.isFetching || !hasTaskId}
        aria-label="Refresh activity log"
        title="Refresh audit trail"
      >
        <ArrowClockwise
          weight="bold"
          size={11}
          className={
            query.isFetching ? "animate-spin motion-reduce:animate-none" : undefined
          }
        />
        refresh
      </button>
    </div>
  );

  return (
    <WindowPanel title="activity" tone="info" actions={headerActions}>
      <h2 className="sr-only">Activity</h2>

      {hasTaskId ? (
        <div
          className="flex items-center flex-wrap"
          style={{ gap: 8, marginBottom: 12 }}
        >
          <span
            className="inline-flex items-center font-mono uppercase"
            style={{
              gap: 4,
              fontSize: 10,
              letterSpacing: "0.08em",
              color: "var(--text-muted)",
            }}
          >
            <Funnel weight="fill" size={11} />
            filter
          </span>
          <label className="inline-flex items-center" style={{ gap: 4 }}>
            <span
              className="font-mono uppercase"
              style={{
                fontSize: 10,
                letterSpacing: "0.08em",
                color: "var(--text-muted)",
              }}
            >
              action
            </span>
            <input
              type="text"
              value={actionFilter}
              onChange={(e) => setActionFilter(e.target.value)}
              placeholder="scan.start,ssh.execute"
              aria-label="Filter activity events by action (comma-separated)"
              className="font-mono"
              style={{ ...CTRL, width: 176 }}
            />
          </label>
          <label className="inline-flex items-center" style={{ gap: 4 }}>
            <span
              className="font-mono uppercase"
              style={{
                fontSize: 10,
                letterSpacing: "0.08em",
                color: "var(--text-muted)",
              }}
            >
              status
            </span>
            <input
              type="text"
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              placeholder="completed,failed"
              aria-label="Filter activity events by status (comma-separated)"
              className="font-mono"
              style={{ ...CTRL, width: 156 }}
            />
          </label>
          {actionFilter || statusFilter ? (
            <button
              type="button"
              onClick={clearFilters}
              className="font-mono uppercase"
              style={{
                fontSize: 10,
                letterSpacing: "0.08em",
                color: "var(--text-muted)",
                background: "transparent",
                border: "none",
                cursor: "pointer",
                padding: 0,
              }}
            >
              clear
            </button>
          ) : null}
        </div>
      ) : null}

      {!hasTaskId ? (
        <div
          className="font-mono"
          style={{
            padding: 20,
            fontSize: 11.5,
            color: "var(--text-muted)",
            letterSpacing: "0.04em",
            textAlign: "center",
          }}
        >
          no workflow run bound yet. audit trail populates once the
          investigation dispatches a worker task.
        </div>
      ) : query.isLoading ? (
        <LoadingSkeletonGroup lines={4} />
      ) : query.isError ? (
        <div
          className="font-mono"
          style={{
            padding: 20,
            fontSize: 11.5,
            color: "var(--accent)",
            letterSpacing: "0.04em",
            textAlign: "center",
          }}
        >
          failed to load audit trail. retry above.
        </div>
      ) : items.length === 0 ? (
        <div
          className="font-mono"
          style={{
            padding: 20,
            fontSize: 11.5,
            color: "var(--text-muted)",
            letterSpacing: "0.04em",
            textAlign: "center",
          }}
        >
          {actionFilter || statusFilter
            ? "no events match the current filters."
            : "no audit events recorded for this run yet."}
        </div>
      ) : (
        <ol
          aria-label="Investigation audit trail (oldest first)"
          style={{ listStyle: "none", margin: 0, padding: 0 }}
        >
          {items.map((ev, idx) => (
            <li
              key={`${ev.id ?? ""}:${ev.created_at ?? ""}:${ev.action}`}
              className="flex items-start"
              style={{
                gap: 10,
                padding: "8px 4px",
                borderBottom:
                  idx === items.length - 1
                    ? "none"
                    : "1px solid var(--border-faint)",
              }}
            >
              <span
                className="font-mono tabular-nums"
                style={{
                  fontSize: 10,
                  color: "var(--text-faint)",
                  letterSpacing: "0.04em",
                  whiteSpace: "nowrap",
                  flex: "0 0 auto",
                  paddingTop: 2,
                }}
              >
                {formatTs(ev.created_at)}
              </span>
              <span style={{ flex: "0 0 auto", paddingTop: 1 }}>
                <MonoBadge tone={SEVERITY_TONE[statusSeverity(ev.status)]}>
                  {ev.status || "--"}
                </MonoBadge>
              </span>
              <div className="min-w-0" style={{ flex: 1 }}>
                <div
                  className="flex items-baseline flex-wrap"
                  style={{ gap: 8 }}
                >
                  <span
                    className="font-mono truncate"
                    style={{
                      fontSize: 11.5,
                      color: "var(--text-primary)",
                      letterSpacing: "0.02em",
                    }}
                  >
                    {ev.action || "(no action)"}
                  </span>
                  {ev.stage ? (
                    <span
                      className="font-mono"
                      style={{
                        fontSize: 10,
                        color: "var(--text-muted)",
                        letterSpacing: "0.04em",
                      }}
                    >
                      stage:{ev.stage}
                    </span>
                  ) : null}
                  {ev.target ? (
                    <span
                      className="font-mono truncate"
                      title={ev.target}
                      style={{
                        fontSize: 10,
                        color: "var(--text-muted)",
                        letterSpacing: "0.04em",
                      }}
                    >
                      target:{ev.target}
                    </span>
                  ) : null}
                </div>
                <div
                  className="flex items-center flex-wrap font-mono"
                  style={{
                    gap: 12,
                    marginTop: 2,
                    fontSize: 10,
                    color: "var(--text-faint)",
                    letterSpacing: "0.04em",
                  }}
                >
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
