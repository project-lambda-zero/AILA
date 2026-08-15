import { Clock } from "@phosphor-icons/react/dist/csr/Clock";

import { LoadingSkeleton } from "@/components/aila/LoadingSkeleton";
import { WindowPanel } from "@/components/aila/WindowPanel";
import { MonoBadge } from "@/components/aila/mock";

import { useAuditEvents, type AuditEvent } from "../hooks/useAuditEvents";

interface ActivityPanelProps {
  /** Preferred: the investigation's task_id (workflow run id). Falls back to
   *  the investigation id itself if no task is bound yet. May be null when
   *  the caller has not resolved either -- panel renders the empty state. */
  runId: string | null | undefined;
}

// Status -> mock semantic tone. Preserves the earlier STATUS_SEVERITY
// mapping but speaks the mock tone vocabulary (info/ok/medium/critical).
const STATUS_TONE: Record<string, string> = {
  completed: "ok",
  ok: "ok",
  success: "ok",
  started: "info",
  running: "medium",
  warning: "medium",
  failed: "critical",
  error: "critical",
};

function formatTimestamp(value: string | null): string {
  if (!value) return "--";
  const d = new Date(value);
  return isNaN(d.getTime()) ? value : d.toLocaleString();
}

function ActivityRow({ event }: { event: AuditEvent }) {
  const tone = STATUS_TONE[event.status] ?? "muted";
  return (
    <li
      className="flex flex-col"
      style={{
        gap: 4,
        borderBottom: "1px solid var(--border-faint)",
        padding: "8px 0",
      }}
    >
      <div className="flex items-center flex-wrap" style={{ gap: 8 }}>
        <MonoBadge tone={tone}>{event.status || "--"}</MonoBadge>
        <span
          className="font-mono break-all"
          style={{ fontSize: 11, color: "var(--text-primary)" }}
        >
          {event.action}
        </span>
        {event.stage && (
          <span
            className="font-mono uppercase"
            style={{
              fontSize: 9,
              letterSpacing: "0.1em",
              color: "var(--text-faint)",
            }}
          >
            {event.stage}
          </span>
        )}
        <span
          className="font-mono ml-auto"
          style={{ fontSize: 9.5, color: "var(--text-faint)" }}
        >
          {formatTimestamp(event.created_at)}
        </span>
      </div>
      {(event.target || event.user_id) && (
        <div
          className="flex flex-wrap font-mono"
          style={{ gap: 12, fontSize: 9.5, color: "var(--text-faint)" }}
        >
          {event.target && <span>target: {event.target}</span>}
          {event.user_id && <span>by: {event.user_id}</span>}
        </div>
      )}
    </li>
  );
}

/**
 * ActivityPanel -- forensics investigation audit trail. Reads the audit
 * router keyed by `run_id`; degrades gracefully when the id is missing or
 * when the router has nothing to show for it.
 */
export function ActivityPanel({ runId }: ActivityPanelProps) {
  const enabled = !!runId;
  const { data, isLoading, isError } = useAuditEvents(runId);

  return (
    <WindowPanel
      title="activity"
      status={
        data && data.total > 0
          ? `audit ; ${data.items.length} of ${data.total} events`
          : "forensics ; audit trail"
      }
    >
      <div className="space-y-3">
        {!enabled && (
          <p
            className="font-mono"
            style={{ fontSize: 11, color: "var(--text-muted)" }}
          >
            No run id bound to this investigation yet -- audit trail unavailable.
          </p>
        )}
        {enabled && isLoading && (
          <div className="space-y-2">
            <LoadingSkeleton size="sm" width="full" />
            <LoadingSkeleton size="sm" width="full" />
            <LoadingSkeleton size="sm" width="third" />
          </div>
        )}
        {enabled && isError && (
          <p
            className="font-mono"
            style={{ fontSize: 11, color: "var(--text-muted)" }}
          >
            Audit trail temporarily unavailable.
          </p>
        )}
        {enabled &&
          !isLoading &&
          !isError &&
          data &&
          data.items.length === 0 && (
            <div
              className="flex flex-col items-center justify-center"
              style={{ gap: 10, padding: "32px 0" }}
            >
              <Clock
                aria-hidden="true"
                className="h-8 w-8"
                style={{ color: "var(--text-faint)" }}
              />
              <p
                className="font-mono"
                style={{
                  fontSize: 11,
                  color: "var(--text-muted)",
                  textAlign: "center",
                  maxWidth: 420,
                  lineHeight: 1.55,
                }}
              >
                No audit events recorded for this run. Workflow events, LLM
                calls, and stage transitions appear here once the audit router
                logs them.
              </p>
            </div>
          )}
        {enabled && !isLoading && data && data.items.length > 0 && (
          <ul>
            {data.items.map((ev, i) => (
              <ActivityRow
                // eslint-disable-next-line react/no-array-index-key
                key={ev.id ?? `${ev.created_at ?? ""}-${ev.action}-${i}`}
                event={ev}
              />
            ))}
          </ul>
        )}
      </div>
    </WindowPanel>
  );
}
