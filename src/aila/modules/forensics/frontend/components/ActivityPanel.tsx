import { Clock } from "@phosphor-icons/react/dist/csr/Clock";

import { AilaBadge } from "@/components/aila/AilaBadge";
import { AilaCard } from "@/components/aila/AilaCard";
import { EmptyState } from "@/components/aila/EmptyState";
import { LoadingSkeleton } from "@/components/aila/LoadingSkeleton";

import { useAuditEvents, type AuditEvent } from "../hooks/useAuditEvents";

interface ActivityPanelProps {
  /** Preferred: the investigation's task_id (workflow run id). Falls back to
   *  the investigation id itself if no task is bound yet. May be null when
   *  the caller has not resolved either -- panel renders the empty state. */
  runId: string | null | undefined;
}

const STATUS_SEVERITY: Record<
  string,
  Parameters<typeof AilaBadge>[0]["severity"]
> = {
  completed: "low",
  ok: "low",
  success: "low",
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
  const severity = STATUS_SEVERITY[event.status] ?? "neutral";
  return (
    <li className="flex flex-col gap-1 border-b border-border last:border-0 py-2">
      <div className="flex items-center gap-2 flex-wrap">
        <AilaBadge severity={severity} size="sm">
          {event.status || "--"}
        </AilaBadge>
        <span className="text-xs font-mono text-foreground break-all">
          {event.action}
        </span>
        {event.stage && (
          <span className="text-3xs font-mono uppercase tracking-wider text-text-muted">
            {event.stage}
          </span>
        )}
        <span className="ml-auto text-3xs font-mono text-text-muted">
          {formatTimestamp(event.created_at)}
        </span>
      </div>
      {(event.target || event.user_id) && (
        <div className="flex gap-3 text-3xs font-mono text-text-muted flex-wrap">
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
    <AilaCard padding="md" className="space-y-3" techBorder glow>
      <div className="flex items-center justify-between gap-2 flex-wrap">
        <h2 className="text-sm font-semibold text-foreground">Activity</h2>
        {data && data.total > 0 && (
          <span className="text-3xs font-mono text-text-muted">
            {data.items.length} of {data.total} events
          </span>
        )}
      </div>
      {!enabled && (
        <p className="font-mono text-xs text-text-muted">
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
        <p className="font-mono text-xs text-text-muted">
          Audit trail temporarily unavailable.
        </p>
      )}
      {enabled && !isLoading && !isError && data && data.items.length === 0 && (
        <EmptyState
          icon={<Clock className="h-10 w-10" />}
          title="No audit events recorded for this run."
          description="Workflow events, LLM calls, and stage transitions appear here once the audit router logs them for this run."
        />
      )}
      {enabled && !isLoading && data && data.items.length > 0 && (
        <ul className="text-sm">
          {data.items.map((ev, i) => (
            <ActivityRow
              // eslint-disable-next-line react/no-array-index-key
              key={ev.id ?? `${ev.created_at ?? ""}-${ev.action}-${i}`}
              event={ev}
            />
          ))}
        </ul>
      )}
    </AilaCard>
  );
}
