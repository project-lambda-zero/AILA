/**
 * TransitionTimeline -- compact audit trail for a workflow run (Phase 181).
 *
 * Shows one row per WorkflowStateTransition in seq-ascending order.
 * Displayed inside TaskDetailPanel below the metadata table.
 *
 * Design: mono font, cyberpunk density, event-type colour coding.
 * No accordion -- all rows visible, scroll container clips overflow.
 */
import type { TransitionView } from "./transitions";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function formatDuration(ms: number | null): string {
  if (ms === null) return "--";
  if (ms < 1000) return `${ms}ms`;
  return `${(ms / 1000).toFixed(2)}s`;
}

function formatTime(iso: string): string {
  try {
    return new Date(iso).toLocaleTimeString(undefined, {
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
      fractionalSecondDigits: 3,
    });
  } catch {
    return iso;
  }
}

/** Colour token for the event label badge. */
function eventColour(event: string): string {
  if (event === "entered") return "text-text-muted";
  if (event === "exited:ok") return "text-[oklch(72%_0.18_150)]";        // green
  if (event === "exited:retry") return "text-[oklch(78%_0.18_80)]";      // amber
  if (event === "exited:phase_handoff") return "text-[oklch(72%_0.18_260)]"; // blue
  if (event.startsWith("exited:fail") || event === "exited:timeout") {
    return "text-destructive";
  }
  return "text-text";
}

/** Short human label for the event string. */
function eventLabel(event: string): string {
  const map: Record<string, string> = {
    "entered": "entered",
    "exited:ok": "ok",
    "exited:retry": "retry",
    "exited:failed": "failed",
    "exited:timeout": "timeout",
    "exited:failed_in_failure_handler": "handler_failed",
    "exited:phase_handoff": "handoff",
  };
  return map[event] ?? event;
}

// ---------------------------------------------------------------------------
// Row
// ---------------------------------------------------------------------------

function TransitionRow({ row }: { row: TransitionView }) {
  const colour = eventColour(row.event);
  const isError = row.error_class !== null;

  return (
    <div className="flex flex-col gap-0.5 border-b border-border py-1.5 last:border-0">
      {/* Main line */}
      <div className="flex items-center gap-2 font-mono text-[11px]">
        {/* seq */}
        <span className="shrink-0 w-6 text-right text-text-muted opacity-60">
          {row.seq}
        </span>

        {/* event badge */}
        <span className={`shrink-0 w-[88px] font-semibold ${colour}`}>
          {eventLabel(row.event)}
        </span>

        {/* from → to */}
        <span className="flex-1 truncate text-text">
          {row.from_state !== null ? (
            <>
              <span className="opacity-60">{row.from_state}</span>
              <span className="mx-1 opacity-40">→</span>
            </>
          ) : null}
          <span>{row.to_state}</span>
        </span>

        {/* duration */}
        <span className="shrink-0 text-text-muted opacity-60 tabular-nums">
          {formatDuration(row.duration_ms)}
        </span>
      </div>

      {/* Time */}
      <div className="flex items-center gap-2 font-mono text-[10px] text-text-muted opacity-50 pl-8">
        {formatTime(row.happened_at)}
      </div>

      {/* Error detail */}
      {isError && (
        <div className="ml-8 mt-0.5 rounded-[2px] border border-destructive/40 bg-destructive/5 px-2 py-1 font-mono text-[10px] text-destructive">
          {row.error_class}
          {row.error_message && row.error_message !== row.error_class ? (
            <span className="opacity-75"> -- {row.error_message}</span>
          ) : null}
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Timeline
// ---------------------------------------------------------------------------

interface TransitionTimelineProps {
  rows: TransitionView[];
  isLoading: boolean;
  isError: boolean;
}

export function TransitionTimeline({
  rows,
  isLoading,
  isError,
}: TransitionTimelineProps) {
  return (
    <div className="mt-4">
      <h3 className="font-mono text-[10px] font-semibold uppercase tracking-wider text-text-muted mb-2">
        State Transitions
      </h3>

      {isLoading && (
        <div className="font-mono text-[11px] text-text-muted opacity-60 py-2">
          Loading…
        </div>
      )}

      {isError && (
        <div className="font-mono text-[11px] text-destructive py-1">
          Failed to load transitions.
        </div>
      )}

      {!isLoading && !isError && rows.length === 0 && (
        <div className="font-mono text-[11px] text-text-muted opacity-60 py-2">
          No workflow transitions recorded.
        </div>
      )}

      {!isLoading && !isError && rows.length > 0 && (
        <div className="max-h-64 overflow-y-auto rounded-[2px] border border-border">
          {rows.map((row) => (
            <TransitionRow key={`${row.run_id}-${row.seq}`} row={row} />
          ))}
        </div>
      )}
    </div>
  );
}
