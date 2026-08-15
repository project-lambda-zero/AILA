/**
 * TransitionTimeline -- compact audit trail for a workflow run (Phase 181).
 *
 * Shown inside the task detail column as a flush WindowPanel of dense
 * mono rows -- one row per WorkflowStateTransition in seq-ascending order.
 * from_state -> to_state, event, actor, timestamp, error.
 */
import { WindowPanel } from "@/components/aila/WindowPanel";
import { MonoBadge } from "@/components/aila/mock";
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

/** Tone token for the event label badge. */
function eventTone(event: string): string {
  if (event === "entered") return "muted";
  if (event === "exited:ok") return "ok";
  if (event === "exited:retry") return "warn";
  if (event === "exited:phase_handoff") return "info";
  if (event.startsWith("exited:fail") || event === "exited:timeout") {
    return "critical";
  }
  return "muted";
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

interface TransitionRowProps {
  row: TransitionView;
  onSelect?: (row: TransitionView) => void;
}

function TransitionRow({ row, onSelect }: TransitionRowProps) {
  const tone = eventTone(row.event);
  const isError = row.error_class !== null;
  const clickable = onSelect !== undefined;

  return (
    <div
      className={`flex flex-col font-mono${
        clickable ? " cursor-pointer" : ""
      }`}
      style={{
        gap: 3,
        padding: "6px 10px",
        borderBottom: "1px solid var(--border-faint)",
        background: "transparent",
        transition: "background 100ms",
      }}
      onMouseEnter={(e) => {
        if (clickable) e.currentTarget.style.background = "var(--surface-hover)";
      }}
      onMouseLeave={(e) => {
        if (clickable) e.currentTarget.style.background = "transparent";
      }}
      onClick={clickable ? () => onSelect(row) : undefined}
      onKeyDown={
        clickable
          ? (e) => {
              if (e.key === "Enter" || e.key === " ") {
                e.preventDefault();
                onSelect(row);
              }
            }
          : undefined
      }
      role={clickable ? "button" : undefined}
      tabIndex={clickable ? 0 : undefined}
    >
      {/* Main line: seq | event | from -> to | duration */}
      <div className="flex items-center" style={{ gap: 8, fontSize: 11 }}>
        <span
          className="shrink-0 text-right tabular-nums"
          style={{ width: 26, color: "var(--text-faint)", fontSize: 10 }}
        >
          {row.seq}
        </span>
        <span className="shrink-0" style={{ width: 88 }}>
          <MonoBadge tone={tone}>{eventLabel(row.event)}</MonoBadge>
        </span>
        <span
          className="flex-1 truncate"
          style={{ color: "var(--text-primary)" }}
        >
          {row.from_state !== null ? (
            <>
              <span style={{ color: "var(--text-muted)" }}>
                {row.from_state}
              </span>
              <span
                style={{
                  margin: "0 6px",
                  color: "var(--text-faint)",
                }}
              >
                {"\u2192"}
              </span>
            </>
          ) : null}
          <span>{row.to_state}</span>
        </span>
        <span
          className="shrink-0 tabular-nums"
          style={{ color: "var(--text-muted)", fontSize: 10 }}
        >
          {formatDuration(row.duration_ms)}
        </span>
      </div>

      {/* Meta line: timestamp */}
      <div
        className="flex items-center"
        style={{
          gap: 8,
          fontSize: 10,
          color: "var(--text-faint)",
          paddingLeft: 34,
        }}
      >
        {formatTime(row.happened_at)}
      </div>

      {/* Error detail */}
      {isError && (
        <div
          className="font-mono"
          style={{
            marginLeft: 34,
            marginTop: 2,
            padding: "4px 8px",
            border: "1px solid color-mix(in srgb, var(--status-warn) 40%, transparent)",
            background: "color-mix(in srgb, var(--status-warn) 10%, transparent)",
            color: "var(--status-warn)",
            fontSize: 10,
            borderRadius: 3,
          }}
        >
          {row.error_class}
          {row.error_message && row.error_message !== row.error_class ? (
            <span style={{ opacity: 0.75 }}> -- {row.error_message}</span>
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
  /**
   * Optional per-row click handler. When supplied, each row becomes a
   * keyboard-activatable button that surfaces the row upward (e.g. for a
   * drill-down drawer). When omitted, rows are non-interactive as before.
   */
  onRowSelect?: (row: TransitionView) => void;
}

export function TransitionTimeline({
  rows,
  isLoading,
  isError,
  onRowSelect,
}: TransitionTimelineProps) {
  const status = isLoading
    ? "LOADING"
    : isError
      ? "ERROR"
      : `${rows.length} EVENT${rows.length === 1 ? "" : "S"}`;

  return (
    <WindowPanel
      title="state transitions"
      status={status}
      tone={isError ? "warn" : "muted"}
      flush
    >
      {isLoading ? (
        <div
          className="font-mono"
          style={{
            padding: "10px 12px",
            fontSize: 11,
            color: "var(--text-muted)",
          }}
        >
          loading transitions...
        </div>
      ) : isError ? (
        <div
          className="font-mono"
          style={{
            padding: "10px 12px",
            fontSize: 11,
            color: "var(--status-warn)",
          }}
        >
          failed to load transitions.
        </div>
      ) : rows.length === 0 ? (
        <div
          className="font-mono"
          style={{
            padding: "10px 12px",
            fontSize: 11,
            color: "var(--text-faint)",
          }}
        >
          no workflow transitions recorded.
        </div>
      ) : (
        <div style={{ maxHeight: 260, overflowY: "auto" }}>
          {rows.map((row) => (
            <TransitionRow
              key={`${row.run_id}-${row.seq}`}
              row={row}
              onSelect={onRowSelect}
            />
          ))}
        </div>
      )}
    </WindowPanel>
  );
}
