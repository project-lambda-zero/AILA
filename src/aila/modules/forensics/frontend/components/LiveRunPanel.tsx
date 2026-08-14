/**
 * LiveRunPanel -- additive, running-only summary of one forensics
 * investigation. Renders a status pill, an attempts progress bar, a
 * client-side elapsed timer, an SSE-feed indicator and a short
 * recent-activity ticker sourced from the module's investigation
 * event stream.
 *
 *  Rules of the road:
 *   - PURELY ADDITIVE. The existing Live tab, StepCard timeline and
 *     header row keep working. This panel sits between the header
 *     and the sub-panels while ``isRunning`` is true and unmounts
 *     as soon as the investigation reaches a terminal status.
 *   - Reduced motion is respected: the streaming-feed indicator
 *     pulses only under ``motion-safe:``; the elapsed timer is a
 *     plain text update (not an animation) and continues to tick
 *     for users who opted out of motion because the value change
 *     is information, not decoration.
 *   - No new deps. The SSE data flows in via
 *     :func:`useForensicsInvestigationEvents` -- callers pass the
 *     already-fetched events / feed status / latest stage in as
 *     props to keep this component free of hook-order surprises
 *     and to avoid opening a second SSE connection.
 */
import { useEffect, useState } from "react";

import { AilaBadge } from "@/components/aila/AilaBadge";
import { AilaCard } from "@/components/aila/AilaCard";

import type {
  InvestigationEvent,
  InvestigationFeedStatus,
} from "../queries";

type BadgeSeverity =
  | "critical"
  | "high"
  | "medium"
  | "low"
  | "info"
  | "neutral";

interface StatusVisual {
  severity: BadgeSeverity;
  label: string;
  /** true = show a live pulse dot next to the label (running-only). */
  liveDot: boolean;
}

const STATUS_VISUAL: Record<string, StatusVisual> = {
  pending: { severity: "info", label: "pending", liveDot: true },
  queued: { severity: "info", label: "queued", liveDot: true },
  running: { severity: "medium", label: "running", liveDot: true },
  analyzing: { severity: "medium", label: "analyzing", liveDot: true },
  completed: { severity: "low", label: "completed", liveDot: false },
  failed: { severity: "critical", label: "failed", liveDot: false },
  cancelled: { severity: "high", label: "cancelled", liveDot: false },
  exhausted: { severity: "high", label: "exhausted", liveDot: false },
};

interface FeedVisual {
  label: string;
  color: string;
  pulse: boolean;
}

const FEED_VISUAL: Record<InvestigationFeedStatus, FeedVisual> = {
  idle: { label: "idle", color: "#6b7280", pulse: false },
  connecting: { label: "connecting", color: "#f59e0b", pulse: true },
  live: { label: "streaming", color: "#22c55e", pulse: false },
  unavailable: { label: "no stream", color: "#6b7280", pulse: false },
  closed: { label: "closed", color: "#ef4444", pulse: false },
  error: { label: "error", color: "#ef4444", pulse: false },
};

const FALLBACK_STATUS_VISUAL: StatusVisual = {
  severity: "neutral",
  label: "unknown",
  liveDot: false,
};

const RECENT_TICKER_MAX = 5;

/** Format ms elapsed as ``h`` / ``m`` / ``s`` with zero-padded minutes
 *  and seconds. Not a one-liner: the branch cascade drops the higher
 *  unit segments when they'd read as ``0h 00m ...``, and the pad-to-2
 *  is a real formatting rule the inlined expression would not
 *  self-explain. */
function formatElapsed(ms: number): string {
  const total = Math.max(0, Math.floor(ms / 1000));
  const h = Math.floor(total / 3600);
  const m = Math.floor((total % 3600) / 60);
  const s = total % 60;
  const mm = m.toString().padStart(2, "0");
  const ss = s.toString().padStart(2, "0");
  if (h > 0) return `${h}h ${mm}m ${ss}s`;
  if (m > 0) return `${m}m ${ss}s`;
  return `${s}s`;
}

function stageColorClass(stage: string): string {
  if (stage.includes("error") || stage.includes("failed")) return "text-red-400";
  if (
    stage === "completed" ||
    stage.includes("done") ||
    stage.includes("detected")
  ) {
    return "text-green-400";
  }
  if (stage.includes("start") || stage.includes("begin")) return "text-amber-400";
  if (stage === "artifact_added") return "text-blue-400";
  return "text-accent";
}

export interface LiveRunPanelProps {
  status: string;
  attemptsUsed: number;
  maxAttempts: number | null;
  events: InvestigationEvent[];
  feedStatus: InvestigationFeedStatus;
  /** The most recent non-null stage from the stream, surfaced as a
   *  short chip in the header. Omit / pass null to hide. */
  latestStage: string | null;
}

export function LiveRunPanel({
  status,
  attemptsUsed,
  maxAttempts,
  events,
  feedStatus,
  latestStage,
}: LiveRunPanelProps) {
  // Anchor at first mount and tick once per second. Not a CSS
  // animation -- number updates are information, not decoration, so
  // this stays active even under prefers-reduced-motion.
  const [anchor] = useState<number>(() => Date.now());
  const [elapsedMs, setElapsedMs] = useState<number>(0);

  useEffect(() => {
    const id = window.setInterval(() => {
      setElapsedMs(Date.now() - anchor);
    }, 1000);
    return () => {
      window.clearInterval(id);
    };
  }, [anchor]);

  const badge: StatusVisual =
    STATUS_VISUAL[status] ??
    { ...FALLBACK_STATUS_VISUAL, label: status || "unknown" };
  const feed = FEED_VISUAL[feedStatus];
  const attemptsPct =
    maxAttempts && maxAttempts > 0
      ? Math.min(100, Math.round((attemptsUsed / maxAttempts) * 100))
      : null;

  // Recent activity ticker: last N events, newest first, dropping the
  // no-signal heartbeat frames (the streaming dot in the header is
  // enough of a "still alive" cue).
  const recent = events
    .filter((ev) => ev.stage !== "heartbeat")
    .slice(-RECENT_TICKER_MAX)
    .reverse();

  return (
    <AilaCard techBorder glow>
      <div className="space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex flex-wrap items-center gap-3">
            <AilaBadge
              severity={badge.severity}
              size="md"
              dot={badge.liveDot}
              aria-label={`investigation status: ${badge.label}`}
            >
              {badge.label}
            </AilaBadge>
            <span
              className="inline-flex items-center gap-1.5 text-3xs font-mono uppercase tracking-wide"
              aria-label={`stream ${feed.label}`}
            >
              <span
                aria-hidden
                className={`inline-block rounded-full ${
                  feed.pulse ? "motion-safe:animate-pulse" : ""
                }`}
                style={{
                  width: 6,
                  height: 6,
                  backgroundColor: feed.color,
                  boxShadow: `0 0 4px ${feed.color}80`,
                }}
              />
              <span className="text-text-muted">{feed.label}</span>
            </span>
            {latestStage && latestStage !== "heartbeat" && (
              <span className="text-3xs font-mono uppercase tracking-wide text-text-muted">
                stage: <span className="text-foreground">{latestStage}</span>
              </span>
            )}
          </div>
          <div className="flex items-center gap-4 text-xs font-mono text-text-muted">
            <span>
              elapsed:{" "}
              <span
                className="text-foreground tabular-nums"
                aria-live="off"
              >
                {formatElapsed(elapsedMs)}
              </span>
            </span>
          </div>
        </div>

        {attemptsPct !== null && (
          <div className="space-y-1">
            <div className="flex justify-between text-3xs font-mono uppercase tracking-wide text-text-muted">
              <span>attempts</span>
              <span className="tabular-nums">
                {attemptsUsed}/{maxAttempts}
              </span>
            </div>
            <div
              className="h-1.5 w-full overflow-hidden rounded-full bg-surface-secondary"
              role="progressbar"
              aria-valuemin={0}
              aria-valuemax={maxAttempts ?? undefined}
              aria-valuenow={attemptsUsed}
              aria-label="investigation attempts used"
            >
              <div
                className="h-full bg-accent"
                style={{ width: `${attemptsPct}%` }}
              />
            </div>
          </div>
        )}

        <div className="space-y-1">
          <div className="text-3xs font-mono uppercase tracking-wide text-text-muted">
            recent activity
          </div>
          {recent.length === 0 ? (
            <p className="text-xs italic text-text-muted">
              Waiting for events{"\u2026"}
            </p>
          ) : (
            <ul className="space-y-1 text-xs font-mono">
              {recent.map((ev, i) => {
                const stage = ev.stage ?? "--";
                const color = stageColorClass(stage);
                const pct = ev.percent;
                return (
                  <li key={i} className="flex items-baseline gap-2">
                    {pct !== null && pct !== undefined && pct > 0 && (
                      <span className="w-9 shrink-0 text-right text-text-muted tabular-nums">
                        {pct}%
                      </span>
                    )}
                    <span className={`shrink-0 font-semibold ${color}`}>
                      [{stage}]
                    </span>
                    <span className="break-all text-foreground">
                      {ev.message ?? ""}
                    </span>
                  </li>
                );
              })}
            </ul>
          )}
        </div>
      </div>
    </AilaCard>
  );
}
