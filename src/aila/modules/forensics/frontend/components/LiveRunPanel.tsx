/**
 * LiveRunPanel -- additive, running-only summary of one forensics
 * investigation. Renders a status pill, an attempts progress bar, a
 * client-side elapsed timer, an SSE-feed indicator and a short
 * recent-activity ticker sourced from the module's investigation
 * event stream. Rebuilt on the AILA mock kit (WindowPanel +
 * MonoBadge + StatBar); presentation only, data hooks unchanged.
 */
import { useEffect, useState } from "react";

import { WindowPanel } from "@/components/aila/WindowPanel";
import { MonoBadge, StatBar } from "@/components/aila/mock";

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
  idle: { label: "idle", color: "var(--text-muted)", pulse: false },
  connecting: { label: "connecting", color: "var(--status-warn)", pulse: true },
  live: { label: "streaming", color: "var(--status-ok)", pulse: false },
  unavailable: { label: "no stream", color: "var(--text-muted)", pulse: false },
  closed: { label: "closed", color: "var(--accent)", pulse: false },
  error: { label: "error", color: "var(--accent)", pulse: false },
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

function stageColor(stage: string): string {
  if (stage.includes("error") || stage.includes("failed")) return "var(--accent)";
  if (
    stage === "completed" ||
    stage.includes("done") ||
    stage.includes("detected")
  ) {
    return "var(--status-ok)";
  }
  if (stage.includes("start") || stage.includes("begin")) return "var(--status-warn)";
  if (stage === "artifact_added") return "var(--status-info)";
  return "var(--accent)";
}

/** BadgeSeverity -> MonoBadge tone. The two vocabularies overlap on 4 keys
 *  and diverge on ``neutral -> muted`` so the mapping is one lookup, not a
 *  passthrough. */
const SEVERITY_TO_TONE: Record<BadgeSeverity, string> = {
  critical: "critical",
  high: "high",
  medium: "medium",
  low: "low",
  info: "info",
  neutral: "muted",
};

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

  // Recent activity ticker: last N events, newest first, dropping the
  // no-signal heartbeat frames (the streaming dot in the header is
  // enough of a "still alive" cue).
  const recent = events
    .filter((ev) => ev.stage !== "heartbeat")
    .slice(-RECENT_TICKER_MAX)
    .reverse();

  return (
    <WindowPanel title="live run" tone="accent" status="investigation ; streaming">
      <div className="space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex flex-wrap items-center gap-3">
            <span aria-label={`investigation status: ${badge.label}`}>
              <MonoBadge tone={SEVERITY_TO_TONE[badge.severity]}>
                {badge.label}
              </MonoBadge>
            </span>
            <span
              className="inline-flex items-center gap-2 font-mono uppercase"
              style={{ fontSize: 9, letterSpacing: "0.08em", color: "var(--text-muted)" }}
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
                  boxShadow: `0 0 4px color-mix(in srgb, ${feed.color} 50%, transparent)`,
                }}
              />
              <span>
                stream ;{" "}
                <span style={{ color: "var(--text-primary)" }}>{feed.label}</span>
              </span>
            </span>
            {latestStage && latestStage !== "heartbeat" && (
              <span
                className="inline-flex items-center font-mono uppercase"
                style={{ fontSize: 9, letterSpacing: "0.08em", color: "var(--text-muted)" }}
              >
                stage ;
                <span style={{ color: "var(--text-primary)", marginLeft: 4 }}>
                  {latestStage}
                </span>
              </span>
            )}
          </div>
          <div
            className="flex items-center font-mono uppercase"
            style={{ fontSize: 9, letterSpacing: "0.08em", color: "var(--text-muted)" }}
          >
            <span>
              elapsed ;{" "}
              <span
                className="tabular-nums"
                style={{ color: "var(--text-primary)" }}
                aria-live="off"
              >
                {formatElapsed(elapsedMs)}
              </span>
            </span>
          </div>
        </div>

        {maxAttempts !== null && maxAttempts > 0 && (
          <div
            className="space-y-1"
            role="progressbar"
            aria-valuemin={0}
            aria-valuemax={maxAttempts}
            aria-valuenow={attemptsUsed}
            aria-label="investigation attempts used"
          >
            <StatBar
              label="ATTEMPTS"
              color="var(--accent)"
              value={attemptsUsed}
              max={maxAttempts}
            />
            <div
              className="font-mono tabular-nums"
              style={{ fontSize: 10, color: "var(--text-muted)", textAlign: "right" }}
            >
              <span>
                {attemptsUsed}/{maxAttempts}
              </span>
            </div>
          </div>
        )}

        <div className="space-y-1">
          <div
            className="font-mono uppercase"
            style={{ fontSize: 9, letterSpacing: "0.1em", color: "var(--text-muted)" }}
          >
            RECENT ACTIVITY
          </div>
          {recent.length === 0 ? (
            <p
              className="font-mono italic"
              style={{ fontSize: 11, color: "var(--text-muted)" }}
            >
              Waiting for events{"\u2026"}
            </p>
          ) : (
            <ol
              className="font-mono"
              style={{ fontSize: 11, margin: 0, padding: 0, listStyle: "none" }}
            >
              {recent.map((ev, i) => {
                const stage = ev.stage ?? "--";
                const color = stageColor(stage);
                const pct = ev.percent;
                return (
                  <li
                    key={i}
                    className="flex items-baseline gap-2"
                    style={{ padding: "2px 0" }}
                  >
                    {pct !== null && pct !== undefined && pct > 0 && (
                      <span
                        className="shrink-0 tabular-nums"
                        style={{
                          width: 36,
                          textAlign: "right",
                          color: "var(--text-muted)",
                        }}
                      >
                        {pct}%
                      </span>
                    )}
                    <span
                      className="shrink-0"
                      style={{ fontWeight: 600, color }}
                    >
                      [{stage}]
                    </span>
                    <span
                      className="break-all"
                      style={{ color: "var(--text-primary)" }}
                    >
                      {ev.message ?? ""}
                    </span>
                  </li>
                );
              })}
            </ol>
          )}
        </div>
      </div>
    </WindowPanel>
  );
}
