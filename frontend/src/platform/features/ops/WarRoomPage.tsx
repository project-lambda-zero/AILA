/**
 * WarRoomPage -- Ops War Room, security-operations-center surface.
 *
 * Rebuilt to the AILA mock: SectionHeader top, a grid of WindowPanels for
 * incidents / alert stream / active runs / system health. Every table is a
 * DataGrid; every status/severity chip is a MonoBadge; every scope filter is
 * a FilterChip. All data hooks (queue-depth, dead-letter, SSE, activity feed)
 * are preserved verbatim.
 *
 * Renders bare content -- protectPage() in the router owns the title bar.
 */
import * as React from "react";
import { useQuery } from "@tanstack/react-query";
import { Broadcast } from "@phosphor-icons/react/dist/csr/Broadcast";
import { Pulse } from "@phosphor-icons/react/dist/csr/Pulse";
import { WarningOctagon } from "@phosphor-icons/react/dist/csr/WarningOctagon";

import { SectionHeader, MonoBadge, FilterChip, StatBar, BigStat, DataGrid, toneColor } from "@/components/aila/mock";
import { WindowPanel } from "@/components/aila/WindowPanel";
import { FeatureBoundary } from "@app/FeatureBoundary";
import { authorizedRequestJson } from "@platform/api/http";
import { useAuthStore } from "@platform/auth/useAuthStore";
import { useReducedMotion } from "@/hooks/useReducedMotion";
import { useSSEContext } from "@/providers/SSEProvider";
import {
  useActivityFeed,
  type ActivityEvent,
  type ActivityScope,
} from "@/providers/ActivityFeedProvider";

// ---------------------------------------------------------------------------
// Backend contracts
// ---------------------------------------------------------------------------

interface DataEnvelope<T> {
  data: T;
  error: string | null;
  meta: Record<string, unknown>;
}

type QueueDepthPayload = Record<string, number>;

interface DeadLetterEntry {
  task_id: string;
  track: string;
  fn_path: string;
  attempts: number;
}

// ---------------------------------------------------------------------------
// Chip config -- filter chips for the alert stream
// ---------------------------------------------------------------------------

interface ChipDef { scope: ActivityScope; label: string; color: string }

const CHIP_DEFS: readonly ChipDef[] = [
  { scope: "scan", label: "SCAN", color: "var(--status-info)" },
  { scope: "investigation", label: "INVESTIGATION", color: "var(--status-info)" },
  { scope: "finding", label: "FINDING", color: "var(--status-warn)" },
  { scope: "notification", label: "NOTIFICATION", color: "var(--accent)" },
  { scope: "task", label: "TASK", color: "var(--status-info)" },
  { scope: "mcp", label: "MCP", color: "var(--status-ok)" },
  { scope: "system", label: "SYSTEM", color: "var(--status-signal)" },
  { scope: "other", label: "OTHER", color: "var(--text-faint)" },
];

// ---------------------------------------------------------------------------
// Helpers -- pure display formatting; feed data is untouched.
// ---------------------------------------------------------------------------

function formatRelative(now: number, at: number): string {
  const delta = Math.max(0, now - at);
  if (delta < 1_000) return "now";
  if (delta < 60_000) return `${Math.floor(delta / 1_000)}s`;
  if (delta < 3_600_000) return `${Math.floor(delta / 60_000)}m`;
  if (delta < 86_400_000) return `${Math.floor(delta / 3_600_000)}h`;
  return `${Math.floor(delta / 86_400_000)}d`;
}

function formatClock(at: number): string {
  const d = new Date(at);
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
}

type EventSeverity = "critical" | "high" | "medium" | "low" | "info" | "neutral";

function severityForEvent(event: ActivityEvent): EventSeverity {
  const type = event.type;
  if (type === "system_unreachable") return "high";
  if (type === "finding_arrived") {
    const payload = event.payload as { criticality?: string; score?: number } | null;
    if (payload?.criticality === "CRITICAL" || Number(payload?.score ?? 0) >= 9) return "critical";
    return "medium";
  }
  if (type === "scan_complete") {
    const payload = event.payload as { status?: string } | null;
    if (payload?.status === "failed") return "high";
    if (payload?.status === "cancelled") return "medium";
    return "info";
  }
  if (type === "notification") {
    const payload = event.payload as { category?: string } | null;
    if (payload?.category === "critical") return "critical";
    if (payload?.category === "warning") return "high";
    return "info";
  }
  return "neutral";
}

const SEVERITY_TONE: Record<EventSeverity, string> = {
  critical: "critical",
  high: "high",
  medium: "medium",
  low: "low",
  info: "info",
  neutral: "muted",
};

// ---------------------------------------------------------------------------
// Wall-clock chip (self-contained 1Hz tick, decorative only)
// ---------------------------------------------------------------------------
function LiveClock() {
  const [now, setNow] = React.useState(() => Date.now());
  React.useEffect(() => {
    const id = window.setInterval(() => setNow(Date.now()), 1_000);
    return () => window.clearInterval(id);
  }, []);
  return (
    <span
      className="font-mono"
      style={{ fontSize: 11, color: "var(--text-primary)", letterSpacing: "0.06em" }}
    >
      {formatClock(now)}
    </span>
  );
}

// ---------------------------------------------------------------------------
// Alerts stream -- WindowPanel with filter chips + severity-coloured rows.
// Freezes on hover so a click never races an inbound event.
// ---------------------------------------------------------------------------
interface AlertsStreamProps {
  events: readonly ActivityEvent[];
  activeScopes: ReadonlySet<ActivityScope>;
  onToggleScope: (scope: ActivityScope) => void;
  onReset: () => void;
  scopeCounts: Readonly<Record<ActivityScope, number>>;
  totalIngested: number;
}

function AlertsStream({
  events,
  activeScopes,
  onToggleScope,
  onReset,
  scopeCounts,
  totalIngested,
}: AlertsStreamProps) {
  const [paused, setPaused] = React.useState(false);
  const pausedSnapshotRef = React.useRef<readonly ActivityEvent[] | null>(null);
  const [now, setNow] = React.useState(() => Date.now());

  React.useEffect(() => {
    const id = window.setInterval(() => setNow(Date.now()), 1_000);
    return () => window.clearInterval(id);
  }, []);

  if (paused) {
    if (pausedSnapshotRef.current === null) pausedSnapshotRef.current = events;
  } else {
    pausedSnapshotRef.current = null;
  }

  const visibleAll = pausedSnapshotRef.current ?? events;
  const visible = activeScopes.size === 0
    ? visibleAll
    : visibleAll.filter((event) => activeScopes.has(event.scope));

  return (
    <WindowPanel
      title="alert stream"
      tone={paused ? "muted" : "accent"}
      status={
        <span style={{ color: "var(--text-faint)" }}>
          {paused ? "PAUSED" : "LIVE"} {"\u00b7"} {totalIngested} total {"\u00b7"} {visible.length} shown
        </span>
      }
      actions={activeScopes.size > 0 ? (
        <button
          type="button"
          onClick={onReset}
          className="font-mono uppercase"
          style={{
            height: 22, padding: "0 9px", fontSize: 9, letterSpacing: "0.08em",
            border: "1px solid var(--border-soft)", background: "transparent",
            color: "var(--text-muted)", borderRadius: 3, cursor: "pointer",
          }}
        >
          CLEAR
        </button>
      ) : undefined}
    >
      <div className="flex flex-col" style={{ gap: 10 }}>
        <div className="flex flex-wrap items-center" style={{ gap: 6 }}>
          {CHIP_DEFS.map((chip) => {
            const active = activeScopes.has(chip.scope);
            const count = scopeCounts[chip.scope] ?? 0;
            return (
              <FilterChip
                key={chip.scope}
                active={active}
                color={chip.color}
                onClick={() => onToggleScope(chip.scope)}
              >
                {chip.label}{count > 0 ? ` \u00b7 ${count}` : ""}
              </FilterChip>
            );
          })}
        </div>

        <div
          onMouseEnter={() => setPaused(true)}
          onMouseLeave={() => setPaused(false)}
          style={{
            maxHeight: 520, overflowY: "auto",
            border: "1px solid var(--border-soft)", borderRadius: 3,
            background: "var(--surface-sunk)",
          }}
        >
          {visible.length === 0 ? (
            <div
              className="font-mono uppercase"
              style={{
                padding: 34, textAlign: "center",
                fontSize: 10, letterSpacing: "0.1em", color: "var(--text-faint)",
              }}
            >
              {activeScopes.size > 0 ? "no matching events" : "waiting for events\u2026"}
            </div>
          ) : (
            <ul className="flex flex-col" style={{ padding: 0, margin: 0, listStyle: "none" }}>
              {visible.map((event) => (
                <StreamRow key={event.id} event={event} now={now} />
              ))}
            </ul>
          )}
        </div>
      </div>
    </WindowPanel>
  );
}

function StreamRow({ event, now }: { event: ActivityEvent; now: number }) {
  const sev = severityForEvent(event);
  const tone = SEVERITY_TONE[sev];
  const barColor = toneColor(tone);
  return (
    <li
      className="flex items-center font-mono"
      style={{
        position: "relative",
        gap: 10,
        padding: "6px 12px 6px 14px",
        borderBottom: "1px solid var(--border-faint)",
        fontSize: 11,
      }}
    >
      <span
        aria-hidden
        style={{
          position: "absolute", left: 0, top: 0, bottom: 0, width: 2,
          background: barColor,
        }}
      />
      <span style={{ flex: "0 0 62px", color: "var(--text-faint)", fontSize: 10 }}>
        {formatClock(event.at)}
      </span>
      <span style={{ flex: "0 0 96px", color: "var(--text-muted)", fontSize: 9.5, letterSpacing: "0.08em", textTransform: "uppercase" }}>
        {event.scope}
      </span>
      <MonoBadge tone={tone}>{event.type}</MonoBadge>
      <span
        className="truncate"
        style={{ flex: 1, minWidth: 0, color: "var(--text-primary)" }}
      >
        {event.summary}
      </span>
      {event.resourceId && (
        <span style={{ flex: "0 0 auto", color: "var(--text-faint)", fontSize: 10, maxWidth: 96, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
          {event.resourceId.slice(0, 10)}
        </span>
      )}
      <span style={{ flex: "0 0 34px", textAlign: "right", color: "var(--text-muted)", fontSize: 10 }}>
        {formatRelative(now, event.at)}
      </span>
    </li>
  );
}

// ---------------------------------------------------------------------------
// Active runs -- DataGrid derived from the activity feed. A run is "active"
// if it has produced events without a terminal marker.
// ---------------------------------------------------------------------------
interface ActiveRun {
  resourceId: string;
  scope: ActivityScope;
  lastEvent: ActivityEvent;
  eventCount: number;
}

function deriveActiveRuns(events: readonly ActivityEvent[]): ActiveRun[] {
  const seen: Record<string, ActiveRun> = {};
  const terminated: Record<string, true> = {};
  for (const event of events) {
    if (!event.resourceId) continue;
    if (event.resourceId in seen) {
      seen[event.resourceId].eventCount += 1;
      continue;
    }
    const payload = event.payload as { status?: string } | null;
    const status = payload?.status;
    const isTerminal =
      event.type === "scan_complete"
      || event.type === "task_complete"
      || (typeof status === "string" && ["done", "failed", "cancelled", "completed"].includes(status));
    if (isTerminal) {
      terminated[event.resourceId] = true;
      continue;
    }
    seen[event.resourceId] = {
      resourceId: event.resourceId,
      scope: event.scope,
      lastEvent: event,
      eventCount: 1,
    };
  }
  return Object.values(seen)
    .filter((run) => !terminated[run.resourceId])
    .sort((a, b) => b.lastEvent.at - a.lastEvent.at);
}

function TeamActivity({
  events,
  queueDepth,
  isLoading,
}: {
  events: readonly ActivityEvent[];
  queueDepth: QueueDepthPayload | undefined;
  isLoading: boolean;
}) {
  const [now, setNow] = React.useState(() => Date.now());
  React.useEffect(() => {
    const id = window.setInterval(() => setNow(Date.now()), 2_000);
    return () => window.clearInterval(id);
  }, []);

  const runs = React.useMemo(() => deriveActiveRuns(events), [events]);
  const runningCount = queueDepth?.running ?? 0;
  const queuedCount = queueDepth?.queued ?? 0;

  return (
    <WindowPanel
      title="team activity"
      status={
        <span style={{ color: "var(--text-faint)" }}>
          {runs.length} TRACKED {"\u00b7"} {runningCount} RUN {"\u00b7"} {queuedCount} Q
        </span>
      }
      flush
    >
      <DataGrid
        columns={[
          { label: "SCOPE", width: "110px" },
          { label: "RESOURCE", width: "1fr" },
          { label: "LAST EVENT", width: "1.4fr" },
          { label: "EVT", width: "44px", align: "right" },
          { label: "AGE", width: "48px", align: "right" },
        ]}
        rows={runs}
        getKey={(r) => r.resourceId}
        renderCells={(run) => {
          const sev = severityForEvent(run.lastEvent);
          const tone = SEVERITY_TONE[sev];
          return [
            <MonoBadge tone={tone}>{run.scope}</MonoBadge>,
            <span className="truncate" style={{ color: "var(--text-primary)", fontSize: 11 }}>
              {run.resourceId}
            </span>,
            <span className="truncate" style={{ fontSize: 10, color: "var(--text-muted)" }}>
              <span style={{ color: toneColor(tone) }}>{run.lastEvent.type}</span>
              {" : "}
              {run.lastEvent.summary}
            </span>,
            <span style={{ color: "var(--text-primary)", fontSize: 10 }}>{run.eventCount}</span>,
            <span style={{ color: "var(--text-muted)", fontSize: 10 }}>{formatRelative(now, run.lastEvent.at)}</span>,
          ];
        }}
        empty={
          <div
            className="font-mono uppercase"
            style={{
              padding: 30, textAlign: "center",
              fontSize: 10, letterSpacing: "0.1em", color: "var(--text-faint)",
            }}
          >
            {isLoading
              ? "loading queue snapshot\u2026"
              : runningCount > 0
                ? `${runningCount} task${runningCount === 1 ? "" : "s"} running \u00b7 cards appear as events arrive`
                : "no active runs \u2014 kick off a scan or investigation"}
          </div>
        }
      />
    </WindowPanel>
  );
}

// ---------------------------------------------------------------------------
// System health -- StatBars per queue status + BigStat for dead-letter.
// ---------------------------------------------------------------------------
function SystemHealth({
  queueDepth,
  queueDepthError,
  deadLetterCount,
  deadLetterError,
  isAdmin,
  sseStatus,
  reducedMotion,
}: {
  queueDepth: QueueDepthPayload | undefined;
  queueDepthError: unknown;
  deadLetterCount: number | undefined;
  deadLetterError: unknown;
  isAdmin: boolean;
  sseStatus: "connecting" | "connected" | "disconnected";
  reducedMotion: boolean;
}) {
  const queueRows = React.useMemo(() => {
    if (!queueDepth) return [] as [string, number][];
    return Object.entries(queueDepth)
      .filter(([, count]) => typeof count === "number")
      .sort((a, b) => b[1] - a[1]);
  }, [queueDepth]);

  const maxQ = queueRows.reduce((m, [, c]) => Math.max(m, c), 0);
  const panelTone: "ok" | "info" | "warn" =
    sseStatus === "connected" ? "ok" : sseStatus === "disconnected" ? "warn" : "info";
  const dotColor =
    sseStatus === "connected" ? toneColor("ok")
    : sseStatus === "connecting" ? toneColor("medium")
    : toneColor("critical");
  const badgeTone = sseStatus === "connected" ? "ok" : sseStatus === "connecting" ? "medium" : "critical";
  const shouldPulse = sseStatus === "connected" && !reducedMotion;

  return (
    <WindowPanel title="system health" tone={panelTone}>
      <div className="flex flex-col" style={{ gap: 14 }}>
        {/* SSE row */}
        <div className="flex flex-col" style={{ gap: 6 }}>
          <div
            className="font-mono uppercase"
            style={{ fontSize: 9, letterSpacing: "0.14em", color: "var(--text-faint)" }}
          >
            SSE STREAM
          </div>
          <div className="flex items-center" style={{ gap: 8 }}>
            <span
              aria-hidden
              className={shouldPulse ? "animate-pulse" : undefined}
              style={{
                width: 10, height: 10, borderRadius: 999, background: dotColor,
                boxShadow: shouldPulse ? `0 0 6px ${dotColor}` : undefined,
              }}
            />
            <MonoBadge tone={badgeTone}>{sseStatus}</MonoBadge>
          </div>
        </div>

        {/* Queue depth block */}
        <div className="flex flex-col" style={{ gap: 8, paddingTop: 8, borderTop: "1px solid var(--border-faint)" }}>
          <div className="flex items-center justify-between">
            <div
              className="font-mono uppercase"
              style={{ fontSize: 9, letterSpacing: "0.14em", color: "var(--text-faint)" }}
            >
              QUEUE DEPTH
            </div>
            <span className="font-mono" style={{ fontSize: 9, color: "var(--text-faint)" }}>5s</span>
          </div>
          {queueDepthError ? (
            <div
              className="font-mono"
              style={{
                border: "1px solid color-mix(in srgb, var(--status-warn) 40%, transparent)",
                background: "color-mix(in srgb, var(--status-warn) 10%, transparent)",
                color: "var(--status-warn)",
                padding: "6px 10px", fontSize: 10, borderRadius: 3, letterSpacing: "0.08em",
                textTransform: "uppercase",
              }}
            >
              unavailable
            </div>
          ) : queueRows.length === 0 ? (
            <div
              className="font-mono"
              style={{ fontSize: 18, color: "var(--text-faint)" }}
            >
              --
            </div>
          ) : (
            <div className="flex flex-col" style={{ gap: 6 }}>
              {queueRows.map(([status, count]) => (
                <StatBar
                  key={status}
                  label={status}
                  color={count > 0 ? "var(--accent)" : "var(--text-faint)"}
                  value={count}
                  max={Math.max(maxQ, 1)}
                />
              ))}
            </div>
          )}
        </div>

        {/* Dead-letter (admin only) -- BigStat */}
        {isAdmin && (
          <div className="flex flex-col" style={{ gap: 6, paddingTop: 8, borderTop: "1px solid var(--border-faint)" }}>
            <div className="flex items-center justify-between">
              <div
                className="font-mono uppercase"
                style={{ fontSize: 9, letterSpacing: "0.14em", color: "var(--text-faint)" }}
              >
                DEAD LETTER
              </div>
              <span className="font-mono" style={{ fontSize: 9, color: "var(--text-faint)" }}>30s</span>
            </div>
            {deadLetterError ? (
              <div
                className="font-mono"
                style={{
                  border: "1px solid color-mix(in srgb, var(--status-warn) 40%, transparent)",
                  background: "color-mix(in srgb, var(--status-warn) 10%, transparent)",
                  color: "var(--status-warn)",
                  padding: "6px 10px", fontSize: 10, borderRadius: 3, letterSpacing: "0.08em",
                  textTransform: "uppercase",
                }}
              >
                unavailable
              </div>
            ) : (
              <BigStat
                value={deadLetterCount ?? "--"}
                sub="exhausted retries"
              />
            )}
          </div>
        )}
      </div>
    </WindowPanel>
  );
}

// ---------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------

export function WarRoomPage() {
  const isAuthenticated = useAuthStore((s) => s.isAuthenticated);
  const role = useAuthStore((s) => s.role);
  const isAdmin = role === "admin";
  const reducedMotion = useReducedMotion();

  const { status: sseStatus, lastHttpError } = useSSEContext();
  const feed = useActivityFeed();

  const [activeScopes, setActiveScopes] = React.useState<ReadonlySet<ActivityScope>>(new Set());
  const toggleScope = React.useCallback((scope: ActivityScope) => {
    setActiveScopes((prev) => {
      const next = new Set(prev);
      if (next.has(scope)) next.delete(scope);
      else next.add(scope);
      return next;
    });
  }, []);
  const resetScopes = React.useCallback(() => setActiveScopes(new Set()), []);

  const queueDepthQuery = useQuery({
    queryKey: ["ops", "war-room", "queue-depth"],
    queryFn: () =>
      authorizedRequestJson<DataEnvelope<QueueDepthPayload>>("/tasks/queue-depth"),
    refetchInterval: 5_000,
    enabled: isAuthenticated,
    retry: false,
    throwOnError: false,
  });

  const deadLetterQuery = useQuery({
    queryKey: ["ops", "war-room", "dead-letter"],
    queryFn: () =>
      authorizedRequestJson<DataEnvelope<DeadLetterEntry[]>>("/admin/tasks/dead-letter"),
    refetchInterval: 30_000,
    enabled: isAuthenticated && isAdmin,
    retry: false,
    throwOnError: false,
  });

  const queueDepth = queueDepthQuery.data?.data;
  const deadLetterCount = deadLetterQuery.data?.data.length;

  const sseBanner = (() => {
    if (!isAuthenticated) return null;
    if (lastHttpError === 503) {
      return {
        title: "SSE ceiling hit",
        body: "The backend returned 503 for /events/stream -- per-user connection ceiling reached. Live events are paused; reconnect will retry with back-off.",
      };
    }
    if (lastHttpError !== null && lastHttpError >= 500) {
      return {
        title: `SSE upstream error ${lastHttpError}`,
        body: "The event stream returned a server error. Reconnect is running in the background.",
      };
    }
    if (sseStatus === "disconnected") {
      return {
        title: "SSE stream disconnected",
        body: "Live events are not flowing. Reconnect is running in the background.",
      };
    }
    return null;
  })();

  const sseDotColor =
    sseStatus === "connected" ? toneColor("ok")
    : sseStatus === "connecting" ? toneColor("medium")
    : toneColor("critical");

  return (
    <div className="flex flex-col" style={{ gap: 16, padding: 20 }}>
      <SectionHeader
        icon={"\u25ce"}
        title="war room"
        actions={
          <div className="flex items-center" style={{ gap: 12 }}>
            <span className="inline-flex items-center" style={{ gap: 6 }}>
              <span
                aria-hidden
                className={sseStatus === "connected" && !reducedMotion ? "animate-pulse" : undefined}
                style={{ width: 8, height: 8, borderRadius: 999, background: sseDotColor }}
              />
              <span
                className="font-mono uppercase"
                style={{ fontSize: 9.5, letterSpacing: "0.1em", color: "var(--text-muted)" }}
              >
                SSE {sseStatus}
              </span>
            </span>
            <span
              aria-hidden
              style={{ width: 1, height: 14, background: "var(--border-soft)" }}
            />
            <LiveClock />
          </div>
        }
      />

      {/* Incident banner -- present iff SSE is faulted */}
      {sseBanner && (
        <WindowPanel
          title="incident"
          tone="warn"
          status="LIVE"
          {...({ role: "alert", "aria-live": "assertive" } as Record<string, unknown>)}
        >
          <div className="flex items-start" style={{ gap: 10 }}>
            <WarningOctagon
              aria-hidden
              size={18}
              style={{ color: "var(--status-warn)", flex: "0 0 auto", marginTop: 2 }}
            />
            <div className="flex flex-col" style={{ gap: 4, minWidth: 0 }}>
              <div
                className="font-mono uppercase"
                style={{ fontSize: 11, letterSpacing: "0.1em", color: "var(--status-warn)" }}
              >
                {sseBanner.title}
              </div>
              <div
                className="font-mono"
                style={{ fontSize: 11, lineHeight: 1.55, color: "var(--text-muted)" }}
              >
                {sseBanner.body}
              </div>
            </div>
          </div>
        </WindowPanel>
      )}

      {/* Main grid: alerts stream | system health */}
      <div
        className="grid"
        style={{ gridTemplateColumns: "minmax(0, 1.5fr) minmax(0, 1fr)", gap: 16 }}
      >
        <FeatureBoundary
          label="Alert stream"
          resetKeys={[activeScopes]}
          onReset={resetScopes}
        >
          <AlertsStream
            events={feed.events}
            activeScopes={activeScopes}
            onToggleScope={toggleScope}
            onReset={resetScopes}
            scopeCounts={feed.scopeCounts}
            totalIngested={feed.totalIngested}
          />
        </FeatureBoundary>
        <FeatureBoundary
          label="System health"
          resetKeys={[queueDepthQuery.dataUpdatedAt, deadLetterQuery.dataUpdatedAt]}
          onReset={() => {
            void queueDepthQuery.refetch();
            if (isAdmin) void deadLetterQuery.refetch();
          }}
        >
          <SystemHealth
            queueDepth={queueDepth}
            queueDepthError={queueDepthQuery.error}
            deadLetterCount={deadLetterCount}
            deadLetterError={deadLetterQuery.error}
            isAdmin={isAdmin}
            sseStatus={sseStatus}
            reducedMotion={reducedMotion}
          />
        </FeatureBoundary>
      </div>

      {/* Team activity (active runs) */}
      <FeatureBoundary
        label="Active runs board"
        resetKeys={[queueDepthQuery.dataUpdatedAt]}
        onReset={() => void queueDepthQuery.refetch()}
      >
        <TeamActivity
          events={feed.events}
          queueDepth={queueDepth}
          isLoading={queueDepthQuery.isLoading}
        />
      </FeatureBoundary>

      {/* Broadcast identifier row -- purely decorative footer */}
      <div
        className="flex items-center font-mono uppercase"
        style={{
          gap: 8, padding: "6px 12px", fontSize: 9, letterSpacing: "0.14em",
          color: "var(--text-faint)",
          border: "1px solid var(--border-faint)", borderRadius: 3,
          background: "var(--surface-sunk)",
        }}
      >
        <Broadcast size={12} aria-hidden style={{ color: "var(--accent)" }} />
        <span>OPS WAR ROOM {"\u00b7"} REAL-TIME OPERATIONS</span>
        <span style={{ flex: 1 }} />
        <Pulse size={12} aria-hidden style={{ color: "var(--text-faint)" }} />
      </div>
    </div>
  );
}
