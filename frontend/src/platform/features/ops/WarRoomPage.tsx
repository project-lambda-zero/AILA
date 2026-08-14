/**
 * WarRoomPage -- Ops War Room, a console-aesthetic real-time surface.
 *
 * Three columns on wide viewports (stack on narrow):
 *   1. Live event stream from the shared SSE fan-out (buffered by
 *      {@link ActivityFeedProvider}). Newest on top, mono, type/scope
 *      colouring, chip filters, freeze-on-hover so a clicking user does
 *      not race a fresh event that reorders the list under the pointer.
 *   2. Active runs grid seeded from ``GET /tasks/queue-depth`` and any
 *      run ids observed in the activity buffer. Each card shows the
 *      last event for that resource; per-run drill-down streams are
 *      opt-in and stay out of this initial cut.
 *   3. Vitals rail: queue depth (5s), dead-letter count (admin only,
 *      30s), and SSE connection state from {@link useSSEContext}.
 *
 * Renders bare content (no PageShell/PageFrame) -- ``protectPage`` in
 * the router owns the title bar.
 */
import * as React from "react";
import { useQuery } from "@tanstack/react-query";
import { Broadcast } from "@phosphor-icons/react/dist/csr/Broadcast";
import { CircleNotch } from "@phosphor-icons/react/dist/csr/CircleNotch";
import { Pulse } from "@phosphor-icons/react/dist/csr/Pulse";
import { Queue } from "@phosphor-icons/react/dist/csr/Queue";
import { Skull } from "@phosphor-icons/react/dist/csr/Skull";
import { WarningOctagon } from "@phosphor-icons/react/dist/csr/WarningOctagon";

import { AilaCard } from "@/components/aila/AilaCard";
import { AilaBadge } from "@/components/aila/AilaBadge";
import { EmptyState } from "@/components/aila/EmptyState";
import { Button } from "@/components/ui/button";
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
// Chip config
// ---------------------------------------------------------------------------

interface ChipDef {
  scope: ActivityScope;
  label: string;
}

const CHIP_DEFS: readonly ChipDef[] = [
  { scope: "scan", label: "SCAN" },
  { scope: "investigation", label: "INVESTIGATION" },
  { scope: "finding", label: "FINDING" },
  { scope: "notification", label: "NOTIFICATION" },
  { scope: "task", label: "TASK" },
  { scope: "mcp", label: "MCP" },
  { scope: "system", label: "SYSTEM" },
  { scope: "other", label: "OTHER" },
];

const SCOPE_TEXT_CLASS: Record<ActivityScope, string> = {
  scan: "text-lavender",
  investigation: "text-medium",
  finding: "text-high",
  notification: "text-accent",
  task: "text-lavender",
  mcp: "text-mint",
  system: "text-medium",
  other: "text-text-muted",
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function formatRelative(now: number, at: number): string {
  const delta = Math.max(0, now - at);
  if (delta < 1_000) return "now";
  if (delta < 60_000) return `${Math.floor(delta / 1_000)}s`;
  if (delta < 3_600_000) return `${Math.floor(delta / 60_000)}m`;
  if (delta < 86_400_000) return `${Math.floor(delta / 3_600_000)}h`;
  return `${Math.floor(delta / 86_400_000)}d`;
}

function severityForEvent(event: ActivityEvent): "critical" | "high" | "medium" | "low" | "info" | "neutral" {
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

// ---------------------------------------------------------------------------
// Live event stream column
// ---------------------------------------------------------------------------

interface EventStreamProps {
  events: readonly ActivityEvent[];
  activeScopes: ReadonlySet<ActivityScope>;
  onToggleScope: (scope: ActivityScope) => void;
  onReset: () => void;
  scopeCounts: Readonly<Record<ActivityScope, number>>;
  totalIngested: number;
}

function LiveEventStream({
  events,
  activeScopes,
  onToggleScope,
  onReset,
  scopeCounts,
  totalIngested,
}: EventStreamProps) {
  const [paused, setPaused] = React.useState(false);
  const pausedSnapshotRef = React.useRef<readonly ActivityEvent[] | null>(null);
  const [now, setNow] = React.useState(() => Date.now());

  // 1Hz relative-time tick. Cheap: only re-renders this column.
  React.useEffect(() => {
    const id = window.setInterval(() => setNow(Date.now()), 1_000);
    return () => window.clearInterval(id);
  }, []);

  // Freeze the snapshot exactly at pause moment so hover-to-click never
  // races an inbound event that reorders the list under the cursor.
  if (paused) {
    if (pausedSnapshotRef.current === null) {
      pausedSnapshotRef.current = events;
    }
  } else {
    pausedSnapshotRef.current = null;
  }

  const visibleAll = pausedSnapshotRef.current ?? events;
  const visible = activeScopes.size === 0
    ? visibleAll
    : visibleAll.filter((event) => activeScopes.has(event.scope));

  return (
    <AilaCard variant="elevated" padding="md" className="flex flex-col" style={{ minHeight: 640 }}>
      <div className="flex items-center justify-between gap-3">
        <div className="flex items-center gap-2">
          <Broadcast className="h-4 w-4 text-accent" />
          <span className="font-mono text-xs uppercase tracking-wider text-text-muted">
            Live Event Stream
          </span>
        </div>
        <div className="flex items-center gap-2">
          <span className="font-mono text-[10px] uppercase tracking-wider text-text-muted">
            {totalIngested} total | showing {visible.length}
          </span>
          {activeScopes.size > 0 && (
            <Button variant="ghost" size="sm" onClick={onReset} className="h-6 px-2 font-mono text-[10px]">
              CLEAR FILTERS
            </Button>
          )}
        </div>
      </div>

      <div className="mt-3 flex flex-wrap gap-1.5">
        {CHIP_DEFS.map((chip) => {
          const active = activeScopes.has(chip.scope);
          const count = scopeCounts[chip.scope] ?? 0;
          return (
            <button
              key={chip.scope}
              type="button"
              onClick={() => onToggleScope(chip.scope)}
              className={
                "rounded-[2px] border px-2 py-0.5 font-mono text-[10px] uppercase tracking-wider transition-colors " +
                (active
                  ? "border-accent bg-accent/15 text-accent"
                  : "border-border text-text-muted hover:border-accent hover:text-accent")
              }
            >
              {chip.label} {count > 0 ? `[${count}]` : ""}
            </button>
          );
        })}
      </div>

      <div
        className="mt-3 flex-1 overflow-y-auto rounded-[2px] border border-border bg-black/30 p-2 font-mono text-xs"
        style={{ maxHeight: 560 }}
        onMouseEnter={() => setPaused(true)}
        onMouseLeave={() => setPaused(false)}
      >
        {paused && (
          <div className="sticky top-0 z-10 mb-1 rounded-[2px] border border-accent/40 bg-black/70 px-2 py-0.5 text-center text-[10px] uppercase tracking-wider text-accent">
            paused -- move cursor away to resume
          </div>
        )}
        {visible.length === 0 ? (
          <div className="flex h-full items-center justify-center text-text-muted">
            {activeScopes.size > 0 ? "no matching events" : "waiting for events…"}
          </div>
        ) : (
          <ul className="space-y-0.5">
            {visible.map((event) => (
              <StreamRow key={event.id} event={event} now={now} />
            ))}
          </ul>
        )}
      </div>
    </AilaCard>
  );
}

function StreamRow({ event, now }: { event: ActivityEvent; now: number }) {
  const severity = severityForEvent(event);
  const scopeClass = SCOPE_TEXT_CLASS[event.scope];
  return (
    <li className="flex items-baseline gap-2 border-b border-border/30 py-0.5 last:border-b-0">
      <span className="w-8 shrink-0 text-right text-[10px] text-text-muted">
        {formatRelative(now, event.at)}
      </span>
      <span className={`w-24 shrink-0 truncate text-[10px] uppercase tracking-wider ${scopeClass}`}>
        {event.scope}
      </span>
      <AilaBadge severity={severity} size="sm" className="shrink-0">
        {event.type}
      </AilaBadge>
      <span className="min-w-0 flex-1 truncate text-text-primary">
        {event.summary}
      </span>
      {event.resourceId && (
        <span className="w-24 shrink-0 truncate text-right text-[10px] text-text-muted">
          {event.resourceId.slice(0, 8)}
        </span>
      )}
    </li>
  );
}

// ---------------------------------------------------------------------------
// Active runs grid
// ---------------------------------------------------------------------------

interface ActiveRun {
  resourceId: string;
  scope: ActivityScope;
  lastEvent: ActivityEvent;
  eventCount: number;
}

function deriveActiveRuns(events: readonly ActivityEvent[]): ActiveRun[] {
  // A run is "active" if we've seen any event for it AND we have NOT
  // seen a terminal marker (scan_complete with status done/failed/
  // cancelled, task marked completed) since. Since events arrive
  // newest-first we walk in reverse chronological order and record
  // the first (=latest) event per resource, then filter out those
  // whose latest event is terminal.
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

interface ActiveRunsGridProps {
  events: readonly ActivityEvent[];
  queueDepth: QueueDepthPayload | undefined;
  isLoading: boolean;
}

function ActiveRunsGrid({ events, queueDepth, isLoading }: ActiveRunsGridProps) {
  const [now, setNow] = React.useState(() => Date.now());
  React.useEffect(() => {
    const id = window.setInterval(() => setNow(Date.now()), 2_000);
    return () => window.clearInterval(id);
  }, []);

  const runs = React.useMemo(() => deriveActiveRuns(events), [events]);
  const runningCount = queueDepth?.running ?? 0;
  const queuedCount = queueDepth?.queued ?? 0;

  return (
    <AilaCard variant="elevated" padding="md" className="flex flex-col" style={{ minHeight: 640 }}>
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <CircleNotch className="h-4 w-4 text-accent" />
          <span className="font-mono text-xs uppercase tracking-wider text-text-muted">
            Active Runs
          </span>
        </div>
        <span className="font-mono text-[10px] uppercase tracking-wider text-text-muted">
          {runs.length} tracked | {runningCount} running | {queuedCount} queued
        </span>
      </div>

      <div className="mt-3 flex-1 overflow-y-auto pr-1" style={{ maxHeight: 560 }}>
        {isLoading && runs.length === 0 ? (
          <div className="grid gap-2">
            {[0, 1, 2].map((n) => (
              <div key={n} className="h-16 animate-pulse rounded-[2px] border border-border bg-surface/40" />
            ))}
          </div>
        ) : runs.length === 0 ? (
          <EmptyState
            icon={<CircleNotch className="h-8 w-8" />}
            title="No active runs"
            description={
              runningCount > 0
                ? `${runningCount} task${runningCount === 1 ? "" : "s"} running -- cards appear as their events arrive.`
                : "Kick off a scan or investigation to see live progress here."
            }
          />
        ) : (
          <ul className="grid gap-2">
            {runs.map((run) => (
              <RunCard key={run.resourceId} run={run} now={now} />
            ))}
          </ul>
        )}
      </div>
    </AilaCard>
  );
}

function RunCard({ run, now }: { run: ActiveRun; now: number }) {
  const severity = severityForEvent(run.lastEvent);
  return (
    <li className="rounded-[2px] border border-border bg-surface/40 p-3 transition-colors hover:border-accent/60">
      <div className="flex items-center justify-between gap-2">
        <div className="flex items-center gap-2 min-w-0">
          <AilaBadge severity={severity} size="sm">{run.scope}</AilaBadge>
          <span className="truncate font-mono text-xs text-text-primary">
            {run.resourceId}
          </span>
        </div>
        <span className="shrink-0 font-mono text-[10px] uppercase tracking-wider text-text-muted">
          {formatRelative(now, run.lastEvent.at)} | {run.eventCount} evt
        </span>
      </div>
      <div className="mt-1.5 truncate font-mono text-[11px] text-text-muted">
        {run.lastEvent.type}: {run.lastEvent.summary}
      </div>
    </li>
  );
}

// ---------------------------------------------------------------------------
// Vitals rail
// ---------------------------------------------------------------------------

interface VitalsRailProps {
  queueDepth: QueueDepthPayload | undefined;
  queueDepthError: unknown;
  deadLetterCount: number | undefined;
  deadLetterError: unknown;
  isAdmin: boolean;
  sseStatus: "connecting" | "connected" | "disconnected";
  reducedMotion: boolean;
}

function VitalsRail({
  queueDepth,
  queueDepthError,
  deadLetterCount,
  deadLetterError,
  isAdmin,
  sseStatus,
  reducedMotion,
}: VitalsRailProps) {
  const queueRows = React.useMemo(() => {
    if (!queueDepth) return [];
    return Object.entries(queueDepth)
      .filter(([, count]) => typeof count === "number")
      .sort((a, b) => b[1] - a[1]);
  }, [queueDepth]);

  const sseDotClass = sseStatus === "connected"
    ? "bg-mint"
    : sseStatus === "connecting"
      ? "bg-medium"
      : "bg-critical";
  const shouldPulse = sseStatus === "connected" && !reducedMotion;

  return (
    <AilaCard variant="elevated" padding="md" className="flex flex-col" style={{ minHeight: 640 }}>
      <div className="flex items-center gap-2">
        <Pulse className="h-4 w-4 text-accent" />
        <span className="font-mono text-xs uppercase tracking-wider text-text-muted">
          Vitals
        </span>
      </div>

      {/* SSE connection */}
      <div className="mt-4">
        <div className="font-mono text-[10px] uppercase tracking-wider text-text-muted">
          SSE Stream
        </div>
        <div className="mt-1 flex items-center gap-2">
          <span
            className={`inline-block h-2 w-2 rounded-full ${sseDotClass} ${shouldPulse ? "animate-pulse" : ""}`}
            aria-hidden
          />
          <span className="font-mono text-sm uppercase tracking-wider text-text-primary">
            {sseStatus}
          </span>
        </div>
      </div>

      {/* Queue depth */}
      <div className="mt-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-1.5 font-mono text-[10px] uppercase tracking-wider text-text-muted">
            <Queue className="h-3 w-3" />
            Queue Depth
          </div>
          <span className="font-mono text-[10px] text-text-muted">5s</span>
        </div>
        {queueDepthError ? (
          <div className="mt-1 rounded-[2px] border border-destructive bg-destructive/10 px-2 py-1 font-mono text-[10px] text-destructive">
            unavailable
          </div>
        ) : queueRows.length === 0 ? (
          <div className="mt-1 font-mono text-xs text-text-muted">--</div>
        ) : (
          <ul className="mt-1 space-y-0.5">
            {queueRows.map(([status, count]) => (
              <li key={status} className="flex items-center justify-between font-mono text-xs">
                <span className="uppercase tracking-wider text-text-muted">{status}</span>
                <span className="tabular-nums text-text-primary">{count}</span>
              </li>
            ))}
          </ul>
        )}
      </div>

      {/* Dead-letter (admin only) */}
      {isAdmin && (
        <div className="mt-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-1.5 font-mono text-[10px] uppercase tracking-wider text-text-muted">
              <Skull className="h-3 w-3" />
              Dead Letter
            </div>
            <span className="font-mono text-[10px] text-text-muted">30s</span>
          </div>
          {deadLetterError ? (
            <div className="mt-1 rounded-[2px] border border-destructive bg-destructive/10 px-2 py-1 font-mono text-[10px] text-destructive">
              unavailable
            </div>
          ) : (
            <div className="mt-1 flex items-baseline gap-2">
              <span className="font-mono text-xl tabular-nums text-text-primary">
                {deadLetterCount ?? "--"}
              </span>
              <span className="font-mono text-[10px] uppercase tracking-wider text-text-muted">
                exhausted retries
              </span>
            </div>
          )}
        </div>
      )}
    </AilaCard>
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
      if (next.has(scope)) {
        next.delete(scope);
      } else {
        next.add(scope);
      }
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

  return (
    <div className="flex flex-col gap-4">
      {sseBanner && (
        <div
          role="alert"
          className="flex items-start gap-3 rounded-[4px] border border-destructive bg-destructive/10 px-4 py-3"
        >
          <WarningOctagon className="mt-0.5 h-5 w-5 shrink-0 text-destructive" />
          <div className="min-w-0">
            <div className="font-mono text-sm uppercase tracking-wider text-destructive">
              {sseBanner.title}
            </div>
            <div className="mt-0.5 font-mono text-xs text-text-muted">
              {sseBanner.body}
            </div>
          </div>
        </div>
      )}

      <div className="grid gap-4 lg:grid-cols-12">
        <div className="lg:col-span-5">
          <LiveEventStream
            events={feed.events}
            activeScopes={activeScopes}
            onToggleScope={toggleScope}
            onReset={resetScopes}
            scopeCounts={feed.scopeCounts}
            totalIngested={feed.totalIngested}
          />
        </div>
        <div className="lg:col-span-4">
          <ActiveRunsGrid
            events={feed.events}
            queueDepth={queueDepth}
            isLoading={queueDepthQuery.isLoading}
          />
        </div>
        <div className="lg:col-span-3">
          <VitalsRail
            queueDepth={queueDepth}
            queueDepthError={queueDepthQuery.error}
            deadLetterCount={deadLetterCount}
            deadLetterError={deadLetterQuery.error}
            isAdmin={isAdmin}
            sseStatus={sseStatus}
            reducedMotion={reducedMotion}
          />
        </div>
      </div>
    </div>
  );
}
