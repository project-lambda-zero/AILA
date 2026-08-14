/**
 * ActivityFeedProvider -- rolling in-memory window over the shared SSE
 * stream. Consumes the SSEProvider fan-out via {@link useSSESubscribe};
 * does NOT open a second ``/events/stream`` socket.
 *
 * The buffer is bounded at {@link ACTIVITY_FEED_CAPACITY} entries
 * (newest first). Every inbound frame is normalised to
 * {@link ActivityEvent} -- a stable shape the Ops War Room and any
 * other surface can render without re-implementing scope/summary
 * heuristics per page.
 *
 * Filter chips work off {@link ActivityEvent.scope}; per-run drill-down
 * uses {@link ActivityEvent.resourceId}. Type counts are maintained in
 * lockstep with the buffer so a chip row can render badge counts
 * without O(N) recompute.
 */
import * as React from "react";

import { useSSESubscribe, type SSEListener } from "@/providers/SSEProvider";
import type { SSEEvent } from "@/hooks/useSSE";

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/** Filter/colour bucket every event is classified into. ``other`` is the
 *  catch-all for frame types the front-end has not modelled yet -- kept
 *  visible so an unrecognised event stream is still audit-able. */
export type ActivityScope =
  | "scan"
  | "investigation"
  | "finding"
  | "notification"
  | "task"
  | "mcp"
  | "system"
  | "other";

export interface ActivityEvent {
  /** Monotonic sequence assigned at ingest so React keys are stable and
   *  ties (same wall-clock ms) sort deterministically. */
  id: number;
  /** Raw SSE ``event:`` frame type (``scan_complete``, ``notification``,
   *  etc.). Kept alongside ``scope`` because the built-in event types
   *  drive severity/colour and toast copy. */
  type: string;
  /** Classification for chip filtering and colour. */
  scope: ActivityScope;
  /** Best-effort per-event resource identifier (task id, run id, scan
   *  id, notification id) plucked out of the payload. Empty when the
   *  event does not describe a specific resource. */
  resourceId?: string;
  /** Wall-clock ingest time in ms (Date.now()). Prefer this over the
   *  server ``timestamp`` for UI display -- monotonic within the tab. */
  at: number;
  /** Raw payload verbatim, so the drill-down can render anything the
   *  card summary elides. */
  payload: unknown;
  /** One-line human summary, ready to drop into a mono terminal row. */
  summary: string;
}

export type ActivityTypeCounts = Record<string, number>;

export interface ActivityFeedContextValue {
  events: readonly ActivityEvent[];
  typeCounts: Readonly<ActivityTypeCounts>;
  scopeCounts: Readonly<Record<ActivityScope, number>>;
  totalIngested: number;
  clear: () => void;
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Rolling window size. 500 is enough for a busy operator to scroll
 *  ~10 minutes of activity in a heavy scan; beyond that memory pressure
 *  outweighs the value of scrollback and older entries drop off. */
export const ACTIVITY_FEED_CAPACITY = 500;

const EMPTY_SCOPE_COUNTS: Record<ActivityScope, number> = {
  scan: 0,
  investigation: 0,
  finding: 0,
  notification: 0,
  task: 0,
  mcp: 0,
  system: 0,
  other: 0,
};

const defaultContext: ActivityFeedContextValue = {
  events: [],
  typeCounts: {},
  scopeCounts: EMPTY_SCOPE_COUNTS,
  totalIngested: 0,
  clear: () => {},
};

const ActivityFeedContext = React.createContext<ActivityFeedContextValue>(defaultContext);

// ---------------------------------------------------------------------------
// Normalisation
// ---------------------------------------------------------------------------

function asRecord(data: unknown): Record<string, unknown> | null {
  if (data !== null && typeof data === "object" && !Array.isArray(data)) {
    return data as Record<string, unknown>;
  }
  return null;
}

function firstString(record: Record<string, unknown> | null, keys: readonly string[]): string | undefined {
  if (!record) return undefined;
  for (const key of keys) {
    const value = record[key];
    if (typeof value === "string" && value.length > 0) {
      return value;
    }
  }
  return undefined;
}

/** Map an SSE frame ``type`` (and optional payload ``scope``) onto the
 *  chip bucket. The payload's declared scope wins when present because
 *  backends occasionally reuse a generic frame type across scopes. */
function classifyScope(type: string, payload: Record<string, unknown> | null): ActivityScope {
  const payloadScope = firstString(payload, ["scope", "module_id", "module"]);
  if (payloadScope) {
    const lowered = payloadScope.toLowerCase();
    if (lowered.includes("scan")) return "scan";
    if (lowered.includes("vuln")) return "finding";
    if (lowered.includes("forensic") || lowered.includes("investigation") || lowered === "vr") {
      return "investigation";
    }
    if (lowered.includes("notification")) return "notification";
    if (lowered.includes("mcp") || lowered.includes("audit_mcp")) return "mcp";
    if (lowered.includes("task") || lowered.includes("queue")) return "task";
    if (lowered.includes("system") || lowered.includes("host")) return "system";
  }
  const lower = type.toLowerCase();
  if (lower.startsWith("scan") || lower.includes("scan_")) return "scan";
  if (lower.startsWith("finding") || lower.includes("_finding")) return "finding";
  if (lower.startsWith("investigation") || lower.startsWith("vr_") || lower.includes("investigation")) {
    return "investigation";
  }
  if (lower.startsWith("notification")) return "notification";
  if (lower.startsWith("task") || lower.includes("queue")) return "task";
  if (lower.startsWith("mcp") || lower.includes("mcp_")) return "mcp";
  if (lower.startsWith("system") || lower.includes("unreachable")) return "system";
  return "other";
}

function summarise(type: string, scope: ActivityScope, payload: Record<string, unknown> | null): string {
  if (!payload) {
    return type;
  }
  switch (type) {
    case "notification": {
      const title = firstString(payload, ["title"]) ?? "notification";
      const category = firstString(payload, ["category"]) ?? "info";
      return `${category.toUpperCase()} ${title}`;
    }
    case "scan_complete": {
      const scanStatus = firstString(payload, ["status"]) ?? "done";
      const host = firstString(payload, ["host", "hostname", "target"]);
      return host ? `scan ${scanStatus} on ${host}` : `scan ${scanStatus}`;
    }
    case "finding_arrived": {
      const cve = firstString(payload, ["cve_id", "cve"]);
      const host = firstString(payload, ["host", "hostname"]);
      const criticality = firstString(payload, ["criticality", "severity"]);
      const prefix = criticality ? `${criticality.toUpperCase()} finding` : "finding";
      if (cve && host) return `${prefix} ${cve} @ ${host}`;
      if (cve) return `${prefix} ${cve}`;
      if (host) return `${prefix} on ${host}`;
      return prefix;
    }
    case "system_unreachable": {
      const host = firstString(payload, ["hostname", "host"]) ?? "unknown host";
      return `${host} unreachable`;
    }
    case "ping":
      return "keepalive";
    default: {
      const label = firstString(payload, ["message", "title", "name", "status", "state"]);
      return label ? `${type} -- ${label}` : `${scope}/${type}`;
    }
  }
}

let ingestSequence = 0;

function normaliseEvent(event: SSEEvent): ActivityEvent {
  const payload = asRecord(event.data);
  const scope = classifyScope(event.type, payload);
  const resourceId = firstString(payload, [
    "run_id",
    "task_id",
    "scan_id",
    "investigation_id",
    "target_id",
    "notification_id",
    "id",
  ]);
  ingestSequence += 1;
  return {
    id: ingestSequence,
    type: event.type,
    scope,
    resourceId,
    at: Date.now(),
    payload: event.data,
    summary: summarise(event.type, scope, payload),
  };
}

// ---------------------------------------------------------------------------
// Reducer -- push newest to the front, cap at ACTIVITY_FEED_CAPACITY.
// ---------------------------------------------------------------------------

interface FeedState {
  events: ActivityEvent[];
  typeCounts: ActivityTypeCounts;
  scopeCounts: Record<ActivityScope, number>;
  totalIngested: number;
}

type FeedAction =
  | { kind: "push"; event: ActivityEvent }
  | { kind: "clear" };

function initialFeedState(): FeedState {
  return {
    events: [],
    typeCounts: {},
    scopeCounts: { ...EMPTY_SCOPE_COUNTS },
    totalIngested: 0,
  };
}

function decrement(counts: Record<string, number>, key: string): Record<string, number> {
  const current = counts[key] ?? 0;
  if (current <= 1) {
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const { [key]: _dropped, ...rest } = counts;
    return rest;
  }
  return { ...counts, [key]: current - 1 };
}

function feedReducer(state: FeedState, action: FeedAction): FeedState {
  switch (action.kind) {
    case "clear":
      return initialFeedState();
    case "push": {
      const next = [action.event, ...state.events];
      let typeCounts = { ...state.typeCounts, [action.event.type]: (state.typeCounts[action.event.type] ?? 0) + 1 };
      const scopeCounts = {
        ...state.scopeCounts,
        [action.event.scope]: state.scopeCounts[action.event.scope] + 1,
      };
      let evicted: ActivityEvent | undefined;
      if (next.length > ACTIVITY_FEED_CAPACITY) {
        evicted = next.pop();
      }
      if (evicted) {
        typeCounts = decrement(typeCounts, evicted.type) as ActivityTypeCounts;
        scopeCounts[evicted.scope] -= 1;
      }
      return {
        events: next,
        typeCounts,
        scopeCounts,
        totalIngested: state.totalIngested + 1,
      };
    }
    default:
      return state;
  }
}

// ---------------------------------------------------------------------------
// Provider + hook
// ---------------------------------------------------------------------------

export function ActivityFeedProvider({ children }: { children: React.ReactNode }) {
  const [state, dispatch] = React.useReducer(feedReducer, undefined, initialFeedState);

  const listener = React.useCallback<SSEListener>((event) => {
    // Skip keepalives -- they add zero information but would push out
    // real events at high heartbeat rates and dominate the counters.
    if (event.type === "ping") return;
    dispatch({ kind: "push", event: normaliseEvent(event) });
  }, []);
  useSSESubscribe(listener);

  const clear = React.useCallback(() => dispatch({ kind: "clear" }), []);

  const value = React.useMemo<ActivityFeedContextValue>(
    () => ({
      events: state.events,
      typeCounts: state.typeCounts,
      scopeCounts: state.scopeCounts,
      totalIngested: state.totalIngested,
      clear,
    }),
    [state.events, state.typeCounts, state.scopeCounts, state.totalIngested, clear],
  );

  return <ActivityFeedContext.Provider value={value}>{children}</ActivityFeedContext.Provider>;
}

export function useActivityFeed(): ActivityFeedContextValue {
  return React.useContext(ActivityFeedContext);
}
