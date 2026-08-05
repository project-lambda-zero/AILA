import { useQueryClient } from "@tanstack/react-query";

import { buildApiUrl } from "@platform/api/http";
import { useSSEStream } from "@platform/hooks/useSSEStream";

import { type LiveStatus } from "../components/LiveDot";
import type { Envelope, VRMessageSummary } from "../types";

/** Narrow an unknown JSON value to a VRMessageSummary by its two
 *  discriminant fields. Returns null when either is absent so the
 *  stream drops heartbeats / open / done envelopes that carry no row. */
function asMessageSummary(value: unknown): VRMessageSummary | null {
  if (
    value
    && typeof value === "object"
    && "id" in value
    && "payload_kind" in value
  ) {
    // Discriminant fields present -- the backend contract guarantees the
    // rest of the VRMessageSummary shape on message.created /
    // operator.steering payloads (contracts/events.py).
    return value as VRMessageSummary;
  }
  return null;
}

/** Parse one raw SSE ``data:`` payload into a VRMessageSummary.
 *
 *  The backend wraps every event in a typed VREventEnvelope
 *  (contracts/events.py). The payload of a ``message.created`` or
 *  ``operator.steering`` event is the VRMessageSummary; heartbeat /
 *  open / done envelopes carry no message and are dropped. A legacy
 *  un-enveloped event (bare summary) is still accepted for backward
 *  compat. */
function parseVREvent(raw: string): VRMessageSummary | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return null;
  }
  if (!parsed || typeof parsed !== "object") return null;

  if ("type" in parsed) {
    const t = parsed.type;
    if (t === "message.created" || t === "operator.steering") {
      if ("payload" in parsed) return asMessageSummary(parsed.payload);
    }
    return null;
  }
  // Legacy un-enveloped event (backward compat).
  return asMessageSummary(parsed);
}

/** SSE live tail for investigation messages.
 *
 * Opens a Server-Sent Events connection to
 * /vr/investigations/{id}/messages/stream and merges new VRMessageSummary
 * payloads into the existing ["vr", "investigation-messages", ...] query
 * cache so any consumer of `useInvestigationMessages` sees new turns
 * land as they happen -- no polling latency.
 *
 * Connection lifecycle:
 *   - opens on mount when ``investigationId`` is non-empty,
 *   - closes on unmount via AbortController,
 *   - AUTO-RECONNECTS on stream end / network error / backend restart
 *     with exponential backoff (1s -> 2s -> 4s -> 8s -> 16s capped at
 *     30s; reset to 1s on every successful connect). Without this loop
 *     the LiveDot would settle to disconnected after any worker /
 *     backend restart and new messages would silently stop arriving
 *     until the user navigated away and back.
 *
 * Catch-up cursor:
 *   - Callers pass ``opts.sinceIso`` (the ``created_at`` of the last
 *     message merged into the cache) so a reconnect resumes from the
 *     gap boundary instead of ``Date.now()``. Without the cursor the
 *     window of messages produced during a reconnect backoff is lost.
 *   - When no cursor is supplied the hook falls back to the connect-time
 *     ``Date.now()`` so the initial fill from `useInvestigationMessages`
 *     is not double-counted.
 *
 * The backend polls the DB every 1 s; the frontend gets each message
 * within ~1 s of insertion. Heartbeats every 15 s keep proxies alive.
 */
export function useInvestigationMessagesStream(
  investigationId: string,
  opts: { branchId?: string; sinceIso?: string } = {},
): { status: LiveStatus } {
  const qc = useQueryClient();
  const { branchId, sinceIso } = opts;

  // Cache scope this stream feeds. Declared once, handed to both the
  // platform hook (so a scope change reconnects) and the setQueryData
  // call below (so the merge writes to the same key).
  const queryKeyPrefix = [
    "vr",
    "investigation-messages",
    investigationId,
    branchId,
  ] as const;

  return useSSEStream<VRMessageSummary>({
    buildUrl: () => {
      if (!investigationId) return null;
      const params = new URLSearchParams();
      if (branchId) params.set("branch_id", branchId);
      // Resume from the caller's cursor when supplied; otherwise stream
      // messages that land after we connect (initial fill comes from the
      // polling `useInvestigationMessages` so we don't double-up).
      params.set("since_iso", sinceIso ?? new Date().toISOString());
      const qs = params.toString();
      return buildApiUrl(
        `/vr/investigations/${encodeURIComponent(investigationId)}/messages/stream${qs ? `?${qs}` : ""}`,
      );
    },
    parseEvent: parseVREvent,
    onMessage: (msg) => {
      // Key matches useInvestigationMessages exactly so the same query
      // cache is updated. Default offset/limit are 0/100 -- the list
      // page uses defaults so we mirror.
      const key = [...queryKeyPrefix, 0, 100] as const;
      qc.setQueryData<Envelope<VRMessageSummary[]> | undefined>(key, (prev) => {
        if (!prev) return prev;
        // Skip if we already have this id -- reconnect replays around
        // the cursor boundary and can deliver a row we merged already.
        if (prev.data.some((m) => m.id === msg.id)) return prev;
        return {
          ...prev,
          data: [...prev.data, msg],
          meta: {
            ...prev.meta,
            total: Number(prev.meta?.total ?? prev.data.length) + 1,
          },
        };
      });
    },
    reconnect: true,
    deps: [sinceIso, qc],
    queryKeyPrefix,
  });
}
