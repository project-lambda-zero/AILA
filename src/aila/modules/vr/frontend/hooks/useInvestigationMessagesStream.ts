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
 * Opens a single Server-Sent Events connection to
 * /vr/investigations/{id}/messages/stream and merges new VRMessageSummary
 * payloads into the existing ["vr", "investigation-messages", ...] query
 * cache so any consumer of `useInvestigationMessages` sees new turns
 * land as they happen -- no polling latency.
 *
 * Connection lifecycle:
 *   - opens on mount when ``investigationId`` is non-empty
 *   - closes on unmount via AbortController
 *   - runs a single attempt and settles to ``disconnected`` when the
 *     server emits ``event: done`` (investigation reached terminal
 *     status) or the stream otherwise ends; a remount reopens it
 *
 * The backend polls the DB every 1 s; the frontend gets each message
 * within ~1 s of insertion. Heartbeats every 15 s keep proxies alive.
 */
export function useInvestigationMessagesStream(
  investigationId: string,
  branchId?: string,
): { status: LiveStatus } {
  const qc = useQueryClient();

  return useSSEStream<VRMessageSummary>({
    buildUrl: () => {
      if (!investigationId) return null;
      const params = new URLSearchParams();
      if (branchId) params.set("branch_id", branchId);
      // Stream messages that land after we connect. Initial fill comes
      // from the polling `useInvestigationMessages` so we don't double-up.
      params.set("since_iso", new Date().toISOString());
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
      const key = [
        "vr",
        "investigation-messages",
        investigationId,
        branchId,
        0,
        100,
      ] as const;
      qc.setQueryData<Envelope<VRMessageSummary[]> | undefined>(key, (prev) => {
        if (!prev) return prev;
        // Skip if we already have this id.
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
    reconnect: false,
    deps: [investigationId, branchId, qc],
  });
}
