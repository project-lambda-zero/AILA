import { useQueryClient } from "@tanstack/react-query";

import { buildApiUrl } from "@platform/api/http";
import { useSSEStream, type SSEStreamStatus } from "@platform/hooks/useSSEStream";

/** Placeholder message shape.
 *
 *  Replace with the module's real summary contract -- normally a
 *  pydantic-generated TS type mirrored under `../types`. The only
 *  required field for the sample cache merge below is the discriminant
 *  used to dedupe by identity. */
export interface TemplateMessageSummary {
  id: string;
}

/** Parse one raw SSE ``data:`` payload into a message summary.
 *
 *  The backend wraps every event in a typed envelope
 *  ``{ type, payload }`` (see the reference modules'
 *  contracts/events.py). This scaffold accepts ``message.created`` and
 *  falls back to a bare summary for backward compat; adjust the
 *  accepted event types to match the module's real envelope. Any
 *  frame missing the discriminant `id` returns null so heartbeats and
 *  open / done envelopes are dropped by the platform hook. */
function parseTemplateEvent(raw: string): TemplateMessageSummary | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return null;
  }
  if (!parsed || typeof parsed !== "object") return null;

  // Envelope-wrapped events carry the summary under `payload`; legacy
  // un-enveloped events ARE the summary. Both paths funnel through
  // the discriminant-field check below.
  let candidate: unknown = parsed;
  if ("type" in parsed) {
    if (parsed.type !== "message.created" || !("payload" in parsed)) {
      return null;
    }
    candidate = parsed.payload;
  }

  if (
    candidate
    && typeof candidate === "object"
    && "id" in candidate
    && typeof candidate.id === "string"
  ) {
    // Narrowing above proved the discriminant; the backend contract
    // guarantees the rest of the shape on message.created payloads.
    return candidate as TemplateMessageSummary;
  }
  return null;
}

/** SSE live tail scaffold for an investigation's messages.
 *
 *  Thin wrapper over the platform ``useSSEStream``: everything
 *  transport-related (auth, backoff, abort, line splitting) lives in
 *  the platform hook; this wrapper owns only the URL shape, event
 *  framing, and cache merge.
 *
 *  A copier customizes:
 *    - ``TemplateMessageSummary`` -> the real summary contract
 *    - the URL path segment (``/_template/investigations/...``)
 *    - the accepted event types in ``parseTemplateEvent``
 *    - ``queryKey`` inside ``onMessage`` so cache writes land in the
 *      same react-query key the module's fetch hook reads
 *    - ``queryKeyPrefix`` so the platform can scope invalidations to
 *      this module's namespace
 *
 *  ``reconnect: false`` matches the reference module: a single attempt
 *  runs and the status settles to ``disconnected`` when the server
 *  emits ``event: done`` (workflow reached terminal status) or the
 *  stream otherwise ends. A component remount reopens it. Flip to
 *  ``true`` for long-lived tails that must survive proxy timeouts on
 *  their own. */
export function useInvestigationMessagesStream(
  investigationId: string,
): { status: SSEStreamStatus } {
  const qc = useQueryClient();

  return useSSEStream<TemplateMessageSummary>({
    buildUrl: () => {
      if (!investigationId) return null;
      const params = new URLSearchParams();
      // Stream messages that land after we connect; initial fill comes
      // from the polling fetch hook so the two don't double-count.
      params.set("since_iso", new Date().toISOString());
      const qs = params.toString();
      return buildApiUrl(
        `/_template/investigations/${encodeURIComponent(investigationId)}/messages/stream${qs ? `?${qs}` : ""}`,
      );
    },
    parseEvent: parseTemplateEvent,
    onMessage: (msg) => {
      // The cache key MUST match the module's fetch hook exactly so a
      // single ["_template", "investigation-messages", ...] entry is
      // updated in place. See vr/frontend/hooks for the canonical
      // fetch + stream pair.
      const key = ["_template", "investigation-messages", investigationId] as const;
      qc.setQueryData<TemplateMessageSummary[] | undefined>(key, (prev) => {
        if (!prev) return prev;
        if (prev.some((m) => m.id === msg.id)) return prev;
        return [...prev, msg];
      });
    },
    reconnect: false,
    deps: [investigationId, qc],
    // Scopes cross-module cache invalidations to this module's
    // namespace. Keep the first segment aligned with the fetch hook's
    // key so `queryClient.invalidateQueries({ queryKey: [<prefix>] })`
    // reaches every read this module owns.
    queryKeyPrefix: ["_template"] as const,
  });
}
