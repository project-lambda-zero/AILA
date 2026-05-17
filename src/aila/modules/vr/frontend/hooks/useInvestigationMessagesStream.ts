import { useEffect } from "react";

import { useQueryClient } from "@tanstack/react-query";

import { buildApiUrl } from "@platform/api/http";
import { getAuthTokenStandalone } from "@platform/auth/useAuthStore";

import type { Envelope, VRMessageSummary } from "../types";

/** SSE live tail for investigation messages.
 *
 * Opens a single Server-Sent Events connection to
 * /vr/investigations/{id}/messages/stream and merges new VRMessageSummary
 * payloads into the existing ["vr", "investigation-messages", ...] query
 * cache so any consumer of `useInvestigationMessages` sees new turns
 * land as they happen — no polling latency.
 *
 * Connection lifecycle:
 *   - opens on mount when ``investigationId`` is non-empty
 *   - closes on unmount via AbortController
 *   - automatically terminates when the server emits ``event: done``
 *     (investigation reached terminal status)
 *
 * The backend polls the DB every 1 s; the frontend gets each message
 * within ~1 s of insertion. Heartbeats every 15 s keep proxies alive.
 */
export function useInvestigationMessagesStream(
  investigationId: string,
  branchId?: string,
): void {
  const qc = useQueryClient();

  useEffect(() => {
    if (!investigationId) return;
    const ac = new AbortController();

    void (async () => {
      let token: string | null = null;
      try {
        token = await getAuthTokenStandalone();
      } catch {
        // unauthenticated — server will reject
      }

      const params = new URLSearchParams();
      if (branchId) params.set("branch_id", branchId);
      // Stream messages that land after we connect. Initial fill comes
      // from the polling `useInvestigationMessages` so we don't double-up.
      params.set("since_iso", new Date().toISOString());
      const qs = params.toString();
      const url = buildApiUrl(
        `/vr/investigations/${encodeURIComponent(investigationId)}/messages/stream${qs ? `?${qs}` : ""}`,
      );

      let response: Response;
      try {
        response = await fetch(url, {
          headers: {
            Accept: "text/event-stream",
            ...(token ? { Authorization: `Bearer ${token}` } : {}),
          },
          signal: ac.signal,
        });
      } catch {
        return;
      }
      if (!response.ok || !response.body) return;

      const reader = response.body.getReader();
      const decoder = new TextDecoder();
      let buf = "";

      const mergeMessage = (msg: VRMessageSummary) => {
        // Key matches useInvestigationMessages exactly so the same query
        // cache is updated. Default offset/limit are 0/100 — the list
        // page uses defaults so we mirror.
        const key = [
          "vr",
          "investigation-messages",
          investigationId,
          branchId,
          0,
          100,
        ] as const;
        qc.setQueryData<Envelope<VRMessageSummary[]> | undefined>(
          key,
          (prev) => {
            if (!prev) return prev;
            // Skip if we already have this id
            if (prev.data.some((m) => m.id === msg.id)) return prev;
            return {
              ...prev,
              data: [...prev.data, msg],
              meta: {
                ...prev.meta,
                total: Number(prev.meta?.total ?? prev.data.length) + 1,
              },
            };
          },
        );
      };

      const pushLine = (line: string) => {
        if (!line.startsWith("data:")) return;
        const raw = line.slice(5).trimStart();
        if (!raw) return;
        try {
          // Backend wraps every event in a typed VREventEnvelope
          // (see contracts/events.py). The payload of a
          // message.created or operator.steering event is the
          // VRMessageSummary; heartbeat / open / done envelopes
          // carry no message and we drop them.
          const parsed = JSON.parse(raw) as
            | { type: string; payload?: unknown }
            | { id: string; payload_kind: string };
          if ("type" in parsed) {
            const t = parsed.type;
            if (t === "message.created" || t === "operator.steering") {
              const payload = (parsed as { payload?: unknown }).payload;
              if (
                payload
                && typeof payload === "object"
                && "id" in payload
                && "payload_kind" in payload
              ) {
                mergeMessage(payload as VRMessageSummary);
              }
            }
            return;
          }
          // Legacy un-enveloped event (backward compat).
          if ("id" in parsed && "payload_kind" in parsed) {
            mergeMessage(parsed as VRMessageSummary);
          }
        } catch {
          // malformed event — skip
        }
      };

      try {
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          buf += decoder.decode(value, { stream: true });
          const lines = buf.split(/\r?\n/);
          buf = lines.pop() ?? "";
          for (const line of lines) pushLine(line);
        }
      } catch {
        // aborted or network error
      }
    })();

    return () => {
      ac.abort();
    };
  }, [investigationId, branchId, qc]);
}
