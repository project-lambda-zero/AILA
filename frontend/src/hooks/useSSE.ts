/**
 * useSSE -- connects to an SSE endpoint, calls onEvent for each event,
 * and reconnects on disconnect with exponential back-off.
 *
 * Manages connection lifecycle: mounts = connect, unmounts = disconnect.
 * Token is obtained from useAuthStore.getAccessToken() so it always uses
 * the current (possibly refreshed) token without re-rendering.
 *
 * Back-off schedule (ms): 1 000, 2 000, 4 000, 8 000, 16 000, 30 000 (max),
 * with ±25% random jitter (#47) so a cluster of clients kicked off by a
 * transient server failure do NOT re-storm the endpoint in lockstep. The
 * jitter is applied per-step, not to the base step, so the attempt
 * counter still climbs deterministically for tests / diagnostics.
 */
import { useEffect, useRef, useState } from "react";

import { buildApiUrl } from "@platform/api/http";
import { useAuthStore } from "@platform/auth/useAuthStore";

export type SSEConnectionStatus = "connecting" | "connected" | "disconnected";

export interface SSEEvent {
  type: string;
  data: unknown;
  user_id?: string;
  timestamp?: string;
}

export interface UseSSEOptions {
  /** Path (relative or absolute URL) of the SSE endpoint. */
  url: string;
  /** When false the hook does nothing. Defaults to true. */
  enabled?: boolean;
  /** Called for every complete SSE event frame received. */
  onEvent: (event: SSEEvent) => void;
  /** Optional callback for connection status changes. */
  onStatusChange?: (status: SSEConnectionStatus) => void;
}

const BACKOFF_STEPS_MS = [1_000, 2_000, 4_000, 8_000, 16_000, 30_000];
// #47: ±25% jitter around the step; keeps the schedule shape while
// spreading a synchronized reconnect burst across a ~half-step window.
const BACKOFF_JITTER_FRACTION = 0.25;

export function computeBackoffDelayMs(
  attempt: number,
  random: () => number = Math.random,
): number {
  const idx = Math.min(Math.max(attempt, 0), BACKOFF_STEPS_MS.length - 1);
  const base = BACKOFF_STEPS_MS[idx];
  const spread = base * BACKOFF_JITTER_FRACTION;
  // random() -> [0, 1); scale to [-spread, +spread).
  const jitter = (random() * 2 - 1) * spread;
  return Math.max(0, Math.round(base + jitter));
}

/**
 * useSSE -- persistent SSE connection with reconnect back-off.
 *
 * Returns the current connection status so callers can render indicators.
 * The hook is stable -- it does NOT reconnect on every render.
 */
export function useSSE({
  url,
  enabled = true,
  onEvent,
  onStatusChange,
}: UseSSEOptions): SSEConnectionStatus {
  const [status, setStatus] = useState<SSEConnectionStatus>("disconnected");
  const abortRef = useRef<AbortController | null>(null);
  const attemptRef = useRef(0);
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  // Stable reference to getAccessToken -- does not change after login
  const getAccessToken = useAuthStore((s) => s.getAccessToken);

  // Keep latest callbacks in a ref to avoid restarting the connection loop
  // when the parent re-renders with a new onEvent/onStatusChange reference.
  const onEventRef = useRef(onEvent);
  onEventRef.current = onEvent;
  const onStatusChangeRef = useRef(onStatusChange);
  onStatusChangeRef.current = onStatusChange;

  useEffect(() => {
    if (!enabled) {
      setStatus("disconnected");
      onStatusChangeRef.current?.("disconnected");
      return;
    }

    let cancelled = false;

    function updateStatus(next: SSEConnectionStatus) {
      setStatus(next);
      onStatusChangeRef.current?.(next);
    }

    async function connect() {
      if (cancelled) return;

      updateStatus("connecting");

      let token: string;
      try {
        token = await getAccessToken();
      } catch {
        scheduleReconnect();
        return;
      }

      const controller = new AbortController();
      abortRef.current = controller;

      try {
        const response = await fetch(buildApiUrl(url), {
          headers: {
            Accept: "text/event-stream",
            Authorization: `Bearer ${token}`,
          },
          signal: controller.signal,
        });

        if (!response.ok || !response.body) {
          scheduleReconnect();
          return;
        }

        updateStatus("connected");
        attemptRef.current = 0; // reset back-off on successful connect

        const reader = response.body.getReader();
        const decoder = new TextDecoder();
        let buffer = "";
        let currentType = "message";
        let currentData: string[] = [];

        while (true) {
          const { done, value } = await reader.read();
          if (done || cancelled) break;

          buffer += decoder.decode(value, { stream: true });
          const lines = buffer.split(/\r?\n/);
          buffer = lines.pop() ?? "";

          for (const line of lines) {
            if (line === "") {
              // Empty line = end of event frame
              if (currentData.length > 0) {
                try {
                  const parsed = JSON.parse(currentData.join("\n")) as SSEEvent;
                  onEventRef.current({ ...parsed, type: currentType });
                } catch {
                  // Malformed data -- discard silently
                }
              }
              currentType = "message";
              currentData = [];
              continue;
            }

            if (line.startsWith(":")) continue; // SSE comment / ping

            if (line.startsWith("event:")) {
              currentType = line.slice(6).trim();
              continue;
            }

            if (line.startsWith("data:")) {
              currentData.push(line.slice(5).trimStart());
            }
          }
        }
      } catch (err) {
        // AbortError is expected on unmount -- do not reconnect
        if ((err as Error)?.name === "AbortError" || cancelled) return;
      }

      if (!cancelled) {
        updateStatus("disconnected");
        scheduleReconnect();
      }
    }

    function scheduleReconnect() {
      if (cancelled) return;
      const backoff = computeBackoffDelayMs(attemptRef.current);
      attemptRef.current += 1;
      timerRef.current = setTimeout(() => {
        void connect();
      }, backoff);
    }

    void connect();

    return () => {
      cancelled = true;
      if (timerRef.current !== null) {
        clearTimeout(timerRef.current);
        timerRef.current = null;
      }
      abortRef.current?.abort();
    };
  }, [url, enabled, getAccessToken]);

  return status;
}
