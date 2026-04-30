import { useEffect, useState } from "react";

import { ApiHttpError } from "@platform/api/http";
import { getAuthTokenStandalone } from "@platform/auth/useAuthStore";
import { streamJsonEvents } from "@platform/api/sse";

import type { SessionSseEvent } from "../../types";

export type StreamStatus = "idle" | "connecting" | "live" | "unavailable" | "closed" | "error";
export type ResolutionStatus = "idle" | "started" | "completed" | "failed";

export interface SessionEventsResult {
  streamStatus: StreamStatus;
  latestEvent: SessionSseEvent | null;
  resolutionStatus: ResolutionStatus;
  streamError: string | null;
}

/**
 * SSE event streaming hook for NFR wizard resolution events (D-09, Pattern 3).
 *
 * Follows the useScanEventFeed pattern from platform/features/scans/api.ts
 * exactly: AbortController, closedByAbort flag, ApiHttpError handling.
 *
 * Backend emits three meaningful event types:
 *   - "resolution_started"   { answer_count }
 *   - "resolution_completed" { component_count }
 *   - "resolution_failed"    { error }
 * Plus "ping" keepalives.
 *
 * IMPORTANT (T-137-01): After "resolution_completed", the consumer must call
 * GET /sessions/{id}/resolution to load the full 25-component classification.
 * This hook does NOT contain icon states — it only streams events.
 *
 * Security (T-137-03): getAuthTokenStandalone() provides a fresh JWT;
 * streamJsonEvents sends the Authorization header (no EventSource fallback).
 */
export function useSessionEvents(sessionId: string, enabled: boolean): SessionEventsResult {
  const [streamStatus, setStreamStatus] = useState<StreamStatus>("idle");
  const [latestEvent, setLatestEvent] = useState<SessionSseEvent | null>(null);
  const [resolutionStatus, setResolutionStatus] = useState<ResolutionStatus>("idle");
  const [streamError, setStreamError] = useState<string | null>(null);

  useEffect(() => {
    if (!enabled || !sessionId.trim()) {
      setStreamStatus("idle");
      setLatestEvent(null);
      setResolutionStatus("idle");
      setStreamError(null);
      return;
    }

    const controller = new AbortController();
    let closedByAbort = false;

    setStreamStatus("connecting");
    setLatestEvent(null);
    setStreamError(null);

    void getAuthTokenStandalone()
      .then((token) =>
        streamJsonEvents<SessionSseEvent>(
          `/sbd_nfr/sessions/${encodeURIComponent(sessionId)}/events`,
          {
            token,
            signal: controller.signal,
            onEvent: (event) => {
              const eventName = event.event;
              const data = event.data;

              // Skip ping keepalives — don't update latestEvent for pings
              if (eventName === "ping") {
                setStreamStatus("live");
                return;
              }

              setStreamStatus("live");
              setLatestEvent(data);

              if (eventName === "resolution_started") {
                setResolutionStatus("started");
              } else if (eventName === "resolution_completed") {
                setResolutionStatus("completed");
              } else if (eventName === "resolution_failed") {
                setResolutionStatus("failed");
              }
            },
          },
        ),
      )
      .then(() => {
        if (!closedByAbort) {
          setStreamStatus((current) => (current === "idle" ? current : "closed"));
        }
      })
      .catch((streamErr: unknown) => {
        if (closedByAbort || controller.signal.aborted) {
          return;
        }
        const message =
          streamErr instanceof ApiHttpError || streamErr instanceof Error
            ? streamErr.message
            : "Session event streaming failed.";
        setStreamStatus("error");
        setStreamError(message);
      });

    return () => {
      closedByAbort = true;
      controller.abort();
    };
  }, [enabled, sessionId]);

  return { streamStatus, latestEvent, resolutionStatus, streamError };
}
