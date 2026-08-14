import { useCallback, useMemo, useState } from "react";

import { useQueryClient } from "@tanstack/react-query";

import { buildApiUrl } from "@platform/api/http";
import { useSSEStream } from "@platform/hooks/useSSEStream";

/** Typed event payload (matches src/aila/modules/vr/contracts/events.py). */
export type VREvent = {
  type:
    | "message.created"
    | "turn.started"
    | "turn.completed"
    | "branch.created"
    | "branch.state_changed"
    | "hypothesis.state_changed"
    | "outcome.created"
    | "campaign.crash_found"
    | "campaign.progress"
    | "obligation.changed"
    | "disclosure.state_changed"
    | "operator.steering"
    | "heartbeat"
    | "done";
  ts: string;
  project_id?: string | null;
  investigation_id?: string | null;
  campaign_id?: string | null;
  branch_id?: string | null;
  payload?: Record<string, unknown>;
};

/** SSE multiplexed event stream for one project (08_FRONTEND_UX.md §2.1).
 *
 *  Connects to `/vr/projects/{id}/events` and exposes the latest event
 *  via a state hook so any consumer can react (toast, refetch,
 *  in-view animation). The hook also invalidates relevant React Query
 *  caches on event types that affect them -- `campaign.crash_found`
 *  invalidates the campaign's crash list, `branch.state_changed` and
 *  `outcome.created` invalidate the investigation's branches /
 *  outcomes.
 *
 *  Connection lifecycle:
 *   - opens on mount when `projectId` is non-empty,
 *   - closes on unmount via AbortController,
 *   - AUTO-RECONNECTS on stream end / network error / backend restart
 *     with exponential backoff (1s -> 2s -> 4s -> 8s -> 16s capped at
 *     30s; reset to 1s on every successful connect). Without this loop
 *     the project-level live indicator would settle to disconnected
 *     after any worker / backend restart and cache invalidations for
 *     branch/hypothesis/outcome/disclosure updates would silently stop
 *     firing until the operator navigated away and back (#111).
 *
 *  Heartbeat events update `lastSeenAt` so the UI can render a live
 *  dot. */
export function useProjectEventsStream(projectId: string | undefined): {
  lastEvent: VREvent | null;
  lastSeenAt: number;
  connected: boolean;
} {
  const qc = useQueryClient();
  const [lastEvent, setLastEvent] = useState<VREvent | null>(null);
  const [lastSeenAt, setLastSeenAt] = useState<number>(0);

  const buildUrl = useCallback((): string | null => {
    if (!projectId) return null;
    // Cursor is computed at connect time inside useSSEStream so a
    // reconnect after backoff starts from "now-ish" rather than the
    // original mount time -- avoiding a flood of buffered events on
    // resume.
    const params = new URLSearchParams();
    params.set("since_iso", new Date().toISOString());
    return buildApiUrl(
      `/vr/projects/${encodeURIComponent(projectId)}/events?${params.toString()}`,
    );
  }, [projectId]);

  const onMessage = useCallback(
    (ev: VREvent) => {
      setLastEvent(ev);
      setLastSeenAt(Date.now());
      // Cache invalidation by event type. We invalidate exact query
      // keys that the React Query setup uses.
      if (ev.type === "campaign.crash_found" && ev.campaign_id) {
        qc.invalidateQueries({
          queryKey: ["vr", "campaign-crashes", ev.campaign_id],
        });
      } else if (
        ev.type === "branch.state_changed"
        || ev.type === "hypothesis.state_changed"
        || ev.type === "branch.created"
      ) {
        if (ev.investigation_id) {
          qc.invalidateQueries({
            queryKey: ["vr", "investigation-branches", ev.investigation_id],
          });
        }
      } else if (ev.type === "outcome.created" && ev.investigation_id) {
        qc.invalidateQueries({
          queryKey: ["vr", "investigation-outcomes", ev.investigation_id],
        });
      } else if (ev.type === "disclosure.state_changed") {
        qc.invalidateQueries({
          queryKey: ["vr", "disclosures"],
        });
      }
    },
    [qc],
  );

  // Cache-scope declared for the platform hook so a projectId change
  // reconnects against the new scope without listing projectId in the
  // caller's deps.
  const queryKeyPrefix = useMemo(
    () => ["vr", "project-events", projectId ?? ""] as const,
    [projectId],
  );

  const { status } = useSSEStream<VREvent>({
    buildUrl,
    parseEvent: (raw) => {
      try {
        const ev = JSON.parse(raw) as VREvent;
        return ev && typeof ev === "object" && ev.type ? ev : null;
      } catch {
        return null;
      }
    },
    onMessage,
    reconnect: true,
    deps: [qc],
    queryKeyPrefix,
  });

  return { lastEvent, lastSeenAt, connected: status === "connected" };
}
