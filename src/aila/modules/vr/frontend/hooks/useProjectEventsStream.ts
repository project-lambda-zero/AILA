import { useEffect, useState } from "react";

import { useQueryClient } from "@tanstack/react-query";

import { buildApiUrl } from "@platform/api/http";
import { getAuthTokenStandalone } from "@platform/auth/useAuthStore";

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
  const [connected, setConnected] = useState<boolean>(false);

  useEffect(() => {
    if (!projectId) return;
    const ac = new AbortController();

    void (async () => {
      let token: string | null = null;
      try {
        token = await getAuthTokenStandalone();
      } catch {
        // unauthenticated -- server will reject
      }
      const params = new URLSearchParams();
      params.set("since_iso", new Date().toISOString());
      const url = buildApiUrl(
        `/vr/projects/${encodeURIComponent(projectId)}/events?${params.toString()}`,
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
        setConnected(false);
        return;
      }
      if (!response.ok || !response.body) {
        setConnected(false);
        return;
      }
      setConnected(true);
      const reader = response.body.getReader();
      const decoder = new TextDecoder();
      let buf = "";

      const handle = (raw: string) => {
        if (!raw) return;
        try {
          const ev = JSON.parse(raw) as VREvent;
          if (!ev.type) return;
          setLastEvent(ev);
          setLastSeenAt(Date.now());
          // Cache invalidation by event type. We invalidate exact
          // query keys that the React Query setup uses.
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
        } catch {
          // malformed event -- skip
        }
      };

      try {
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          buf += decoder.decode(value, { stream: true });
          const lines = buf.split(/\r?\n/);
          buf = lines.pop() ?? "";
          for (const line of lines) {
            if (line.startsWith("data:")) handle(line.slice(5).trimStart());
          }
        }
      } catch {
        // aborted or network error
      }
      setConnected(false);
    })();

    return () => {
      ac.abort();
      setConnected(false);
    };
  }, [projectId, qc]);

  return { lastEvent, lastSeenAt, connected };
}
