/**
 * useForensicsInvestigationEvents -- live investigation-event subscription
 * with terminal-driven cache invalidation.
 *
 * Wraps :func:`useInvestigationEventFeed` from ``queries.ts`` (which itself
 * delegates to the platform ``useSSEStream`` hook -- one fetch, reconnect
 * with exponential backoff, single AbortController on unmount) and adds:
 *
 *  - Terminal-status detection off BOTH the stage-carrying data frames
 *    (``stage: completed | failed``) AND the SSE terminator frame
 *    (``event: done\ndata: {"status": "..."}``). The platform hook only
 *    decodes ``data:`` lines, so the terminator lands here as a bare
 *    ``{status: "..."}`` payload with no stage / message -- both shapes
 *    are recognised.
 *  - Automatic invalidation of the investigation-detail, project-answer
 *    and per-project investigation-list caches when a terminal event
 *    arrives, so the detail screen flips from ``running`` to its
 *    terminal status without requiring a manual refresh. Additive to
 *    :func:`useForensicsListLive` (which invalidates list scopes off
 *    the platform SSE fan-out); this hook targets the exact
 *    investigation.
 *  - A single-subscription contract: callers MUST NOT also call
 *    ``useInvestigationEventFeed`` for the same investigation, else a
 *    second scoped EventSource-style fetch is opened.
 *
 *  Pass ``isRunning=false`` to disable the subscription without
 *  unmounting; the underlying feed drops to ``idle`` and no HTTP
 *  request is opened.
 */
import { useEffect, useMemo } from "react";

import { useQueryClient } from "@tanstack/react-query";

import {
  type InvestigationEvent,
  type InvestigationFeedStatus,
  useInvestigationEventFeed,
} from "../queries";

const TERMINAL_STATUSES: Record<string, true> = {
  completed: true,
  failed: true,
  exhausted: true,
  cancelled: true,
};

export interface ForensicsInvestigationLive {
  events: InvestigationEvent[];
  feedStatus: InvestigationFeedStatus;
  /** The most recent non-null ``stage`` seen on the stream, or null
   *  when no stage-bearing frame has landed yet. Useful for showing
   *  the current agent phase in the run panel header. */
  latestStage: string | null;
  /** Set to the terminal status string (``completed`` / ``failed`` /
   *  ``exhausted`` / ``cancelled``) as soon as a terminal frame lands
   *  on the stream. Null until then. Callers can use this to hide the
   *  panel or flip local UI state; the hook itself also invalidates
   *  the affected TanStack Query caches so the detail refetch fires
   *  automatically. */
  terminalStatus: string | null;
}

export function useForensicsInvestigationEvents(opts: {
  projectId: string;
  investigationId: string;
  isRunning: boolean;
}): ForensicsInvestigationLive {
  const { projectId, investigationId, isRunning } = opts;
  const queryClient = useQueryClient();

  // Empty ids disable the underlying feed -- ``useInvestigationEventFeed``
  // calls ``buildUrl`` which returns null, and the platform hook settles
  // to ``disconnected`` without opening a request.
  const scopedProjectId = isRunning ? projectId : "";
  const scopedInvId = isRunning ? investigationId : "";

  const { events, feedStatus } = useInvestigationEventFeed(
    scopedProjectId,
    scopedInvId,
  );

  const { latestStage, terminalStatus } = useMemo(() => {
    let stage: string | null = null;
    let terminal: string | null = null;
    for (const ev of events) {
      if (ev.stage) {
        stage = ev.stage;
        if (TERMINAL_STATUSES[ev.stage]) {
          terminal = ev.stage;
        }
      }
      // ``event: done`` terminator: platform hook only reads ``data:``
      // lines, so the terminator lands here as a bare ``{status: "..."}``
      // payload with no stage / message. ``InvestigationEvent`` does
      // not declare ``status``, so narrow via ``in`` + typeof rather
      // than an unchecked cast.
      if (ev && typeof ev === "object" && "status" in ev) {
        const maybeStatus = ev.status;
        if (typeof maybeStatus === "string" && TERMINAL_STATUSES[maybeStatus]) {
          terminal = maybeStatus;
        }
      }
    }
    return { latestStage: stage, terminalStatus: terminal };
  }, [events]);

  useEffect(() => {
    if (!terminalStatus) return;
    if (!projectId || !investigationId) return;
    // Refetch the detail so status / final_answer / attempts_used flip
    // right after the SSE terminator, and the parent project's list
    // + answers so dashboards sharing the same rows update in the
    // same beat.
    void queryClient.invalidateQueries({
      queryKey: ["forensics", "investigation", projectId, investigationId],
    });
    void queryClient.invalidateQueries({
      queryKey: ["forensics", "answers", projectId],
    });
    void queryClient.invalidateQueries({
      queryKey: ["forensics", "investigations", projectId],
    });
  }, [terminalStatus, projectId, investigationId, queryClient]);

  return { events, feedStatus, latestStage, terminalStatus };
}
