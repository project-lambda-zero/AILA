/**
 * useForensicsListLive -- additively invalidate a forensics list query
 * cache when a relevant platform SSE event lands.
 *
 * The platform SSE stream (``/events/stream``) is fanned out to every
 * subscriber by :func:`SSEProvider`. Each list screen (projects,
 * investigations) mounts this hook with its list ``queryKey`` prefix;
 * on any event that scopes to forensics or names an
 * investigation/finding lifecycle transition, the matching TanStack
 * Query cache entries are invalidated so the list refetches.
 *
 * Invariants:
 *  - Purely additive: any existing ``refetchInterval`` continues to
 *    tick, and unrelated events are ignored (no-op).
 *  - One subscription per hook invocation; cleaned up on unmount via
 *    the SSE fan-out registry.
 *  - Cross-module isolation: vulnerability-only events (e.g. a
 *    finding_arrived with module_id=vulnerability) are ignored.
 */
import { useCallback } from "react";
import { useQueryClient, type QueryKey } from "@tanstack/react-query";

import type { SSEEvent } from "@/hooks/useSSE";
import { useSSESubscribe } from "@/providers/SSEProvider";

/** Classify an SSE frame as belonging to the forensics module.
 *
 *  Precedence:
 *   1. Explicit payload scope (``scope`` / ``module_id`` / ``module``).
 *      An explicit non-forensics scope wins -- vulnerability events do
 *      not invalidate forensics lists.
 *   2. Event type substring match on ``forensic``/``investigation``.
 */
export function isForensicsListEvent(event: SSEEvent): boolean {
  const type = event.type.toLowerCase();
  if (type === "ping") return false;

  const data = event.data;
  if (data !== null && typeof data === "object" && !Array.isArray(data)) {
    const rec: Record<string, unknown> = data as Record<string, unknown>;
    const rawScope = rec.scope ?? rec.module_id ?? rec.module;
    if (typeof rawScope === "string" && rawScope.length > 0) {
      const scope = rawScope.toLowerCase();
      return (
        scope.includes("forensic") ||
        scope.includes("investigation") ||
        scope === "vr"
      );
    }
  }
  return type.includes("forensic") || type.includes("investigation");
}

/** Subscribe a forensics list screen to platform SSE-driven cache
 *  invalidation. Pass the list's ``queryKey`` prefix, e.g.
 *  ``["forensics", "projects"]`` or
 *  ``["forensics", "investigations", projectId]``. The prefix matches
 *  every downstream key via TanStack Query's default prefix semantics,
 *  so per-page / per-filter cache entries all refetch together. */
export function useForensicsListLive(keyPrefix: QueryKey): void {
  const queryClient = useQueryClient();
  const listener = useCallback(
    (event: SSEEvent) => {
      if (!isForensicsListEvent(event)) return;
      void queryClient.invalidateQueries({ queryKey: keyPrefix });
    },
    // useSSESubscribe captures the listener via ref so the closure is
    // always up to date -- the deps here just satisfy React lint.
    [queryClient, keyPrefix],
  );
  useSSESubscribe(listener);
}
