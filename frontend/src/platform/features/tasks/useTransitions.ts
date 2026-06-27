/**
 * TanStack Query hook for workflow state transitions (Phase 181).
 *
 * Fetches GET /tasks/{task_id}/transitions.
 * Returns empty array for tasks with no workflow history -- never throws 404.
 *
 * Polling: disabled by default. The SSE stream pushes live transition events;
 * this hook is the initial-load / catch-up path (D-17 late-connect).
 */
import { useQuery } from "@tanstack/react-query";

import { fetchTransitions, type TransitionView } from "./transitions";

export type { TransitionView };

export function useTransitions(taskId: string) {
  return useQuery<TransitionView[]>({
    queryKey: ["platform", "transitions", taskId],
    enabled: taskId.trim().length > 0,
    queryFn: () => fetchTransitions(taskId),
    // Stale after 10 s -- the list only grows, refetch is cheap.
    staleTime: 10_000,
  });
}
