/**
 * TanStack Query hook for the per-run audit trail.
 *
 * Runs GET /audit/events?run_id=... only when a runId is provided. The
 * backend gracefully returns an empty page (never 404) for unknown runs,
 * so the ActivityTimeline component can render a benign empty state from
 * the resolved response instead of an error.
 */
import { useQuery } from "@tanstack/react-query";

import { authorizedRequestJson } from "@platform/api/http";

import type { ActivityFilters, ActivityListResponse } from "./api";

export interface UseActivityOptions extends ActivityFilters {
  /**
   * When true, the query is disabled regardless of runId. Callers use this
   * to skip fetching until a tab becomes active or a panel opens.
   */
  disabled?: boolean;
  /**
   * When true, refetch every 5 s -- appropriate for a live/running entity.
   * Defaults to false.
   */
  live?: boolean;
}

export function useActivity(runId: string, options: UseActivityOptions = {}) {
  const enabled = !options.disabled && runId.trim().length > 0;

  return useQuery<ActivityListResponse>({
    queryKey: [
      "platform",
      "activity",
      runId,
      options.action ?? "",
      options.status ?? "",
      options.since ?? "",
      options.until ?? "",
      options.page ?? 1,
      options.pageSize ?? 50,
    ],
    enabled,
    queryFn: () => {
      const params = new URLSearchParams();
      params.set("run_id", runId);
      if (options.action) params.set("action", options.action);
      if (options.status) params.set("status", options.status);
      if (options.since) params.set("since", options.since);
      if (options.until) params.set("until", options.until);
      params.set("page", String(options.page ?? 1));
      params.set("page_size", String(options.pageSize ?? 50));
      return authorizedRequestJson<ActivityListResponse>(
        `/audit/events?${params.toString()}`,
      );
    },
    staleTime: 10_000,
    refetchInterval: options.live ? 5_000 : false,
  });
}
