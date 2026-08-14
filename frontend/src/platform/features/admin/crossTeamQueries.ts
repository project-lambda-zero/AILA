/**
 * crossTeamQueries -- TanStack Query hook for /admin/teams/cross-view.
 *
 * Extracted from TeamsPage so the per-team comparison section and any
 * future admin surface (dashboards, exports) share a single query key
 * and cache entry. Admin-gated route -- if a non-admin ever mounts the
 * calling component the request 403s and `useCrossTeamStats` returns
 * `isError=true`; render sites hide the section rather than fake data.
 */
import { useQuery, type UseQueryResult } from "@tanstack/react-query";

import { authorizedRequestJson } from "@platform/api/http";

// ---------------------------------------------------------------------------
// Contract mirror -- matches aila.api.schemas.admin_teams.CrossTeamStatsRow
// ---------------------------------------------------------------------------

export interface CrossTeamStatsRow {
  team_id: string;
  team_name: string;
  systems_count: number;
  runs_count: number;
  members_count: number;
}

interface DataEnvelope<T> {
  data: T;
  error: string | null;
  meta: Record<string, unknown>;
}

export const CROSS_TEAM_QUERY_KEY = [
  "platform",
  "admin-teams",
  "cross-view",
] as const;

/**
 * Fetch cross-team aggregates. Refetched at the same cadence as other
 * admin dashboards; retry disabled because a 403 is a permission signal,
 * not a transient error.
 */
export function useCrossTeamStats(): UseQueryResult<
  DataEnvelope<CrossTeamStatsRow[]>,
  Error
> {
  return useQuery({
    queryKey: CROSS_TEAM_QUERY_KEY,
    queryFn: () =>
      authorizedRequestJson<DataEnvelope<CrossTeamStatsRow[]>>(
        "/admin/teams/cross-view",
      ),
    staleTime: 30_000,
    retry: false,
  });
}
