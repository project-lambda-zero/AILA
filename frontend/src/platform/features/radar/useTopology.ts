/**
 * useTopology -- TanStack Query hook for GET /topology.
 *
 * staleTime=120_000ms respects the 30/minute server-side rate limit.
 * Operator+ role is enforced server-side; the hook does not re-enforce it
 * (the router wraps RadarPage with requiredRole="operator").
 *
 * Per D-04 (Phase 144 context): client-side filter/colorby changes do not
 * trigger additional API calls -- the full topology is fetched once and
 * transformations are applied in memory.
 */
import { useQuery } from "@tanstack/react-query";

import { authorizedRequestJson } from "@platform/api/http";
import type { DataEnvelope, TopologyResponse } from "./types";

export function useTopology() {
  return useQuery({
    queryKey: ["platform", "topology"],
    queryFn: async () => {
      const envelope = await authorizedRequestJson<DataEnvelope<TopologyResponse>>("/topology");
      return envelope.data;
    },
    staleTime: 120_000,
    retry: 1,
  });
}
