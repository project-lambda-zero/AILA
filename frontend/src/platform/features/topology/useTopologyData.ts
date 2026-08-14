/**
 * useTopologyData.ts -- data layer for the full Topology console page.
 *
 * Two independent queries so the subnet sidebar can render before the
 * full graph payload lands, and so a refetch of one doesn't blow the
 * other's cache:
 *
 *   GET /topology          -> nodes[] + edges[] + subnets[] (~30/minute)
 *   GET /topology/subnets  -> subnet_prefix + system_ids[] (~60/minute)
 *
 * Both endpoints require operator+ (enforced server-side; the router
 * wraps TopologyPage with requiredRole="operator"). staleTime mirrors
 * the server-side rate ceilings so mount-then-mount doesn't refetch.
 */
import { useQuery } from "@tanstack/react-query";

import { authorizedRequestJson } from "@platform/api/http";
import type {
  DataEnvelope,
  SubnetGroup,
  TopologyResponse,
} from "@platform/features/radar/types";

export const topologyQueryKeys = {
  full: ["platform", "topology", "full"] as const,
  subnets: ["platform", "topology", "subnets"] as const,
};

export function useTopologyFull() {
  return useQuery({
    queryKey: topologyQueryKeys.full,
    queryFn: async () => {
      const envelope = await authorizedRequestJson<DataEnvelope<TopologyResponse>>(
        "/topology",
      );
      return envelope.data;
    },
    staleTime: 120_000,
    retry: 1,
  });
}

export function useTopologySubnets() {
  return useQuery({
    queryKey: topologyQueryKeys.subnets,
    queryFn: async () => {
      const envelope = await authorizedRequestJson<DataEnvelope<SubnetGroup[]>>(
        "/topology/subnets",
      );
      return envelope.data;
    },
    staleTime: 60_000,
    retry: 1,
  });
}
