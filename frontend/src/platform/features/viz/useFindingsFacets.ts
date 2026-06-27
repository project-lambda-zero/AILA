/**
 * useFindingsFacets -- TanStack Query hook for GET /vulnerability/findings/facets.
 *
 * Returns the severity facet group for use in VIZ-01 (SeverityDonutChart).
 * Returns an empty object if the vulnerability module is unavailable.
 */
import { useQuery } from "@tanstack/react-query";

import { authorizedRequestJson } from "@platform/api/http";
import type { SeverityFacets } from "./types";

interface FacetsEnvelope {
  data: {
    facets: {
      severity?: SeverityFacets;
      [key: string]: unknown;
    };
  };
  error: string | null;
  meta: Record<string, unknown>;
}

export function useFindingsFacets() {
  return useQuery({
    queryKey: ["platform", "findings-facets"],
    queryFn: async (): Promise<{ severity: SeverityFacets }> => {
      try {
        const resp = await authorizedRequestJson<FacetsEnvelope>("/vulnerability/findings/facets");
        return { severity: resp?.data?.facets?.severity ?? {} };
      } catch {
        // Vulnerability module may not be available -- return empty
        return { severity: {} };
      }
    },
    staleTime: 60_000,
    retry: 1,
  });
}
