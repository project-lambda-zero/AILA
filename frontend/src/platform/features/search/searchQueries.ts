/**
 * Global search data layer.
 *
 * Wraps GET /search returning DataEnvelope<SearchResult[]> with paginated
 * meta. `entityRoute` maps an entity_type + module_id + entity_id to the
 * canonical client route so both the command palette and the search page
 * navigate to the same detail surface for a given hit.
 *
 * Contract mirrors `aila.api.schemas.endpoints.SearchResult` and the
 * `DataEnvelope[list[SearchResult]]` returned by
 * `aila.api.routers.search.global_search`.
 */
import { keepPreviousData, useQuery } from "@tanstack/react-query";

import { authorizedRequestJson } from "@platform/api/http";

// ---------------------------------------------------------------------------
// Contract types -- mirror src/aila/api/schemas/endpoints.py:SearchResult
// and src/aila/api/schemas/envelope.py:PaginatedMeta.
// ---------------------------------------------------------------------------

export interface SearchResult {
  entity_type: string;
  entity_id: string;
  title: string;
  snippet: string;
  module_id: string | null;
  score: number;
}

export interface PaginatedMeta {
  total: number;
  offset: number;
  limit: number;
}

interface DataEnvelope<T> {
  data: T;
  meta?: PaginatedMeta | Record<string, unknown>;
}

export interface GlobalSearchResponse {
  results: SearchResult[];
  total: number;
  offset: number;
  limit: number;
}

// ---------------------------------------------------------------------------
// Hook
// ---------------------------------------------------------------------------

export interface GlobalSearchParams {
  q: string;
  entityTypes?: readonly string[];
  limit?: number;
  offset?: number;
  /** When false, the query stays disabled regardless of `q`. */
  enabled?: boolean;
}

export const globalSearchQueryKeys = {
  all: ["global-search"] as const,
  search: (q: string, types: string, limit: number, offset: number) =>
    [...globalSearchQueryKeys.all, q, types, limit, offset] as const,
};

export function useGlobalSearch(params: GlobalSearchParams) {
  const { q, entityTypes, limit = 20, offset = 0, enabled = true } = params;
  const typesKey =
    entityTypes && entityTypes.length > 0
      ? entityTypes.slice().sort().join(",")
      : "";
  const trimmed = q.trim();
  return useQuery({
    queryKey: globalSearchQueryKeys.search(trimmed, typesKey, limit, offset),
    queryFn: async (): Promise<GlobalSearchResponse> => {
      const search = new URLSearchParams();
      search.set("q", trimmed);
      search.set("limit", String(limit));
      search.set("offset", String(offset));
      if (typesKey) {
        search.set("entity_types", typesKey);
      }
      const env = await authorizedRequestJson<DataEnvelope<SearchResult[]>>(
        `/search?${search.toString()}`,
      );
      const meta = (env.meta ?? {}) as Partial<PaginatedMeta>;
      return {
        results: env.data ?? [],
        total: typeof meta.total === "number" ? meta.total : (env.data ?? []).length,
        offset: typeof meta.offset === "number" ? meta.offset : offset,
        limit: typeof meta.limit === "number" ? meta.limit : limit,
      };
    },
    enabled: enabled && trimmed.length >= 1,
    staleTime: 10_000,
    placeholderData: keepPreviousData,
  });
}

// ---------------------------------------------------------------------------
// Entity → route mapping
// ---------------------------------------------------------------------------

const MODULE_INDEX_ROUTE: Record<string, string> = {
  vulnerability: "/vulnerability/findings",
  forensics: "/forensics",
  vr: "/vr",
  malware: "/malware",
  hello_world: "/hello-world",
};

/**
 * Map a search result to a client route.
 *
 * `finding` routing branches on `module_id`: the VR module owns a real
 * per-finding page (`/vr/findings/:id`); the vulnerability module has no
 * per-finding route (FindingDetailSheet opens from the list), so we land
 * the operator on the list page with the id preserved as a query hint.
 *
 * For unknown types we fall back to the global search page pre-filled
 * with the hit's title, per the epic contract.
 */
export function entityRoute(result: SearchResult): string {
  const id = encodeURIComponent(result.entity_id);
  const moduleId = result.module_id ?? "";
  switch (result.entity_type) {
    case "system":
      return `/systems/${id}`;
    case "session":
      return `/settings/sessions?session=${id}`;
    case "task":
      return `/tasks/${id}`;
    case "cve":
      return `/vulnerability/findings/cve/${id}`;
    case "finding":
      if (moduleId === "vr") return `/vr/findings/${id}`;
      return `/vulnerability/findings?finding=${id}`;
    case "investigation":
      if (moduleId === "malware") return `/malware/investigations/${id}`;
      if (moduleId === "vr") return `/vr/investigations/${id}`;
      break;
    default:
      break;
  }
  const prefix = moduleId ? MODULE_INDEX_ROUTE[moduleId] : undefined;
  if (prefix) return prefix;
  return `/search?q=${encodeURIComponent(result.title || result.entity_id)}`;
}

// ---------------------------------------------------------------------------
// Entity type presentation
// ---------------------------------------------------------------------------

const ENTITY_TYPE_LABELS: Record<string, string> = {
  system: "System",
  finding: "Finding",
  cve: "CVE",
  session: "Session",
  task: "Task",
  investigation: "Investigation",
  report: "Report",
  target: "Target",
  module: "Module",
};

export function entityTypeLabel(type: string): string {
  return ENTITY_TYPE_LABELS[type] ?? type;
}

/** Map an entity type to the AilaBadge severity palette. Keeps
 *  differing types visually distinguishable in dense result lists. */
export function entityTypeSeverity(
  type: string,
): "critical" | "high" | "medium" | "low" | "info" | "neutral" {
  switch (type) {
    case "finding":
      return "high";
    case "cve":
      return "critical";
    case "system":
      return "info";
    case "session":
      return "low";
    case "task":
      return "medium";
    case "investigation":
      return "info";
    default:
      return "neutral";
  }
}
