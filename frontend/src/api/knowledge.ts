/**
 * React Query hooks + narrowed TS interfaces for the platform-owned
 * knowledge (RAG corpus) API.
 *
 * Endpoints (mounted under /platform, admin-guarded server-side):
 *   GET   /platform/knowledge/stats
 *       -> KnowledgeStats { total_entries, edge_count, by_namespace[],
 *          by_source_type[], by_model[] }
 *   GET   /platform/knowledge/entries?namespace=&source_type=&q=&limit=&offset=
 *       -> KnowledgeEntriesResponse { items: KnowledgeEntry[], total }
 *   POST  /platform/knowledge/search
 *       -> KnowledgeHit[] via KnowledgeService.retrieve_routed; the backend
 *          returns an empty array when nothing clears the score floor (no
 *          synthetic hits).
 *
 * All shapes here mirror the backend contract published in this workstream.
 * `apiFetch` unwraps the `DataEnvelope.data` layer server-side.
 */

import { keepPreviousData, useMutation, useQuery } from "@tanstack/react-query";
import type { UseMutationResult, UseQueryResult } from "@tanstack/react-query";

import { apiFetch } from "./client";

/* ------------------------------- shapes ---------------------------------- */

/** One row of any `by_<facet>` histogram on `KnowledgeStats`. */
export interface KnowledgeBucket {
  key: string;
  count: number;
}

/** GET /platform/knowledge/stats payload. */
export interface KnowledgeStats {
  total_entries: number;
  edge_count: number;
  by_namespace: KnowledgeBucket[];
  by_source_type: KnowledgeBucket[];
  by_model: KnowledgeBucket[];
}

/** One entry from GET /platform/knowledge/entries.items. Mirrors the
 *  admin-exposed subset of KnowledgeEntryRecord; the raw pgvector column
 *  is not serialised. `entry_metadata` is a free-form JSON bag. */
export interface KnowledgeEntry {
  id: string;
  namespace: string;
  content: string;
  source_type: string | null;
  model_id: string | null;
  created_at: string | null;
  entry_metadata: Record<string, unknown> | null;
}

/** GET /platform/knowledge/entries envelope. */
export interface KnowledgeEntriesResponse {
  items: KnowledgeEntry[];
  total: number;
}

/** Query params for `useKnowledgeEntries`. Missing / empty fields are
 *  dropped from the URL so the backend applies its own defaults. */
export interface KnowledgeEntriesQuery {
  namespace?: string;
  source_type?: string;
  q?: string;
  limit?: number;
  offset?: number;
}

/** POST /platform/knowledge/search body. */
export interface KnowledgeSearchRequest {
  query: string;
  namespace_prefix?: string;
  top_k?: number;
}

/** One row of the KnowledgeSearch response array. `score` is the
 *  post-routing similarity (higher is more relevant). */
export interface KnowledgeHit {
  id: string;
  namespace: string;
  content: string;
  score: number;
  source_type: string | null;
  model_id: string | null;
}

/* ------------------------------- helpers --------------------------------- */

function buildQs(params: Record<string, string | number | undefined>): string {
  const parts: string[] = [];
  for (const [k, v] of Object.entries(params)) {
    if (v === undefined || v === null) continue;
    if (typeof v === "string" && v === "") continue;
    parts.push(`${encodeURIComponent(k)}=${encodeURIComponent(String(v))}`);
  }
  return parts.length ? `?${parts.join("&")}` : "";
}

/* -------------------------------- hooks ---------------------------------- */

export function useKnowledgeStats(): UseQueryResult<KnowledgeStats> {
  return useQuery({
    queryKey: ["platform", "knowledge", "stats"],
    queryFn: () => apiFetch<KnowledgeStats>("/platform/knowledge/stats"),
    staleTime: 30_000,
  });
}

/** Paginated browser list. `placeholderData: keepPreviousData` keeps the
 *  prior page rendered while the next page fetches so pagination doesn't
 *  flash an empty state. */
export function useKnowledgeEntries(
  params: KnowledgeEntriesQuery,
): UseQueryResult<KnowledgeEntriesResponse> {
  const limit = params.limit ?? 50;
  const offset = params.offset ?? 0;
  const qs = buildQs({
    namespace: params.namespace,
    source_type: params.source_type,
    q: params.q,
    limit,
    offset,
  });
  return useQuery({
    queryKey: [
      "platform",
      "knowledge",
      "entries",
      params.namespace ?? "",
      params.source_type ?? "",
      params.q ?? "",
      limit,
      offset,
    ],
    queryFn: () =>
      apiFetch<KnowledgeEntriesResponse>(`/platform/knowledge/entries${qs}`),
    placeholderData: keepPreviousData,
    staleTime: 15_000,
  });
}

/** Search is a mutation (POST body carries the query), not a query. The
 *  caller keeps the last result in local state and displays honest
 *  loading / error / empty states directly from the mutation. */
export function useKnowledgeSearch(): UseMutationResult<
  KnowledgeHit[],
  Error,
  KnowledgeSearchRequest
> {
  return useMutation({
    mutationFn: (body: KnowledgeSearchRequest) =>
      apiFetch<KnowledgeHit[]>("/platform/knowledge/search", {
        method: "POST",
        body: JSON.stringify(body),
      }),
  });
}
