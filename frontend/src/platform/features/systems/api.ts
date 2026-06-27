import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { authorizedRequestJson } from "@platform/api/http";

// ---------------------------------------------------------------------------
// Base types
// ---------------------------------------------------------------------------

export interface SystemSummary {
  id: number;
  name: string;
  host: string;
  username: string;
  port: number;
  distro: string;
  description: string;
  created_at: string | null;
  updated_at: string | null;
}

export interface TagItem {
  tag_key: string;
  tag_value: string;
}

export type ConnectivityStatus = "reachable" | "unreachable" | "unknown";
export type SeverityLevel = "critical" | "high" | "medium" | "low";

/** Enriched system summary returned by GET /systems list endpoint (D-01/D-20). */
export interface SystemSummaryEnriched extends SystemSummary {
  tags: TagItem[];
  connectivity_status: ConnectivityStatus | null;
  last_scan_at: string | null;
  last_scan_status: string | null;
  top_severity: SeverityLevel | null;
}

export interface SystemDetail extends SystemSummary {
  module_summaries: Record<string, Record<string, unknown>>;
  scan_count: number;
}

export interface SystemMutationInput {
  name: string;
  host: string;
  username: string;
  port: number;
  distro: string;
  description: string;
  private_key?: string | null;
  password?: string | null;
  private_key_passphrase?: string | null;
}

export interface SystemFinding {
  id?: number | null;
  run_id: string;
  cve_id: string | null;
  package: string | null;
  host: string | null;
  severity: string | null;
  kev: boolean;
  score: number | null;
  status: string | null;
}

export interface SystemScanSummary {
  run_id: string;
  query_text: string;
  module_id: string;
  status: string;
  target_count?: number;
  total_findings?: number;
  kev_count?: number;
  severity_breakdown?: Record<string, number>;
  created_at: string | null;
  completed_at: string | null;
}

export interface TagVocabEntry {
  id: number;
  tag_key: string;
  description: string;
  is_system_default: boolean;
}

export interface TagRecord {
  id: number;
  system_id: number;
  tag_key: string;
  tag_value: string;
  created_at: string | null;
}

export interface ConnectivityResult {
  status: ConnectivityStatus;
  last_checked: string | null;
}

export interface CSVImportResponse {
  created: SystemSummary[];
  errors: Array<{ row_index: number; name: string; reason: string }>;
}

interface PaginatedResponse<TItem> {
  total: number;
  page: number;
  page_size: number;
  pages: number;
  items: TItem[];
}

/** DataEnvelope wrapper used by the tags API (D-27). */
interface DataEnvelope<T> {
  data: T;
  error: string | null;
  meta: Record<string, unknown>;
}

// ---------------------------------------------------------------------------
// Utility
// ---------------------------------------------------------------------------

function buildSearchPath(pathname: string, params: Record<string, string | number | undefined>) {
  const searchParams = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value === undefined || value === "") {
      continue;
    }
    searchParams.set(key, String(value));
  }
  const search = searchParams.toString();
  return search ? `${pathname}?${search}` : pathname;
}

/**
 * Format a UTC ISO date string as a relative time string (e.g. "3 hours ago").
 * Returns "Never" for null/empty input. No external date library -- simple arithmetic.
 */
export function formatRelativeTime(dateString: string | null): string {
  if (!dateString) {
    return "Never";
  }
  const diffMs = Date.now() - Date.parse(dateString);
  if (Number.isNaN(diffMs) || diffMs < 0) {
    return "Just now";
  }
  const minutes = Math.floor(diffMs / 60_000);
  if (minutes < 1) return "Just now";
  if (minutes < 60) return `${minutes} minute${minutes === 1 ? "" : "s"} ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours} hour${hours === 1 ? "" : "s"} ago`;
  const days = Math.floor(hours / 24);
  if (days < 7) return `${days} day${days === 1 ? "" : "s"} ago`;
  const weeks = Math.floor(days / 7);
  return `${weeks} week${weeks === 1 ? "" : "s"} ago`;
}

// ---------------------------------------------------------------------------
// Systems queries
// ---------------------------------------------------------------------------

export function useSystems(page = 1, pageSize = 50) {
  return useQuery({
    queryKey: ["platform", "systems", page, pageSize],
    queryFn: () =>
      authorizedRequestJson<PaginatedResponse<SystemSummaryEnriched>>(
        buildSearchPath("/systems", { page, page_size: pageSize }),
      ),
  });
}

export function useSystemDetail(systemId: number | null) {
  return useQuery({
    queryKey: ["platform", "system-detail", systemId],
    enabled: systemId !== null,
    queryFn: () => authorizedRequestJson<SystemDetail>(`/systems/${systemId}`),
  });
}

export function useSystemFindings(systemId: number | null, page = 1, pageSize = 25) {
  return useQuery({
    queryKey: ["platform", "system-findings", systemId, page, pageSize],
    enabled: systemId !== null,
    queryFn: () =>
      authorizedRequestJson<PaginatedResponse<SystemFinding>>(
        buildSearchPath(`/systems/${systemId}/findings`, { page, page_size: pageSize }),
      ),
  });
}

export function useSystemScans(systemId: number | null, page = 1, pageSize = 25) {
  return useQuery({
    queryKey: ["platform", "system-scans", systemId, page, pageSize],
    enabled: systemId !== null,
    queryFn: () =>
      authorizedRequestJson<PaginatedResponse<SystemScanSummary>>(
        buildSearchPath(`/systems/${systemId}/scans`, { page, page_size: pageSize }),
      ),
  });
}

export function useSystemConnectivity(systemId: number | null) {
  return useQuery({
    queryKey: ["platform", "system-connectivity", systemId],
    enabled: systemId !== null,
    queryFn: () =>
      authorizedRequestJson<ConnectivityResult>(`/systems/${systemId}/connectivity`),
  });
}

// ---------------------------------------------------------------------------
// Tag queries
// ---------------------------------------------------------------------------

export function useSystemTags(systemId: number | null) {
  return useQuery({
    queryKey: ["platform", "system-tags", systemId],
    enabled: systemId !== null,
    queryFn: async () => {
      const envelope = await authorizedRequestJson<DataEnvelope<TagRecord[]>>(
        `/tags/systems/${systemId}`,
      );
      return envelope.data;
    },
  });
}

export function useTagVocabulary() {
  return useQuery({
    queryKey: ["platform", "tag-vocabulary"],
    queryFn: async () => {
      const envelope = await authorizedRequestJson<DataEnvelope<TagVocabEntry[]>>(
        "/tags/vocabulary",
      );
      return envelope.data;
    },
  });
}

export function useCreateTagVocab() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (payload: { tag_key: string; description: string }) =>
      authorizedRequestJson<DataEnvelope<TagVocabEntry>>("/tags/vocabulary", {
        method: "POST",
        body: payload,
      }),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["platform", "tag-vocabulary"] });
    },
  });
}

export function useDeleteTagVocab() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (tagKey: string) =>
      authorizedRequestJson<void>(`/tags/vocabulary/${encodeURIComponent(tagKey)}`, {
        method: "DELETE",
      }),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["platform", "tag-vocabulary"] });
      void queryClient.invalidateQueries({ queryKey: ["platform", "systems"] });
    },
  });
}

// ---------------------------------------------------------------------------
// Mutations
// ---------------------------------------------------------------------------

export function useCreateSystem() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (payload: SystemMutationInput) =>
      authorizedRequestJson<SystemSummary>("/systems", {
        method: "POST",
        body: payload,
      }),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["platform", "systems"] });
    },
  });
}

export function useUpdateSystem(systemId: number | null) {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (payload: Partial<SystemMutationInput>) =>
      authorizedRequestJson<SystemSummary>(`/systems/${systemId}`, {
        method: "PUT",
        body: payload,
      }),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["platform", "systems"] });
      void queryClient.invalidateQueries({ queryKey: ["platform", "system-detail", systemId] });
      void queryClient.invalidateQueries({ queryKey: ["platform", "system-scans", systemId] });
      void queryClient.invalidateQueries({ queryKey: ["platform", "system-findings", systemId] });
    },
  });
}

export function useDeleteSystem(systemId: number | null) {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: () =>
      authorizedRequestJson<void>(`/systems/${systemId}`, {
        method: "DELETE",
      }),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["platform", "systems"] });
    },
  });
}

export function useAssignTag(systemId: number) {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (payload: { tag_key: string; tag_value: string }) =>
      authorizedRequestJson<DataEnvelope<TagRecord>>(`/tags/systems/${systemId}`, {
        method: "POST",
        body: payload,
      }),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["platform", "system-tags", systemId] });
      void queryClient.invalidateQueries({ queryKey: ["platform", "systems"] });
    },
  });
}

export function useRemoveTag(systemId: number) {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (tagId: number) =>
      authorizedRequestJson<void>(`/tags/systems/${systemId}/${tagId}`, {
        method: "DELETE",
      }),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["platform", "system-tags", systemId] });
      void queryClient.invalidateQueries({ queryKey: ["platform", "systems"] });
    },
  });
}

export function useImportCSV() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (payload: { systems: SystemMutationInput[] }) =>
      authorizedRequestJson<CSVImportResponse>("/systems/import-csv", {
        method: "POST",
        body: payload,
      }),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["platform", "systems"] });
    },
  });
}
