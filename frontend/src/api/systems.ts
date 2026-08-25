/**
 * React Query hooks + narrowed TS interfaces for the platform-owned systems
 * + topology surface. Not module-prefixed on purpose: /systems and /topology
 * are mounted at the API root.
 *
 * Backend routers:
 *   src/aila/api/routers/systems.py
 *   src/aila/api/routers/topology.py
 *
 * Endpoints:
 *   GET    /systems?page=&page_size=       -> PaginatedResponse[SystemEnrichedResponse]
 *   GET    /systems/{id}                   -> SystemDetailResponse
 *   GET    /systems/{id}/connectivity      -> ConnectivityStatusResponse
 *   GET    /systems/{id}/heartbeat         -> HeartbeatEnvelope (data-wrapped)
 *   GET    /systems/{id}/findings          -> FindingsListResponse
 *   GET    /systems/{id}/scans             -> ScanHistoryResponse
 *   POST   /systems                        -> SystemResponse (SystemCreateRequest body)
 *   PUT    /systems/{id}                   -> SystemResponse (SystemUpdateRequest body)
 *   DELETE /systems/{id}                   -> 204
 *   POST   /systems/import-csv             -> SystemCSVImportResponse
 *   GET    /topology                       -> DataEnvelope[TopologyResponse]
 *   GET    /topology/subnets               -> DataEnvelope[list[SubnetGroup]]
 *
 * Asset-tag hooks below hit the platform /tags router (src/aila/api/routers/tags.py),
 * co-located here because the vocabulary governs Systems tagging:
 *   GET/POST /tags/vocabulary              -> admin-managed tag key vocabulary
 *   DELETE   /tags/vocabulary/{tag_key}    -> remove a vocabulary key (admin)
 *   GET/POST /tags/systems/{id}            -> tags assigned to a system (operator+)
 *   DELETE   /tags/systems/{id}/{tag_id}   -> remove a tag from a system (operator+)
 *
 * apiFetch unwraps the single DataEnvelope layer (`data` key) for every hook.
 * Every request/response mirror the exact Pydantic schemas at
 * src/aila/api/schemas/systems.py and src/aila/api/schemas/topology.py.
 */

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { apiFetch } from "./client";
import type { VulnFindingsPage } from "./vulnerability";

/* -------------------------------- shapes --------------------------------- */

/** Mirrors SystemResponse (base row shape). */
export interface SystemBase {
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

/** Mirrors SystemEnrichedResponse (list rows). */
export interface SystemEnriched extends SystemBase {
  connectivity_status: string | null;
  tags: Array<{ tag_key: string; tag_value: string }>;
  last_scan_at: string | null;
  last_scan_status: string | null;
  top_severity: string | null;
}

/** Mirrors SystemDetailResponse. */
export interface SystemDetail extends SystemBase {
  module_summaries: Record<string, Record<string, unknown>>;
  scan_count: number;
}

/** Mirrors PaginatedResponse[SystemEnrichedResponse]. */
export interface SystemsPage {
  total: number;
  page: number;
  page_size: number;
  pages: number;
  items: SystemEnriched[];
}

/** Mirrors TagVocabResponse -- an admin-managed assignable tag key. `id` is a
 *  string on this endpoint (unlike the int `SystemTag.id`). */
export interface TagVocabEntry {
  id: string;
  tag_key: string;
  description: string;
  is_system_default: boolean;
  created_at: string | null;
}

/** Mirrors TagResponse -- one tag assigned to a system. */
export interface SystemTag {
  id: number;
  system_id: number;
  tag_key: string;
  tag_value: string;
  created_at: string | null;
}

/** POST /systems body -- SystemCreateRequest. name/host required; the four
 *  secret fields (private_key, password, private_key_passphrase) are all
 *  optional and encrypted server-side via SecretRecord. */
export interface SystemCreateRequest {
  name: string;
  host: string;
  username?: string;
  port?: number;
  distro?: string;
  description?: string;
  private_key?: string | null;
  password?: string | null;
  private_key_passphrase?: string | null;
}

/** PUT /systems/{id} body -- SystemUpdateRequest (every field optional).
 *  Sending null on a secret field clears it server-side. */
export interface SystemUpdateRequest {
  name?: string;
  host?: string;
  username?: string;
  port?: number;
  distro?: string;
  description?: string;
  private_key?: string | null;
  password?: string | null;
  private_key_passphrase?: string | null;
}

/** GET /systems/{id}/connectivity. Mirrors ConnectivityStatusResponse. */
export interface ConnectivityStatus {
  status: string;              // 'reachable' | 'unreachable' | 'unknown'
  last_checked: string | null;
}

/** GET /systems/{id}/heartbeat: the endpoint returns HeartbeatEnvelope
 *  ({data: HeartbeatResponse}); apiFetch unwraps the outer `data` for us. */
export interface HeartbeatResponse {
  system_id: number;
  reachable: boolean;
  latency_ms: number | null;
  checked_at: string | null;
  error: string | null;
}

/** GET /systems/{id}/scans row. ScanHistoryResponse.items[] is
 *  intentionally free-form on the backend; the console only requires the
 *  handful of columns below. Unknown extra keys stay as unknown. */
export interface SystemScanRow {
  run_id?: string;
  status?: string;
  created_at?: string;
  completed_at?: string | null;
  query_text?: string;
  finding_count?: number;
  [key: string]: unknown;
}

export interface SystemScansPage {
  total: number;
  page: number;
  page_size: number;
  pages: number;
  items: SystemScanRow[];
}

/* --------------------------- topology shapes ----------------------------- */

/** Mirrors PortInfo. */
export interface TopologyPort {
  port: number;
  protocol: string;
  local_address: string;
  process_name: string | null;
}

/** Mirrors ServiceInfo. */
export interface TopologyService {
  service_name: string;
  state: string;
  sub_state: string;
}

/** Mirrors SeverityCounts. */
export interface TopologySeverityCounts {
  critical: number;
  high: number;
  medium: number;
  low: number;
}

/** Mirrors SystemMetadata (neofetch-like host info). */
export interface TopologySystemMetadata {
  gateway_ip: string | null;
  gateway_interface: string | null;
  external_ip: string | null;
  os_name: string | null;
  os_pretty_name: string | null;
  kernel: string | null;
  cpu_cores: number | null;
  memory_mb: number | null;
  disk_gb: number | null;
  uptime_seconds: number | null;
  last_collected: string | null;
  is_stale: boolean;
}

/** Mirrors TopologyNode. */
export interface TopologyNode {
  id: number;
  name: string;
  host: string;
  distro: string;
  subnet: string | null;
  group_tags: string[];
  ports: TopologyPort[];
  services: TopologyService[];
  severity_counts: TopologySeverityCounts | null;
  last_collected: string | null;
  is_stale: boolean;
  metadata: TopologySystemMetadata | null;
}

/** Mirrors TopologyEdge. */
export interface TopologyEdge {
  source_system_id: number;
  dest_system_id: number;
  dest_port: number;
  protocol: string;
  state: string;
  is_stale: boolean;
}

/** Mirrors SubnetGroup. */
export interface TopologySubnet {
  subnet_prefix: string;
  system_ids: number[];
}

/** Mirrors TopologyResponse (the DataEnvelope.data payload). */
export interface TopologyResponse {
  nodes: TopologyNode[];
  edges: TopologyEdge[];
  subnets: TopologySubnet[];
}

/* -------------------------------- hooks ---------------------------------- */

export function useSystems(page: number = 1, pageSize: number = 100) {
  const qs = `page=${page}&page_size=${pageSize}`;
  return useQuery({
    queryKey: ["systems", "list", qs],
    queryFn: () => apiFetch<SystemsPage>(`/systems?${qs}`),
    staleTime: 15_000,
  });
}

export function useSystem(id: number | null) {
  return useQuery({
    queryKey: ["systems", "detail", id],
    queryFn: () => apiFetch<SystemDetail>(`/systems/${id}`),
    enabled: id !== null,
    staleTime: 15_000,
  });
}

export function useSystemConnectivity(id: number | null) {
  return useQuery({
    queryKey: ["systems", "connectivity", id],
    queryFn: () => apiFetch<ConnectivityStatus>(`/systems/${id}/connectivity`),
    enabled: id !== null,
    staleTime: 15_000,
  });
}

/** Live SSH heartbeat -- 60/min rate limit + 30s server-side cache. The hook
 *  refetches every 30s so the operator sees stale-vs-fresh naturally; consumers
 *  can also invalidate the key to force an immediate re-probe. */
export function useSystemHeartbeat(id: number | null) {
  return useQuery({
    queryKey: ["systems", "heartbeat", id],
    queryFn: () => apiFetch<HeartbeatResponse>(`/systems/${id}/heartbeat`),
    enabled: id !== null,
    retry: false,
    refetchInterval: 30_000,
    staleTime: 25_000,
  });
}

export function useSystemFindings(id: number | null, page: number = 1, pageSize: number = 50) {
  const qs = `page=${page}&page_size=${pageSize}`;
  return useQuery({
    queryKey: ["systems", "findings", id, qs],
    queryFn: () => apiFetch<VulnFindingsPage>(`/systems/${id}/findings?${qs}`),
    enabled: id !== null,
    staleTime: 15_000,
  });
}

export function useSystemScans(id: number | null, page: number = 1, pageSize: number = 50) {
  const qs = `page=${page}&page_size=${pageSize}`;
  return useQuery({
    queryKey: ["systems", "scans", id, qs],
    queryFn: () => apiFetch<SystemScansPage>(`/systems/${id}/scans?${qs}`),
    enabled: id !== null,
    staleTime: 15_000,
  });
}

export function useCreateSystem() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: SystemCreateRequest) =>
      apiFetch<SystemBase>("/systems", {
        method: "POST",
        body: JSON.stringify(body),
      }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["systems", "list"] });
      void qc.invalidateQueries({ queryKey: ["topology"] });
    },
  });
}

export function useUpdateSystem(id: number | null) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: SystemUpdateRequest) =>
      apiFetch<SystemBase>(`/systems/${id}`, {
        method: "PUT",
        body: JSON.stringify(body),
      }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["systems", "list"] });
      void qc.invalidateQueries({ queryKey: ["systems", "detail", id] });
      void qc.invalidateQueries({ queryKey: ["topology"] });
    },
  });
}

export function useDeleteSystem() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: number) =>
      apiFetch<unknown>(`/systems/${id}`, { method: "DELETE" }),
    onSuccess: (_data, id) => {
      void qc.invalidateQueries({ queryKey: ["systems", "list"] });
      void qc.invalidateQueries({ queryKey: ["systems", "detail", id] });
      void qc.invalidateQueries({ queryKey: ["topology"] });
    },
  });
}

/* ------------------------------ asset tags ------------------------------- */

/** Admin-managed tag vocabulary (GET /tags/vocabulary is admin-only). Pass
 *  `enabled=false` for non-admin callers so the query never fires a 403. */
export function useTagVocabulary(enabled: boolean = true) {
  return useQuery({
    queryKey: ["tags", "vocabulary"],
    queryFn: () => apiFetch<TagVocabEntry[]>("/tags/vocabulary?limit=250"),
    enabled,
    staleTime: 30_000,
  });
}

export function useCreateVocabEntry() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: { tag_key: string; description: string }) =>
      apiFetch<TagVocabEntry>("/tags/vocabulary", {
        method: "POST",
        body: JSON.stringify(body),
      }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["tags", "vocabulary"] });
    },
  });
}

export function useDeleteVocabEntry() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (tagKey: string) =>
      apiFetch<unknown>(`/tags/vocabulary/${encodeURIComponent(tagKey)}`, { method: "DELETE" }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["tags", "vocabulary"] });
    },
  });
}

/** Tags currently assigned to a system (GET /tags/systems/{id}); operator+. */
export function useSystemTags(id: number | null, enabled: boolean = true) {
  return useQuery({
    queryKey: ["tags", "system", id],
    queryFn: () => apiFetch<SystemTag[]>(`/tags/systems/${id}`),
    enabled: id !== null && enabled,
    staleTime: 15_000,
  });
}

export function useAssignSystemTag(id: number | null) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: { tag_key: string; tag_value: string }) =>
      apiFetch<SystemTag>(`/tags/systems/${id}`, {
        method: "POST",
        body: JSON.stringify(body),
      }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["tags", "system", id] });
      void qc.invalidateQueries({ queryKey: ["systems", "detail", id] });
      void qc.invalidateQueries({ queryKey: ["systems", "list"] });
    },
  });
}

export function useDeleteSystemTag(id: number | null) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (tagId: number) =>
      apiFetch<unknown>(`/tags/systems/${id}/${tagId}`, { method: "DELETE" }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["tags", "system", id] });
      void qc.invalidateQueries({ queryKey: ["systems", "detail", id] });
      void qc.invalidateQueries({ queryKey: ["systems", "list"] });
    },
  });
}

export function useTopology() {
  return useQuery({
    queryKey: ["topology", "graph"],
    queryFn: () => apiFetch<TopologyResponse>("/topology"),
    staleTime: 30_000,
  });
}

export function useTopologySubnets() {
  return useQuery({
    queryKey: ["topology", "subnets"],
    queryFn: () => apiFetch<TopologySubnet[]>("/topology/subnets"),
    staleTime: 30_000,
  });
}
