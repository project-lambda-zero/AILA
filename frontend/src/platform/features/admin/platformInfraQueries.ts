/**
 * Platform Infra data layer.
 *
 * TanStack Query hooks for the platform-infra control surfaces surfaced
 * on `/admin/platform-infra`:
 *
 *   MCP Registry -- src/aila/api/routers/mcp_instances.py
 *     GET    /platform/mcp/instances?include_disabled=true
 *     POST   /platform/mcp/instances
 *     PATCH  /platform/mcp/instances/{id}
 *     DELETE /platform/mcp/instances/{id}
 *     POST   /platform/mcp/instances/{id}/approve
 *     POST   /platform/mcp/instances/{id}/revoke   { reason }
 *     GET    /platform/mcp/instances/{id}/tools
 *
 *   Specialist agents -- src/aila/api/routers/specialist_agents.py
 *     GET    /agents/specialists?module_id=
 *     POST   /agents/specialists                    (create/update)
 *     POST   /agents/specialists/{module_id}/seed
 *     DELETE /agents/specialists/{module_id}/{name}
 *
 *   State reconcile -- src/aila/api/routers/admin_reconcile.py
 *     POST   /admin/reconcile   { task_id }
 *
 * Every response is wrapped in the platform-wide DataEnvelope; the
 * hooks unwrap `.data` so callers work with plain contract types.
 */
import { useMutation, useQuery, useQueryClient, type QueryClient } from "@tanstack/react-query";

import { authorizedRequestJson } from "@platform/api/http";

// ---------------------------------------------------------------------------
// Envelope -- mirrors aila.api.schemas.envelope.DataEnvelope.
// ---------------------------------------------------------------------------

interface DataEnvelope<T> {
  data: T;
  error?: string | null;
  meta?: Record<string, unknown>;
}

// ---------------------------------------------------------------------------
// MCP registry contracts -- mirror aila/api/routers/mcp_instances.py
// ---------------------------------------------------------------------------

export interface McpInstance {
  id: string;
  name: string;
  transport: string;
  endpoint: string;
  capability_tags: string[];
  enabled: boolean;
  module_scope: string | null;
  team_id: string | null;
  approval_state: string;
  approved_hash: string | null;
  schema_hash: string | null;
  has_server_card: boolean;
  created_at: string | null;
  updated_at: string | null;
}

export interface McpInstanceTools {
  tools: Array<Record<string, unknown>>;
  schema_hash: string;
  approved_hash: string | null;
  drift: boolean;
}

export interface McpInstanceCreateRequest {
  name: string;
  transport: string;
  endpoint: string;
  capability_tags?: string[];
  enabled?: boolean;
  module_scope?: string | null;
  team_id?: string | null;
  instance_id?: string | null;
}

export interface McpInstancePatchRequest {
  endpoint?: string;
  enabled?: boolean;
  capability_tags?: string[];
  team_id?: string | null;
}

export const platformInfraQueryKeys = {
  all: ["platform", "platform-infra"] as const,
  mcpInstances: (includeDisabled: boolean) =>
    [...platformInfraQueryKeys.all, "mcp-instances", { includeDisabled }] as const,
  mcpInstanceTools: (instanceId: string) =>
    [...platformInfraQueryKeys.all, "mcp-instance-tools", instanceId] as const,
  specialists: (moduleId: string) =>
    [...platformInfraQueryKeys.all, "specialists", moduleId] as const,
};

export function useMcpInstances(includeDisabled: boolean = true) {
  return useQuery({
    queryKey: platformInfraQueryKeys.mcpInstances(includeDisabled),
    queryFn: () =>
      authorizedRequestJson<DataEnvelope<McpInstance[]>>(
        `/platform/mcp/instances?include_disabled=${includeDisabled ? "true" : "false"}`,
      ),
    select: (env) => env.data,
    refetchInterval: 30_000,
  });
}

export function useMcpInstanceTools(instanceId: string | null) {
  return useQuery({
    queryKey: platformInfraQueryKeys.mcpInstanceTools(instanceId ?? ""),
    queryFn: () =>
      authorizedRequestJson<DataEnvelope<McpInstanceTools>>(
        `/platform/mcp/instances/${encodeURIComponent(instanceId ?? "")}/tools`,
      ),
    select: (env) => env.data,
    enabled: instanceId !== null && instanceId.length > 0,
  });
}

function invalidateMcp(queryClient: QueryClient) {
  void queryClient.invalidateQueries({
    queryKey: [...platformInfraQueryKeys.all, "mcp-instances"],
  });
}

export function useCreateMcpInstance() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (body: McpInstanceCreateRequest) =>
      authorizedRequestJson<DataEnvelope<McpInstance>>(
        "/platform/mcp/instances",
        { method: "POST", body },
      ),
    onSuccess: () => invalidateMcp(queryClient),
  });
}

export function usePatchMcpInstance() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ id, patch }: { id: string; patch: McpInstancePatchRequest }) =>
      authorizedRequestJson<DataEnvelope<McpInstance>>(
        `/platform/mcp/instances/${encodeURIComponent(id)}`,
        { method: "PATCH", body: patch },
      ),
    onSuccess: () => invalidateMcp(queryClient),
  });
}

export function useDeleteMcpInstance() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (id: string) =>
      authorizedRequestJson<void>(
        `/platform/mcp/instances/${encodeURIComponent(id)}`,
        { method: "DELETE" },
      ),
    onSuccess: () => invalidateMcp(queryClient),
  });
}

export function useApproveMcpInstance() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (id: string) =>
      authorizedRequestJson<DataEnvelope<McpInstance>>(
        `/platform/mcp/instances/${encodeURIComponent(id)}/approve`,
        { method: "POST" },
      ),
    onSuccess: (_data, id) => {
      invalidateMcp(queryClient);
      void queryClient.invalidateQueries({
        queryKey: platformInfraQueryKeys.mcpInstanceTools(id),
      });
    },
  });
}

export function useRevokeMcpInstance() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ id, reason }: { id: string; reason: string }) =>
      authorizedRequestJson<DataEnvelope<McpInstance>>(
        `/platform/mcp/instances/${encodeURIComponent(id)}/revoke`,
        { method: "POST", body: { reason } },
      ),
    onSuccess: () => invalidateMcp(queryClient),
  });
}

// ---------------------------------------------------------------------------
// Specialist-agent contracts -- mirror aila/api/routers/specialist_agents.py
// ---------------------------------------------------------------------------

export interface SpecialistAgent {
  id: string;
  module_id: string;
  name: string;
  capability: string;
  strategy_family: string | null;
  description: string;
  enabled: boolean;
  team_id: string | null;
  created_at: string | null;
  updated_at: string | null;
}

export interface SpecialistAgentCreateRequest {
  module_id: string;
  name: string;
  capability: string;
  strategy_family?: string | null;
  description?: string;
  enabled?: boolean;
}

export const SPECIALIST_MODULE_IDS = [
  "vr",
  "malware",
  "forensics",
  "vulnerability",
] as const;

export type SpecialistModuleId = (typeof SPECIALIST_MODULE_IDS)[number];

export function useSpecialists(moduleId: string) {
  return useQuery({
    queryKey: platformInfraQueryKeys.specialists(moduleId),
    queryFn: () =>
      authorizedRequestJson<DataEnvelope<SpecialistAgent[]>>(
        `/agents/specialists?module_id=${encodeURIComponent(moduleId)}`,
      ),
    select: (env) => env.data,
    enabled: moduleId.length > 0,
    refetchInterval: 60_000,
  });
}

function invalidateSpecialists(
  queryClient: QueryClient,
  moduleId: string,
) {
  void queryClient.invalidateQueries({
    queryKey: platformInfraQueryKeys.specialists(moduleId),
  });
}

export function useUpsertSpecialist() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (body: SpecialistAgentCreateRequest) =>
      authorizedRequestJson<DataEnvelope<SpecialistAgent>>(
        "/agents/specialists",
        { method: "POST", body },
      ),
    onSuccess: (_data, variables) =>
      invalidateSpecialists(queryClient, variables.module_id),
  });
}

export function useSeedSpecialists() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (moduleId: string) =>
      authorizedRequestJson<DataEnvelope<{ inserted: number }>>(
        `/agents/specialists/${encodeURIComponent(moduleId)}/seed`,
        { method: "POST" },
      ),
    onSuccess: (_data, moduleId) => invalidateSpecialists(queryClient, moduleId),
  });
}

export function useDeleteSpecialist() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ moduleId, name }: { moduleId: string; name: string }) =>
      authorizedRequestJson<DataEnvelope<{ deleted: boolean }>>(
        `/agents/specialists/${encodeURIComponent(moduleId)}/${encodeURIComponent(name)}`,
        { method: "DELETE" },
      ),
    onSuccess: (_data, variables) =>
      invalidateSpecialists(queryClient, variables.moduleId),
  });
}

// ---------------------------------------------------------------------------
// State reconcile -- mirrors aila/api/routers/admin_reconcile.py
// ---------------------------------------------------------------------------

export interface TaskSignals {
  task_id: string;
  task_status: string | null;
  task_heartbeat_at: string | null;
  task_started_at: string | null;
  cursor_state: string | null;
  lock_present: boolean | null;
}

export interface ReconcileAction {
  kind: string;
  reason: string;
}

export interface ReconcileReport {
  task_id: string;
  signals: TaskSignals;
  healed: boolean;
  actions: ReconcileAction[];
  action_kinds: string[];
}

export function useReconcileTask() {
  return useMutation({
    mutationFn: (taskId: string) =>
      authorizedRequestJson<DataEnvelope<ReconcileReport>>(
        "/admin/reconcile",
        { method: "POST", body: { task_id: taskId } },
      ),
  });
}
