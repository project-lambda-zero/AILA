/**
 * ML-Ops data layer.
 *
 * TanStack Query hooks for the three god-tier admin endpoint families
 * surfaced on `/admin/ml-ops`:
 *
 *   Agent lifecycle (`aila/api/routers/admin_lifecycle.py`)
 *     GET  /admin/lifecycle/metrics/versions       per-version metrics roll-up
 *     GET  /admin/lifecycle/transitions            append-only journal (newest first)
 *     GET  /admin/lifecycle/route                  cohort route preview
 *     POST /admin/lifecycle/evaluate               score a candidate + journal transition
 *     POST /admin/lifecycle/approve                add a distinct approver on a passing eval
 *     POST /admin/lifecycle/promote                flip production alias (eval + quorum gate)
 *     POST /admin/lifecycle/rollback               flip production alias back
 *     POST /admin/lifecycle/shadow                 register a shadow assignment
 *     POST /admin/lifecycle/canary                 register a canary at cohort_percent
 *     POST /admin/lifecycle/shadow/run             off-path shadow comparison
 *     GET  /admin/lifecycle/shadow/report          latest shadow report for (key, version)
 *
 *   Eval harness (`aila/api/routers/admin_eval.py`)
 *     GET  /admin/eval/runs                        eval runs for a key
 *     POST /admin/eval/runs                        score a candidate against a benchmark
 *     POST /admin/eval/benchmarks                  register a benchmark
 *     GET  /admin/eval/calibrators                 list calibrator versions
 *     POST /admin/eval/calibrators/train           fit calibrators for task_type
 *     POST /admin/eval/calibrators/{id}/promote    promote a calibrator behind quorum gate
 *
 *   Prompt version store (`aila/api/routers/admin_prompts.py`)
 *     GET  /admin/prompts/versions                 list registered versions for a key
 *     POST /admin/prompts/versions                 register an immutable version
 *     GET  /admin/prompts/aliases                  list alias pointers for a key
 *     PUT  /admin/prompts/aliases                  point an alias at a version
 *
 * Every response is wrapped in the platform-wide DataEnvelope; the
 * hooks unwrap `.data` so callers work with plain contract types.
 */
import {
  useMutation,
  useQuery,
  useQueryClient,
  type QueryClient,
} from "@tanstack/react-query";

import { authorizedRequestJson } from "@platform/api/http";

// ---------------------------------------------------------------------------
// Envelope -- mirrors aila.api.schemas.envelope.DataEnvelope.
// ---------------------------------------------------------------------------

interface DataEnvelope<T> {
  data: T;
  error: string | null;
  meta: Record<string, unknown>;
}

// ---------------------------------------------------------------------------
// Lifecycle contracts -- mirror admin_lifecycle.py response models
// ---------------------------------------------------------------------------

export interface TransitionInfo {
  id: string;
  key: string;
  version: string;
  from_stage: string;
  to_stage: string;
  actor: string;
  reason: string;
  metrics_snapshot: Record<string, unknown> | null;
  created_at: string;
}

export interface VersionMetricsRow {
  key: string;
  version: string;
  latest_stage: string | null;
  eval_verdict: string | null;
  eval_run_id: string | null;
  eval_created_at: string | null;
  approver_count: number;
  evaluated_count: number;
  quorum_accept_rate: number;
  cost_usd_total: number;
  cost_call_count: number;
  drift_status: string | null;
  drift_last_recorded: string | null;
}

export interface VersionMetricsResponse {
  key: string;
  rows: VersionMetricsRow[];
}

export interface CohortRouteResponse {
  key: string;
  version: string | null;
  bucket: number;
  on_canary: boolean;
  canary_version: string | null;
  production_version: string | null;
  cohort_percent: number | null;
}

export interface ShadowReportInfo {
  id: string;
  key: string;
  version: string;
  assignment_id: string | null;
  sample_attempted: number;
  sample_succeeded: number;
  mean_faithfulness: number;
  mean_determinism: number;
  regressions: number;
  diff_summary: Record<string, unknown>;
  actor: string;
  created_at: string;
}

// ---------------------------------------------------------------------------
// Eval contracts -- mirror admin_eval.py response models
// ---------------------------------------------------------------------------

export interface EvalRunInfo {
  id: string;
  key: string;
  candidate_version: string;
  baseline_version: string | null;
  benchmark_id: string;
  verdict: string;
  actor: string;
  created_at: string;
  report: Record<string, unknown>;
}

export interface BenchmarkCaseSpec {
  outcome_kind: string;
  predicted_verdict: string;
  verified_verdict: string;
  confidence: number;
  version?: string | null;
}

export interface BenchmarkInfo {
  id: string;
  key: string;
  name: string;
  case_count: number;
  created_by: string;
  created_at: string;
}

export interface CalibratorVersionInfo {
  id: string;
  task_type: string;
  method: string;
  params: Record<string, unknown>;
  ece_before: number;
  ece_after: number;
  sample_count: number;
  status: string;
  superseded_by: string | null;
  actor: string;
  created_at: string;
}

// ---------------------------------------------------------------------------
// Prompt contracts -- mirror admin_prompts.py response models
// ---------------------------------------------------------------------------

export interface PromptVersionInfo {
  key: string;
  version: string;
  content_hash: string;
  author: string;
  notes: string;
  created_at: string;
}

export interface PromptAliasInfo {
  key: string;
  alias: string;
  version: string;
  updated_at: string;
}

// The prompt version store's list_versions endpoint returns metadata but NOT
// the body -- the body is only reachable via the resolve path or by registering
// a new (content-hash-deduplicated) version with the same body. For the
// two-version diff view we need the raw text, so we let the operator paste
// it in from the prior register call, OR we register the same version again
// (idempotent) to fetch. The simplest contract-safe path is to make the diff
// view work off `notes` and `content_hash` for the metadata line, and hydrate
// the body lazily from a supplied side-map -- the tab keeps a body cache
// keyed by version. See PromptsTab in MlOpsPage.tsx.

// ---------------------------------------------------------------------------
// Query keys
// ---------------------------------------------------------------------------

export const mlOpsQueryKeys = {
  all: ["platform", "ml-ops"] as const,
  lifecycleMetrics: (key: string) =>
    [...mlOpsQueryKeys.all, "lifecycle", "metrics", key] as const,
  lifecycleTransitions: (key: string) =>
    [...mlOpsQueryKeys.all, "lifecycle", "transitions", key] as const,
  lifecycleRoute: (key: string, investigationId: string) =>
    [...mlOpsQueryKeys.all, "lifecycle", "route", key, investigationId] as const,
  shadowReport: (key: string, version: string) =>
    [...mlOpsQueryKeys.all, "lifecycle", "shadow-report", key, version] as const,
  evalRuns: (key: string) =>
    [...mlOpsQueryKeys.all, "eval", "runs", key] as const,
  calibrators: (taskType: string | null) =>
    [...mlOpsQueryKeys.all, "eval", "calibrators", taskType ?? ""] as const,
  promptVersions: (key: string) =>
    [...mlOpsQueryKeys.all, "prompts", "versions", key] as const,
  promptAliases: (key: string) =>
    [...mlOpsQueryKeys.all, "prompts", "aliases", key] as const,
};

// ---------------------------------------------------------------------------
// Lifecycle queries
// ---------------------------------------------------------------------------

export function useLifecycleVersionMetrics(key: string) {
  return useQuery({
    queryKey: mlOpsQueryKeys.lifecycleMetrics(key),
    queryFn: () =>
      authorizedRequestJson<DataEnvelope<VersionMetricsResponse>>(
        `/admin/lifecycle/metrics/versions?key=${encodeURIComponent(key)}`,
      ),
    select: (env) => env.data,
    enabled: key.length > 0,
  });
}

export function useLifecycleTransitions(key: string, limit = 50) {
  return useQuery({
    queryKey: mlOpsQueryKeys.lifecycleTransitions(key),
    queryFn: () =>
      authorizedRequestJson<DataEnvelope<TransitionInfo[]>>(
        `/admin/lifecycle/transitions?key=${encodeURIComponent(key)}&limit=${limit}`,
      ),
    select: (env) => env.data,
    enabled: key.length > 0,
  });
}

export function useLifecycleRoutePreview(
  key: string,
  investigationId: string,
  enabled: boolean,
) {
  return useQuery({
    queryKey: mlOpsQueryKeys.lifecycleRoute(key, investigationId),
    queryFn: () =>
      authorizedRequestJson<DataEnvelope<CohortRouteResponse>>(
        `/admin/lifecycle/route?key=${encodeURIComponent(key)}&investigation_id=${encodeURIComponent(investigationId)}`,
      ),
    select: (env) => env.data,
    enabled: enabled && key.length > 0 && investigationId.length > 0,
  });
}

export function useShadowReport(key: string, version: string, enabled: boolean) {
  return useQuery({
    queryKey: mlOpsQueryKeys.shadowReport(key, version),
    queryFn: () =>
      authorizedRequestJson<DataEnvelope<ShadowReportInfo | null>>(
        `/admin/lifecycle/shadow/report?key=${encodeURIComponent(key)}&version=${encodeURIComponent(version)}`,
      ),
    select: (env) => env.data,
    enabled: enabled && key.length > 0 && version.length > 0,
  });
}

// ---------------------------------------------------------------------------
// Lifecycle mutations
// ---------------------------------------------------------------------------

interface KeyVersionReason {
  key: string;
  version: string;
  reason?: string;
}

function invalidateLifecycleForKey(
  queryClient: QueryClient,
  key: string,
): void {
  void queryClient.invalidateQueries({
    queryKey: mlOpsQueryKeys.lifecycleMetrics(key),
  });
  void queryClient.invalidateQueries({
    queryKey: mlOpsQueryKeys.lifecycleTransitions(key),
  });
}

export function useLifecycleEvaluate() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (body: { key: string; version: string; benchmark_id: string }) =>
      authorizedRequestJson<DataEnvelope<TransitionInfo>>(
        "/admin/lifecycle/evaluate",
        { method: "POST", body },
      ),
    onSuccess: (_data, vars) => {
      invalidateLifecycleForKey(queryClient, vars.key);
      void queryClient.invalidateQueries({
        queryKey: mlOpsQueryKeys.evalRuns(vars.key),
      });
    },
  });
}

export function useLifecycleApprove() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (body: KeyVersionReason) =>
      authorizedRequestJson<DataEnvelope<TransitionInfo>>(
        "/admin/lifecycle/approve",
        { method: "POST", body },
      ),
    onSuccess: (_data, vars) => invalidateLifecycleForKey(queryClient, vars.key),
  });
}

export function useLifecyclePromote() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (body: KeyVersionReason) =>
      authorizedRequestJson<DataEnvelope<TransitionInfo>>(
        "/admin/lifecycle/promote",
        { method: "POST", body },
      ),
    onSuccess: (_data, vars) => {
      invalidateLifecycleForKey(queryClient, vars.key);
      void queryClient.invalidateQueries({
        queryKey: mlOpsQueryKeys.promptAliases(vars.key),
      });
    },
  });
}

export function useLifecycleRollback() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (body: KeyVersionReason & { target_version?: string | null }) =>
      authorizedRequestJson<DataEnvelope<TransitionInfo>>(
        "/admin/lifecycle/rollback",
        { method: "POST", body },
      ),
    onSuccess: (_data, vars) => {
      invalidateLifecycleForKey(queryClient, vars.key);
      void queryClient.invalidateQueries({
        queryKey: mlOpsQueryKeys.promptAliases(vars.key),
      });
    },
  });
}

export function useLifecycleShadow() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (body: KeyVersionReason) =>
      authorizedRequestJson<DataEnvelope<TransitionInfo>>(
        "/admin/lifecycle/shadow",
        { method: "POST", body },
      ),
    onSuccess: (_data, vars) => invalidateLifecycleForKey(queryClient, vars.key),
  });
}

export function useLifecycleCanary() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (body: KeyVersionReason & { cohort_percent: number }) =>
      authorizedRequestJson<DataEnvelope<TransitionInfo>>(
        "/admin/lifecycle/canary",
        { method: "POST", body },
      ),
    onSuccess: (_data, vars) => invalidateLifecycleForKey(queryClient, vars.key),
  });
}

export function useShadowRun() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (body: { key: string; version: string; sample_n: number }) =>
      authorizedRequestJson<DataEnvelope<ShadowReportInfo>>(
        "/admin/lifecycle/shadow/run",
        { method: "POST", body },
      ),
    onSuccess: (_data, vars) => {
      void queryClient.invalidateQueries({
        queryKey: mlOpsQueryKeys.shadowReport(vars.key, vars.version),
      });
      invalidateLifecycleForKey(queryClient, vars.key);
    },
  });
}

// ---------------------------------------------------------------------------
// Eval queries + mutations
// ---------------------------------------------------------------------------

export function useEvalRuns(key: string) {
  return useQuery({
    queryKey: mlOpsQueryKeys.evalRuns(key),
    queryFn: () =>
      authorizedRequestJson<DataEnvelope<EvalRunInfo[]>>(
        `/admin/eval/runs?key=${encodeURIComponent(key)}`,
      ),
    select: (env) => env.data,
    enabled: key.length > 0,
  });
}

export function useRunEval() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (body: {
      key: string;
      candidate_version: string;
      benchmark_id: string;
    }) =>
      authorizedRequestJson<DataEnvelope<EvalRunInfo>>("/admin/eval/runs", {
        method: "POST",
        body,
      }),
    onSuccess: (_data, vars) => {
      void queryClient.invalidateQueries({
        queryKey: mlOpsQueryKeys.evalRuns(vars.key),
      });
    },
  });
}

export function useRegisterBenchmark() {
  return useMutation({
    mutationFn: (body: {
      key: string;
      name: string;
      cases: BenchmarkCaseSpec[];
    }) =>
      authorizedRequestJson<DataEnvelope<BenchmarkInfo>>(
        "/admin/eval/benchmarks",
        { method: "POST", body },
      ),
  });
}

export function useCalibrators(taskType: string | null) {
  const suffix = taskType ? `?task_type=${encodeURIComponent(taskType)}` : "";
  return useQuery({
    queryKey: mlOpsQueryKeys.calibrators(taskType),
    queryFn: () =>
      authorizedRequestJson<DataEnvelope<CalibratorVersionInfo[]>>(
        `/admin/eval/calibrators${suffix}`,
      ),
    select: (env) => env.data,
  });
}

export function useTrainCalibrator() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (body: { task_type: string }) =>
      authorizedRequestJson<DataEnvelope<CalibratorVersionInfo>>(
        "/admin/eval/calibrators/train",
        { method: "POST", body },
      ),
    onSuccess: (_data, vars) => {
      void queryClient.invalidateQueries({
        queryKey: mlOpsQueryKeys.calibrators(vars.task_type),
      });
      void queryClient.invalidateQueries({
        queryKey: mlOpsQueryKeys.calibrators(null),
      });
    },
  });
}

export function usePromoteCalibrator() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (vars: { id: string; approver_ids: string[] }) =>
      authorizedRequestJson<DataEnvelope<CalibratorVersionInfo>>(
        `/admin/eval/calibrators/${encodeURIComponent(vars.id)}/promote`,
        { method: "POST", body: { approver_ids: vars.approver_ids } },
      ),
    onSuccess: () => {
      // Task type is not known from the id alone -- invalidate the whole
      // calibrators family so any open task_type filter refetches.
      void queryClient.invalidateQueries({
        queryKey: [...mlOpsQueryKeys.all, "eval", "calibrators"],
      });
    },
  });
}

// ---------------------------------------------------------------------------
// Prompt queries + mutations
// ---------------------------------------------------------------------------

export function usePromptVersions(key: string) {
  return useQuery({
    queryKey: mlOpsQueryKeys.promptVersions(key),
    queryFn: () =>
      authorizedRequestJson<DataEnvelope<PromptVersionInfo[]>>(
        `/admin/prompts/versions?key=${encodeURIComponent(key)}`,
      ),
    select: (env) => env.data,
    enabled: key.length > 0,
  });
}

export function usePromptAliases(key: string) {
  return useQuery({
    queryKey: mlOpsQueryKeys.promptAliases(key),
    queryFn: () =>
      authorizedRequestJson<DataEnvelope<PromptAliasInfo[]>>(
        `/admin/prompts/aliases?key=${encodeURIComponent(key)}`,
      ),
    select: (env) => env.data,
    enabled: key.length > 0,
  });
}

export function useRegisterPromptVersion() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (body: {
      key: string;
      body: string;
      author?: string;
      notes?: string;
    }) =>
      authorizedRequestJson<DataEnvelope<PromptVersionInfo>>(
        "/admin/prompts/versions",
        { method: "POST", body },
      ),
    onSuccess: (_data, vars) => {
      void queryClient.invalidateQueries({
        queryKey: mlOpsQueryKeys.promptVersions(vars.key),
      });
    },
  });
}

export function useSetPromptAlias() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (body: {
      key: string;
      alias: string;
      version: string;
      reason?: string;
    }) =>
      authorizedRequestJson<DataEnvelope<PromptAliasInfo>>(
        "/admin/prompts/aliases",
        { method: "PUT", body },
      ),
    onSuccess: (_data, vars) => {
      void queryClient.invalidateQueries({
        queryKey: mlOpsQueryKeys.promptAliases(vars.key),
      });
    },
  });
}
