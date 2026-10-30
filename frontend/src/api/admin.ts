/**
 * Admin console hooks for the god-tier operator surfaces (#212): ML-Ops
 * lifecycle, eval benchmarks and runs, prompt aliases, state reconciliation,
 * audit seals, workflow transition drill-down, global search, and the
 * cross-team stats. Every shape mirrors the backend response model named in
 * its doc comment.
 */
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import type { UseMutationResult, UseQueryResult } from "@tanstack/react-query";

import { useAuth } from "./auth";
import { apiFetch, apiFetchEnvelope } from "./client";

/** God-tier admin: role admin with no team binding (TEAM-06). The lifecycle,
 * eval, prompt, reconcile, workflow and teams routers refuse anyone else. */
export function useIsGodTierAdmin(): boolean {
  const user = useAuth((s) => s.user);
  return user?.role === "admin" && !user.team_id;
}

export function useIsAdmin(): boolean {
  return useAuth((s) => s.user?.role === "admin");
}

const json = (method: string, body: unknown): RequestInit => ({ method, body: JSON.stringify(body) });

/* ------------------------------ lifecycle ------------------------------- */

/** admin_lifecycle.py TransitionInfo. */
export interface LifecycleTransition {
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

/** admin_lifecycle.py ShadowReportInfo. */
export interface ShadowReport {
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

/** admin_lifecycle.py CanarySignalResponse. */
export interface CanarySignalResult {
  fired: boolean;
  reason: string;
  signal: Record<string, unknown> | null;
  transition: LifecycleTransition | null;
}

/** admin_lifecycle.py CohortRouteResponse. */
export interface CohortRoute {
  key: string;
  version: string | null;
  bucket: number;
  on_canary: boolean;
  canary_version: string | null;
  production_version: string | null;
  cohort_percent: number | null;
}

/** admin_lifecycle.py VersionMetricsRow. */
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

/** POST /admin/lifecycle/{action} bodies; every action journals one transition. */
export type LifecycleAction =
  | { action: "evaluate"; body: { key: string; version: string; benchmark_id: string } }
  | { action: "approve" | "promote" | "shadow"; body: { key: string; version: string; reason: string } }
  | { action: "rollback"; body: { key: string; version: string; target_version: string | null; reason: string } }
  | { action: "canary"; body: { key: string; version: string; cohort_percent: number; reason: string } };

const lifecycleKey = (key: string) => ["admin", "lifecycle", key] as const;

export function useLifecycleTransitions(key: string): UseQueryResult<LifecycleTransition[]> {
  return useQuery<LifecycleTransition[]>({
    queryKey: [...lifecycleKey(key), "transitions"],
    queryFn: () => apiFetch<LifecycleTransition[]>(`/admin/lifecycle/transitions?key=${encodeURIComponent(key)}&limit=200`),
    enabled: key !== "",
    retry: false,
  });
}

export function useVersionMetrics(key: string): UseQueryResult<VersionMetricsRow[]> {
  return useQuery<VersionMetricsRow[]>({
    queryKey: [...lifecycleKey(key), "metrics"],
    queryFn: async () =>
      (await apiFetch<{ key: string; rows: VersionMetricsRow[] }>(`/admin/lifecycle/metrics/versions?key=${encodeURIComponent(key)}`)).rows,
    enabled: key !== "",
    retry: false,
  });
}

export function useShadowReport(key: string, version: string): UseQueryResult<ShadowReport | null> {
  return useQuery<ShadowReport | null>({
    queryKey: [...lifecycleKey(key), "shadow-report", version],
    queryFn: () =>
      apiFetch<ShadowReport | null>(
        `/admin/lifecycle/shadow/report?key=${encodeURIComponent(key)}&version=${encodeURIComponent(version)}`,
      ),
    enabled: key !== "" && version !== "",
    retry: false,
  });
}

export function useCohortRoute(key: string, investigationId: string): UseQueryResult<CohortRoute> {
  return useQuery<CohortRoute>({
    queryKey: [...lifecycleKey(key), "route", investigationId],
    queryFn: () =>
      apiFetch<CohortRoute>(
        `/admin/lifecycle/route?key=${encodeURIComponent(key)}&investigation_id=${encodeURIComponent(investigationId)}`,
      ),
    enabled: key !== "" && investigationId !== "",
    retry: false,
  });
}

export function useLifecycleAction(): UseMutationResult<LifecycleTransition, Error, LifecycleAction> {
  const qc = useQueryClient();
  return useMutation<LifecycleTransition, Error, LifecycleAction>({
    mutationFn: (a) => apiFetch<LifecycleTransition>(`/admin/lifecycle/${a.action}`, json("POST", a.body)),
    onSuccess: (_t, a) => qc.invalidateQueries({ queryKey: lifecycleKey(a.body.key) }),
  });
}

export function useCanarySignal(): UseMutationResult<CanarySignalResult, Error, { key: string; drift: number; cost: number }> {
  const qc = useQueryClient();
  return useMutation<CanarySignalResult, Error, { key: string; drift: number; cost: number }>({
    mutationFn: (body) => apiFetch<CanarySignalResult>("/admin/lifecycle/canary/signal", json("POST", body)),
    onSuccess: (_r, body) => qc.invalidateQueries({ queryKey: lifecycleKey(body.key) }),
  });
}

export function useShadowRun(): UseMutationResult<ShadowReport, Error, { key: string; version: string; sample_n: number }> {
  const qc = useQueryClient();
  return useMutation<ShadowReport, Error, { key: string; version: string; sample_n: number }>({
    mutationFn: (body) => apiFetch<ShadowReport>("/admin/lifecycle/shadow/run", json("POST", body)),
    onSuccess: (_r, body) => qc.invalidateQueries({ queryKey: lifecycleKey(body.key) }),
  });
}

/* --------------------------------- eval --------------------------------- */

/** admin_eval.py BenchmarkCaseSpec. */
export interface BenchmarkCase {
  outcome_kind: string;
  predicted_verdict: string;
  verified_verdict: string;
  confidence: number;
  version: string | null;
}

/** admin_eval.py BenchmarkInfo. */
export interface BenchmarkInfo {
  id: string;
  key: string;
  name: string;
  case_count: number;
  created_by: string;
  created_at: string;
}

/** admin_eval.py EvalRunInfo. */
export interface EvalRun {
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

export function useEvalRuns(key: string): UseQueryResult<EvalRun[]> {
  return useQuery<EvalRun[]>({
    queryKey: ["admin", "eval", "runs", key],
    queryFn: () => apiFetch<EvalRun[]>(`/admin/eval/runs?key=${encodeURIComponent(key)}&limit=200`),
    enabled: key !== "",
    retry: false,
  });
}

export function useRegisterBenchmark(): UseMutationResult<BenchmarkInfo, Error, { key: string; name: string; cases: BenchmarkCase[] }> {
  return useMutation<BenchmarkInfo, Error, { key: string; name: string; cases: BenchmarkCase[] }>({
    mutationFn: (body) => apiFetch<BenchmarkInfo>("/admin/eval/benchmarks", json("POST", body)),
  });
}

export function useStartEvalRun(): UseMutationResult<EvalRun, Error, { key: string; candidate_version: string; benchmark_id: string }> {
  const qc = useQueryClient();
  return useMutation<EvalRun, Error, { key: string; candidate_version: string; benchmark_id: string }>({
    mutationFn: (body) => apiFetch<EvalRun>("/admin/eval/runs", json("POST", body)),
    onSuccess: (_r, body) => qc.invalidateQueries({ queryKey: ["admin", "eval", "runs", body.key] }),
  });
}

/* -------------------------------- prompts ------------------------------- */

/** admin_prompts.py PromptSummary (the fields the alias page reads). */
export interface PromptKeySummary {
  key: string;
  version: string;
  production_version: string | null;
  aliases: string[];
}

/** admin_prompts.py VersionInfo. */
export interface PromptVersion {
  key: string;
  version: string;
  content_hash: string;
  author: string;
  notes: string;
  created_at: string;
}

/** admin_prompts.py AliasInfo. */
export interface PromptAlias {
  key: string;
  alias: string;
  version: string;
  updated_at: string;
}

/** admin_prompts.py PromptDetail. */
export interface PromptBody {
  key: string;
  version: string;
  body: string;
  content_hash: string;
  author: string;
  notes: string;
  aliases: string[];
  created_at: string;
}

export function usePromptKeys(): UseQueryResult<PromptKeySummary[]> {
  return useQuery<PromptKeySummary[]>({
    queryKey: ["admin", "prompts", "keys"],
    queryFn: () => apiFetch<PromptKeySummary[]>("/admin/prompts"),
    retry: false,
  });
}

export function usePromptVersions(key: string): UseQueryResult<PromptVersion[]> {
  return useQuery<PromptVersion[]>({
    queryKey: ["admin", "prompts", "versions", key],
    queryFn: () => apiFetch<PromptVersion[]>(`/admin/prompts/versions?key=${encodeURIComponent(key)}`),
    enabled: key !== "",
    retry: false,
  });
}

export function usePromptAliases(key: string): UseQueryResult<PromptAlias[]> {
  return useQuery<PromptAlias[]>({
    queryKey: ["admin", "prompts", "aliases", key],
    queryFn: () => apiFetch<PromptAlias[]>(`/admin/prompts/aliases?key=${encodeURIComponent(key)}`),
    enabled: key !== "",
    retry: false,
  });
}

export function usePromptBody(key: string, version: string): UseQueryResult<PromptBody> {
  return useQuery<PromptBody>({
    queryKey: ["admin", "prompts", "body", key, version],
    queryFn: () =>
      apiFetch<PromptBody>(`/admin/prompts/body?key=${encodeURIComponent(key)}&version=${encodeURIComponent(version)}`),
    enabled: key !== "" && version !== "",
    retry: false,
    staleTime: Infinity,
  });
}

export function useSetPromptAlias(): UseMutationResult<PromptAlias, Error, { key: string; alias: string; version: string; reason: string }> {
  const qc = useQueryClient();
  return useMutation<PromptAlias, Error, { key: string; alias: string; version: string; reason: string }>({
    mutationFn: (body) => apiFetch<PromptAlias>("/admin/prompts/aliases", json("PUT", body)),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["admin", "prompts"] }),
  });
}

/* ------------------------------- reconcile ------------------------------ */

/** admin_reconcile.py ReconcileReportResponse. */
export interface ReconcileReport {
  task_id: string;
  signals: {
    task_id: string;
    task_status: string | null;
    task_heartbeat_at: string | null;
    task_started_at: string | null;
    cursor_state: string | null;
    lock_present: boolean | null;
  };
  healed: boolean;
  actions: { kind: string; reason: string }[];
  action_kinds: string[];
}

export function useReconcileTask(): UseMutationResult<ReconcileReport, Error, string> {
  return useMutation<ReconcileReport, Error, string>({
    mutationFn: (taskId) => apiFetch<ReconcileReport>("/admin/reconcile", json("POST", { task_id: taskId })),
  });
}

/* ------------------------------ audit seals ----------------------------- */

/** api/schemas/audit.py AuditSealResponse. */
export interface AuditSeal {
  id: number | null;
  run_id: string;
  seal_hash: string;
  input_hash: string;
  output_hash: string;
  model_id: string;
  task_type: string;
  timestamp: string;
  classification: string | null;
  confidence: string | null;
  evidence_validation_pass: boolean | null;
  content_stored: boolean;
  prompt_content: string | null;
  response_content: string | null;
  created_at: string | null;
}

/** AuditSealListResponse (PaginatedResponse, not a DataEnvelope). */
export interface AuditSealPage {
  total: number;
  page: number;
  page_size: number;
  pages: number;
  items: AuditSeal[];
}

export function useAuditSeals(runId: string, includeContent: boolean, page: number): UseQueryResult<AuditSealPage> {
  return useQuery<AuditSealPage>({
    queryKey: ["admin", "audit-seals", runId, includeContent, page],
    queryFn: () =>
      apiFetch<AuditSealPage>(
        `/audit/seals?run_id=${encodeURIComponent(runId)}&include_content=${includeContent}&page=${page}&page_size=50`,
      ),
    enabled: runId !== "",
    retry: false,
  });
}

/** Walk every page of GET /audit/seals/export for the window and return the
 * concatenated rows (the route caps page_size at 250). */
export async function fetchAuditSealExport(since: string, until: string, includeContent: boolean): Promise<AuditSeal[]> {
  const rows: AuditSeal[] = [];
  for (let page = 1; ; page += 1) {
    const res = await apiFetch<AuditSealPage>(
      `/audit/seals/export?since=${encodeURIComponent(since)}&until=${encodeURIComponent(until)}&include_content=${includeContent}&page=${page}&page_size=250`,
    );
    rows.push(...res.items);
    if (page >= res.pages) return rows;
  }
}

/* ------------------------------- workflows ------------------------------ */

/** api/schemas/transitions.py TransitionView. */
export interface WorkflowTransition {
  run_id: string;
  seq: number;
  from_state: string | null;
  to_state: string;
  event: string;
  duration_ms: number | null;
  error_class: string | null;
  error_message: string | null;
  happened_at: string;
  task_id: string | null;
}

export function useWorkflowTransitions(runId: string): UseQueryResult<WorkflowTransition[]> {
  return useQuery<WorkflowTransition[]>({
    queryKey: ["admin", "workflow-transitions", runId],
    queryFn: () => apiFetch<WorkflowTransition[]>(`/admin/workflows/runs/${encodeURIComponent(runId)}/transitions`),
    enabled: runId !== "",
    retry: false,
    refetchOnWindowFocus: false,
  });
}

export function useWorkflowTransition(runId: string, seq: number | null): UseQueryResult<WorkflowTransition> {
  return useQuery<WorkflowTransition>({
    queryKey: ["admin", "workflow-transitions", runId, seq],
    queryFn: () => apiFetch<WorkflowTransition>(`/admin/workflows/runs/${encodeURIComponent(runId)}/transitions/${seq ?? 0}`),
    enabled: runId !== "" && seq !== null,
    retry: false,
    refetchOnWindowFocus: false,
  });
}

/* -------------------------------- search -------------------------------- */

/** api/schemas/endpoints.py SearchResult. */
export interface SearchResult {
  entity_type: string;
  entity_id: string;
  title: string;
  snippet: string;
  module_id: string | null;
  score: number;
}

export interface SearchPage {
  results: SearchResult[];
  total: number;
}

export function useGlobalSearch(q: string, entityTypes: readonly string[]): UseQueryResult<SearchPage> {
  const types = entityTypes.join(",");
  return useQuery<SearchPage>({
    queryKey: ["search", q, types],
    queryFn: async () => {
      const env = await apiFetchEnvelope<{ data: SearchResult[]; meta: { total: number } | null }>(
        `/search?q=${encodeURIComponent(q)}&limit=100${types ? `&entity_types=${encodeURIComponent(types)}` : ""}`,
      );
      return { results: env.data, total: env.meta?.total ?? env.data.length };
    },
    enabled: q.trim() !== "",
    retry: false,
    staleTime: 15_000,
  });
}

/* --------------------------------- teams -------------------------------- */

/** admin_teams.py CrossTeamStatsRow. */
export interface CrossTeamStats {
  team_id: string;
  team_name: string;
  systems_count: number;
  runs_count: number;
  members_count: number;
}

export function useCrossTeamStats(enabled: boolean): UseQueryResult<CrossTeamStats[]> {
  return useQuery<CrossTeamStats[]>({
    queryKey: ["admin", "teams", "cross-view"],
    queryFn: () => apiFetch<CrossTeamStats[]>("/admin/teams/cross-view"),
    enabled,
    retry: false,
  });
}

/* --------------------------- benchmark suites --------------------------- */

/** vr/eval_suites/contracts.py TaskResultSummary. */
export interface TaskResult {
  task_id: string;
  name: string;
  category: string | null;
  investigation_id: string | null;
  status: string;
  solved: boolean;
  cost_usd: number;
  polarity: string | null;
}

/** vr/eval_suites/contracts.py SuiteRunSummary. */
export interface SuiteRun {
  id: string;
  suite: string;
  status: string;
  solved_count: number;
  total_count: number;
  total_cost_usd: number;
  created_at: string | null;
  finished_at: string | null;
  results: TaskResult[];
}

/** vr/eval_suites/contracts.py LeaderboardRow. */
export interface LeaderboardRow {
  suite: string;
  solved_count: number;
  total_count: number;
  solve_rate: number;
  avg_cost_usd: number;
  last_run_at: string | null;
}

export function useEvalSuiteRuns(): UseQueryResult<SuiteRun[]> {
  return useQuery<SuiteRun[]>({
    queryKey: ["admin", "eval-suites", "runs"],
    queryFn: () => apiFetch<SuiteRun[]>("/vr/eval-suites/runs?limit=100"),
    retry: false,
  });
}

export function useEvalSuiteRun(id: string | null): UseQueryResult<SuiteRun | null> {
  return useQuery<SuiteRun | null>({
    queryKey: ["admin", "eval-suites", "run", id],
    queryFn: () => apiFetch<SuiteRun>(`/vr/eval-suites/runs/${encodeURIComponent(id ?? "")}`),
    enabled: id !== null,
    retry: false,
  });
}

export function useEvalSuiteLeaderboard(): UseQueryResult<LeaderboardRow[]> {
  return useQuery<LeaderboardRow[]>({
    queryKey: ["admin", "eval-suites", "leaderboard"],
    queryFn: () => apiFetch<LeaderboardRow[]>("/vr/eval-suites/leaderboard"),
    retry: false,
  });
}

export function useStartEvalSuiteRun(): UseMutationResult<{ task_id: string; suite: string | null; run_id: string | null }, Error, { suite: string }> {
  const qc = useQueryClient();
  return useMutation<{ task_id: string; suite: string | null; run_id: string | null }, Error, { suite: string }>({
    mutationFn: (body) => apiFetch("/vr/eval-suites/runs", json("POST", body)),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ["admin", "eval-suites"] }),
  });
}

export function useCollectEvalSuiteRun(): UseMutationResult<{ task_id: string; run_id: string | null }, Error, string> {
  const qc = useQueryClient();
  return useMutation<{ task_id: string; run_id: string | null }, Error, string>({
    mutationFn: (runId) => apiFetch(`/vr/eval-suites/runs/${encodeURIComponent(runId)}/collect`, json("POST", {})),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ["admin", "eval-suites"] }),
  });
}
