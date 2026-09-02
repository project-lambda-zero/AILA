/**
 * Cost & reporting API hooks (req 47).
 *
 * Backs the bespoke `admin:cost` console page: the overview timeseries +
 * breakdowns (`/cost/history`), the ROI trio (`/cost/roi`), the per-run
 * drill-in (`/cost/runs/{id}`), the detail interaction log (`/admin/llm-log`),
 * and the cost-family config editors (`/config/platform`). No new backend
 * endpoint -- every field maps 1:1 to an existing response model:
 *   - CostHistoryResponse / MonthlyCostEntry / ModelCostEntry (schemas/cost.py)
 *   - ROIResponse, CostBreakdownResponse (schemas/cost.py)
 *   - LLMLogResponse / LLMLogEntry (schemas/llm_log.py)
 *   - the platform ConfigRegistry rows (routers/config.py)
 *
 * The cost routes are DataEnvelope-wrapped and `apiFetch` unwraps `.data`.
 */
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import type { UseMutationResult, UseQueryResult } from "@tanstack/react-query";

import { apiFetch } from "./client";

/* ------------------------------ cost shapes ------------------------------ */

/** Per-model cost entry within a run or month (ModelCostEntry). */
export interface ModelCostEntry {
  model_id: string;
  prompt_tokens: number;
  completion_tokens: number;
  total_tokens: number;
  cost_usd: number;
  call_count: number;
}

/** One month of aggregated cost with its per-model breakdown. */
export interface MonthlyCostEntry {
  year_month: string; // "2026-04"
  total_cost_usd: number;
  total_tokens: number;
  models: ModelCostEntry[];
}

/** GET /cost/history (CostHistoryResponse). */
export interface CostHistory {
  months: MonthlyCostEntry[];
  grand_total_usd: number;
}

/** GET /cost/roi (ROIResponse). */
export interface CostRoi {
  period_start: string;
  period_end: string;
  llm_cost_usd: number;
  human_equivalent_cost_usd: number;
  human_equivalent_hours: number;
  roi_percentage: number;
  run_count: number;
}

/** GET /cost/runs/{run_id} (CostBreakdownResponse). */
export interface CostBreakdown {
  run_id: string;
  total_cost_usd: number;
  total_tokens: number;
  models: ModelCostEntry[];
  cache_hit_rate: number;
  cache_read_tokens: number;
  cache_write_tokens: number;
}

/* ---------------------------- llm-log shapes ----------------------------- */

/** One LLM call row (LLMLogEntry). */
export interface LlmLogEntry {
  id: string;
  timestamp: string;
  model: string;
  task_type: string;
  input_tokens: number;
  output_tokens: number;
  cost_usd: number;
  duration_ms: number | null;
  status: string;
  run_id: string;
  user_id: string | null;
  team_id: string | null;
  prompt_preview: string | null;
  response_preview: string | null;
}

/** Paginated llm-log page (LLMLogResponse). `total` and `total_cost_usd`
 *  are summed across ALL matching rows (SQL aggregate), not just this page. */
export interface LlmLogPage {
  items: LlmLogEntry[];
  total: number;
  limit: number;
  offset: number;
  total_cost_usd: number;
}

/** Query for GET /admin/llm-log. `model`/`task_type`/`status` repeat as
 *  separate params (the backend flattens repeated-or-comma-OR); everything
 *  else is a scalar. */
export interface LlmLogQuery {
  limit?: number;
  offset?: number;
  model?: string[];
  task_type?: string[];
  status?: string[];
  user_id?: string;
  timestamp_since?: string;
  timestamp_until?: string;
  cost_usd_min?: string;
  cost_usd_max?: string;
  search?: string;
}

/* ------------------------------ config shapes ---------------------------- */

/** One GET /config/platform row (ConfigEntryResponse subset the editor uses). */
export interface CostConfigRow {
  namespace: string;
  key: string;
  value_type: "str" | "int" | "float" | "bool";
  effective_value: string;
  effective_source: "env" | "db" | "default";
  overridden_by_env: boolean;
  env_key: string;
}

interface ConfigListEnvelope {
  items: CostConfigRow[];
}

/** Cost-family config key prefixes surfaced in the configs segment. Ordered
 *  by family so the editor can group + label them. */
export const COST_CONFIG_PREFIXES = [
  "llm_monthly_budget_usd_",
  "llm_cost_per_1k_prompt_",
  "llm_cost_per_1k_completion_",
  "llm_budget_max_total_tokens_",
  "llm_cost_estimate_fallback_",
] as const;

/* -------------------------------- hooks ---------------------------------- */

/** Monthly spend history with per-model breakdown (LLM-COST-04). */
export function useCostHistory(months: number): UseQueryResult<CostHistory> {
  return useQuery<CostHistory>({
    queryKey: ["cost", "history", months],
    queryFn: () => apiFetch<CostHistory>(`/cost/history?months=${months}`),
    staleTime: 30_000,
    refetchOnWindowFocus: false,
  });
}

/** LLM cost vs human-equivalent cost (LLM-COST-05). */
export function useCostRoi(months: number): UseQueryResult<CostRoi> {
  return useQuery<CostRoi>({
    queryKey: ["cost", "roi", months],
    queryFn: () => apiFetch<CostRoi>(`/cost/roi?months=${months}`),
    staleTime: 30_000,
    refetchOnWindowFocus: false,
  });
}

/** Per-model breakdown for one run; only fires when a run is selected. */
export function useRunBreakdown(runId: string | null): UseQueryResult<CostBreakdown> {
  return useQuery<CostBreakdown>({
    queryKey: ["cost", "run", runId],
    queryFn: () => apiFetch<CostBreakdown>(`/cost/runs/${encodeURIComponent(runId ?? "")}`),
    enabled: runId != null && runId !== "",
    staleTime: 30_000,
    refetchOnWindowFocus: false,
  });
}

/** Build the /admin/llm-log query string from a typed query. */
export function llmLogPath(q: LlmLogQuery): string {
  const p = new URLSearchParams();
  if (q.limit != null) p.set("limit", String(q.limit));
  if (q.offset != null) p.set("offset", String(q.offset));
  for (const m of q.model ?? []) if (m) p.append("model", m);
  for (const t of q.task_type ?? []) if (t) p.append("task_type", t);
  for (const s of q.status ?? []) if (s) p.append("status", s);
  if (q.user_id) p.set("user_id", q.user_id);
  if (q.timestamp_since) p.set("timestamp_since", q.timestamp_since);
  if (q.timestamp_until) p.set("timestamp_until", q.timestamp_until);
  if (q.cost_usd_min) p.set("cost_usd_min", q.cost_usd_min);
  if (q.cost_usd_max) p.set("cost_usd_max", q.cost_usd_max);
  if (q.search) p.set("search", q.search);
  return `/admin/llm-log?${p.toString()}`;
}

/** Paginated LLM interaction log (require_role admin). */
export function useLlmLog(q: LlmLogQuery): UseQueryResult<LlmLogPage> {
  return useQuery<LlmLogPage>({
    queryKey: ["llm-log", q],
    queryFn: () => apiFetch<LlmLogPage>(llmLogPath(q)),
    staleTime: 15_000,
    refetchOnWindowFocus: false,
  });
}

/** Cost-family platform config rows (single page; the platform namespace is
 *  well under the 250 cap, same honest single-fetch the sandbox editor uses). */
export function useCostConfig(): UseQueryResult<CostConfigRow[]> {
  return useQuery<CostConfigRow[]>({
    queryKey: ["cost", "config"],
    queryFn: async () => {
      const env = await apiFetch<ConfigListEnvelope>("/config/platform?page=1&page_size=250");
      return env.items.filter((row) => COST_CONFIG_PREFIXES.some((p) => row.key.startsWith(p)));
    },
    staleTime: 10_000,
    refetchOnWindowFocus: false,
  });
}

/** Write one platform config key; invalidates the cost-config read. */
export function useUpdateCostConfig(): UseMutationResult<
  CostConfigRow,
  Error,
  { key: string; value: string; value_type: CostConfigRow["value_type"] }
> {
  const qc = useQueryClient();
  return useMutation<CostConfigRow, Error, { key: string; value: string; value_type: CostConfigRow["value_type"] }>({
    mutationFn: ({ key, value, value_type }) =>
      apiFetch<CostConfigRow>(`/config/platform/${encodeURIComponent(key)}`, {
        method: "PUT",
        body: JSON.stringify({ value, value_type }),
      }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["cost", "config"] });
    },
  });
}
