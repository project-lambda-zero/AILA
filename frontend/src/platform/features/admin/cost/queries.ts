/**
 * Cost intelligence data layer (Phase 175 wire-up).
 *
 * TanStack Query hooks over the /cost/* router at
 * src/aila/api/routers/cost.py. Types mirror
 * src/aila/api/schemas/cost.py exactly.
 *
 * Endpoints wired:
 *   GET  /cost/runs/{run_id}      -> useRunCostBreakdown
 *   GET  /cost/history?months=N   -> useCostHistory
 *   GET  /cost/roi?months=N       -> useCostRoi
 *   POST /cost/estimate           -> useEstimateScanCost
 *   POST /cost/estimate-human     -> useEstimateHumanCost
 */
import { useMutation, useQuery } from "@tanstack/react-query";

import { authorizedRequestJson } from "@platform/api/http";

// ---------------------------------------------------------------------------
// Envelope + response types -- mirror src/aila/api/schemas/cost.py
// ---------------------------------------------------------------------------

interface DataEnvelope<T> {
  data: T;
  error: string | null;
  meta: Record<string, unknown>;
}

export interface ModelCostEntry {
  model_id: string;
  prompt_tokens: number;
  completion_tokens: number;
  total_tokens: number;
  cost_usd: number;
  call_count: number;
}

export interface CostBreakdownResponse {
  run_id: string;
  total_cost_usd: number;
  total_tokens: number;
  models: ModelCostEntry[];
}

export interface MonthlyCostEntry {
  year_month: string;
  total_cost_usd: number;
  total_tokens: number;
  models: ModelCostEntry[];
}

export interface CostHistoryResponse {
  months: MonthlyCostEntry[];
  grand_total_usd: number;
}

export interface ROIResponse {
  period_start: string;
  period_end: string;
  llm_cost_usd: number;
  human_equivalent_cost_usd: number;
  human_equivalent_hours: number;
  roi_percentage: number;
  run_count: number;
}

export interface TaskTypeEstimate {
  task_type: string;
  avg_cost_usd: number;
  sample_count: number;
}

export interface CostEstimateRequest {
  target_count: number;
  task_types: string[];
}

export interface CostEstimateResponse {
  estimated_cost_usd: number;
  confidence: string; // "historical" | "worst_case"
  breakdown: TaskTypeEstimate[];
}

export interface HumanEstimateRequest {
  run_id: string;
  target_count: number;
  finding_count: number;
  task_types_performed: string[];
  scan_duration_minutes: number;
}

export interface HumanEstimateResponse {
  estimated_hours: number;
  human_cost_usd: number;
  confidence: string; // "high" | "medium" | "low"
  reasoning: string;
}

/**
 * Per-model rollup across the requested cost-history window. Aggregated
 * client-side from `CostHistoryResponse.months[].models[]`; the /cost/history
 * endpoint already groups by (year_month, model_id) so this fold is exact --
 * no double-counting, no rounding drift beyond what the SQL SUM produced.
 */
export interface ModelUsageEntry {
  model_id: string;
  cost_usd: number;
  total_tokens: number;
  call_count: number;
}

/**
 * aggregateModelsAcrossMonths -- collapse the (month, model) matrix into a
 * per-model rollup for the requested window. Feeds the "Model usage" chart on
 * the CostPage. Ordered by cost descending so the pie / bar chart's first
 * slot is always the biggest spender.
 */
export function aggregateModelsAcrossMonths(
  months: MonthlyCostEntry[],
): ModelUsageEntry[] {
  const map = new Map<string, ModelUsageEntry>();
  for (const month of months) {
    for (const mc of month.models) {
      const prior = map.get(mc.model_id);
      if (prior) {
        prior.cost_usd += mc.cost_usd;
        prior.total_tokens += mc.total_tokens;
        prior.call_count += mc.call_count;
        continue;
      }
      map.set(mc.model_id, {
        model_id: mc.model_id,
        cost_usd: mc.cost_usd,
        total_tokens: mc.total_tokens,
        call_count: mc.call_count,
      });
    }
  }
  const rows = Array.from(map.values());
  rows.sort((a, b) => b.cost_usd - a.cost_usd);
  return rows;
}

// ---------------------------------------------------------------------------
// Query keys
// ---------------------------------------------------------------------------

export const costQueryKeys = {
  all: ["platform", "cost"] as const,
  history: (months: number) => ["platform", "cost", "history", months] as const,
  roi: (months: number) => ["platform", "cost", "roi", months] as const,
  run: (runId: string) => ["platform", "cost", "run", runId] as const,
};

// ---------------------------------------------------------------------------
// Read hooks
// ---------------------------------------------------------------------------

export function useCostHistory(months: number) {
  return useQuery({
    queryKey: costQueryKeys.history(months),
    queryFn: () =>
      authorizedRequestJson<DataEnvelope<CostHistoryResponse>>(
        `/cost/history?months=${months}`,
      ),
  });
}

export function useCostRoi(months: number) {
  return useQuery({
    queryKey: costQueryKeys.roi(months),
    queryFn: () =>
      authorizedRequestJson<DataEnvelope<ROIResponse>>(
        `/cost/roi?months=${months}`,
      ),
  });
}

/**
 * useRunCostBreakdown -- GET /cost/runs/{run_id}.
 *
 * Disabled when runId is empty so an unfilled input does not fire a 404
 * loop. Set staleTime high; run costs are immutable once written.
 */
export function useRunCostBreakdown(runId: string | null) {
  const enabled = typeof runId === "string" && runId.trim().length > 0;
  const trimmed = (runId ?? "").trim();
  return useQuery({
    queryKey: costQueryKeys.run(trimmed),
    queryFn: () =>
      authorizedRequestJson<DataEnvelope<CostBreakdownResponse>>(
        `/cost/runs/${encodeURIComponent(trimmed)}`,
      ),
    enabled,
    staleTime: 5 * 60 * 1000,
    retry: false,
  });
}

// ---------------------------------------------------------------------------
// Mutations
// ---------------------------------------------------------------------------

/**
 * useEstimateScanCost -- POST /cost/estimate.
 *
 * Team-scoped historical average * target_count per requested task_type.
 * Confidence: "historical" if the caller's team has prior scans, else
 * "worst_case" (falls back to ConfigRegistry defaults, not hardcoded).
 */
export function useEstimateScanCost() {
  return useMutation({
    mutationFn: (body: CostEstimateRequest) =>
      authorizedRequestJson<DataEnvelope<CostEstimateResponse>>(
        "/cost/estimate",
        { method: "POST", body },
      ),
  });
}

/**
 * useEstimateHumanCost -- POST /cost/estimate-human.
 *
 * Post-scan human-equivalent estimation for a specific run. The backend
 * writes the result into the ROI ledger so subsequent /cost/roi reflects
 * the new sample; we do not invalidate here (the ROI query has its own
 * refresh cadence and callers usually inspect the response inline).
 */
export function useEstimateHumanCost() {
  return useMutation({
    mutationFn: (body: HumanEstimateRequest) =>
      authorizedRequestJson<DataEnvelope<HumanEstimateResponse>>(
        "/cost/estimate-human",
        { method: "POST", body },
      ),
  });
}
