/**
 * CostPage — LLM cost intelligence and ROI dashboard.
 *
 * Phase 175: visualises monthly cost trend (with per-model breakdown) and
 * compares LLM spend to the human-equivalent cost AILA replaced.
 *
 * Endpoints:
 *   GET /cost/history?months=N   — monthly cost aggregated by model
 *   GET /cost/roi?months=N        — LLM cost vs human-equivalent ROI
 */
import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { CurrencyDollar } from "@phosphor-icons/react/dist/csr/CurrencyDollar";
import { TrendUp } from "@phosphor-icons/react/dist/csr/TrendUp";
import { TrendDown } from "@phosphor-icons/react/dist/csr/TrendDown";
import { ChartLineUp } from "@phosphor-icons/react/dist/csr/ChartLineUp";

import { AilaCard } from "@/components/aila/AilaCard";
import { AilaBadge } from "@/components/aila/AilaBadge";
import { LoadingSkeletonGroup } from "@/components/aila/LoadingSkeleton";
import { EmptyState } from "@/components/aila/EmptyState";
import { authorizedRequestJson } from "@platform/api/http";

// ---------------------------------------------------------------------------
// Types — mirror src/aila/api/schemas/cost.py
// ---------------------------------------------------------------------------

interface ModelCostEntry {
  model_id: string;
  prompt_tokens: number;
  completion_tokens: number;
  total_tokens: number;
  cost_usd: number;
  call_count: number;
}

interface MonthlyCostEntry {
  year_month: string;
  total_cost_usd: number;
  total_tokens: number;
  models: ModelCostEntry[];
}

interface CostHistoryResponse {
  months: MonthlyCostEntry[];
  grand_total_usd: number;
}

interface ROIResponse {
  period_start: string;
  period_end: string;
  llm_cost_usd: number;
  human_equivalent_cost_usd: number;
  human_equivalent_hours: number;
  roi_percentage: number;
  run_count: number;
}

interface DataEnvelope<T> {
  data: T;
  error: string | null;
  meta: Record<string, unknown>;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function formatUsd(value: number, fractionDigits = 2): string {
  return new Intl.NumberFormat("en-US", {
    style: "currency",
    currency: "USD",
    minimumFractionDigits: fractionDigits,
    maximumFractionDigits: fractionDigits,
  }).format(value);
}

function formatTokens(value: number): string {
  return new Intl.NumberFormat("en-US").format(value);
}

// ---------------------------------------------------------------------------
// Trend bar — inline horizontal bar per month
// ---------------------------------------------------------------------------

function MonthlyTrend({ months }: { months: MonthlyCostEntry[] }) {
  if (months.length === 0) {
    return (
      <p className="font-mono text-xs text-text-muted">
        No cost data in the selected window.
      </p>
    );
  }
  const max = Math.max(...months.map((m) => m.total_cost_usd), 0.0001);

  return (
    <div className="flex flex-col gap-3">
      {months.map((m) => {
        const pct = (m.total_cost_usd / max) * 100;
        return (
          <div key={m.year_month} className="flex flex-col gap-1">
            <div className="flex items-center justify-between font-mono text-xs">
              <span className="text-text-muted">{m.year_month}</span>
              <span className="text-text">
                {formatUsd(m.total_cost_usd, 4)} ·{" "}
                <span className="text-text-muted">
                  {formatTokens(m.total_tokens)} tokens
                </span>
              </span>
            </div>
            <div className="h-2 w-full rounded-[2px] bg-base border border-border overflow-hidden">
              <div
                className="h-full bg-accent transition-all duration-200"
                style={{ width: `${pct}%` }}
                aria-label={`${m.year_month} cost ${formatUsd(m.total_cost_usd, 4)}`}
              />
            </div>
            {m.models.length > 0 && (
              <div className="flex flex-wrap gap-1.5 mt-0.5">
                {m.models.map((mc) => (
                  <AilaBadge
                    key={`${m.year_month}-${mc.model_id}`}
                    severity="neutral"
                    size="sm"
                  >
                    <span className="text-text">{mc.model_id}</span>
                    <span className="ml-1 text-text-muted">
                      {formatUsd(mc.cost_usd, 4)}
                    </span>
                  </AilaBadge>
                ))}
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------

const RANGE_OPTIONS: { label: string; months: number }[] = [
  { label: "1m", months: 1 },
  { label: "3m", months: 3 },
  { label: "6m", months: 6 },
  { label: "12m", months: 12 },
];

export function CostPage() {
  const [historyMonths, setHistoryMonths] = useState(6);
  const [roiMonths, setRoiMonths] = useState(3);

  const historyQuery = useQuery({
    queryKey: ["platform", "cost-history", historyMonths],
    queryFn: () =>
      authorizedRequestJson<DataEnvelope<CostHistoryResponse>>(
        `/cost/history?months=${historyMonths}`,
      ),
  });

  const roiQuery = useQuery({
    queryKey: ["platform", "cost-roi", roiMonths],
    queryFn: () =>
      authorizedRequestJson<DataEnvelope<ROIResponse>>(
        `/cost/roi?months=${roiMonths}`,
      ),
  });

  const history = historyQuery.data?.data;
  const roi = roiQuery.data?.data;

  const months = history?.months ?? [];
  const grandTotal = history?.grand_total_usd ?? 0;

  const costPerRun = useMemo(() => {
    if (!roi || roi.run_count === 0) return 0;
    return roi.llm_cost_usd / roi.run_count;
  }, [roi]);

  const trendDelta = useMemo(() => {
    if (months.length < 2) return null;
    const last = months[months.length - 1].total_cost_usd;
    const prev = months[months.length - 2].total_cost_usd;
    if (prev === 0) return null;
    return ((last - prev) / prev) * 100;
  }, [months]);

  return (
    <div className="flex flex-col gap-6 p-4 lg:p-6">
      <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
      </div>

      {/* Top metric cards */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <AilaCard variant="elevated" padding="md" techBorder glow><p className="font-mono text-xs uppercase tracking-wider text-text-muted">
          Total Cost ({historyMonths}m)
        </p>
        <p className="font-mono text-2xl font-semibold text-text mt-1">
          {historyQuery.isLoading ? "—" : formatUsd(grandTotal, 2)}
        </p>
        <p className="font-mono text-xs text-text-muted mt-0.5">
          Sum of monthly spend
        </p></AilaCard>

        <AilaCard variant="elevated" padding="md" techBorder glow><p className="font-mono text-xs uppercase tracking-wider text-text-muted">
          Cost / Scan
        </p>
        <p className="font-mono text-2xl font-semibold text-text mt-1">
          {roiQuery.isLoading ? "—" : formatUsd(costPerRun, 4)}
        </p>
        <p className="font-mono text-xs text-text-muted mt-0.5">
          {roi ? `${roi.run_count} runs · ${roiMonths}m` : "—"}
        </p></AilaCard>

        <AilaCard variant="elevated" padding="md" techBorder glow><p className="font-mono text-xs uppercase tracking-wider text-text-muted">
          MoM Trend
        </p>
        <p className="font-mono text-2xl font-semibold text-text mt-1 flex items-center gap-1.5">
          {historyQuery.isLoading || trendDelta === null
            ? "—"
            : `${trendDelta >= 0 ? "+" : ""}${trendDelta.toFixed(1)}%`}
          {trendDelta !== null && trendDelta >= 0 && (
            <TrendUp className="h-5 w-5 text-high" />
          )}
          {trendDelta !== null && trendDelta < 0 && (
            <TrendDown className="h-5 w-5 text-low" />
          )}
        </p>
        <p className="font-mono text-xs text-text-muted mt-0.5">
          Latest vs previous month
        </p></AilaCard>

        <AilaCard variant="elevated" padding="md" techBorder glow><p className="font-mono text-xs uppercase tracking-wider text-text-muted">
          ROI ({roiMonths}m)
        </p>
        <p
          className={`font-mono text-2xl font-semibold mt-1 ${
            roi && roi.roi_percentage >= 0 ? "text-low" : "text-high"
          }`}
        >
          {roiQuery.isLoading || !roi
            ? "—"
            : `${roi.roi_percentage >= 0 ? "+" : ""}${roi.roi_percentage.toFixed(1)}%`}
        </p>
        <p className="font-mono text-xs text-text-muted mt-0.5">
          vs human-equivalent
        </p></AilaCard>
      </div>

      {/* History card */}
      <AilaCard variant="default" padding="md" techBorder glow><div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2">
          <ChartLineUp className="h-4 w-4 text-accent" />
          <h2 className="font-mono text-sm font-semibold text-text">
            Cost trend
          </h2>
        </div>
        <div className="flex gap-1">
          {RANGE_OPTIONS.map((opt) => (
            <button
              key={opt.label}
              type="button"
              onClick={() => setHistoryMonths(opt.months)}
              className={`px-2.5 py-1 rounded-[2px] border font-mono text-xs transition-colors ${
                historyMonths === opt.months
                  ? "border-accent text-accent bg-accent/10"
                  : "border-border text-text-muted hover:border-border-hover"
              }`}
            >
              {opt.label}
            </button>
          ))}
        </div>
      </div>
      
      {historyQuery.isError && (
        <div className="rounded-[4px] border border-destructive bg-destructive/10 px-4 py-3 font-mono text-sm text-destructive">
          Failed to load cost history: {(historyQuery.error as Error).message}
        </div>
      )}
      
      {historyQuery.isLoading && <LoadingSkeletonGroup lines={4} />}
      
      {!historyQuery.isLoading &&
        !historyQuery.isError &&
        months.length === 0 && (
          <EmptyState
            icon={<CurrencyDollar className="h-10 w-10" />}
            title="No cost data"
            description="No LLM cost records exist for the selected window. Run a scan to start populating the ledger."
          />
        )}
      
      {!historyQuery.isLoading && months.length > 0 && (
        <MonthlyTrend months={months} />
      )}</AilaCard>

      {/* ROI card */}
      <AilaCard variant="default" padding="md" techBorder glow><div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2">
          <TrendUp className="h-4 w-4 text-accent" />
          <h2 className="font-mono text-sm font-semibold text-text">
            ROI summary
          </h2>
        </div>
        <div className="flex gap-1">
          {RANGE_OPTIONS.map((opt) => (
            <button
              key={opt.label}
              type="button"
              onClick={() => setRoiMonths(opt.months)}
              className={`px-2.5 py-1 rounded-[2px] border font-mono text-xs transition-colors ${
                roiMonths === opt.months
                  ? "border-accent text-accent bg-accent/10"
                  : "border-border text-text-muted hover:border-border-hover"
              }`}
            >
              {opt.label}
            </button>
          ))}
        </div>
      </div>
      
      {roiQuery.isError && (
        <div className="rounded-[4px] border border-destructive bg-destructive/10 px-4 py-3 font-mono text-sm text-destructive">
          Failed to load ROI: {(roiQuery.error as Error).message}
        </div>
      )}
      
      {roiQuery.isLoading && <LoadingSkeletonGroup lines={4} />}
      
      {!roiQuery.isLoading && !roiQuery.isError && roi && (
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
          <div className="flex flex-col gap-0.5">
            <p className="font-mono text-xs text-text-muted">LLM Spend</p>
            <p className="font-mono text-lg text-text">
              {formatUsd(roi.llm_cost_usd, 2)}
            </p>
          </div>
          <div className="flex flex-col gap-0.5">
            <p className="font-mono text-xs text-text-muted">
              Human-Equivalent
            </p>
            <p className="font-mono text-lg text-text">
              {formatUsd(roi.human_equivalent_cost_usd, 2)}
            </p>
            <p className="font-mono text-xs text-text-muted">
              {roi.human_equivalent_hours.toFixed(1)}h
            </p>
          </div>
          <div className="flex flex-col gap-0.5">
            <p className="font-mono text-xs text-text-muted">Run Count</p>
            <p className="font-mono text-lg text-text">{roi.run_count}</p>
          </div>
          <div className="flex flex-col gap-0.5">
            <p className="font-mono text-xs text-text-muted">Period</p>
            <p className="font-mono text-xs text-text">
              {roi.period_start} → {roi.period_end}
            </p>
          </div>
        </div>
      )}</AilaCard>
    </div>
  );
}
