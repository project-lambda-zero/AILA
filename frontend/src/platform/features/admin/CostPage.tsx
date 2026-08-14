/**
 * CostPage -- LLM cost intelligence and ROI dashboard.
 *
 * Phase 175: visualises monthly cost trend (with per-model breakdown),
 * compares LLM spend to the human-equivalent cost AILA replaced, drills
 * into a single run's per-model breakdown, and estimates the cost of a
 * pre-scan submission or a post-scan human-equivalent write-up.
 *
 * Endpoints (all wired via ./cost/queries):
 *   GET  /cost/history?months=N   -- monthly cost aggregated by model
 *   GET  /cost/roi?months=N       -- LLM cost vs human-equivalent ROI
 *   GET  /cost/runs/{run_id}      -- per-model breakdown for a single run
 *   POST /cost/estimate           -- pre-scan cost estimate from team history
 *   POST /cost/estimate-human     -- post-scan human-equivalent estimate
 */
import { useMemo, useState } from "react";
import { CurrencyDollar } from "@phosphor-icons/react/dist/csr/CurrencyDollar";
import { TrendUp } from "@phosphor-icons/react/dist/csr/TrendUp";
import { TrendDown } from "@phosphor-icons/react/dist/csr/TrendDown";
import { ChartLineUp } from "@phosphor-icons/react/dist/csr/ChartLineUp";
import { MagnifyingGlass } from "@phosphor-icons/react/dist/csr/MagnifyingGlass";
import { Calculator } from "@phosphor-icons/react/dist/csr/Calculator";
import { UsersThree } from "@phosphor-icons/react/dist/csr/UsersThree";

import { AilaCard } from "@/components/aila/AilaCard";
import { AilaBadge } from "@/components/aila/AilaBadge";
import { AilaChart } from "@/components/aila/AilaChart";
import { LoadingSkeletonGroup } from "@/components/aila/LoadingSkeleton";
import { EmptyState } from "@/components/aila/EmptyState";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { useThemeChartColors } from "@platform/features/viz/chartColors";

import {
  aggregateModelsAcrossMonths,
  useCostHistory,
  useCostRoi,
  useEstimateHumanCost,
  useEstimateScanCost,
  useRunCostBreakdown,
  type CostBreakdownResponse,
  type CostEstimateResponse,
  type HumanEstimateResponse,
  type MonthlyCostEntry,
  type ModelUsageEntry,
} from "./cost/queries";

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

/** Parse a comma / whitespace / newline separated list, trim, drop blanks. */
function parseList(raw: string): string[] {
  return raw
    .split(/[\s,;]+/)
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
}

function confidenceTone(
  confidence: string,
): "critical" | "high" | "medium" | "low" | "neutral" {
  switch (confidence) {
    case "high":
    case "historical":
      return "low"; // green -- reliable
    case "medium":
      return "medium";
    case "low":
    case "worst_case":
      return "high"; // amber -- shaky
    default:
      return "neutral";
  }
}

// ---------------------------------------------------------------------------
// Trend bar -- inline horizontal bar per month
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
// Cost trend chart -- AilaChart area over months
// ---------------------------------------------------------------------------
//
// Chronological view of monthly cost totals. The inline MonthlyTrend bars
// above stay as the detailed per-month per-model drilldown; this chart
// provides the at-a-glance direction (up/down/flat) that a stack of bars
// with mixed magnitudes does not read cleanly.

interface CostTrendPoint extends Record<string, unknown> {
  year_month: string;
  total_cost_usd: number;
  total_tokens: number;
}

function CostTrendChart({
  months,
  accent,
}: {
  months: MonthlyCostEntry[];
  accent: string;
}) {
  const points: CostTrendPoint[] = months.map((m) => ({
    year_month: m.year_month,
    // recharts serialises the value verbatim; round to a stable dollar
    // precision so tooltips don't leak float-add drift like 3.1400000000004.
    total_cost_usd: Math.round(m.total_cost_usd * 10000) / 10000,
    total_tokens: m.total_tokens,
  }));
  return (
    <AilaChart
      type="area"
      data={points}
      dataKey="total_cost_usd"
      xKey="year_month"
      colors={[accent]}
      size="md"
      ariaLabel="Monthly LLM cost trend"
    />
  );
}

// ---------------------------------------------------------------------------
// Model usage chart -- per-model rollup pie across the requested window
// ---------------------------------------------------------------------------
//
// Which models drove spend in the selected window. Sourced from the same
// `/cost/history` payload as the trend above; no extra round trip.

function ModelUsageChart({
  rows,
  palette,
}: {
  rows: ModelUsageEntry[];
  palette: string[];
}) {
  if (rows.length === 0) {
    return (
      <p className="font-mono text-xs text-text-muted">
        No model-level cost records in the selected window.
      </p>
    );
  }
  const data = rows.map((r) => ({
    ...r,
    cost_usd: Math.round(r.cost_usd * 10000) / 10000,
  }));
  return (
    <AilaChart
      type="pie"
      data={data}
      dataKey="cost_usd"
      xKey="model_id"
      colors={palette}
      size="md"
      ariaLabel="Cost distribution by model"
    />
  );
}

// ---------------------------------------------------------------------------
// Per-run breakdown -- GET /cost/runs/{run_id}
// ---------------------------------------------------------------------------

function RunBreakdownTable({ data }: { data: CostBreakdownResponse }) {
  if (data.models.length === 0) {
    return (
      <p className="font-mono text-xs text-text-muted">
        No per-model cost records for run{" "}
        <span className="text-text">{data.run_id}</span>.
      </p>
    );
  }
  return (
    <div className="overflow-x-auto">
      <table aria-label="Cost aggregates" className="w-full font-mono text-xs">
        <thead>
          <tr className="text-left text-text-muted">
            <th className="py-1.5 pr-4 font-normal uppercase tracking-wider">
              Model
            </th>
            <th className="py-1.5 pr-4 font-normal uppercase tracking-wider text-right">
              Calls
            </th>
            <th className="py-1.5 pr-4 font-normal uppercase tracking-wider text-right">
              Prompt tok
            </th>
            <th className="py-1.5 pr-4 font-normal uppercase tracking-wider text-right">
              Completion tok
            </th>
            <th className="py-1.5 pr-4 font-normal uppercase tracking-wider text-right">
              Total tok
            </th>
            <th className="py-1.5 font-normal uppercase tracking-wider text-right">
              Cost
            </th>
          </tr>
        </thead>
        <tbody>
          {data.models.map((m) => (
            <tr key={m.model_id} className="border-t border-border">
              <td className="py-1.5 pr-4 text-text">{m.model_id}</td>
              <td className="py-1.5 pr-4 text-right text-text-muted">
                {formatTokens(m.call_count)}
              </td>
              <td className="py-1.5 pr-4 text-right text-text-muted">
                {formatTokens(m.prompt_tokens)}
              </td>
              <td className="py-1.5 pr-4 text-right text-text-muted">
                {formatTokens(m.completion_tokens)}
              </td>
              <td className="py-1.5 pr-4 text-right text-text-muted">
                {formatTokens(m.total_tokens)}
              </td>
              <td className="py-1.5 text-right text-text">
                {formatUsd(m.cost_usd, 4)}
              </td>
            </tr>
          ))}
          <tr className="border-t border-border">
            <td className="py-1.5 pr-4 text-text font-semibold" colSpan={4}>
              Total
            </td>
            <td className="py-1.5 pr-4 text-right text-text">
              {formatTokens(data.total_tokens)}
            </td>
            <td className="py-1.5 text-right text-text font-semibold">
              {formatUsd(data.total_cost_usd, 4)}
            </td>
          </tr>
        </tbody>
      </table>
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

const DEFAULT_ESTIMATE_TASK_TYPES = "vulnerability_scan, remediation_planning";
const DEFAULT_HUMAN_TASK_TYPES = "triage, remediation_planning";

export function CostPage() {
  const [historyMonths, setHistoryMonths] = useState(6);
  const [roiMonths, setRoiMonths] = useState(3);

  // Per-run drilldown state
  const [runIdInput, setRunIdInput] = useState("");
  const [activeRunId, setActiveRunId] = useState<string | null>(null);

  // Pre-scan estimate state
  const [estTargetCount, setEstTargetCount] = useState("10");
  const [estTaskTypesRaw, setEstTaskTypesRaw] = useState(
    DEFAULT_ESTIMATE_TASK_TYPES,
  );
  const [estResult, setEstResult] = useState<CostEstimateResponse | null>(null);
  const [estError, setEstError] = useState<string | null>(null);

  // Human-equivalent estimate state
  const [humRunId, setHumRunId] = useState("");
  const [humTargetCount, setHumTargetCount] = useState("10");
  const [humFindingCount, setHumFindingCount] = useState("0");
  const [humDurationMinutes, setHumDurationMinutes] = useState("60");
  const [humTaskTypesRaw, setHumTaskTypesRaw] = useState(
    DEFAULT_HUMAN_TASK_TYPES,
  );
  const [humResult, setHumResult] = useState<HumanEstimateResponse | null>(
    null,
  );
  const [humError, setHumError] = useState<string | null>(null);

  const historyQuery = useCostHistory(historyMonths);
  const roiQuery = useCostRoi(roiMonths);
  const runQuery = useRunCostBreakdown(activeRunId);
  const estimateMutation = useEstimateScanCost();
  const humanMutation = useEstimateHumanCost();

  const history = historyQuery.data?.data;
  const roi = roiQuery.data?.data;
  const runBreakdown = runQuery.data?.data;

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

  // Chart palette resolved from active theme so recharts SVG fills render
  // reliably (CSS var(--*) doesn't resolve in SVG presentation attributes).
  const themeColors = useThemeChartColors();

  // Per-model rollup across the requested history window -- reuses the same
  // /cost/history payload the trend card renders (no extra request).
  const modelRollup = useMemo(
    () => aggregateModelsAcrossMonths(months),
    [months],
  );

  // Palette for the model-usage pie: cycle through the semantic accents so
  // no two adjacent slices share a hue. Slice count is small (few LLMs per
  // window) so a 6-color rotation is plenty.
  const modelPalette = useMemo<string[]>(
    () => [
      themeColors.accent,
      themeColors.high,
      themeColors.medium,
      themeColors.critical,
      themeColors.low,
      themeColors.textMuted,
    ],
    [themeColors],
  );

  function handleRunSubmit(e: React.FormEvent) {
    e.preventDefault();
    const trimmed = runIdInput.trim();
    if (trimmed.length === 0) {
      setActiveRunId(null);
      return;
    }
    setActiveRunId(trimmed);
  }

  function handleEstimateSubmit(e: React.FormEvent) {
    e.preventDefault();
    setEstError(null);
    setEstResult(null);
    const targetCount = Number(estTargetCount);
    if (!Number.isInteger(targetCount) || targetCount < 1) {
      setEstError("target_count must be a positive integer");
      return;
    }
    const taskTypes = parseList(estTaskTypesRaw);
    if (taskTypes.length === 0) {
      setEstError("Provide at least one task_type");
      return;
    }
    if (taskTypes.length > 20) {
      setEstError("task_types capped at 20 entries");
      return;
    }
    estimateMutation.mutate(
      { target_count: targetCount, task_types: taskTypes },
      {
        onSuccess: (envelope) => setEstResult(envelope.data),
        onError: (err: unknown) =>
          setEstError(err instanceof Error ? err.message : "Estimate failed"),
      },
    );
  }

  function handleHumanSubmit(e: React.FormEvent) {
    e.preventDefault();
    setHumError(null);
    setHumResult(null);
    const runId = humRunId.trim();
    if (!runId) {
      setHumError("run_id is required");
      return;
    }
    const targetCount = Number(humTargetCount);
    const findingCount = Number(humFindingCount);
    const durationMinutes = Number(humDurationMinutes);
    if (!Number.isInteger(targetCount) || targetCount < 1) {
      setHumError("target_count must be a positive integer");
      return;
    }
    if (!Number.isInteger(findingCount) || findingCount < 0) {
      setHumError("finding_count must be a non-negative integer");
      return;
    }
    if (!Number.isFinite(durationMinutes) || durationMinutes < 0) {
      setHumError("scan_duration_minutes must be a non-negative number");
      return;
    }
    const taskTypes = parseList(humTaskTypesRaw);
    if (taskTypes.length === 0) {
      setHumError("Provide at least one task_types_performed entry");
      return;
    }
    if (taskTypes.length > 50) {
      setHumError("task_types_performed capped at 50 entries");
      return;
    }
    humanMutation.mutate(
      {
        run_id: runId,
        target_count: targetCount,
        finding_count: findingCount,
        task_types_performed: taskTypes,
        scan_duration_minutes: durationMinutes,
      },
      {
        onSuccess: (envelope) => setHumResult(envelope.data),
        onError: (err: unknown) =>
          setHumError(err instanceof Error ? err.message : "Estimate failed"),
      },
    );
  }

  return (
    <div className="flex flex-col gap-6 p-4 lg:p-6">
      {/* Top metric cards */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <AilaCard variant="elevated" padding="md" techBorder glow>
          <p className="font-mono text-xs uppercase tracking-wider text-text-muted">
            Total Cost ({historyMonths}m)
          </p>
          <p className="font-mono text-2xl font-semibold text-text mt-1">
            {historyQuery.isLoading ? "--" : formatUsd(grandTotal, 2)}
          </p>
          <p className="font-mono text-xs text-text-muted mt-0.5">
            Sum of monthly spend
          </p>
        </AilaCard>

        <AilaCard variant="elevated" padding="md" techBorder glow>
          <p className="font-mono text-xs uppercase tracking-wider text-text-muted">
            Cost / Scan
          </p>
          <p className="font-mono text-2xl font-semibold text-text mt-1">
            {roiQuery.isLoading ? "--" : formatUsd(costPerRun, 4)}
          </p>
          <p className="font-mono text-xs text-text-muted mt-0.5">
            {roi ? `${roi.run_count} runs · ${roiMonths}m` : "--"}
          </p>
        </AilaCard>

        <AilaCard variant="elevated" padding="md" techBorder glow>
          <p className="font-mono text-xs uppercase tracking-wider text-text-muted">
            MoM Trend
          </p>
          <p className="font-mono text-2xl font-semibold text-text mt-1 flex items-center gap-1.5">
            {historyQuery.isLoading || trendDelta === null
              ? "--"
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
          </p>
        </AilaCard>

        <AilaCard variant="elevated" padding="md" techBorder glow>
          <p className="font-mono text-xs uppercase tracking-wider text-text-muted">
            ROI ({roiMonths}m)
          </p>
          <p
            className={`font-mono text-2xl font-semibold mt-1 ${
              roi && roi.roi_percentage >= 0 ? "text-low" : "text-high"
            }`}
          >
            {roiQuery.isLoading || !roi
              ? "--"
              : `${roi.roi_percentage >= 0 ? "+" : ""}${roi.roi_percentage.toFixed(1)}%`}
          </p>
          <p className="font-mono text-xs text-text-muted mt-0.5">
            vs human-equivalent
          </p>
        </AilaCard>
      </div>

      {/* History card */}
      <AilaCard variant="default" padding="md" techBorder glow>
        <div className="flex items-center justify-between mb-4">
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
                className={`touch-target px-2.5 py-1 rounded-[2px] border font-mono text-xs transition-colors ${
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
            Failed to load cost history:{" "}
            {(historyQuery.error as Error).message}
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
        )}
      </AilaCard>

      {/* Cost trend + Model usage side-by-side on wide viewports. Both feed
          off the same /cost/history payload so no extra request fires. */}
      {!historyQuery.isLoading && !historyQuery.isError && months.length > 0 && (
        <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
          <AilaCard variant="default" padding="md" techBorder glow>
            <div className="flex items-center gap-2 mb-3">
              <ChartLineUp className="h-4 w-4 text-accent" />
              <h2 className="font-mono text-sm font-semibold text-text">
                Cost over time
              </h2>
            </div>
            <p className="font-mono text-xs text-text-muted mb-3">
              Monthly LLM spend across the selected window.
            </p>
            <CostTrendChart months={months} accent={themeColors.accent} />
          </AilaCard>

          <AilaCard variant="default" padding="md" techBorder glow>
            <div className="flex items-center gap-2 mb-3">
              <CurrencyDollar className="h-4 w-4 text-accent" />
              <h2 className="font-mono text-sm font-semibold text-text">
                Model usage
              </h2>
            </div>
            <p className="font-mono text-xs text-text-muted mb-3">
              Cost distribution by model across the selected window
              {modelRollup.length > 0
                ? ` \u00b7 ${modelRollup.length} model${modelRollup.length === 1 ? "" : "s"}`
                : ""}
              .
            </p>
            <ModelUsageChart rows={modelRollup} palette={modelPalette} />
          </AilaCard>
        </div>
      )}

      {/* ROI card */}
      <AilaCard variant="default" padding="md" techBorder glow>
        <div className="flex items-center justify-between mb-4">
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
                className={`touch-target px-2.5 py-1 rounded-[2px] border font-mono text-xs transition-colors ${
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
        )}
      </AilaCard>

      {/* Per-run drilldown -- GET /cost/runs/{run_id} */}
      <AilaCard variant="default" padding="md" techBorder glow>
        <div className="flex items-center gap-2 mb-3">
          <MagnifyingGlass className="h-4 w-4 text-accent" />
          <h2 className="font-mono text-sm font-semibold text-text">
            Run cost drilldown
          </h2>
        </div>
        <p className="font-mono text-xs text-text-muted mb-4">
          Look up per-model cost for a single scan run. Uses the run_id
          returned by the scan submit endpoint.
        </p>
        <form
          className="flex flex-col gap-2 sm:flex-row sm:items-end"
          onSubmit={handleRunSubmit}
        >
          <div className="flex flex-col gap-1 flex-1">
            <label
              className="font-mono text-xs text-text-muted"
              htmlFor="cost-run-id"
            >
              Run ID
            </label>
            <Input
              id="cost-run-id"
              value={runIdInput}
              onChange={(e) => setRunIdInput(e.target.value)}
              placeholder="e.g. 4f0f1b6c-…"
              className="touch-target font-mono text-sm"
            />
          </div>
          <Button
            type="submit"
            size="sm"
            className="gap-1.5"
            disabled={runIdInput.trim().length === 0 || runQuery.isFetching}
          >
            <MagnifyingGlass className="h-4 w-4" />
            {runQuery.isFetching ? "Loading…" : "Load run"}
          </Button>
        </form>

        {runQuery.isError && (
          <div className="mt-3 rounded-[4px] border border-destructive bg-destructive/10 px-4 py-3 font-mono text-xs text-destructive">
            Failed to load run cost: {(runQuery.error as Error).message}
          </div>
        )}

        {runBreakdown && (
          <div className="mt-4 flex flex-col gap-3">
            <div className="flex flex-wrap items-center gap-3 font-mono text-xs">
              <span className="text-text-muted">Run</span>
              <span className="text-text">{runBreakdown.run_id}</span>
              <span className="text-text-muted">Total</span>
              <span className="text-text">
                {formatUsd(runBreakdown.total_cost_usd, 4)}
              </span>
              <span className="text-text-muted">Tokens</span>
              <span className="text-text">
                {formatTokens(runBreakdown.total_tokens)}
              </span>
            </div>
            <RunBreakdownTable data={runBreakdown} />
          </div>
        )}
      </AilaCard>

      {/* Pre-scan estimate -- POST /cost/estimate */}
      <AilaCard variant="default" padding="md" techBorder glow>
        <div className="flex items-center gap-2 mb-3">
          <Calculator className="h-4 w-4 text-accent" />
          <h2 className="font-mono text-sm font-semibold text-text">
            Pre-scan cost estimate
          </h2>
        </div>
        <p className="font-mono text-xs text-text-muted mb-4">
          Projects LLM spend for a hypothetical scan from your team's
          historical averages per task_type. Falls back to worst-case
          multipliers when the team has no prior scans.
        </p>
        <form
          className="grid grid-cols-1 gap-3 sm:grid-cols-3"
          onSubmit={handleEstimateSubmit}
        >
          <div className="flex flex-col gap-1">
            <label
              className="font-mono text-xs text-text-muted"
              htmlFor="est-targets"
            >
              Target count
            </label>
            <Input
              id="est-targets"
              value={estTargetCount}
              onChange={(e) => setEstTargetCount(e.target.value)}
              inputMode="numeric"
              className="touch-target font-mono text-sm"
            />
          </div>
          <div className="flex flex-col gap-1 sm:col-span-2">
            <label
              className="font-mono text-xs text-text-muted"
              htmlFor="est-tasks"
            >
              Task types (comma-separated, max 20)
            </label>
            <Input
              id="est-tasks"
              value={estTaskTypesRaw}
              onChange={(e) => setEstTaskTypesRaw(e.target.value)}
              placeholder="vulnerability_scan, remediation_planning"
              className="touch-target font-mono text-sm"
            />
          </div>
          <div className="sm:col-span-3">
            <Button
              type="submit"
              size="sm"
              className="gap-1.5"
              disabled={estimateMutation.isPending}
            >
              <Calculator className="h-4 w-4" />
              {estimateMutation.isPending ? "Estimating…" : "Estimate cost"}
            </Button>
          </div>
        </form>

        {estError && (
          <div className="mt-3 rounded-[4px] border border-destructive bg-destructive/10 px-4 py-3 font-mono text-xs text-destructive">
            {estError}
          </div>
        )}

        {estResult && (
          <div className="mt-4 flex flex-col gap-3">
            <div className="flex flex-wrap items-center gap-3 font-mono text-sm">
              <span className="text-text-muted uppercase tracking-wider text-xs">
                Projected
              </span>
              <span className="text-text text-lg">
                {formatUsd(estResult.estimated_cost_usd, 4)}
              </span>
              <AilaBadge
                severity={confidenceTone(estResult.confidence)}
                size="sm"
              >
                {estResult.confidence}
              </AilaBadge>
            </div>
            {estResult.breakdown.length > 0 && (
              <div className="overflow-x-auto">
                <table aria-label="Cost breakdown" className="w-full font-mono text-xs">
                  <thead>
                    <tr className="text-left text-text-muted">
                      <th className="py-1.5 pr-4 font-normal uppercase tracking-wider">
                        Task type
                      </th>
                      <th className="py-1.5 pr-4 font-normal uppercase tracking-wider text-right">
                        Avg cost / target
                      </th>
                      <th className="py-1.5 font-normal uppercase tracking-wider text-right">
                        Sample size
                      </th>
                    </tr>
                  </thead>
                  <tbody>
                    {estResult.breakdown.map((row) => (
                      <tr
                        key={row.task_type}
                        className="border-t border-border"
                      >
                        <td className="py-1.5 pr-4 text-text">
                          {row.task_type}
                        </td>
                        <td className="py-1.5 pr-4 text-right text-text-muted">
                          {formatUsd(row.avg_cost_usd, 6)}
                        </td>
                        <td className="py-1.5 text-right text-text-muted">
                          {formatTokens(row.sample_count)}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        )}
      </AilaCard>

      {/* Human-equivalent estimate -- POST /cost/estimate-human */}
      <AilaCard variant="default" padding="md" techBorder glow>
        <div className="flex items-center gap-2 mb-3">
          <UsersThree className="h-4 w-4 text-accent" />
          <h2 className="font-mono text-sm font-semibold text-text">
            Human-equivalent estimate
          </h2>
        </div>
        <p className="font-mono text-xs text-text-muted mb-4">
          For a completed run, project what the same triage and remediation
          work would cost done by a human. Feeds the ROI ledger.
        </p>
        <form
          className="grid grid-cols-1 gap-3 sm:grid-cols-2"
          onSubmit={handleHumanSubmit}
        >
          <div className="flex flex-col gap-1 sm:col-span-2">
            <label
              className="font-mono text-xs text-text-muted"
              htmlFor="hum-run-id"
            >
              Run ID
            </label>
            <Input
              id="hum-run-id"
              value={humRunId}
              onChange={(e) => setHumRunId(e.target.value)}
              placeholder="Completed scan run_id"
              className="touch-target font-mono text-sm"
            />
          </div>
          <div className="flex flex-col gap-1">
            <label
              className="font-mono text-xs text-text-muted"
              htmlFor="hum-targets"
            >
              Target count
            </label>
            <Input
              id="hum-targets"
              value={humTargetCount}
              onChange={(e) => setHumTargetCount(e.target.value)}
              inputMode="numeric"
              className="touch-target font-mono text-sm"
            />
          </div>
          <div className="flex flex-col gap-1">
            <label
              className="font-mono text-xs text-text-muted"
              htmlFor="hum-findings"
            >
              Finding count
            </label>
            <Input
              id="hum-findings"
              value={humFindingCount}
              onChange={(e) => setHumFindingCount(e.target.value)}
              inputMode="numeric"
              className="touch-target font-mono text-sm"
            />
          </div>
          <div className="flex flex-col gap-1">
            <label
              className="font-mono text-xs text-text-muted"
              htmlFor="hum-duration"
            >
              Scan duration (min)
            </label>
            <Input
              id="hum-duration"
              value={humDurationMinutes}
              onChange={(e) => setHumDurationMinutes(e.target.value)}
              inputMode="decimal"
              className="touch-target font-mono text-sm"
            />
          </div>
          <div className="flex flex-col gap-1">
            <label
              className="font-mono text-xs text-text-muted"
              htmlFor="hum-tasks"
            >
              Task types performed (max 50)
            </label>
            <Input
              id="hum-tasks"
              value={humTaskTypesRaw}
              onChange={(e) => setHumTaskTypesRaw(e.target.value)}
              placeholder="triage, remediation_planning"
              className="touch-target font-mono text-sm"
            />
          </div>
          <div className="sm:col-span-2">
            <Button
              type="submit"
              size="sm"
              className="gap-1.5"
              disabled={humanMutation.isPending}
            >
              <UsersThree className="h-4 w-4" />
              {humanMutation.isPending
                ? "Estimating…"
                : "Estimate human cost"}
            </Button>
          </div>
        </form>

        {humError && (
          <div className="mt-3 rounded-[4px] border border-destructive bg-destructive/10 px-4 py-3 font-mono text-xs text-destructive">
            {humError}
          </div>
        )}

        {humResult && (
          <div className="mt-4 flex flex-col gap-3">
            <div className="flex flex-wrap items-center gap-3 font-mono text-sm">
              <span className="text-text-muted uppercase tracking-wider text-xs">
                Human cost
              </span>
              <span className="text-text text-lg">
                {formatUsd(humResult.human_cost_usd, 2)}
              </span>
              <span className="text-text-muted uppercase tracking-wider text-xs">
                Hours
              </span>
              <span className="text-text">
                {humResult.estimated_hours.toFixed(1)}h
              </span>
              <AilaBadge
                severity={confidenceTone(humResult.confidence)}
                size="sm"
              >
                {humResult.confidence}
              </AilaBadge>
            </div>
            {humResult.reasoning && (
              <div
                className="rounded-[4px] border border-border bg-base px-3 py-2 font-mono text-xs text-text-muted whitespace-pre-wrap"
                // reasoning is html-escaped server-side (schemas/cost.py:sanitize_reasoning)
                dangerouslySetInnerHTML={{ __html: humResult.reasoning }}
              />
            )}
          </div>
        )}
      </AilaCard>
    </div>
  );
}
