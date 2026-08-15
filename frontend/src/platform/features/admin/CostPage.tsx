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

import { WindowPanel } from "@/components/aila/WindowPanel";
import { AilaChart } from "@/components/aila/AilaChart";
import { LoadingSkeletonGroup } from "@/components/aila/LoadingSkeleton";
import {
  SectionHeader,
  FilterChip,
  BigStat,
  StatBar,
  MonoBadge,
  DataGrid,
} from "@/components/aila/mock";
import { FeatureBoundary } from "@app/FeatureBoundary";
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

type ConfidenceTone = "critical" | "high" | "medium" | "low" | "muted";

function confidenceTone(confidence: string): ConfidenceTone {
  switch (confidence) {
    case "high":
    case "historical":
      return "low";
    case "medium":
      return "medium";
    case "low":
    case "worst_case":
      return "high";
    default:
      return "muted";
  }
}

// ---------------------------------------------------------------------------
// Mock chrome
// ---------------------------------------------------------------------------

const BTN_STYLE: React.CSSProperties = {
  height: 26,
  fontSize: 9.5,
  padding: "0 11px",
  letterSpacing: "0.08em",
  borderRadius: 3,
  border: "1px solid var(--border-soft)",
  background: "var(--surface-sunk)",
  color: "var(--text-primary)",
  cursor: "pointer",
  fontFamily: "var(--font-mono)",
  textTransform: "uppercase",
};

const BTN_ACCENT_STYLE: React.CSSProperties = {
  ...BTN_STYLE,
  border: "1px solid var(--accent)",
  background: "color-mix(in srgb, var(--accent) 14%, transparent)",
  color: "var(--accent)",
};

const INPUT_STYLE: React.CSSProperties = {
  height: 28,
  fontSize: 11,
  padding: "0 10px",
  borderRadius: 3,
  border: "1px solid var(--border-soft)",
  background: "var(--surface-sunk)",
  color: "var(--text-primary)",
  outline: "none",
  fontFamily: "var(--font-mono)",
  width: "100%",
};

const LABEL_STYLE: React.CSSProperties = {
  fontSize: 9,
  letterSpacing: "0.1em",
  color: "var(--text-faint)",
  fontFamily: "var(--font-mono)",
  textTransform: "uppercase",
};

function ErrorBox({ children }: { children: React.ReactNode }) {
  return (
    <div
      className="font-mono"
      style={{
        border:
          "1px solid color-mix(in srgb, var(--status-warn) 40%, transparent)",
        background: "color-mix(in srgb, var(--status-warn) 10%, transparent)",
        color: "var(--status-warn)",
        padding: "8px 12px",
        fontSize: 11,
        borderRadius: 3,
      }}
    >
      {children}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Monthly trend bars (inline StatBar per month with per-model chips beneath)
// ---------------------------------------------------------------------------

function MonthlyTrend({ months }: { months: MonthlyCostEntry[] }) {
  if (months.length === 0) {
    return (
      <p
        className="font-mono"
        style={{ fontSize: 11, color: "var(--text-muted)" }}
      >
        no cost data in the selected window.
      </p>
    );
  }
  const max = Math.max(...months.map((m) => m.total_cost_usd), 0.0001);

  return (
    <div className="flex flex-col" style={{ gap: 10 }}>
      {months.map((m) => (
        <div key={m.year_month} className="flex flex-col" style={{ gap: 4 }}>
          <div
            className="flex items-center justify-between font-mono"
            style={{ fontSize: 10.5 }}
          >
            <span style={{ color: "var(--text-faint)" }}>{m.year_month}</span>
            <span style={{ color: "var(--text-primary)" }}>
              {formatUsd(m.total_cost_usd, 4)}
              {"  \u00b7  "}
              <span style={{ color: "var(--text-faint)" }}>
                {formatTokens(m.total_tokens)} tokens
              </span>
            </span>
          </div>
          <StatBar
            label={m.year_month.slice(-5)}
            color="var(--accent)"
            value={Math.round((m.total_cost_usd / max) * 100)}
            max={100}
          />
          {m.models.length > 0 && (
            <div className="flex flex-wrap" style={{ gap: 5, marginTop: 2 }}>
              {m.models.map((mc) => (
                <MonoBadge
                  key={`${m.year_month}-${mc.model_id}`}
                  tone="muted"
                >
                  {mc.model_id}
                  {"  "}
                  <span style={{ color: "var(--text-muted)", marginLeft: 4 }}>
                    {formatUsd(mc.cost_usd, 4)}
                  </span>
                </MonoBadge>
              ))}
            </div>
          )}
        </div>
      ))}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Cost trend chart -- AilaChart area over months
// ---------------------------------------------------------------------------

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
// Model usage pie
// ---------------------------------------------------------------------------

function ModelUsageChart({
  rows,
  palette,
}: {
  rows: ModelUsageEntry[];
  palette: string[];
}) {
  if (rows.length === 0) {
    return (
      <p
        className="font-mono"
        style={{ fontSize: 11, color: "var(--text-muted)" }}
      >
        no model-level cost records in the selected window.
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
// Per-run breakdown -- DataGrid replacement of the old table
// ---------------------------------------------------------------------------

function RunBreakdownGrid({ data }: { data: CostBreakdownResponse }) {
  if (data.models.length === 0) {
    return (
      <p
        className="font-mono"
        style={{ fontSize: 11, color: "var(--text-muted)" }}
      >
        no per-model cost records for run{" "}
        <span style={{ color: "var(--text-primary)" }}>{data.run_id}</span>.
      </p>
    );
  }
  return (
    <DataGrid
      columns={[
        { label: "MODEL", width: "1fr" },
        { label: "CALLS", width: "80px", align: "right" },
        { label: "PROMPT", width: "110px", align: "right" },
        { label: "COMPLETION", width: "120px", align: "right" },
        { label: "TOTAL TOK", width: "110px", align: "right" },
        { label: "COST", width: "110px", align: "right" },
      ]}
      rows={data.models}
      getKey={(m) => m.model_id}
      renderCells={(m) => [
        <span
          key="m"
          style={{ color: "var(--text-primary)", fontSize: 11 }}
        >
          {m.model_id}
        </span>,
        <span
          key="c"
          style={{ color: "var(--text-muted)", fontSize: 11 }}
        >
          {formatTokens(m.call_count)}
        </span>,
        <span
          key="p"
          style={{ color: "var(--text-muted)", fontSize: 11 }}
        >
          {formatTokens(m.prompt_tokens)}
        </span>,
        <span
          key="cp"
          style={{ color: "var(--text-muted)", fontSize: 11 }}
        >
          {formatTokens(m.completion_tokens)}
        </span>,
        <span
          key="t"
          style={{ color: "var(--text-muted)", fontSize: 11 }}
        >
          {formatTokens(m.total_tokens)}
        </span>,
        <span
          key="$"
          style={{ color: "var(--text-primary)", fontSize: 11 }}
        >
          {formatUsd(m.cost_usd, 4)}
        </span>,
      ]}
    />
  );
}

// ---------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------

const RANGE_OPTIONS: { label: string; months: number }[] = [
  { label: "1M", months: 1 },
  { label: "3M", months: 3 },
  { label: "6M", months: 6 },
  { label: "12M", months: 12 },
];

const DEFAULT_ESTIMATE_TASK_TYPES = "vulnerability_scan, remediation_planning";
const DEFAULT_HUMAN_TASK_TYPES = "triage, remediation_planning";

export function CostPage() {
  const [historyMonths, setHistoryMonths] = useState(6);
  const [roiMonths, setRoiMonths] = useState(3);
  const [moduleFilter, setModuleFilter] = useState<string | null>(null);

  const [runIdInput, setRunIdInput] = useState("");
  const [activeRunId, setActiveRunId] = useState<string | null>(null);

  const [estTargetCount, setEstTargetCount] = useState("10");
  const [estTaskTypesRaw, setEstTaskTypesRaw] = useState(
    DEFAULT_ESTIMATE_TASK_TYPES,
  );
  const [estResult, setEstResult] = useState<CostEstimateResponse | null>(null);
  const [estError, setEstError] = useState<string | null>(null);

  const [humRunId, setHumRunId] = useState("");
  const [humTargetCount, setHumTargetCount] = useState("10");
  const [humFindingCount, setHumFindingCount] = useState("0");
  const [humDurationMinutes, setHumDurationMinutes] = useState("60");
  const [humTaskTypesRaw, setHumTaskTypesRaw] = useState(
    DEFAULT_HUMAN_TASK_TYPES,
  );
  const [humResult, setHumResult] = useState<HumanEstimateResponse | null>(null);
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

  const themeColors = useThemeChartColors();

  const modelRollup = useMemo(
    () => aggregateModelsAcrossMonths(months),
    [months],
  );

  const filteredRollup = useMemo(() => {
    if (!moduleFilter) return modelRollup;
    // The rollup is keyed by model_id; "module" here is best-effort match
    // against the model_id string (e.g. filter by provider prefix).
    return modelRollup.filter((r) =>
      r.model_id.toLowerCase().includes(moduleFilter.toLowerCase()),
    );
  }, [modelRollup, moduleFilter]);

  const rollupTotal = useMemo(
    () => filteredRollup.reduce((sum, r) => sum + r.cost_usd, 0),
    [filteredRollup],
  );

  const providerFacets = useMemo(() => {
    const set = new Set<string>();
    for (const r of modelRollup) {
      const [head] = r.model_id.split(/[/:]/);
      if (head) set.add(head);
    }
    return Array.from(set).sort();
  }, [modelRollup]);

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

  const trendGlyph =
    trendDelta === null ? "" : trendDelta >= 0 ? " \u25b2" : " \u25bc";

  return (
    <div className="flex flex-col" style={{ gap: 16, padding: 20 }}>
      <SectionHeader
        icon={"\u25c9"}
        title="LLM cost"
        actions={
          <div className="flex items-center" style={{ gap: 6 }}>
            {RANGE_OPTIONS.map((opt) => (
              <FilterChip
                key={opt.label}
                active={historyMonths === opt.months}
                color="var(--accent)"
                onClick={() => setHistoryMonths(opt.months)}
              >
                {opt.label}
              </FilterChip>
            ))}
          </div>
        }
      />

      {/* Filter chip row: modules / providers */}
      {providerFacets.length > 0 && (
        <div className="flex flex-wrap items-center" style={{ gap: 6 }}>
          <span
            className="font-mono uppercase"
            style={{
              fontSize: 9,
              letterSpacing: "0.1em",
              color: "var(--text-faint)",
              marginRight: 4,
            }}
          >
            module
          </span>
          <FilterChip
            active={moduleFilter === null}
            color="var(--status-info)"
            onClick={() => setModuleFilter(null)}
          >
            ALL
          </FilterChip>
          {providerFacets.map((facet) => (
            <FilterChip
              key={facet}
              active={moduleFilter === facet}
              color="var(--status-info)"
              onClick={() =>
                setModuleFilter(moduleFilter === facet ? null : facet)
              }
            >
              {facet}
            </FilterChip>
          ))}
        </div>
      )}

      {/* BigStat headline row */}
      <div
        className="grid"
        style={{
          gridTemplateColumns: "repeat(4, minmax(0, 1fr))",
          gap: 12,
        }}
      >
        <WindowPanel title={`total spend / ${historyMonths}m`}>
          <BigStat
            value={formatUsd(grandTotal, 2)}
            sub="sum of monthly spend"
          />
        </WindowPanel>
        <WindowPanel title="cost / scan">
          <BigStat
            value={formatUsd(costPerRun, 4)}
            sub={roi ? `${roi.run_count} runs \u00b7 ${roiMonths}m` : "\u2014"}
          />
        </WindowPanel>
        <WindowPanel title="mom trend">
          <BigStat
            value={
              trendDelta === null
                ? "\u2014"
                : `${trendDelta >= 0 ? "+" : ""}${trendDelta.toFixed(1)}%${trendGlyph}`
            }
            sub="latest vs previous month"
          />
        </WindowPanel>
        <WindowPanel title={`roi / ${roiMonths}m`}>
          <BigStat
            value={
              !roi
                ? "\u2014"
                : `${roi.roi_percentage >= 0 ? "+" : ""}${roi.roi_percentage.toFixed(1)}%`
            }
            sub="vs human-equivalent"
          />
        </WindowPanel>
      </div>

      {/* Trend + model usage side-by-side */}
      {!historyQuery.isLoading && !historyQuery.isError && months.length > 0 && (
        <div
          className="grid"
          style={{ gridTemplateColumns: "1fr 1fr", gap: 12 }}
        >
          <FeatureBoundary
            label="Cost over time chart"
            resetKeys={[historyMonths, months.length]}
            onReset={() => void historyQuery.refetch()}
          >
            <WindowPanel title="cost over time">
              <p
                className="font-mono"
                style={{
                  fontSize: 10.5,
                  color: "var(--text-muted)",
                  marginBottom: 8,
                }}
              >
                monthly LLM spend across the selected window.
              </p>
              <CostTrendChart months={months} accent={themeColors.accent} />
            </WindowPanel>
          </FeatureBoundary>

          <FeatureBoundary
            label="Model usage chart"
            resetKeys={[historyMonths, filteredRollup.length]}
            onReset={() => void historyQuery.refetch()}
          >
            <WindowPanel title="model usage">
              <p
                className="font-mono"
                style={{
                  fontSize: 10.5,
                  color: "var(--text-muted)",
                  marginBottom: 8,
                }}
              >
                cost distribution by model across the selected window
                {filteredRollup.length > 0
                  ? ` \u00b7 ${filteredRollup.length} model${filteredRollup.length === 1 ? "" : "s"}`
                  : ""}
                .
              </p>
              <ModelUsageChart rows={filteredRollup} palette={modelPalette} />
            </WindowPanel>
          </FeatureBoundary>
        </div>
      )}

      {/* Breakdown by module (rollup grid) */}
      {!historyQuery.isLoading && !historyQuery.isError && filteredRollup.length > 0 && (
        <WindowPanel title="breakdown by module" flush>
          <DataGrid
            columns={[
              { label: "MODEL", width: "1fr" },
              { label: "CALLS", width: "90px", align: "right" },
              { label: "TOTAL TOKENS", width: "140px", align: "right" },
              { label: "COST", width: "120px", align: "right" },
              { label: "SHARE", width: "80px", align: "right" },
            ]}
            rows={filteredRollup}
            getKey={(r) => r.model_id}
            renderCells={(r) => [
              <span
                key="m"
                style={{ color: "var(--text-primary)", fontSize: 11 }}
              >
                {r.model_id}
              </span>,
              <span
                key="c"
                style={{ color: "var(--text-muted)", fontSize: 11 }}
              >
                {formatTokens(r.call_count)}
              </span>,
              <span
                key="t"
                style={{ color: "var(--text-muted)", fontSize: 11 }}
              >
                {formatTokens(r.total_tokens)}
              </span>,
              <span
                key="$"
                style={{ color: "var(--text-primary)", fontSize: 11 }}
              >
                {formatUsd(r.cost_usd, 4)}
              </span>,
              <span
                key="s"
                style={{ color: "var(--text-faint)", fontSize: 10.5 }}
              >
                {rollupTotal === 0
                  ? "\u2014"
                  : `${((r.cost_usd / rollupTotal) * 100).toFixed(1)}%`}
              </span>,
            ]}
          />
        </WindowPanel>
      )}

      {/* Trend detail (inline bars) */}
      <FeatureBoundary
        label="Cost trend"
        resetKeys={[historyMonths]}
        onReset={() => void historyQuery.refetch()}
      >
        <WindowPanel title="trend">
          {historyQuery.isError && (
            <ErrorBox>
              failed to load cost history:{" "}
              {(historyQuery.error as Error).message}
            </ErrorBox>
          )}
          {historyQuery.isLoading && <LoadingSkeletonGroup lines={4} />}
          {!historyQuery.isLoading &&
            !historyQuery.isError &&
            months.length === 0 && (
              <p
                className="font-mono"
                style={{
                  padding: 22,
                  textAlign: "center",
                  fontSize: 12,
                  color: "var(--text-muted)",
                }}
              >
                no cost data. run a scan to start populating the ledger.
              </p>
            )}
          {!historyQuery.isLoading && months.length > 0 && (
            <MonthlyTrend months={months} />
          )}
        </WindowPanel>
      </FeatureBoundary>

      {/* ROI summary */}
      <FeatureBoundary
        label="ROI summary"
        resetKeys={[roiMonths]}
        onReset={() => void roiQuery.refetch()}
      >
        <WindowPanel
          title="roi summary"
          actions={
            <div className="flex items-center" style={{ gap: 5 }}>
              {RANGE_OPTIONS.map((opt) => (
                <FilterChip
                  key={opt.label}
                  active={roiMonths === opt.months}
                  color="var(--accent)"
                  onClick={() => setRoiMonths(opt.months)}
                >
                  {opt.label}
                </FilterChip>
              ))}
            </div>
          }
        >
          {roiQuery.isError && (
            <ErrorBox>
              failed to load ROI: {(roiQuery.error as Error).message}
            </ErrorBox>
          )}
          {roiQuery.isLoading && <LoadingSkeletonGroup lines={3} />}
          {!roiQuery.isLoading && !roiQuery.isError && roi && (
            <div
              className="grid"
              style={{
                gridTemplateColumns: "repeat(4, minmax(0, 1fr))",
                gap: 12,
              }}
            >
              <div>
                <span
                  className="font-mono uppercase"
                  style={{
                    fontSize: 9,
                    letterSpacing: "0.1em",
                    color: "var(--text-faint)",
                  }}
                >
                  llm spend
                </span>
                <p
                  className="font-mono"
                  style={{
                    fontSize: 16,
                    color: "var(--text-primary)",
                    marginTop: 2,
                  }}
                >
                  {formatUsd(roi.llm_cost_usd, 2)}
                </p>
              </div>
              <div>
                <span
                  className="font-mono uppercase"
                  style={{
                    fontSize: 9,
                    letterSpacing: "0.1em",
                    color: "var(--text-faint)",
                  }}
                >
                  human-equivalent
                </span>
                <p
                  className="font-mono"
                  style={{
                    fontSize: 16,
                    color: "var(--text-primary)",
                    marginTop: 2,
                  }}
                >
                  {formatUsd(roi.human_equivalent_cost_usd, 2)}
                </p>
                <p
                  className="font-mono"
                  style={{ fontSize: 10, color: "var(--text-faint)" }}
                >
                  {roi.human_equivalent_hours.toFixed(1)}h
                </p>
              </div>
              <div>
                <span
                  className="font-mono uppercase"
                  style={{
                    fontSize: 9,
                    letterSpacing: "0.1em",
                    color: "var(--text-faint)",
                  }}
                >
                  run count
                </span>
                <p
                  className="font-mono"
                  style={{
                    fontSize: 16,
                    color: "var(--text-primary)",
                    marginTop: 2,
                  }}
                >
                  {roi.run_count}
                </p>
              </div>
              <div>
                <span
                  className="font-mono uppercase"
                  style={{
                    fontSize: 9,
                    letterSpacing: "0.1em",
                    color: "var(--text-faint)",
                  }}
                >
                  period
                </span>
                <p
                  className="font-mono"
                  style={{
                    fontSize: 10.5,
                    color: "var(--text-primary)",
                    marginTop: 2,
                  }}
                >
                  {roi.period_start} {"\u2192"} {roi.period_end}
                </p>
              </div>
            </div>
          )}
        </WindowPanel>
      </FeatureBoundary>

      {/* Per-run drilldown */}
      <FeatureBoundary
        label="Run cost drilldown"
        resetKeys={[activeRunId]}
        onReset={() => void runQuery.refetch()}
      >
        <WindowPanel title="run cost drilldown">
          <p
            className="font-mono"
            style={{
              fontSize: 10.5,
              color: "var(--text-muted)",
              marginBottom: 10,
            }}
          >
            per-model cost for a single scan run. uses the run_id returned by
            the scan submit endpoint.
          </p>
          <form
            className="flex items-end"
            style={{ gap: 8, marginBottom: 12 }}
            onSubmit={handleRunSubmit}
          >
            <div className="flex flex-col" style={{ gap: 4, flex: 1 }}>
              <label style={LABEL_STYLE} htmlFor="cost-run-id">
                run id
              </label>
              <input
                id="cost-run-id"
                value={runIdInput}
                onChange={(e) => setRunIdInput(e.target.value)}
                placeholder="e.g. 4f0f1b6c-..."
                style={INPUT_STYLE}
              />
            </div>
            <button
              type="submit"
              style={BTN_ACCENT_STYLE}
              disabled={runIdInput.trim().length === 0 || runQuery.isFetching}
            >
              {runQuery.isFetching ? "LOADING\u2026" : "LOAD RUN"}
            </button>
          </form>
          {runQuery.isError && (
            <ErrorBox>
              failed to load run cost: {(runQuery.error as Error).message}
            </ErrorBox>
          )}
          {runBreakdown && (
            <div className="flex flex-col" style={{ gap: 10 }}>
              <div
                className="flex flex-wrap items-center font-mono"
                style={{ gap: 10, fontSize: 10.5 }}
              >
                <span style={{ color: "var(--text-faint)" }}>run</span>
                <span style={{ color: "var(--text-primary)" }}>
                  {runBreakdown.run_id}
                </span>
                <span style={{ color: "var(--text-faint)" }}>total</span>
                <span style={{ color: "var(--text-primary)" }}>
                  {formatUsd(runBreakdown.total_cost_usd, 4)}
                </span>
                <span style={{ color: "var(--text-faint)" }}>tokens</span>
                <span style={{ color: "var(--text-primary)" }}>
                  {formatTokens(runBreakdown.total_tokens)}
                </span>
              </div>
              <RunBreakdownGrid data={runBreakdown} />
            </div>
          )}
        </WindowPanel>
      </FeatureBoundary>

      {/* Pre-scan estimate */}
      <WindowPanel title="pre-scan cost estimate">
        <p
          className="font-mono"
          style={{
            fontSize: 10.5,
            color: "var(--text-muted)",
            marginBottom: 10,
          }}
        >
          projects LLM spend for a hypothetical scan from your team's
          historical averages per task_type. falls back to worst-case
          multipliers when the team has no prior scans.
        </p>
        <form
          className="grid"
          style={{
            gridTemplateColumns: "1fr 2fr",
            gap: 8,
            marginBottom: 12,
          }}
          onSubmit={handleEstimateSubmit}
        >
          <div className="flex flex-col" style={{ gap: 4 }}>
            <label style={LABEL_STYLE} htmlFor="est-targets">
              target count
            </label>
            <input
              id="est-targets"
              value={estTargetCount}
              onChange={(e) => setEstTargetCount(e.target.value)}
              inputMode="numeric"
              style={INPUT_STYLE}
            />
          </div>
          <div className="flex flex-col" style={{ gap: 4 }}>
            <label style={LABEL_STYLE} htmlFor="est-tasks">
              task types (max 20)
            </label>
            <input
              id="est-tasks"
              value={estTaskTypesRaw}
              onChange={(e) => setEstTaskTypesRaw(e.target.value)}
              placeholder="vulnerability_scan, remediation_planning"
              style={INPUT_STYLE}
            />
          </div>
          <div style={{ gridColumn: "1 / -1" }}>
            <button
              type="submit"
              style={BTN_ACCENT_STYLE}
              disabled={estimateMutation.isPending}
            >
              {estimateMutation.isPending ? "ESTIMATING\u2026" : "ESTIMATE COST"}
            </button>
          </div>
        </form>
        {estError && <ErrorBox>{estError}</ErrorBox>}
        {estResult && (
          <div
            className="flex flex-col"
            style={{ gap: 10, marginTop: 12 }}
          >
            <div
              className="flex flex-wrap items-center font-mono"
              style={{ gap: 10 }}
            >
              <span style={LABEL_STYLE}>projected</span>
              <span
                style={{
                  fontSize: 16,
                  color: "var(--text-primary)",
                }}
              >
                {formatUsd(estResult.estimated_cost_usd, 4)}
              </span>
              <MonoBadge tone={confidenceTone(estResult.confidence)}>
                {estResult.confidence}
              </MonoBadge>
            </div>
            {estResult.breakdown.length > 0 && (
              <DataGrid
                columns={[
                  { label: "TASK TYPE", width: "1fr" },
                  { label: "AVG COST / TARGET", width: "170px", align: "right" },
                  { label: "SAMPLE SIZE", width: "130px", align: "right" },
                ]}
                rows={estResult.breakdown}
                getKey={(r) => r.task_type}
                renderCells={(row) => [
                  <span
                    key="t"
                    style={{ color: "var(--text-primary)", fontSize: 11 }}
                  >
                    {row.task_type}
                  </span>,
                  <span
                    key="a"
                    style={{ color: "var(--text-muted)", fontSize: 11 }}
                  >
                    {formatUsd(row.avg_cost_usd, 6)}
                  </span>,
                  <span
                    key="s"
                    style={{ color: "var(--text-muted)", fontSize: 11 }}
                  >
                    {formatTokens(row.sample_count)}
                  </span>,
                ]}
              />
            )}
          </div>
        )}
      </WindowPanel>

      {/* Human-equivalent estimate */}
      <WindowPanel title="human-equivalent estimate">
        <p
          className="font-mono"
          style={{
            fontSize: 10.5,
            color: "var(--text-muted)",
            marginBottom: 10,
          }}
        >
          for a completed run, project what the same triage and remediation
          work would cost done by a human. feeds the ROI ledger.
        </p>
        <form
          className="grid"
          style={{
            gridTemplateColumns: "1fr 1fr",
            gap: 8,
            marginBottom: 12,
          }}
          onSubmit={handleHumanSubmit}
        >
          <div className="flex flex-col" style={{ gap: 4, gridColumn: "1 / -1" }}>
            <label style={LABEL_STYLE} htmlFor="hum-run-id">
              run id
            </label>
            <input
              id="hum-run-id"
              value={humRunId}
              onChange={(e) => setHumRunId(e.target.value)}
              placeholder="Completed scan run_id"
              style={INPUT_STYLE}
            />
          </div>
          <div className="flex flex-col" style={{ gap: 4 }}>
            <label style={LABEL_STYLE} htmlFor="hum-targets">
              target count
            </label>
            <input
              id="hum-targets"
              value={humTargetCount}
              onChange={(e) => setHumTargetCount(e.target.value)}
              inputMode="numeric"
              style={INPUT_STYLE}
            />
          </div>
          <div className="flex flex-col" style={{ gap: 4 }}>
            <label style={LABEL_STYLE} htmlFor="hum-findings">
              finding count
            </label>
            <input
              id="hum-findings"
              value={humFindingCount}
              onChange={(e) => setHumFindingCount(e.target.value)}
              inputMode="numeric"
              style={INPUT_STYLE}
            />
          </div>
          <div className="flex flex-col" style={{ gap: 4 }}>
            <label style={LABEL_STYLE} htmlFor="hum-duration">
              scan duration (min)
            </label>
            <input
              id="hum-duration"
              value={humDurationMinutes}
              onChange={(e) => setHumDurationMinutes(e.target.value)}
              inputMode="decimal"
              style={INPUT_STYLE}
            />
          </div>
          <div className="flex flex-col" style={{ gap: 4 }}>
            <label style={LABEL_STYLE} htmlFor="hum-tasks">
              task types performed (max 50)
            </label>
            <input
              id="hum-tasks"
              value={humTaskTypesRaw}
              onChange={(e) => setHumTaskTypesRaw(e.target.value)}
              placeholder="triage, remediation_planning"
              style={INPUT_STYLE}
            />
          </div>
          <div style={{ gridColumn: "1 / -1" }}>
            <button
              type="submit"
              style={BTN_ACCENT_STYLE}
              disabled={humanMutation.isPending}
            >
              {humanMutation.isPending
                ? "ESTIMATING\u2026"
                : "ESTIMATE HUMAN COST"}
            </button>
          </div>
        </form>
        {humError && <ErrorBox>{humError}</ErrorBox>}
        {humResult && (
          <div
            className="flex flex-col"
            style={{ gap: 10, marginTop: 12 }}
          >
            <div
              className="flex flex-wrap items-center font-mono"
              style={{ gap: 10 }}
            >
              <span style={LABEL_STYLE}>human cost</span>
              <span
                style={{
                  fontSize: 16,
                  color: "var(--text-primary)",
                }}
              >
                {formatUsd(humResult.human_cost_usd, 2)}
              </span>
              <span style={LABEL_STYLE}>hours</span>
              <span
                style={{ fontSize: 12, color: "var(--text-primary)" }}
              >
                {humResult.estimated_hours.toFixed(1)}h
              </span>
              <MonoBadge tone={confidenceTone(humResult.confidence)}>
                {humResult.confidence}
              </MonoBadge>
            </div>
            {humResult.reasoning && (
              <div
                className="font-mono"
                style={{
                  border: "1px solid var(--border-soft)",
                  background: "var(--surface-sunk)",
                  color: "var(--text-muted)",
                  padding: "8px 12px",
                  fontSize: 10.5,
                  borderRadius: 3,
                  whiteSpace: "pre-wrap",
                }}
                // reasoning is html-escaped server-side (schemas/cost.py:sanitize_reasoning)
                dangerouslySetInnerHTML={{ __html: humResult.reasoning }}
              />
            )}
          </div>
        )}
      </WindowPanel>
    </div>
  );
}
