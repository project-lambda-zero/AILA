/**
 * FindingsTrendChart — VIZ-02.
 *
 * Area chart showing findings count over time from real dashboard trend data.
 * Uses Recharts AreaChart directly for full control over axis formatting.
 * Falls back to empty state when no trend data exists.
 */
import * as React from "react";
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
} from "recharts";

import { AilaCard } from "@/components/aila/AilaCard";
import { LoadingSkeleton } from "@/components/aila/LoadingSkeleton";
import { useDashboardTrend } from "./useDashboardTrend";
import { ChartExportButton } from "./ChartExportButton";
import { useThemeChartColors } from "./chartColors";

// ---------------------------------------------------------------------------
// Styles
// ---------------------------------------------------------------------------

const TOOLTIP_STYLE: React.CSSProperties = {
  backgroundColor: "var(--color-elevated)",
  border: "1px solid var(--color-border)",
  borderRadius: "4px",
  fontFamily: "var(--font-mono, monospace)",
  fontSize: "11px",
  color: "var(--color-text)",
};

// CartesianGrid + XAxis line/tick colors must be SVG-safe (no `var()`).
// They are derived from the theme via `useThemeChartColors()` at runtime.

// ---------------------------------------------------------------------------
// Props
// ---------------------------------------------------------------------------

interface FindingsTrendChartProps {
  className?: string;
  exportRef?: React.RefObject<HTMLDivElement | null>;
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export function FindingsTrendChart({ className, exportRef }: FindingsTrendChartProps) {
  const internalRef = React.useRef<HTMLDivElement>(null);
  const chartRef = exportRef ?? internalRef;

  const { data: trendData, isLoading } = useDashboardTrend();
  const colors = useThemeChartColors();

  const gridStyle = { stroke: colors.border, strokeDasharray: "3 3" };
  const axisStyle = {
    fontFamily: "var(--font-mono, monospace)",
    fontSize: 10,
    fill: colors.textMuted,
  };

  if (isLoading) {
    return (
      <AilaCard className={className} techBorder glow><div className="p-4 flex flex-col gap-2">
        <p className="font-mono text-xs text-muted-foreground uppercase tracking-wider">
          Findings Trend
        </p>
        <LoadingSkeleton size="xl" width="full" />
      </div></AilaCard>
    );
  }

  const hasData = trendData && trendData.length > 0;

  return (
    <AilaCard className={className} techBorder glow><div ref={chartRef} className="p-4">
      <div className="flex items-center justify-between mb-3">
        <p className="font-mono text-xs text-muted-foreground uppercase tracking-wider">
          Findings Trend
        </p>
        <ChartExportButton chartRef={chartRef} filename="findings-trend" />
      </div>
    
      {!hasData ? (
        <div className="h-48 flex items-center justify-center">
          <p className="font-mono text-xs text-muted-foreground">
            No trend data available. Run vulnerability scans to populate this chart.
          </p>
        </div>
      ) : (
        <div className="h-48">
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart
              data={trendData}
              margin={{ top: 4, right: 8, left: 0, bottom: 0 }}
            >
              <defs>
                <linearGradient id="trend-gradient" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor={colors.accent} stopOpacity={0.3} />
                  <stop offset="95%" stopColor={colors.accent} stopOpacity={0.02} />
                </linearGradient>
              </defs>
              <CartesianGrid {...gridStyle} />
              <XAxis
                dataKey="date"
                tick={axisStyle}
                axisLine={{ stroke: colors.border }}
                tickLine={false}
                // Abbreviate date labels: "2026-04-09" → "Apr 9"
                tickFormatter={(val: string) => {
                  const d = new Date(val);
                  if (isNaN(d.getTime())) return val;
                  return d.toLocaleDateString("en-US", { month: "short", day: "numeric" });
                }}
              />
              <YAxis
                tick={axisStyle}
                axisLine={false}
                tickLine={false}
                width={30}
              />
              <Tooltip contentStyle={TOOLTIP_STYLE} />
              <Area
                type="monotone"
                dataKey="count"
                stroke={colors.accent}
                strokeWidth={2}
                fill="url(#trend-gradient)"
                name="Findings"
              />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      )}
    </div></AilaCard>
  );
}
