/**
 * FindingsTrendChart.view — recharts-using inner JSX for the area chart.
 *
 * Loaded lazily from the wrapper so recharts stays out of the root entry.
 * Receives already-fetched trend data and theme-resolved colors as
 * props; the data-fetch and empty-state branches live in the wrapper.
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

import type { ChartColors } from "./chartColors";
import type { TrendDataPoint } from "./useDashboardTrend";

const TOOLTIP_STYLE: React.CSSProperties = {
  backgroundColor: "var(--color-elevated)",
  border: "1px solid var(--color-border)",
  borderRadius: "4px",
  fontFamily: "var(--font-mono, monospace)",
  fontSize: "11px",
  color: "var(--color-text)",
};

interface FindingsTrendChartViewProps {
  data: ReadonlyArray<TrendDataPoint>;
  colors: Pick<ChartColors, "accent" | "border" | "textMuted">;
}

export function FindingsTrendChartView({ data, colors }: FindingsTrendChartViewProps) {
  const gridStyle = { stroke: colors.border, strokeDasharray: "3 3" };
  const axisStyle = {
    fontFamily: "var(--font-mono, monospace)",
    fontSize: 10,
    fill: colors.textMuted,
  };

  return (
    <ResponsiveContainer width="100%" height="100%">
      <AreaChart
        data={data as TrendDataPoint[]}
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
  );
}
