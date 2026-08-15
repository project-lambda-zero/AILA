/**
 * FindingsTrendChart.view -- recharts area chart. Lazy-loaded.
 *
 * Colors arrive pre-resolved via useThemeChartColors. Grid + axes use
 * tokenized greys.
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
  backgroundColor: "var(--surface-card)",
  border: "1px solid var(--border-soft)",
  borderRadius: 3,
  fontFamily: "var(--font-mono, monospace)",
  fontSize: 11,
  color: "var(--text-primary)",
  letterSpacing: "0.06em",
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
    letterSpacing: "0.06em",
  };

  return (
    <ResponsiveContainer width="100%" height="100%">
      <AreaChart
        data={data as TrendDataPoint[]}
        margin={{ top: 4, right: 8, left: 0, bottom: 0 }}
      >
        <defs>
          <linearGradient id="trend-gradient" x1="0" y1="0" x2="0" y2="1">
            <stop offset="5%" stopColor={colors.accent} stopOpacity={0.35} />
            <stop offset="95%" stopColor={colors.accent} stopOpacity={0.02} />
          </linearGradient>
        </defs>
        <CartesianGrid {...gridStyle} />
        <XAxis
          dataKey="date"
          tick={axisStyle}
          axisLine={{ stroke: colors.border }}
          tickLine={false}
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
