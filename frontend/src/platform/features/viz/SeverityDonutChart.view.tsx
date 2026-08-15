/**
 * SeverityDonutChart.view -- recharts donut. Lazy-loaded from the
 * wrapper so recharts stays chunk-split.
 *
 * Fills are already resolved to hex/token strings upstream via
 * useThemeChartColors (SVG cannot resolve `var(--*)` in presentation
 * attributes). Chrome (tooltip/legend) uses tokens directly via CSS.
 */
import * as React from "react";
import {
  PieChart,
  Pie,
  Cell,
  Tooltip,
  ResponsiveContainer,
} from "recharts";

const TOOLTIP_STYLE: React.CSSProperties = {
  backgroundColor: "var(--surface-card)",
  border: "1px solid var(--border-soft)",
  borderRadius: 3,
  fontFamily: "var(--font-mono, monospace)",
  fontSize: 11,
  color: "var(--text-primary)",
  letterSpacing: "0.06em",
};

interface SeveritySlice {
  name: string;
  value: number;
  fill: string;
}

interface SeverityDonutChartViewProps {
  slices: ReadonlyArray<SeveritySlice>;
}

export function SeverityDonutChartView({ slices }: SeverityDonutChartViewProps) {
  return (
    <ResponsiveContainer width="100%" height="100%">
      <PieChart>
        <Pie
          data={slices as SeveritySlice[]}
          dataKey="value"
          nameKey="name"
          cx="50%"
          cy="50%"
          innerRadius="45%"
          outerRadius="72%"
          strokeWidth={0}
        >
          {slices.map((slice) => (
            <Cell key={slice.name} fill={slice.fill} />
          ))}
        </Pie>
        <Tooltip contentStyle={TOOLTIP_STYLE} />
      </PieChart>
    </ResponsiveContainer>
  );
}
