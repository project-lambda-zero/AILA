/**
 * SeverityDonutChart.view — recharts-using inner JSX for the donut chart.
 *
 * Loaded lazily from the wrapper so recharts stays out of the root entry.
 * Receives already-derived slices + colors as props; the data-fetch and
 * empty-state branches live in the wrapper.
 */
import * as React from "react";
import {
  PieChart,
  Pie,
  Cell,
  Tooltip,
  Legend,
  ResponsiveContainer,
} from "recharts";

const TOOLTIP_STYLE: React.CSSProperties = {
  backgroundColor: "var(--color-elevated)",
  border: "1px solid var(--color-border)",
  borderRadius: "4px",
  fontFamily: "var(--font-mono, monospace)",
  fontSize: "11px",
  color: "var(--color-text)",
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
          innerRadius="40%"
          outerRadius="70%"
          strokeWidth={0}
        >
          {slices.map((slice) => (
            <Cell key={slice.name} fill={slice.fill} />
          ))}
        </Pie>
        <Tooltip contentStyle={TOOLTIP_STYLE} />
        <Legend
          wrapperStyle={{
            fontFamily: "var(--font-mono, monospace)",
            fontSize: 11,
          }}
        />
      </PieChart>
    </ResponsiveContainer>
  );
}
