/**
 * RadarSeverityPie.view -- recharts pie for the radar inspect panel.
 *
 * Loaded lazily from RadarInspectPanel so recharts stays chunk-split.
 * Fills come from tokens via useThemeChartColors upstream (SVG attrs
 * cannot resolve var(...) directly).
 */
import * as React from "react";
import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer } from "recharts";

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

interface RadarSeverityPieViewProps {
  slices: ReadonlyArray<SeveritySlice>;
}

export function RadarSeverityPieView({ slices }: RadarSeverityPieViewProps) {
  return (
    <ResponsiveContainer width="100%" height="100%">
      <PieChart>
        <Pie
          data={slices as SeveritySlice[]}
          dataKey="value"
          nameKey="name"
          cx="50%"
          cy="50%"
          outerRadius="70%"
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
