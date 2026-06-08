/**
 * RadarSeverityPie.view — recharts-using pie chart for the radar inspect panel.
 *
 * Loaded lazily from RadarInspectPanel so the recharts vendor chunk stays
 * out of the root entry. The panel is itself lazily shown (only when a node
 * is clicked), but the recharts import inside it would otherwise be eager
 * because RadarInspectPanel is imported synchronously by RadarPage.
 */
import * as React from "react";
import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer } from "recharts";

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
