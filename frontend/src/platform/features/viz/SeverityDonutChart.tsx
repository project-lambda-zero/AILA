/**
 * SeverityDonutChart — VIZ-01.
 *
 * Donut chart showing severity distribution from real findings facet data.
 * Uses Recharts PieChart directly (not AilaChart) to support innerRadius.
 * Falls back to an empty state when facets are absent or all-zero.
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

import { AilaCard } from "@/components/aila/AilaCard";
import { LoadingSkeleton } from "@/components/aila/LoadingSkeleton";
import { useFindingsFacets } from "./useFindingsFacets";
import { ChartExportButton } from "./ChartExportButton";
import { useThemeChartColors } from "./chartColors";

// ---------------------------------------------------------------------------
// Tooltip style
// ---------------------------------------------------------------------------

const TOOLTIP_STYLE: React.CSSProperties = {
  backgroundColor: "var(--color-elevated)",
  border: "1px solid var(--color-border)",
  borderRadius: "4px",
  fontFamily: "var(--font-mono, monospace)",
  fontSize: "11px",
  color: "var(--color-text)",
};

// ---------------------------------------------------------------------------
// Props
// ---------------------------------------------------------------------------

interface SeverityDonutChartProps {
  className?: string;
  exportRef?: React.RefObject<HTMLDivElement | null>;
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export function SeverityDonutChart({ className, exportRef }: SeverityDonutChartProps) {
  const internalRef = React.useRef<HTMLDivElement>(null);
  const chartRef = exportRef ?? internalRef;

  const { data, isLoading } = useFindingsFacets();
  const colors = useThemeChartColors();

  if (isLoading) {
    return (
      <AilaCard className={className} techBorder glow><div className="p-4 flex flex-col gap-2">
        <p className="font-mono text-xs text-muted-foreground uppercase tracking-wider">
          Severity Distribution
        </p>
        <LoadingSkeleton size="xl" width="full" />
      </div></AilaCard>
    );
  }

  const rawFacets = data?.severity ?? {};
  // Normalize keys to lowercase for case-insensitive lookup
  const facets: Record<string, number> = {};
  for (const [k, v] of Object.entries(rawFacets)) {
    facets[k.toLowerCase()] = (facets[k.toLowerCase()] ?? 0) + (v as number);
  }

  const slices = [
    { name: "Critical", value: facets["critical"] ?? facets["immediate"] ?? 0, fill: colors.critical },
    { name: "High", value: facets["high"] ?? 0, fill: colors.high },
    { name: "Medium", value: facets["medium"] ?? facets["moderate"] ?? 0, fill: colors.medium },
    { name: "Low", value: facets["low"] ?? facets["planned"] ?? 0, fill: colors.low },
  ].filter((s) => s.value > 0);

  const total = slices.reduce((sum, s) => sum + s.value, 0);

  return (
    <AilaCard className={className} techBorder glow><div ref={chartRef} className="p-4">
      <div className="flex items-center justify-between mb-3">
        <p className="font-mono text-xs text-muted-foreground uppercase tracking-wider">
          Severity Distribution
        </p>
        <ChartExportButton chartRef={chartRef} filename="severity-distribution" />
      </div>
    
      {slices.length === 0 ? (
        <div className="h-48 flex items-center justify-center">
          <p className="font-mono text-xs text-muted-foreground">
            No findings data yet.
          </p>
        </div>
      ) : (
        <>
          <div className="h-48">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={slices}
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
          </div>
          <p className="font-mono text-xs text-muted-foreground text-center mt-1">
            {total} total findings
          </p>
        </>
      )}
    </div></AilaCard>
  );
}
