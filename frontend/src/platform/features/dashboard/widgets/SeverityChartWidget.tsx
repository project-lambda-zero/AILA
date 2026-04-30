import * as React from "react";

import { AilaChart } from "@/components/aila/AilaChart";
import { LoadingSkeleton } from "@/components/aila/LoadingSkeleton";
import { useFindingsFacets } from "@platform/features/viz/useFindingsFacets";
import { useThemeChartColors } from "@platform/features/viz/chartColors";

/**
 * SeverityChartWidget — donut/pie chart showing finding severity distribution.
 *
 * Reads the severity facet group from GET /vulnerability/findings/facets
 * (same source as the standalone Viz donut). The dashboard /fleet_stats
 * counters drop non-canonical criticality values (e.g. "Moderate", "Planned",
 * "Immediate") so they are unsuitable for a multi-segment chart — the facet
 * endpoint preserves the raw distribution.
 *
 * Empty slices (count === 0) are filtered out so the chart never renders a
 * single colored ring when only one severity bucket is populated.
 *
 * Recharts applies the `fill` prop as an SVG presentation attribute, where
 * `var(--token)` does not resolve in any major browser. Colors are resolved
 * to hex via `useThemeChartColors()` so segments render reliably while still
 * tracking the active theme.
 */
export function SeverityChartWidget() {
  const { data, isLoading, isError, error } = useFindingsFacets();
  const themeColors = useThemeChartColors();

  if (isLoading) {
    return (
      <div className="h-full w-full p-4 flex flex-col gap-3">
        <LoadingSkeleton size="full" width="full" className="rounded-full aspect-square max-h-36 mx-auto" />
      </div>
    );
  }

  if (isError) {
    return (
      <div className="h-full w-full p-4 flex items-center justify-center">
        <p className="text-sm text-destructive font-mono">
          {error instanceof Error ? error.message : "Failed to load severity data"}
        </p>
      </div>
    );
  }

  // Normalize raw facet keys (e.g. "High", "Moderate", "Immediate") to lowercase
  // so legacy and canonical naming both map into the same severity buckets.
  const rawFacets = data?.severity ?? {};
  const facets: Record<string, number> = {};
  for (const [k, v] of Object.entries(rawFacets)) {
    const key = k.toLowerCase();
    facets[key] = (facets[key] ?? 0) + (v as number);
  }

  const allSlices = [
    { name: "Critical", count: facets["critical"] ?? facets["immediate"] ?? 0, color: themeColors.critical },
    { name: "High", count: facets["high"] ?? 0, color: themeColors.high },
    { name: "Medium", count: facets["medium"] ?? facets["moderate"] ?? 0, color: themeColors.medium },
    { name: "Low", count: facets["low"] ?? facets["planned"] ?? 0, color: themeColors.low },
  ];

  const chartData = allSlices.filter((s) => s.count > 0);
  const filteredColors = chartData.map((s) => s.color);

  if (chartData.length === 0) {
    return (
      <div className="h-full w-full p-4 flex flex-col items-center justify-center gap-1">
        <p className="text-sm font-mono font-semibold text-text">Severity Distribution</p>
        <p className="text-xs font-mono text-text-muted">No findings recorded</p>
      </div>
    );
  }

  return (
    <div className="h-full w-full p-2 flex flex-col">
      <p className="text-xs font-mono text-text-muted uppercase tracking-wider px-2 pb-1">
        Severity Distribution
      </p>
      <div className="flex-1 min-h-0">
        <AilaChart
          type="pie"
          data={chartData}
          dataKey="count"
          xKey="name"
          colors={filteredColors}
          size="sm"
          ariaLabel="Finding severity distribution pie chart"
          className="h-full"
        />
      </div>
    </div>
  );
}
