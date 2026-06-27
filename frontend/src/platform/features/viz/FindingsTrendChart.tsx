/**
 * FindingsTrendChart -- VIZ-02.
 *
 * Area chart showing findings count over time from real dashboard trend data.
 * The recharts-using JSX lives in ./FindingsTrendChart.view and is loaded
 * lazily (C17) so the recharts vendor chunk stays out of the root entry.
 * Falls back to empty state when no trend data exists, and to a skeleton
 * while data is in flight.
 */
import * as React from "react";

import { AilaCard } from "@/components/aila/AilaCard";
import { LoadingSkeleton } from "@/components/aila/LoadingSkeleton";

import { useDashboardTrend } from "./useDashboardTrend";
import { ChartExportButton } from "./ChartExportButton";
import { useThemeChartColors } from "./chartColors";

const FindingsTrendChartView = React.lazy(() =>
  import("./FindingsTrendChart.view").then((m) => ({
    default: m.FindingsTrendChartView,
  })),
);

interface FindingsTrendChartProps {
  className?: string;
  exportRef?: React.RefObject<HTMLDivElement | null>;
}

export function FindingsTrendChart({ className, exportRef }: FindingsTrendChartProps) {
  const internalRef = React.useRef<HTMLDivElement>(null);
  const chartRef = exportRef ?? internalRef;

  const { data: trendData, isLoading } = useDashboardTrend();
  const colors = useThemeChartColors();

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
          <React.Suspense fallback={<LoadingSkeleton size="full" width="full" className="h-full" />}>
            <FindingsTrendChartView data={trendData} colors={colors} />
          </React.Suspense>
        </div>
      )}
    </div></AilaCard>
  );
}
