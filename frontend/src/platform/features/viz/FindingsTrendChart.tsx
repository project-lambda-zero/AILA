/**
 * FindingsTrendChart -- VIZ-02 wrapper (mock rebuild).
 *
 * WindowPanel host with mono legend row. Data fetch + suspense/lazy
 * loading unchanged.
 */
import * as React from "react";

import { LoadingSkeleton } from "@/components/aila/LoadingSkeleton";
import { MonoBadge } from "@/components/aila/mock";
import { WindowPanel } from "@/components/aila/WindowPanel";

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
      <WindowPanel title="findings trend" tone="muted" status="LOADING" className={className}>
        <LoadingSkeleton size="xl" width="full" />
      </WindowPanel>
    );
  }

  const hasData = trendData && trendData.length > 0;

  return (
    <WindowPanel
      title="findings trend"
      className={className}
      actions={<ChartExportButton chartRef={chartRef} filename="findings-trend" />}
    >
      <div ref={chartRef} className="flex flex-col" style={{ gap: 10 }}>
        {!hasData ? (
          <div
            className="flex items-center justify-center font-mono"
            style={{
              height: 192,
              fontSize: 11,
              color: "var(--text-muted)",
              textAlign: "center",
              padding: "0 16px",
            }}
          >
            no trend data available. run vulnerability scans to populate this chart.
          </div>
        ) : (
          <>
            <div style={{ height: 192 }}>
              <React.Suspense fallback={<LoadingSkeleton size="full" width="full" className="h-full" />}>
                <FindingsTrendChartView data={trendData} colors={colors} />
              </React.Suspense>
            </div>
            <div className="flex items-center justify-center" style={{ gap: 8 }}>
              <MonoBadge tone="accent">FINDINGS</MonoBadge>
            </div>
          </>
        )}
      </div>
    </WindowPanel>
  );
}
