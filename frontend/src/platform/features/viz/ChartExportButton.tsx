/**
 * ChartExportButton — VIZ-05.
 *
 * Small PNG/SVG export button pair for chart containers.
 * Accepts a ref to the chart's outer div element for html2canvas capture.
 */
import * as React from "react";

import { useChartExport } from "./useChartExport";

interface ChartExportButtonProps {
  chartRef: React.RefObject<HTMLDivElement | null>;
  filename?: string;
}

export function ChartExportButton({ chartRef, filename = "aila-chart" }: ChartExportButtonProps) {
  const { exportChart, isExporting } = useChartExport();

  const buttonClass =
    "text-[10px] font-mono text-muted-foreground px-2 py-0.5 rounded border border-border " +
    "hover:bg-elevated hover:text-foreground disabled:opacity-40 transition-colors";

  return (
    <div className="flex gap-1 shrink-0">
      <button
        type="button"
        className={buttonClass}
        onClick={() => void exportChart(chartRef.current, filename, "png")}
        disabled={isExporting}
        title="Export as PNG"
      >
        {isExporting ? "..." : "PNG"}
      </button>
      <button
        type="button"
        className={buttonClass}
        onClick={() => void exportChart(chartRef.current, filename, "svg")}
        disabled={isExporting}
        title="Export as SVG"
      >
        {isExporting ? "..." : "SVG"}
      </button>
    </div>
  );
}
