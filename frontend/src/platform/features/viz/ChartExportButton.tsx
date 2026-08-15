/**
 * ChartExportButton -- mock-styled PNG/SVG export pair.
 */
import * as React from "react";

import { useChartExport } from "./useChartExport";

interface ChartExportButtonProps {
  chartRef: React.RefObject<HTMLDivElement | null>;
  filename?: string;
}

const BASE_BTN: React.CSSProperties = {
  height: 26,
  fontSize: 9.5,
  letterSpacing: "0.08em",
  padding: "0 11px",
  border: "1px solid var(--border-soft)",
  background: "var(--surface-sunk)",
  color: "var(--text-primary)",
  borderRadius: 3,
  cursor: "pointer",
  fontFamily: "var(--font-mono, ui-monospace, monospace)",
  textTransform: "uppercase",
};

export function ChartExportButton({
  chartRef,
  filename = "aila-chart",
}: ChartExportButtonProps) {
  const { exportChart, isExporting } = useChartExport();

  return (
    <div className="flex" style={{ gap: 6, flex: "0 0 auto" }}>
      <button
        type="button"
        style={{ ...BASE_BTN, opacity: isExporting ? 0.4 : 1 }}
        onClick={() => void exportChart(chartRef.current, filename, "png")}
        disabled={isExporting}
        title="Export as PNG"
      >
        {isExporting ? "..." : "PNG"}
      </button>
      <button
        type="button"
        style={{ ...BASE_BTN, opacity: isExporting ? 0.4 : 1 }}
        onClick={() => void exportChart(chartRef.current, filename, "svg")}
        disabled={isExporting}
        title="Export as SVG"
      >
        {isExporting ? "..." : "SVG"}
      </button>
    </div>
  );
}
