/**
 * useChartExport -- VIZ-05 chart export hook.
 *
 * Exports a DOM element as PNG (via html2canvas) or SVG (via XMLSerializer).
 * html2canvas is loaded dynamically to avoid blocking initial page load.
 *
 * Per the threat model: all processing is client-side. No data leaves the browser.
 */
import { useCallback, useState } from "react";

export type ExportFormat = "png" | "svg";

interface UseChartExportReturn {
  exportChart: (element: HTMLElement | null, filename: string, format: ExportFormat) => Promise<void>;
  isExporting: boolean;
  error: string | null;
}

export function useChartExport(): UseChartExportReturn {
  const [isExporting, setIsExporting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const exportChart = useCallback(async (
    element: HTMLElement | null,
    filename: string,
    format: ExportFormat,
  ) => {
    if (!element) {
      setError("No chart element to export.");
      return;
    }
    setIsExporting(true);
    setError(null);
    try {
      if (format === "png") {
        // Dynamic import -- avoid loading html2canvas on initial page render
        const html2canvas = (await import("html2canvas")).default;
        const canvas = await html2canvas(element, {
          scale: 2, // 2x quality for retina displays
          useCORS: true,
        });
        const dataUrl = canvas.toDataURL("image/png");
        const link = document.createElement("a");
        link.href = dataUrl;
        link.download = `${filename}.png`;
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
      } else {
        // SVG export -- find SVG element inside the chart container
        const svgEl = element.querySelector("svg");
        if (!svgEl) {
          setError("No SVG found in chart. Use PNG export instead.");
          return;
        }
        const serializer = new XMLSerializer();
        const svgStr = serializer.serializeToString(svgEl);
        const blob = new Blob([svgStr], { type: "image/svg+xml" });
        const url = URL.createObjectURL(blob);
        const link = document.createElement("a");
        link.href = url;
        link.download = `${filename}.svg`;
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        URL.revokeObjectURL(url);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Export failed.");
    } finally {
      setIsExporting(false);
    }
  }, []);

  return { exportChart, isExporting, error };
}
