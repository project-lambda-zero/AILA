/**
 * SeverityDonutChart -- VIZ-01 wrapper (mock rebuild).
 *
 * Wraps SeverityDonutChart.view in a WindowPanel with a mono legend row.
 * Data fetch + suspense/lazy loading unchanged. Empty/loading states use
 * mock-styled panels.
 */
import * as React from "react";

import { LoadingSkeleton } from "@/components/aila/LoadingSkeleton";
import { MonoBadge } from "@/components/aila/mock";
import { WindowPanel } from "@/components/aila/WindowPanel";

import { useFindingsFacets } from "./useFindingsFacets";
import { ChartExportButton } from "./ChartExportButton";
import { useThemeChartColors } from "./chartColors";

const SeverityDonutChartView = React.lazy(() =>
  import("./SeverityDonutChart.view").then((m) => ({
    default: m.SeverityDonutChartView,
  })),
);

interface SeverityDonutChartProps {
  className?: string;
  exportRef?: React.RefObject<HTMLDivElement | null>;
}

export function SeverityDonutChart({ className, exportRef }: SeverityDonutChartProps) {
  const internalRef = React.useRef<HTMLDivElement>(null);
  const chartRef = exportRef ?? internalRef;

  const { data, isLoading } = useFindingsFacets();
  const colors = useThemeChartColors();

  if (isLoading) {
    return (
      <WindowPanel title="severity distribution" tone="muted" status="LOADING" className={className}>
        <LoadingSkeleton size="xl" width="full" />
      </WindowPanel>
    );
  }

  const rawFacets = data?.severity ?? {};
  const facets: Record<string, number> = {};
  for (const [k, v] of Object.entries(rawFacets)) {
    const key = k.toLowerCase();
    facets[key] = (facets[key] ?? 0) + (v as number);
  }

  const slices = [
    { name: "Critical", value: facets["critical"] ?? facets["immediate"] ?? 0, fill: colors.critical },
    { name: "High", value: facets["high"] ?? 0, fill: colors.high },
    { name: "Medium", value: facets["medium"] ?? facets["moderate"] ?? 0, fill: colors.medium },
    { name: "Low", value: facets["low"] ?? facets["planned"] ?? 0, fill: colors.low },
  ].filter((s) => s.value > 0);

  const total = slices.reduce((sum, s) => sum + s.value, 0);

  return (
    <WindowPanel
      title="severity distribution"
      className={className}
      actions={<ChartExportButton chartRef={chartRef} filename="severity-distribution" />}
    >
      <div ref={chartRef} className="flex flex-col" style={{ gap: 10 }}>
        {slices.length === 0 ? (
          <div
            className="flex items-center justify-center font-mono"
            style={{
              height: 192,
              fontSize: 11,
              color: "var(--text-muted)",
            }}
          >
            no findings data yet.
          </div>
        ) : (
          <>
            <div style={{ height: 192 }}>
              <React.Suspense fallback={<LoadingSkeleton size="full" width="full" className="h-full" />}>
                <SeverityDonutChartView slices={slices} />
              </React.Suspense>
            </div>
            {/* Mono legend row */}
            <div className="flex items-center justify-center flex-wrap" style={{ gap: 8 }}>
              {slices.map((s) => (
                <SeverityLegendChip key={s.name} name={s.name} value={s.value} color={s.fill} />
              ))}
            </div>
            <p
              className="font-mono uppercase text-center"
              style={{ fontSize: 9, letterSpacing: "0.14em", color: "var(--text-faint)" }}
            >
              {total} TOTAL FINDINGS
            </p>
          </>
        )}
      </div>
    </WindowPanel>
  );
}

function SeverityLegendChip({
  name,
  value,
  color,
}: {
  name: string;
  value: number;
  color: string;
}) {
  // Prefer MonoBadge tone when the severity name maps cleanly.
  const tone = name.toLowerCase();
  const known = tone === "critical" || tone === "high" || tone === "medium" || tone === "low";
  if (known) {
    return <MonoBadge tone={tone}>{`${name.toUpperCase()} ${value}`}</MonoBadge>;
  }
  return (
    <span
      className="flex items-center font-mono uppercase"
      style={{ gap: 5, fontSize: 9, letterSpacing: "0.12em", color: "var(--text-primary)" }}
    >
      <span
        aria-hidden="true"
        style={{ width: 8, height: 8, background: color, borderRadius: 1 }}
      />
      {name} {value}
    </span>
  );
}
