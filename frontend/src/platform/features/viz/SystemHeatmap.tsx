/**
 * SystemHeatmap -- VIZ-03 (mock rebuild).
 *
 * WindowPanel host + tokenized cells. Grid engine (density-scaled cells
 * per severity per system) unchanged. Mono legend row below the grid.
 */
import * as React from "react";

import { LoadingSkeleton } from "@/components/aila/LoadingSkeleton";
import { MonoBadge } from "@/components/aila/mock";
import { WindowPanel } from "@/components/aila/WindowPanel";
import { useTopology } from "@platform/features/radar/useTopology";
import { useThemeChartColors } from "./chartColors";
import { ChartExportButton } from "./ChartExportButton";

interface CellStyle {
  backgroundColor: string;
  opacity: number;
}

function intensityStyle(count: number, hexColor: string): CellStyle {
  if (count === 0) {
    return { backgroundColor: "transparent", opacity: 1 };
  }
  const opacity = Math.min(count / 10, 1) * 0.75 + 0.15;
  return { backgroundColor: hexColor, opacity };
}

interface SystemHeatmapProps {
  className?: string;
  exportRef?: React.RefObject<HTMLDivElement | null>;
}

export function SystemHeatmap({ className, exportRef }: SystemHeatmapProps) {
  const internalRef = React.useRef<HTMLDivElement>(null);
  const chartRef = exportRef ?? internalRef;

  const { data: topology, isLoading } = useTopology();
  const colors = useThemeChartColors();

  const SEVERITY_COLS = React.useMemo(
    () => [
      { key: "critical" as const, label: "C", color: colors.critical, tone: "critical" as const },
      { key: "high" as const, label: "H", color: colors.high, tone: "high" as const },
      { key: "medium" as const, label: "M", color: colors.medium, tone: "medium" as const },
      { key: "low" as const, label: "L", color: colors.low, tone: "low" as const },
    ],
    [colors],
  );

  if (isLoading) {
    return (
      <WindowPanel title="system risk heatmap" tone="muted" status="LOADING" className={className}>
        <LoadingSkeleton size="xl" width="full" />
      </WindowPanel>
    );
  }

  const nodes = topology?.nodes ?? [];
  const allNullSeverity = nodes.every((n) => n.severity_counts === null);

  return (
    <WindowPanel
      title="system risk heatmap"
      className={className}
      actions={<ChartExportButton chartRef={chartRef} filename="system-heatmap" />}
    >
      <div ref={chartRef} className="flex flex-col" style={{ gap: 10 }}>
        {nodes.length === 0 ? (
          <p
            className="font-mono text-center"
            style={{ padding: "18px 0", fontSize: 11, color: "var(--text-muted)" }}
          >
            no network data collected yet. add systems and run a discovery scan.
          </p>
        ) : allNullSeverity ? (
          <p
            className="font-mono text-center"
            style={{ padding: "18px 0", fontSize: 11, color: "var(--text-muted)" }}
          >
            no vulnerability scan data yet. run a vulnerability scan to populate severity data.
          </p>
        ) : (
          <>
            <div style={{ maxHeight: 400, overflowY: "auto", border: "1px solid var(--border-faint)", borderRadius: 3 }}>
              <div
                className="grid font-mono uppercase"
                style={{
                  gridTemplateColumns: "minmax(0,1fr) repeat(4, 56px)",
                  gap: 4,
                  padding: "6px 8px",
                  fontSize: 9,
                  letterSpacing: "0.14em",
                  color: "var(--text-faint)",
                  background: "var(--surface-chrome)",
                  borderBottom: "1px solid var(--border-faint)",
                }}
              >
                <div>SYSTEM</div>
                {SEVERITY_COLS.map((col) => (
                  <div key={col.key} style={{ textAlign: "center" }} title={col.key}>
                    {col.label}
                  </div>
                ))}
              </div>

              {nodes.map((node, ri) => {
                const counts = node.severity_counts;
                return (
                  <div
                    key={node.id}
                    className="grid font-mono"
                    style={{
                      gridTemplateColumns: "minmax(0,1fr) repeat(4, 56px)",
                      gap: 4,
                      padding: "4px 8px",
                      borderBottom:
                        ri === nodes.length - 1 ? "none" : "1px solid var(--border-faint)",
                    }}
                  >
                    <div
                      className="flex items-center"
                      style={{
                        gap: 6,
                        fontSize: 11,
                        color: "var(--text-primary)",
                        overflow: "hidden",
                        textOverflow: "ellipsis",
                        whiteSpace: "nowrap",
                      }}
                      title={`${node.name} (${node.host})`}
                    >
                      <span
                        style={{
                          overflow: "hidden",
                          textOverflow: "ellipsis",
                          whiteSpace: "nowrap",
                        }}
                      >
                        {node.name}
                      </span>
                      {node.is_stale && (
                        <span
                          className="uppercase"
                          style={{
                            fontSize: 8,
                            letterSpacing: "0.14em",
                            color: "var(--status-warn)",
                          }}
                        >
                          [stale]
                        </span>
                      )}
                    </div>

                    {SEVERITY_COLS.map((col) => {
                      const count = counts?.[col.key] ?? 0;
                      const s = intensityStyle(count, col.color);
                      return (
                        <div
                          key={col.key}
                          className="flex items-center justify-center"
                          style={{
                            height: 24,
                            borderRadius: 2,
                            backgroundColor: s.backgroundColor,
                            opacity: s.opacity,
                            border: count > 0 ? `1px solid ${col.color}` : "1px solid var(--border-faint)",
                          }}
                          title={`${col.key}: ${count}`}
                        >
                          {count > 0 && (
                            <span
                              className="font-mono"
                              style={{
                                fontSize: 10,
                                fontWeight: 700,
                                color: "var(--text-on-accent)",
                                opacity: 1 / s.opacity,
                              }}
                            >
                              {count}
                            </span>
                          )}
                        </div>
                      );
                    })}
                  </div>
                );
              })}
            </div>

            {/* Legend row */}
            <div className="flex items-center flex-wrap" style={{ gap: 6 }}>
              {SEVERITY_COLS.map((col) => (
                <MonoBadge key={col.key} tone={col.tone}>
                  {col.key.toUpperCase()}
                </MonoBadge>
              ))}
            </div>
          </>
        )}
      </div>
    </WindowPanel>
  );
}
