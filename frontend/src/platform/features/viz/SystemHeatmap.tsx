/**
 * SystemHeatmap -- VIZ-03.
 *
 * CSS grid heatmap showing severity density per system.
 * Rows = registered systems, Columns = severity levels (Critical/High/Medium/Low).
 * Cell background opacity scales with count (0=transparent, 10+=full color).
 *
 * Data source: useTopology() -- severity_counts per node.
 * No additional API call needed -- topology nodes already carry severity_counts.
 */
import * as React from "react";

import { AilaCard } from "@/components/aila/AilaCard";
import { LoadingSkeleton } from "@/components/aila/LoadingSkeleton";
import { useTopology } from "@platform/features/radar/useTopology";
import { ChartExportButton } from "./ChartExportButton";

// ---------------------------------------------------------------------------
// Color intensity helper
// ---------------------------------------------------------------------------

interface CellStyle {
  backgroundColor: string;
  opacity: number;
}

function intensityStyle(count: number, hexColor: string): CellStyle {
  if (count === 0) {
    return { backgroundColor: "transparent", opacity: 1 };
  }
  // opacity range: 0.15 (count=1) to 0.9 (count=10+)
  const opacity = Math.min(count / 10, 1) * 0.75 + 0.15;
  return { backgroundColor: hexColor, opacity };
}

// Severity column definitions -- using inline hex to avoid CSS var in backgroundColor
const SEVERITY_COLS = [
  { key: "critical" as const, label: "C", color: "#ef4444" }, // --color-critical dark
  { key: "high" as const, label: "H", color: "#f97316" },     // --color-high dark
  { key: "medium" as const, label: "M", color: "#eab308" },   // --color-medium dark
  { key: "low" as const, label: "L", color: "#9ca3af" },      // --color-low dark
];

// ---------------------------------------------------------------------------
// Props
// ---------------------------------------------------------------------------

interface SystemHeatmapProps {
  className?: string;
  exportRef?: React.RefObject<HTMLDivElement | null>;
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export function SystemHeatmap({ className, exportRef }: SystemHeatmapProps) {
  const internalRef = React.useRef<HTMLDivElement>(null);
  const chartRef = exportRef ?? internalRef;

  const { data: topology, isLoading } = useTopology();

  if (isLoading) {
    return (
      <AilaCard className={className} techBorder glow><div className="p-4 flex flex-col gap-2">
        <p className="font-mono text-xs text-muted-foreground uppercase tracking-wider">
          System Risk Heatmap
        </p>
        <LoadingSkeleton size="xl" width="full" />
      </div></AilaCard>
    );
  }

  const nodes = topology?.nodes ?? [];
  const allNullSeverity = nodes.every((n) => n.severity_counts === null);

  return (
    <AilaCard className={className} techBorder glow><div ref={chartRef} className="p-4">
      <div className="flex items-center justify-between mb-3">
        <p className="font-mono text-xs text-muted-foreground uppercase tracking-wider">
          System Risk Heatmap
        </p>
        <ChartExportButton chartRef={chartRef} filename="system-heatmap" />
      </div>
    
      {nodes.length === 0 ? (
        <div className="py-6 text-center">
          <p className="font-mono text-xs text-muted-foreground">
            No network data collected yet. Add systems and run a discovery scan.
          </p>
        </div>
      ) : allNullSeverity ? (
        <div className="py-6 text-center">
          <p className="font-mono text-xs text-muted-foreground">
            No vulnerability scan data yet. Run a vulnerability scan to populate severity data.
          </p>
          {/* Render the grid skeleton with no data to show the structure */}
        </div>
      ) : (
        <div className="max-h-[400px] overflow-y-auto">
          {/* Grid header */}
          <div className="grid gap-1" style={{ gridTemplateColumns: "minmax(0,1fr) repeat(4, 64px)" }}>
            <div className="font-mono text-[10px] text-muted-foreground uppercase tracking-wider py-1">
              System
            </div>
            {SEVERITY_COLS.map((col) => (
              <div
                key={col.key}
                className="font-mono text-[10px] text-muted-foreground uppercase tracking-wider py-1 text-center"
                title={col.key}
              >
                {col.label}
              </div>
            ))}
          </div>
    
          {/* Data rows */}
          {nodes.map((node) => {
            const counts = node.severity_counts;
            return (
              <div
                key={node.id}
                className="grid gap-1 hover:bg-elevated/50 rounded transition-colors"
                style={{ gridTemplateColumns: "minmax(0,1fr) repeat(4, 64px)" }}
              >
                {/* System name */}
                <div
                  className="font-mono text-[11px] py-1 truncate flex items-center"
                  title={`${node.name} (${node.host})`}
                >
                  {node.name}
                  {node.is_stale && (
                    <span className="ml-1 text-[9px] text-muted-foreground">[stale]</span>
                  )}
                </div>
    
                {/* Severity cells */}
                {SEVERITY_COLS.map((col) => {
                  const count = counts?.[col.key] ?? 0;
                  const style = intensityStyle(count, col.color);
                  return (
                    <div
                      key={col.key}
                      className="h-7 rounded flex items-center justify-center"
                      style={{
                        backgroundColor: style.backgroundColor,
                        opacity: style.opacity,
                      }}
                      title={`${col.key}: ${count}`}
                    >
                      {count > 0 && (
                        <span
                          className="font-mono text-[10px] text-white font-medium"
                          style={{ opacity: 1 / style.opacity }} // Ensure text is always readable
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
      )}
    </div></AilaCard>
  );
}
