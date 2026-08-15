import * as React from "react";

import { BigStat, MonoBadge } from "@/components/aila/mock";
import { LoadingSkeleton } from "@/components/aila/LoadingSkeleton";
import { useDashboardData } from "../hooks/useDashboardData";

const CENTER_STYLE: React.CSSProperties = {
  height: "100%",
  padding: 16,
  fontFamily: "var(--font-mono)",
  fontSize: 11,
};

/**
 * ActiveScansWidget -- currently active scan count.
 *
 * Prefers module_data["vulnerability.active_scans"]. Falls back to
 * total findings when the scan provider is absent.
 *
 * Data from GET /dashboard via useDashboardData().
 */
export function ActiveScansWidget() {
  const { data, isLoading, isError, error } = useDashboardData();

  if (isLoading) {
    return (
      <div className="h-full w-full p-4 flex flex-col gap-3">
        <LoadingSkeleton size="lg" width="quarter" />
        <LoadingSkeleton size="sm" width="half" />
      </div>
    );
  }

  if (isError) {
    return (
      <div
        className="flex items-center justify-center"
        style={{ ...CENTER_STYLE, color: "var(--status-warn)" }}
      >
        {error instanceof Error ? error.message : "Failed to load scan data"}
      </div>
    );
  }

  if (!data) {
    return (
      <div
        className="flex items-center justify-center"
        style={{ ...CENTER_STYLE, color: "var(--text-muted)" }}
      >
        No data available
      </div>
    );
  }

  const activeScanData = data.module_data["vulnerability.active_scans"];
  const hasActiveScanData =
    activeScanData !== undefined &&
    activeScanData !== null &&
    typeof activeScanData === "number";

  const value = hasActiveScanData
    ? (activeScanData as number)
    : data.fleet_stats.total_findings;

  return (
    <div
      className="h-full w-full flex flex-col justify-center"
      style={{ padding: 16, gap: 10 }}
    >
      <BigStat
        value={value}
        sub={hasActiveScanData ? "active scans" : "total findings"}
      />
      {!hasActiveScanData && (
        <div className="flex items-center" style={{ gap: 8 }}>
          <MonoBadge tone="warn">fallback</MonoBadge>
          <span
            className="font-mono"
            style={{ fontSize: 10, color: "var(--text-muted)" }}
          >
            no active scan provider
          </span>
        </div>
      )}
    </div>
  );
}
