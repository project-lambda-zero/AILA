import * as React from "react";
import { Activity } from "lucide-react";

import { LoadingSkeleton } from "@/components/aila/LoadingSkeleton";
import { useDashboardData } from "../hooks/useDashboardData";

/**
 * ActiveScansWidget -- shows currently active scan count.
 *
 * Checks module_data["vulnerability.active_scans"] first.
 * Falls back to showing total findings count if scan data is not available.
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
      <div className="h-full w-full p-4 flex items-center justify-center">
        <p className="text-sm text-destructive font-mono">
          {error instanceof Error ? error.message : "Failed to load scan data"}
        </p>
      </div>
    );
  }

  if (!data) {
    return (
      <div className="h-full w-full p-4 flex items-center justify-center">
        <p className="text-sm text-text-muted font-mono">No data available</p>
      </div>
    );
  }

  // Check for active scan count in module_data
  const activeScanData = data.module_data["vulnerability.active_scans"];
  const hasActiveScanData =
    activeScanData !== undefined &&
    activeScanData !== null &&
    typeof activeScanData === "number";

  return (
    <div className="h-full w-full p-4 flex flex-col justify-center gap-2">
      <div className="flex items-center gap-2">
        <Activity className="h-5 w-5 text-accent" aria-hidden="true" />
        <p className="text-xs font-mono text-text-muted uppercase tracking-wider">
          {hasActiveScanData ? "Active Scans" : "Total Findings"}
        </p>
      </div>

      <p className="text-4xl font-mono font-bold text-text">
        {hasActiveScanData
          ? (activeScanData as number)
          : data.fleet_stats.total_findings}
      </p>

      {!hasActiveScanData && (
        <p className="text-xs font-mono text-text-muted">
          No active scan data available
        </p>
      )}
    </div>
  );
}
