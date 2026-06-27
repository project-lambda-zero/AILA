import * as React from "react";

import { LoadingSkeleton } from "@/components/aila/LoadingSkeleton";
import { useDashboardData } from "../hooks/useDashboardData";

/**
 * FleetCoverageWidget -- shows online/total system count with coverage percentage.
 *
 * Data from GET /dashboard via useDashboardData().
 */
export function FleetCoverageWidget() {
  const { data, isLoading, isError, error } = useDashboardData();

  if (isLoading) {
    return (
      <div className="h-full w-full p-4 flex flex-col gap-3">
        <LoadingSkeleton size="lg" width="half" />
        <LoadingSkeleton size="sm" width="full" />
        <LoadingSkeleton size="sm" width="full" />
      </div>
    );
  }

  if (isError) {
    return (
      <div className="h-full w-full p-4 flex items-center justify-center">
        <p className="text-sm text-destructive font-mono">
          {error instanceof Error ? error.message : "Failed to load fleet data"}
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

  const { total_systems, online_systems } = data.fleet_stats;

  if (total_systems === 0) {
    return (
      <div className="h-full w-full p-4 flex flex-col justify-center gap-1">
        <p className="text-sm font-mono font-semibold text-text">Fleet Coverage</p>
        <p className="text-xs font-mono text-text-muted">No systems registered</p>
      </div>
    );
  }

  const pct = Math.round((online_systems / total_systems) * 100);

  return (
    <div className="h-full w-full p-4 flex flex-col justify-center gap-3">
      <div>
        <p className="text-3xl font-mono font-bold text-text">{pct}%</p>
        <p className="text-xs font-mono text-text-muted mt-0.5">Fleet Coverage</p>
      </div>

      {/* Progress bar */}
      <div className="w-full h-2 bg-elevated rounded-[4px] overflow-hidden border border-border">
        <div
          className="h-full bg-accent rounded-[4px] transition-all duration-500"
          style={{ width: `${pct}%` }}
          role="progressbar"
          aria-valuenow={pct}
          aria-valuemin={0}
          aria-valuemax={100}
        />
      </div>

      <p className="text-xs font-mono text-text-muted">
        {online_systems} / {total_systems} systems online
      </p>
    </div>
  );
}
