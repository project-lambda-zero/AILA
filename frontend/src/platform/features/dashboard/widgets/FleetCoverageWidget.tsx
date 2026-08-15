import * as React from "react";

import { StatBar, BigStat } from "@/components/aila/mock";
import { LoadingSkeleton } from "@/components/aila/LoadingSkeleton";
import { useDashboardData } from "../hooks/useDashboardData";

const CENTER_STYLE: React.CSSProperties = {
  height: "100%",
  padding: 16,
  fontFamily: "var(--font-mono)",
  fontSize: 11,
};

/**
 * FleetCoverageWidget -- online/total system count with coverage percentage.
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
      <div
        className="flex items-center justify-center"
        style={{ ...CENTER_STYLE, color: "var(--status-warn)" }}
      >
        {error instanceof Error ? error.message : "Failed to load fleet data"}
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

  const { total_systems, online_systems } = data.fleet_stats;

  if (total_systems === 0) {
    return (
      <div
        className="flex items-center justify-center"
        style={{ ...CENTER_STYLE, color: "var(--text-muted)" }}
      >
        No systems registered
      </div>
    );
  }

  const pct = Math.round((online_systems / total_systems) * 100);

  return (
    <div
      className="h-full w-full flex flex-col justify-center"
      style={{ padding: 16, gap: 12 }}
    >
      <BigStat value={`${pct}%`} sub="fleet coverage" />
      <StatBar
        label="ONLINE"
        color="var(--status-ok)"
        value={online_systems}
        max={total_systems}
      />
      <div
        className="font-mono"
        style={{
          fontSize: 10,
          color: "var(--text-muted)",
          letterSpacing: "0.1em",
          textTransform: "uppercase",
        }}
        role="progressbar"
        aria-valuenow={pct}
        aria-valuemin={0}
        aria-valuemax={100}
      >
        {online_systems} / {total_systems} systems online
      </div>
    </div>
  );
}
