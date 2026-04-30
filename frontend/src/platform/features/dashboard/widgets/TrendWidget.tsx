import * as React from "react";

import { AilaChart } from "@/components/aila/AilaChart";
import { LoadingSkeleton } from "@/components/aila/LoadingSkeleton";
import { useDashboardData } from "../hooks/useDashboardData";

interface TrendDataPoint {
  date: string;
  count: number;
}

function isTrendDataArray(value: unknown): value is TrendDataPoint[] {
  return (
    Array.isArray(value) &&
    value.length > 0 &&
    typeof (value[0] as Record<string, unknown>).date === "string" &&
    typeof (value[0] as Record<string, unknown>).count === "number"
  );
}

/**
 * TrendWidget — time-series area chart of findings over time.
 *
 * Reads module_data["vulnerability.trend"] which should be an array of
 * { date: string, count: number } objects. Shows empty state when not available.
 *
 * Data from GET /dashboard via useDashboardData().
 */
export function TrendWidget() {
  const { data, isLoading, isError, error } = useDashboardData();

  if (isLoading) {
    return (
      <div className="h-full w-full p-4 flex flex-col gap-3">
        <LoadingSkeleton size="full" width="full" />
      </div>
    );
  }

  if (isError) {
    return (
      <div className="h-full w-full p-4 flex items-center justify-center">
        <p className="text-sm text-destructive font-mono">
          {error instanceof Error ? error.message : "Failed to load trend data"}
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

  const trendRaw = data.module_data["vulnerability.trend"];
  const hasTrend = isTrendDataArray(trendRaw);

  if (!hasTrend) {
    return (
      <div className="h-full w-full p-4 flex flex-col justify-center gap-1">
        <p className="text-sm font-mono font-semibold text-text">Findings Trend</p>
        <p className="text-xs font-mono text-text-muted">Trend data not available</p>
      </div>
    );
  }

  return (
    <div className="h-full w-full p-2 flex flex-col">
      <p className="text-xs font-mono text-text-muted uppercase tracking-wider px-2 pb-1">
        Findings Trend
      </p>
      <div className="flex-1 min-h-0">
        <AilaChart
          type="area"
          data={trendRaw as unknown as Record<string, unknown>[]}
          dataKey="count"
          xKey="date"
          size="sm"
          ariaLabel="Findings trend over time area chart"
          className="h-full"
        />
      </div>
    </div>
  );
}
