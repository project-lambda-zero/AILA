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

const CENTER_STYLE: React.CSSProperties = {
  height: "100%",
  padding: 16,
  fontFamily: "var(--font-mono)",
  fontSize: 11,
};

/**
 * TrendWidget -- time-series area chart of findings over time.
 *
 * Reads module_data["vulnerability.trend"]. Renders empty state otherwise.
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
      <div
        className="flex items-center justify-center"
        style={{ ...CENTER_STYLE, color: "var(--status-warn)" }}
      >
        {error instanceof Error ? error.message : "Failed to load trend data"}
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

  const trendRaw = data.module_data["vulnerability.trend"];
  const hasTrend = isTrendDataArray(trendRaw);

  if (!hasTrend) {
    return (
      <div
        className="flex items-center justify-center"
        style={{ ...CENTER_STYLE, color: "var(--text-muted)" }}
      >
        Trend data not available
      </div>
    );
  }

  return (
    <div className="h-full w-full p-2 flex flex-col">
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
