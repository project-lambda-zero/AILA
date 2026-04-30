import * as React from "react";
import { Clock } from "lucide-react";

import { LoadingSkeleton } from "@/components/aila/LoadingSkeleton";
import { useDashboardData } from "../hooks/useDashboardData";

/**
 * MttrWidget — findings closed in the last 30 days.
 *
 * Reads meta.closed_last_30d from the dashboard envelope.
 * Displays count as primary metric with a clock icon.
 *
 * Data from GET /dashboard via useDashboardData().
 */
export function MttrWidget() {
  const { meta, isLoading, isError, error } = useDashboardData();

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
          {error instanceof Error ? error.message : "Failed to load metrics"}
        </p>
      </div>
    );
  }

  const closedLast30d = meta?.closed_last_30d ?? null;

  return (
    <div className="h-full w-full p-4 flex flex-col justify-center gap-2">
      <div className="flex items-center gap-2">
        <Clock className="h-4 w-4 text-accent" aria-hidden="true" />
        <p className="text-xs font-mono text-text-muted uppercase tracking-wider">
          Findings Closed (30d)
        </p>
      </div>

      <p className="text-4xl font-mono font-bold text-text">
        {closedLast30d !== null ? closedLast30d : "--"}
      </p>

      <p className="text-xs font-mono text-text-muted">Last 30 days</p>
    </div>
  );
}
