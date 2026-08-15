import * as React from "react";

import { BigStat } from "@/components/aila/mock";
import { LoadingSkeleton } from "@/components/aila/LoadingSkeleton";
import { useDashboardData } from "../hooks/useDashboardData";

const CENTER_STYLE: React.CSSProperties = {
  height: "100%",
  padding: 16,
  fontFamily: "var(--font-mono)",
  fontSize: 11,
};

/**
 * MttrWidget -- findings closed in the last 30 days.
 *
 * Reads meta.closed_last_30d from the dashboard envelope.
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
      <div
        className="flex items-center justify-center"
        style={{ ...CENTER_STYLE, color: "var(--status-warn)" }}
      >
        {error instanceof Error ? error.message : "Failed to load metrics"}
      </div>
    );
  }

  const closedLast30d = meta?.closed_last_30d ?? null;

  return (
    <div
      className="h-full w-full flex flex-col justify-center"
      style={{ padding: 16 }}
    >
      <BigStat
        value={closedLast30d !== null ? closedLast30d : "--"}
        sub="closed / last 30d"
      />
    </div>
  );
}
