import * as React from "react";

import { LoadingSkeleton } from "@/components/aila/LoadingSkeleton";
import { AilaBadge } from "@/components/aila/AilaBadge";
import { useHealthData } from "../hooks/useDashboardData";

function statusBadgeSeverity(
  status: string,
): "neutral" | "info" | "medium" | "high" | "critical" {
  const s = status.toLowerCase();
  if (s === "healthy") return "info";
  if (s === "degraded") return "medium";
  return "critical";
}

function checkDotColor(status: string): string {
  const s = status.toLowerCase();
  if (s === "up" || s === "healthy") return "bg-mint";
  return "bg-critical";
}

/**
 * HealthStatusWidget — platform health overview with per-check status.
 *
 * Shows overall health badge (healthy / degraded / unhealthy) plus
 * individual service checks with status dots and latency.
 *
 * Data from GET /health via useHealthData().
 */
export function HealthStatusWidget() {
  const { data, isLoading, isError, error } = useHealthData();

  if (isLoading) {
    return (
      <div className="h-full w-full p-4 flex flex-col gap-3">
        <LoadingSkeleton size="md" width="third" />
        <LoadingSkeleton size="sm" width="full" />
        <LoadingSkeleton size="sm" width="full" />
      </div>
    );
  }

  if (isError) {
    return (
      <div className="h-full w-full p-4 flex items-center justify-center">
        <p className="text-sm text-destructive font-mono">
          {error instanceof Error ? error.message : "Failed to load health data"}
        </p>
      </div>
    );
  }

  if (!data) {
    return (
      <div className="h-full w-full p-4 flex items-center justify-center">
        <p className="text-sm text-text-muted font-mono">No health data available</p>
      </div>
    );
  }

  const overallStatus = data.status ?? "unknown";
  const checks = data.checks ?? {};
  const checkEntries = Object.entries(checks);

  return (
    <div className="h-full w-full p-4 flex flex-col gap-3">
      <div className="flex items-center justify-between">
        <p className="text-xs font-mono text-text-muted uppercase tracking-wider">
          Platform Health
        </p>
        <AilaBadge severity={statusBadgeSeverity(overallStatus)} size="sm">
          {overallStatus.toUpperCase()}
        </AilaBadge>
      </div>

      {checkEntries.length === 0 ? (
        <p className="text-xs font-mono text-text-muted">No checks available</p>
      ) : (
        <ul className="flex flex-col gap-1.5" role="list">
          {checkEntries.map(([name, check]) => (
            <li
              key={name}
              className="flex items-center justify-between gap-2 text-xs font-mono"
            >
              <div className="flex items-center gap-1.5 min-w-0">
                <span
                  className={`inline-block h-2 w-2 rounded-full shrink-0 ${checkDotColor(check.status)}`}
                  aria-hidden="true"
                />
                <span className="text-text truncate capitalize">{name}</span>
              </div>
              <span className="text-text-muted shrink-0">
                {check.latency_ms != null ? `${check.latency_ms.toFixed(1)}ms` : check.status}
              </span>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
