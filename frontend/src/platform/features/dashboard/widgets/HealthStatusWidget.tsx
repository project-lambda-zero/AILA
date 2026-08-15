import * as React from "react";

import { LoadingSkeleton } from "@/components/aila/LoadingSkeleton";
import { MonoBadge } from "@/components/aila/mock";
import { useHealthData } from "../hooks/useDashboardData";

type OverallTone = "ok" | "warn" | "critical";

function overallTone(status: string): OverallTone {
  const s = status.toLowerCase();
  if (s === "healthy") return "ok";
  if (s === "degraded") return "warn";
  return "critical";
}

function checkDotColor(status: string): string {
  const s = status.toLowerCase();
  if (s === "up" || s === "healthy") return "var(--status-ok)";
  return "var(--accent)";
}

const CENTER_STYLE: React.CSSProperties = {
  height: "100%",
  padding: 16,
  fontFamily: "var(--font-mono)",
  fontSize: 11,
};

/**
 * HealthStatusWidget -- platform health overview with per-check status.
 *
 * Shows overall health chip (healthy / degraded / unhealthy) plus a mono
 * row per service check with a status dot and latency.
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
      <div
        className="flex items-center justify-center"
        style={{ ...CENTER_STYLE, color: "var(--status-warn)" }}
      >
        {error instanceof Error ? error.message : "Failed to load health data"}
      </div>
    );
  }

  if (!data) {
    return (
      <div
        className="flex items-center justify-center"
        style={{ ...CENTER_STYLE, color: "var(--text-muted)" }}
      >
        No health data available
      </div>
    );
  }

  const overallStatus = data.status ?? "unknown";
  const checks = data.checks ?? {};
  const checkEntries = Object.entries(checks);

  return (
    <div
      className="h-full w-full flex flex-col"
      style={{ padding: 14, gap: 10 }}
    >
      <div className="flex items-center justify-between">
        <span
          className="font-mono uppercase"
          style={{
            fontSize: 9.5,
            letterSpacing: "0.14em",
            color: "var(--text-muted)",
          }}
        >
          overall
        </span>
        <MonoBadge tone={overallTone(overallStatus)}>
          {overallStatus.toUpperCase()}
        </MonoBadge>
      </div>

      {checkEntries.length === 0 ? (
        <div
          className="font-mono"
          style={{ fontSize: 11, color: "var(--text-muted)" }}
        >
          No checks available
        </div>
      ) : (
        <ul
          role="list"
          className="flex flex-col"
          style={{
            gap: 0,
            margin: 0,
            padding: 0,
            listStyle: "none",
            borderTop: "1px solid var(--border-faint)",
          }}
        >
          {checkEntries.map(([name, check]) => (
            <li
              key={name}
              className="flex items-center justify-between font-mono"
              style={{
                fontSize: 10.5,
                padding: "6px 0",
                borderBottom: "1px solid var(--border-faint)",
                gap: 8,
              }}
            >
              <div
                className="flex items-center min-w-0"
                style={{ gap: 8 }}
              >
                <span
                  aria-hidden="true"
                  style={{
                    display: "inline-block",
                    height: 6,
                    width: 6,
                    borderRadius: "50%",
                    background: checkDotColor(check.status),
                    flexShrink: 0,
                  }}
                />
                <span
                  className="truncate capitalize"
                  style={{ color: "var(--text-primary)" }}
                >
                  {name}
                </span>
              </div>
              <span
                className="shrink-0"
                style={{ color: "var(--text-muted)" }}
              >
                {check.latency_ms != null
                  ? `${check.latency_ms.toFixed(1)}ms`
                  : check.status}
              </span>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
