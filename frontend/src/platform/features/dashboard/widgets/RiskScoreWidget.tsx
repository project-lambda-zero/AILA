import * as React from "react";

import { LoadingSkeleton } from "@/components/aila/LoadingSkeleton";
import { useDashboardData } from "../hooks/useDashboardData";

// SVG gauge constants
const CX = 60;
const CY = 60;
const R = 50;
const STROKE_WIDTH = 8;
const CIRCUMFERENCE = 2 * Math.PI * R; // ~314.16

function scoreColor(score: number): string {
  if (score > 7) return "var(--color-critical)";
  if (score >= 5) return "var(--color-high)";
  return "var(--color-accent)";
}

function formatTimestamp(isoString: string): string {
  try {
    return new Date(isoString).toLocaleString(undefined, {
      month: "short",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit",
    });
  } catch {
    return isoString;
  }
}

/**
 * RiskScoreWidget — circular SVG gauge showing composite risk score (0-10).
 *
 * Arc color:
 *   - score < 5 → amber (accent)
 *   - score 5-7 → orange (high)
 *   - score > 7 → red (critical)
 *
 * Data from GET /dashboard via useDashboardData().
 */
export function RiskScoreWidget() {
  const { data, isLoading, isError, error } = useDashboardData();

  if (isLoading) {
    return (
      <div className="h-full w-full p-4 flex flex-col gap-3">
        <LoadingSkeleton size="xl" width="half" className="mx-auto rounded-full" />
        <LoadingSkeleton size="sm" width="third" className="mx-auto" />
      </div>
    );
  }

  if (isError) {
    return (
      <div className="h-full w-full p-4 flex items-center justify-center">
        <p className="text-sm text-destructive font-mono">
          {error instanceof Error ? error.message : "Failed to load risk score"}
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

  const score = data.risk_score;
  const arcColor = scoreColor(score);
  // Offset: full offset = no arc visible; 0 = full arc
  const dashOffset = CIRCUMFERENCE * (1 - score / 10);

  return (
    <div className="h-full w-full p-4 flex flex-col items-center justify-center gap-2">
      <svg
        viewBox="0 0 120 120"
        width={100}
        height={100}
        aria-label={`Risk score: ${score.toFixed(1)} out of 10`}
        role="img"
      >
        {/* Background track */}
        <circle
          cx={CX}
          cy={CY}
          r={R}
          fill="none"
          stroke="var(--color-border)"
          strokeWidth={STROKE_WIDTH}
        />
        {/* Foreground arc — starts from top (rotate -90deg) */}
        <circle
          cx={CX}
          cy={CY}
          r={R}
          fill="none"
          stroke={arcColor}
          strokeWidth={STROKE_WIDTH}
          strokeDasharray={CIRCUMFERENCE}
          strokeDashoffset={dashOffset}
          strokeLinecap="round"
          transform={`rotate(-90 ${CX} ${CY})`}
          style={{ transition: "stroke-dashoffset 0.5s ease, stroke 0.3s ease" }}
        />
        {/* Centered score number */}
        <text
          x={CX}
          y={CY + 1}
          textAnchor="middle"
          dominantBaseline="middle"
          fill={arcColor}
          fontFamily="var(--font-mono)"
          fontSize={24}
          fontWeight={700}
        >
          {score.toFixed(1)}
        </text>
      </svg>

      <p className="text-sm font-mono font-semibold text-text">Risk Score</p>
      <p className="text-xs font-mono text-text-muted">
        Updated {formatTimestamp(data.generated_at)}
      </p>
    </div>
  );
}
