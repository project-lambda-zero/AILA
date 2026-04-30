import * as React from "react";
import { FileText, Clock, CheckCircle } from "lucide-react";

import { LoadingSkeleton } from "@/components/aila/LoadingSkeleton";
import { useDashboardData } from "../hooks/useDashboardData";

interface SbdOverviewData {
  active_sessions: number;
  pending_reviews: number;
  recent_completions: number;
}

function isSbdOverviewData(value: unknown): value is SbdOverviewData {
  if (!value || typeof value !== "object") return false;
  const v = value as Record<string, unknown>;
  return (
    typeof v.active_sessions === "number" &&
    typeof v.pending_reviews === "number" &&
    typeof v.recent_completions === "number"
  );
}

interface MetricRowProps {
  icon: React.ReactNode;
  label: string;
  count: number;
}

function MetricRow({ icon, label, count }: MetricRowProps) {
  return (
    <div className="flex items-center justify-between py-2 border-b border-border last:border-0">
      <div className="flex items-center gap-2">
        <span className="text-accent" aria-hidden="true">
          {icon}
        </span>
        <span className="text-sm font-mono text-text">{label}</span>
      </div>
      <span className="text-sm font-mono font-bold text-text tabular-nums">{count}</span>
    </div>
  );
}

/**
 * SbdOverviewWidget — SbD NFR module overview.
 *
 * Reads module_data["sbd_nfr.overview"] which should contain:
 * { active_sessions, pending_reviews, recent_completions }.
 *
 * Shows graceful empty state when the module is not loaded.
 *
 * Data from GET /dashboard via useDashboardData().
 */
export function SbdOverviewWidget() {
  const { data, isLoading, isError, error } = useDashboardData();

  if (isLoading) {
    return (
      <div className="h-full w-full p-4 flex flex-col gap-3">
        <LoadingSkeleton size="sm" width="full" />
        <LoadingSkeleton size="sm" width="full" />
        <LoadingSkeleton size="sm" width="full" />
      </div>
    );
  }

  if (isError) {
    return (
      <div className="h-full w-full p-4 flex items-center justify-center">
        <p className="text-sm text-destructive font-mono">
          {error instanceof Error ? error.message : "Failed to load SbD data"}
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

  const raw = data.module_data["sbd_nfr.overview"];
  const overview = isSbdOverviewData(raw) ? raw : null;

  if (!overview) {
    return (
      <div className="h-full w-full p-4 flex flex-col justify-center gap-1">
        <p className="text-sm font-mono font-semibold text-text">SbD NFR Overview</p>
        <p className="text-xs font-mono text-text-muted">SbD NFR module not loaded</p>
      </div>
    );
  }

  return (
    <div className="h-full w-full p-4 flex flex-col justify-center">
      <p className="text-xs font-mono text-text-muted uppercase tracking-wider mb-2">
        SbD NFR Overview
      </p>
      <MetricRow
        icon={<FileText className="h-4 w-4" />}
        label="Active Sessions"
        count={overview.active_sessions}
      />
      <MetricRow
        icon={<Clock className="h-4 w-4" />}
        label="Pending Reviews"
        count={overview.pending_reviews}
      />
      <MetricRow
        icon={<CheckCircle className="h-4 w-4" />}
        label="Recent Completions"
        count={overview.recent_completions}
      />
    </div>
  );
}
