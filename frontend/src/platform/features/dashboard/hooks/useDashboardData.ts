import { useQuery } from "@tanstack/react-query";

import { authorizedRequestJson, requestJson } from "@platform/api/http";

// ---------------------------------------------------------------------------
// Backend response types — mirror src/aila/api/schemas/endpoints.py
// ---------------------------------------------------------------------------

export interface FleetStats {
  total_systems: number;
  online_systems: number;
  total_findings: number;
  critical_findings: number;
  high_findings: number;
  medium_findings: number;
  low_findings: number;
}

export interface DashboardResponse {
  risk_score: number;
  fleet_stats: FleetStats;
  /** Module-contributed data keyed by "{module_id}.{provider_name}" */
  module_data: Record<string, unknown>;
  generated_at: string;
}

export interface DashboardEnvelope {
  data: DashboardResponse;
  meta?: { closed_last_30d?: number; [key: string]: unknown };
}

export interface HealthCheckResult {
  status: string;
  latency_ms?: number | null;
  message?: string | null;
}

export interface HealthResponse {
  status: string;
  checks: Record<string, HealthCheckResult>;
}

// ---------------------------------------------------------------------------
// TanStack Query hooks
// ---------------------------------------------------------------------------

/**
 * Fetches aggregated platform dashboard data from GET /dashboard.
 *
 * Refreshes via SSE-driven query invalidation on ``scan_complete`` and
 * ``finding_arrived`` events (see SSEProvider.tsx) — RT-04.
 * Also polls every 60 seconds as a fallback when SSE is disconnected.
 * staleTime: 30_000 prevents redundant refetches between SSE events.
 *
 * Used by: RiskScoreWidget, FleetCoverageWidget, ActiveScansWidget,
 *           SeverityChartWidget, TopFindingsWidget, MttrWidget, TrendWidget,
 *           SbdOverviewWidget.
 */
export function useDashboardData() {
  const { data, isLoading, isError, error } = useQuery<DashboardEnvelope>({
    queryKey: ["dashboard", "stats"],
    queryFn: () => authorizedRequestJson<DashboardEnvelope>("/dashboard"),
    refetchInterval: 60_000,
    staleTime: 30_000,
  });

  return {
    data: data?.data,
    meta: data?.meta,
    isLoading,
    isError,
    error,
  };
}

/**
 * Fetches platform health status from GET /health.
 * Refreshes automatically every 30 seconds (health checks need faster cadence).
 * Used by: HealthStatusWidget.
 */
export function useHealthData() {
  const { data, isLoading, isError, error } = useQuery<HealthResponse>({
    queryKey: ["platform", "health"],
    queryFn: () => requestJson<HealthResponse>("/health"),
    refetchInterval: 30_000,
    staleTime: 15_000,
  });

  return {
    data,
    isLoading,
    isError,
    error,
  };
}
