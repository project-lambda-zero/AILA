/**
 * SystemHealthPage — live component health status dashboard.
 *
 * ADM-04 + 176d:
 *   - Top banner renders the legacy GET /health aggregation (healthy /
 *     degraded / unhealthy) so the page still works for non-admin tools
 *     looking at the basic endpoint shape.
 *   - Admin callers additionally see the Phase 176d GET /health/comprehensive
 *     grid: Redis, OmniRoute, Arch Security, NVD, per-system SSH, ARQ
 *     workers, and per-module activity.
 *
 * Auto-refresh: every 30s via refetchInterval. Manual Refresh button issues
 * an immediate refetch on both queries.
 *
 * Only uses design-system primitives: AilaCard, AilaBadge, LoadingSkeleton,
 * shadcn Button, phosphor icons, Tailwind utilities (per feedback_design_taste).
 */
import { useQuery } from "@tanstack/react-query";
import {
  HeartbeatIcon,
  ArrowClockwise,
  Database,
  CloudArrowDown,
  Cpu,
  HardDrives,
  Plugs,
  Graph,
  Stack,
} from "@phosphor-icons/react";
import type { ComponentType } from "react";

import { AilaCard } from "@/components/aila/AilaCard";
import { AilaBadge } from "@/components/aila/AilaBadge";
import { LoadingSkeletonGroup } from "@/components/aila/LoadingSkeleton";
import { Button } from "@/components/ui/button";
import { authorizedRequestJson } from "@platform/api/http";
import { useAuthStore } from "@platform/auth/useAuthStore";

// ---------------------------------------------------------------------------
// Legacy /health types
// ---------------------------------------------------------------------------

interface HealthCheckResult {
  status: "up" | "degraded" | "down";
  latency_ms: number | null;
  message: string | null;
}

interface HealthCheckResponse {
  status: "healthy" | "degraded" | "unhealthy";
  checks: Record<string, HealthCheckResult>;
}

// ---------------------------------------------------------------------------
// 176d /health/comprehensive types
// ---------------------------------------------------------------------------

type SubsystemStatus =
  | "healthy"
  | "degraded"
  | "unreachable"
  | "rate_limited"
  | "timed_out"
  | "running"
  | "stale"
  | "offline"
  | "error"
  | "unknown";

interface SshReachabilityResult {
  system_id: number;
  system_name: string;
  host: string;
  port: number;
  status: "reachable" | "unreachable" | "timed_out" | "error";
  latency_ms: number | null;
  message: string | null;
}

interface SubsystemHealth {
  name: string;
  status: SubsystemStatus;
  latency_ms: number | null;
  last_checked_at: string;
  message: string | null;
  details: Record<string, unknown> | null;
}

interface ComprehensiveHealthResponse {
  overall_status: "healthy" | "degraded" | "unhealthy";
  checked_at: string;
  subsystems: SubsystemHealth[];
}

interface DataEnvelope<T> {
  data: T;
  error: string | null;
  meta: Record<string, unknown>;
}

// ---------------------------------------------------------------------------
// Constants and style helpers
// ---------------------------------------------------------------------------

const POLL_INTERVAL_MS = 30_000;

const SUBSYSTEM_ICON: Record<string, ComponentType<{ className?: string }>> = {
  redis: Database,
  omniroute: CloudArrowDown,
  arch_security: HardDrives,
  nvd: HardDrives,
  ssh_systems: Plugs,
  arq_worker: Cpu,
  modules: Stack,
};

const SUBSYSTEM_LABEL: Record<string, string> = {
  redis: "Redis / Memurai",
  omniroute: "OmniRoute LLM",
  arch_security: "Arch Security",
  nvd: "NVD",
  ssh_systems: "Managed Systems (SSH)",
  arq_worker: "ARQ Worker",
  modules: "Modules",
};

function overallStatusColor(status: string): string {
  const s = status.toLowerCase();
  if (s === "healthy") return "border-mint/60 bg-mint/10 text-mint";
  if (s === "degraded") return "border-accent/60 bg-accent/10 text-accent";
  return "border-destructive/60 bg-destructive/10 text-destructive";
}

function overallStatusSeverity(
  status: string,
): "info" | "medium" | "critical" {
  const s = status.toLowerCase();
  if (s === "healthy") return "info";
  if (s === "degraded") return "medium";
  return "critical";
}

function checkStatusSeverity(
  status: string,
): "info" | "medium" | "critical" | "neutral" {
  if (status === "up") return "info";
  if (status === "degraded") return "medium";
  if (status === "down") return "critical";
  return "neutral";
}

function subsystemSeverity(
  status: SubsystemStatus,
): "info" | "medium" | "critical" | "neutral" {
  switch (status) {
    case "healthy":
    case "running":
      return "info";
    case "degraded":
    case "stale":
    case "rate_limited":
    case "timed_out":
      return "medium";
    case "unreachable":
    case "offline":
    case "error":
      return "critical";
    case "unknown":
    default:
      return "neutral";
  }
}

function subsystemDotClass(status: SubsystemStatus): string {
  const severity = subsystemSeverity(status);
  if (severity === "info") return "bg-mint";
  if (severity === "medium") return "bg-accent";
  if (severity === "critical") return "bg-destructive";
  return "bg-border";
}

function checkDotClass(status: string): string {
  if (status === "up") return "bg-mint";
  if (status === "degraded") return "bg-accent";
  return "bg-destructive";
}

/**
 * Format a raw check name into a human-readable label.
 * "database" -> "Database"
 * "module.vulnerability.llm" -> "Module: Vulnerability LLM"
 */
function formatCheckName(name: string): string {
  if (!name.includes(".")) {
    return name.charAt(0).toUpperCase() + name.slice(1);
  }
  const parts = name.split(".");
  const prefix = parts[0].charAt(0).toUpperCase() + parts[0].slice(1);
  const rest = parts
    .slice(1)
    .map((p) => p.charAt(0).toUpperCase() + p.slice(1))
    .join(" ");
  return `${prefix}: ${rest}`;
}

// ---------------------------------------------------------------------------
// Legacy /health check card (kept for database visibility)
// ---------------------------------------------------------------------------

interface CheckCardProps {
  name: string;
  check: HealthCheckResult;
}

function CheckCard({ name, check }: CheckCardProps) {
  return (
    <AilaCard variant="elevated" padding="md" className="flex flex-col gap-3">
      <div className="flex items-center justify-between gap-2">
        <div className="flex items-center gap-2 min-w-0">
          <span
            className={`inline-block h-2.5 w-2.5 rounded-full shrink-0 ${checkDotClass(check.status)}`}
            aria-hidden="true"
          />
          <h3 className="font-mono text-sm font-semibold text-text truncate">
            {formatCheckName(name)}
          </h3>
        </div>
        <AilaBadge severity={checkStatusSeverity(check.status)} size="sm">
          {check.status.toUpperCase()}
        </AilaBadge>
      </div>

      {check.latency_ms != null && (
        <div className="flex items-center gap-1.5">
          <span className="font-mono text-xs text-text-muted">Latency:</span>
          <span className="font-mono text-xs text-text">
            {check.latency_ms.toFixed(1)} ms
          </span>
        </div>
      )}

      {check.message && (
        <p className="font-mono text-xs text-text-muted">{check.message}</p>
      )}
    </AilaCard>
  );
}

// ---------------------------------------------------------------------------
// 176d subsystem card
// ---------------------------------------------------------------------------

interface SubsystemCardProps {
  subsystem: SubsystemHealth;
}

function SubsystemCard({ subsystem }: SubsystemCardProps) {
  const Icon = SUBSYSTEM_ICON[subsystem.name] ?? Graph;
  const label = SUBSYSTEM_LABEL[subsystem.name] ?? subsystem.name;

  const sshSystems: SshReachabilityResult[] | undefined = (() => {
    if (subsystem.name !== "ssh_systems") return undefined;
    const raw = subsystem.details?.systems;
    if (!Array.isArray(raw)) return undefined;
    return raw as SshReachabilityResult[];
  })();

  const moduleEntries: Array<{
    module_id: string;
    status: string;
    activity_count?: number | null;
    last_activity_at?: string | null;
  }> | undefined = (() => {
    if (subsystem.name !== "modules") return undefined;
    const raw = subsystem.details?.modules;
    if (!Array.isArray(raw)) return undefined;
    return raw as Array<{
      module_id: string;
      status: string;
      activity_count?: number | null;
      last_activity_at?: string | null;
    }>;
  })();

  return (
    <AilaCard variant="elevated" padding="md" className="flex flex-col gap-3">
      <div className="flex items-center justify-between gap-2">
        <div className="flex items-center gap-2 min-w-0">
          <span
            className={`inline-block h-2.5 w-2.5 rounded-full shrink-0 ${subsystemDotClass(subsystem.status)}`}
            aria-hidden="true"
          />
          <Icon className="h-4 w-4 shrink-0 text-text-muted" />
          <h3 className="font-mono text-sm font-semibold text-text truncate">
            {label}
          </h3>
        </div>
        <AilaBadge severity={subsystemSeverity(subsystem.status)} size="sm">
          {subsystem.status.toUpperCase()}
        </AilaBadge>
      </div>

      {subsystem.latency_ms != null && (
        <div className="flex items-center gap-1.5">
          <span className="font-mono text-xs text-text-muted">Latency:</span>
          <span className="font-mono text-xs text-text">
            {subsystem.latency_ms.toFixed(1)} ms
          </span>
        </div>
      )}

      {subsystem.message && (
        <p className="font-mono text-xs text-text-muted">{subsystem.message}</p>
      )}

      {sshSystems && sshSystems.length > 0 && (
        <div className="flex flex-col gap-1 border-t border-border pt-2 mt-1">
          {sshSystems.slice(0, 8).map((s) => (
            <div
              key={`${s.system_id}:${s.host}:${s.port}`}
              className="flex items-center justify-between gap-2"
            >
              <span className="font-mono text-[11px] truncate flex-1">
                {s.system_name}{" "}
                <span className="text-text-muted">
                  {s.host}:{s.port}
                </span>
              </span>
              <AilaBadge
                severity={
                  s.status === "reachable"
                    ? "info"
                    : s.status === "timed_out"
                      ? "medium"
                      : "critical"
                }
                size="sm"
              >
                {s.status}
              </AilaBadge>
            </div>
          ))}
          {sshSystems.length > 8 && (
            <p className="font-mono text-[10px] text-text-muted mt-1">
              and {sshSystems.length - 8} more
            </p>
          )}
        </div>
      )}

      {moduleEntries && moduleEntries.length > 0 && (
        <div className="flex flex-col gap-1 border-t border-border pt-2 mt-1">
          {moduleEntries.map((m) => (
            <div
              key={m.module_id}
              className="flex items-center justify-between gap-2"
            >
              <span className="font-mono text-[11px] text-text truncate flex-1">
                {m.module_id}
              </span>
              <span className="font-mono text-[10px] text-text-muted">
                {m.activity_count ?? 0} runs
              </span>
              <AilaBadge
                severity={
                  m.status === "healthy"
                    ? "info"
                    : m.status === "stale"
                      ? "medium"
                      : "critical"
                }
                size="sm"
              >
                {m.status}
              </AilaBadge>
            </div>
          ))}
        </div>
      )}
    </AilaCard>
  );
}

// ---------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------

export function SystemHealthPage() {
  const role = useAuthStore((s) => s.role);
  const isAdmin = role === "admin";

  const healthQuery = useQuery({
    queryKey: ["platform", "health"],
    queryFn: () => authorizedRequestJson<HealthCheckResponse>("/health"),
    refetchInterval: POLL_INTERVAL_MS,
    staleTime: 10_000,
  });

  const comprehensiveQuery = useQuery({
    queryKey: ["platform", "health", "comprehensive"],
    queryFn: () =>
      authorizedRequestJson<DataEnvelope<ComprehensiveHealthResponse>>(
        "/health/comprehensive",
      ),
    refetchInterval: POLL_INTERVAL_MS,
    staleTime: 10_000,
    enabled: isAdmin,
  });

  const data = healthQuery.data;
  const overallStatus = data?.status ?? "unknown";
  const checks = data?.checks ?? {};
  const checkEntries = Object.entries(checks);

  const comprehensive = comprehensiveQuery.data?.data;
  const subsystems = comprehensive?.subsystems ?? [];

  const lastChecked = healthQuery.dataUpdatedAt
    ? new Date(healthQuery.dataUpdatedAt).toLocaleTimeString()
    : null;

  const refreshing = healthQuery.isFetching || comprehensiveQuery.isFetching;

  const handleRefresh = (): void => {
    void healthQuery.refetch();
    if (isAdmin) void comprehensiveQuery.refetch();
  };

  return (
    <div className="flex flex-col gap-6 p-4 lg:p-6">
      {/* Page header */}
      <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="font-mono text-xl font-semibold text-text flex items-center gap-2">
            <HeartbeatIcon className="h-5 w-5 text-accent" />
            System Health
          </h1>
          <p className="font-mono text-sm text-text-muted mt-0.5">
            Live component status. Auto-refreshes every 30 seconds.
            {lastChecked && (
              <> Last checked at <span className="text-text">{lastChecked}</span>.</>
            )}
          </p>
        </div>

        <Button
          size="sm"
          variant="outline"
          className="gap-1.5"
          onClick={handleRefresh}
          disabled={refreshing}
        >
          <ArrowClockwise
            className={`h-4 w-4 ${refreshing ? "animate-spin" : ""}`}
          />
          {refreshing ? "Refreshing…" : "Refresh"}
        </Button>
      </div>

      {/* Error banner */}
      {healthQuery.isError && (
        <div className="rounded-[4px] border border-destructive bg-destructive/10 px-4 py-3 font-mono text-sm text-destructive">
          Failed to load health data: {(healthQuery.error as Error).message}
        </div>
      )}
      {isAdmin && comprehensiveQuery.isError && (
        <div className="rounded-[4px] border border-destructive bg-destructive/10 px-4 py-3 font-mono text-sm text-destructive">
          Failed to load comprehensive health:{" "}
          {(comprehensiveQuery.error as Error).message}
        </div>
      )}

      {/* Loading skeleton */}
      {healthQuery.isLoading && (
        <AilaCard variant="default" padding="md">
          <LoadingSkeletonGroup lines={4} />
        </AilaCard>
      )}

      {/* Overall status banner */}
      {data && (
        <div
          className={`rounded-[4px] border px-6 py-5 flex items-center gap-4 ${overallStatusColor(overallStatus)}`}
          role="status"
          aria-live="polite"
        >
          <span
            className={`inline-block h-4 w-4 rounded-full shrink-0 ${checkDotClass(
              overallStatus === "healthy"
                ? "up"
                : overallStatus === "degraded"
                  ? "degraded"
                  : "down",
            )}`}
            aria-hidden="true"
          />
          <div className="flex flex-col gap-0.5">
            <span className="font-mono text-lg font-bold uppercase tracking-wider">
              {overallStatus}
            </span>
            <span className="font-mono text-xs opacity-80">
              {checkEntries.length} core component
              {checkEntries.length !== 1 ? "s" : ""} monitored
            </span>
          </div>
          <div className="ml-auto">
            <AilaBadge severity={overallStatusSeverity(overallStatus)} size="md">
              {overallStatus.toUpperCase()}
            </AilaBadge>
          </div>
        </div>
      )}

      {/* 176d comprehensive subsystem grid (admin only) */}
      {isAdmin && comprehensive && (
        <>
          <h2 className="font-mono text-sm font-semibold text-text-muted uppercase tracking-wider">
            Subsystems ({subsystems.length})
          </h2>
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
            {subsystems.map((sub) => (
              <SubsystemCard key={sub.name} subsystem={sub} />
            ))}
          </div>
        </>
      )}

      {/* Core component cards (database + module checks) */}
      {checkEntries.length > 0 && (
        <>
          <h2 className="font-mono text-sm font-semibold text-text-muted uppercase tracking-wider">
            Core Components ({checkEntries.length})
          </h2>
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
            {checkEntries.map(([name, check]) => (
              <CheckCard key={name} name={name} check={check} />
            ))}
          </div>
        </>
      )}

      {/* No checks available */}
      {data && checkEntries.length === 0 && (
        <div className="rounded-[4px] border border-border bg-elevated px-4 py-6 text-center">
          <p className="font-mono text-sm text-text-muted">
            No health checks reported by the platform.
          </p>
        </div>
      )}

      {/* Polling info */}
      {data && (
        <p className="font-mono text-xs text-text-muted">
          Health status is polled every {POLL_INTERVAL_MS / 1000} seconds.
          Use the Refresh button to check immediately.
        </p>
      )}
    </div>
  );
}
