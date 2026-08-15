/**
 * SystemHealthPage -- live component health status dashboard.
 *
 * ADM-04 + 176d:
 *   - Top banner renders the legacy GET /health aggregation.
 *   - Admin callers additionally see the Phase 176d GET /health/comprehensive
 *     grid: Redis, OmniRoute, Arch Security, NVD, per-system SSH, ARQ
 *     workers, and per-module activity.
 *
 * Auto-refresh: every 30s via refetchInterval. Manual Refresh button issues
 * an immediate refetch on both queries.
 */
import { useQuery } from "@tanstack/react-query";

import { WindowPanel } from "@/components/aila/WindowPanel";
import { LoadingSkeletonGroup } from "@/components/aila/LoadingSkeleton";
import {
  SectionHeader,
  MonoBadge,
  StatBar,
  BigStat,
} from "@/components/aila/mock";
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
// Constants + tone helpers
// ---------------------------------------------------------------------------

const POLL_INTERVAL_MS = 30_000;

const SUBSYSTEM_LABEL: Record<string, string> = {
  redis: "Redis / Memurai",
  omniroute: "OmniRoute LLM",
  arch_security: "Arch Security",
  nvd: "NVD",
  ssh_systems: "Managed Systems (SSH)",
  arq_worker: "ARQ Worker",
  modules: "Modules",
};

function overallTone(status: string): "ok" | "warn" | "critical" {
  const s = status.toLowerCase();
  if (s === "healthy") return "ok";
  if (s === "degraded") return "warn";
  return "critical";
}

function checkTone(status: string): "ok" | "warn" | "critical" | "muted" {
  if (status === "up") return "ok";
  if (status === "degraded") return "warn";
  if (status === "down") return "critical";
  return "muted";
}

function subsystemTone(
  status: SubsystemStatus,
): "ok" | "warn" | "critical" | "muted" {
  switch (status) {
    case "healthy":
    case "running":
      return "ok";
    case "degraded":
    case "stale":
    case "rate_limited":
    case "timed_out":
      return "warn";
    case "unreachable":
    case "offline":
    case "error":
      return "critical";
    default:
      return "muted";
  }
}

function sshTone(status: string): "ok" | "warn" | "critical" {
  if (status === "reachable") return "ok";
  if (status === "timed_out") return "warn";
  return "critical";
}

function moduleTone(status: string): "ok" | "warn" | "critical" {
  if (status === "healthy") return "ok";
  if (status === "stale") return "warn";
  return "critical";
}

/**
 * Format a raw check name into a human-readable label.
 * "database" -> "Database"; "module.vulnerability.llm" -> "Module: Vulnerability Llm"
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
// Mock-styled action button
// ---------------------------------------------------------------------------

const BTN_STYLE: React.CSSProperties = {
  height: 26,
  fontSize: 9.5,
  padding: "0 11px",
  letterSpacing: "0.08em",
  borderRadius: 3,
  border: "1px solid var(--border-soft)",
  background: "var(--surface-sunk)",
  color: "var(--text-primary)",
  cursor: "pointer",
};

// ---------------------------------------------------------------------------
// Metadata row (label / value pair)
// ---------------------------------------------------------------------------

function MetaRow({
  label,
  value,
}: {
  label: React.ReactNode;
  value: React.ReactNode;
}) {
  return (
    <div
      className="flex items-center justify-between font-mono"
      style={{
        gap: 10,
        padding: "5px 0",
        borderBottom: "1px solid var(--border-faint)",
        fontSize: 10.5,
      }}
    >
      <span
        className="uppercase"
        style={{
          color: "var(--text-faint)",
          fontSize: 9,
          letterSpacing: "0.1em",
        }}
      >
        {label}
      </span>
      <span style={{ color: "var(--text-primary)" }}>{value}</span>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Legacy /health check panel (kept for database + module.* visibility)
// ---------------------------------------------------------------------------

function CheckPanel({
  name,
  check,
}: {
  name: string;
  check: HealthCheckResult;
}) {
  const tone = checkTone(check.status);
  return (
    <WindowPanel
      title={formatCheckName(name)}
      tone={tone === "critical" ? "warn" : tone === "muted" ? "muted" : tone}
      actions={
        <MonoBadge tone={tone}>{check.status.toUpperCase()}</MonoBadge>
      }
    >
      <div className="flex flex-col" style={{ gap: 4 }}>
        {check.latency_ms != null && (
          <MetaRow label="latency" value={`${check.latency_ms.toFixed(1)} ms`} />
        )}
        {check.message && (
          <p
            className="font-mono"
            style={{ fontSize: 11, color: "var(--text-muted)", marginTop: 4 }}
          >
            {check.message}
          </p>
        )}
        {check.latency_ms == null && !check.message && (
          <p
            className="font-mono"
            style={{ fontSize: 10.5, color: "var(--text-faint)" }}
          >
            no telemetry reported
          </p>
        )}
      </div>
    </WindowPanel>
  );
}

// ---------------------------------------------------------------------------
// 176d subsystem panel
// ---------------------------------------------------------------------------

function SubsystemPanel({ subsystem }: { subsystem: SubsystemHealth }) {
  const label = SUBSYSTEM_LABEL[subsystem.name] ?? subsystem.name;
  const tone = subsystemTone(subsystem.status);

  const sshSystems: SshReachabilityResult[] | undefined = (() => {
    if (subsystem.name !== "ssh_systems") return undefined;
    const raw = subsystem.details?.systems;
    if (!Array.isArray(raw)) return undefined;
    return raw as SshReachabilityResult[];
  })();

  const moduleEntries:
    | Array<{
        module_id: string;
        status: string;
        activity_count?: number | null;
        last_activity_at?: string | null;
      }>
    | undefined = (() => {
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

  const capacityBar = sshSystems ? (() => {
    const reachable = sshSystems.filter((s) => s.status === "reachable").length;
    return {
      value: reachable,
      max: sshSystems.length,
    };
  })() : null;

  return (
    <WindowPanel
      title={label}
      tone={tone === "critical" ? "warn" : tone === "muted" ? "muted" : tone}
      actions={
        <MonoBadge tone={tone}>
          {subsystem.status.toUpperCase()}
        </MonoBadge>
      }
    >
      <div className="flex flex-col" style={{ gap: 6 }}>
        {subsystem.latency_ms != null && (
          <MetaRow
            label="latency"
            value={`${subsystem.latency_ms.toFixed(1)} ms`}
          />
        )}
        {subsystem.message && (
          <p
            className="font-mono"
            style={{
              fontSize: 10.5,
              color: "var(--text-muted)",
              paddingTop: 2,
            }}
          >
            {subsystem.message}
          </p>
        )}
        {capacityBar && (
          <div style={{ marginTop: 8 }}>
            <StatBar
              label="REACHABLE"
              color="var(--status-ok)"
              value={capacityBar.value}
              max={capacityBar.max}
            />
          </div>
        )}
        {sshSystems && sshSystems.length > 0 && (
          <div
            className="flex flex-col"
            style={{
              gap: 4,
              marginTop: 8,
              paddingTop: 8,
              borderTop: "1px solid var(--border-faint)",
            }}
          >
            {sshSystems.slice(0, 8).map((s) => (
              <div
                key={`${s.system_id}:${s.host}:${s.port}`}
                className="flex items-center justify-between font-mono"
                style={{ gap: 8, fontSize: 10.5 }}
              >
                <span
                  className="truncate"
                  style={{ flex: 1, color: "var(--text-primary)" }}
                >
                  {s.system_name}{" "}
                  <span style={{ color: "var(--text-faint)" }}>
                    {s.host}:{s.port}
                  </span>
                </span>
                <MonoBadge tone={sshTone(s.status)}>{s.status}</MonoBadge>
              </div>
            ))}
            {sshSystems.length > 8 && (
              <p
                className="font-mono"
                style={{
                  fontSize: 9.5,
                  color: "var(--text-faint)",
                  marginTop: 2,
                }}
              >
                and {sshSystems.length - 8} more
              </p>
            )}
          </div>
        )}
        {moduleEntries && moduleEntries.length > 0 && (
          <div
            className="flex flex-col"
            style={{
              gap: 4,
              marginTop: 8,
              paddingTop: 8,
              borderTop: "1px solid var(--border-faint)",
            }}
          >
            {moduleEntries.map((m) => (
              <div
                key={m.module_id}
                className="flex items-center justify-between font-mono"
                style={{ gap: 8, fontSize: 10.5 }}
              >
                <span
                  className="truncate"
                  style={{ flex: 1, color: "var(--text-primary)" }}
                >
                  {m.module_id}
                </span>
                <span style={{ color: "var(--text-faint)", fontSize: 9.5 }}>
                  {m.activity_count ?? 0} runs
                </span>
                <MonoBadge tone={moduleTone(m.status)}>{m.status}</MonoBadge>
              </div>
            ))}
          </div>
        )}
      </div>
    </WindowPanel>
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

  // Roll-up counts for the top BigStat row.
  const healthyCount =
    subsystems.filter((s) => s.status === "healthy" || s.status === "running")
      .length +
    checkEntries.filter(([, c]) => c.status === "up").length;
  const degradedCount =
    subsystems.filter((s) =>
      ["degraded", "stale", "rate_limited", "timed_out"].includes(s.status),
    ).length +
    checkEntries.filter(([, c]) => c.status === "degraded").length;
  const criticalCount =
    subsystems.filter((s) =>
      ["unreachable", "offline", "error"].includes(s.status),
    ).length +
    checkEntries.filter(([, c]) => c.status === "down").length;
  const totalCount = subsystems.length + checkEntries.length;

  return (
    <div className="flex flex-col" style={{ gap: 16, padding: 20 }}>
      <SectionHeader
        icon={"\u25ce"}
        title="System Health"
        actions={
          <div className="flex items-center" style={{ gap: 8 }}>
            {lastChecked && (
              <span
                className="font-mono uppercase"
                style={{
                  fontSize: 9,
                  letterSpacing: "0.1em",
                  color: "var(--text-faint)",
                }}
              >
                POLL / {POLL_INTERVAL_MS / 1000}s / LAST {lastChecked}
              </span>
            )}
            <button
              type="button"
              className="font-mono uppercase"
              style={BTN_STYLE}
              onClick={handleRefresh}
              disabled={refreshing}
            >
              {refreshing ? "REFRESHING\u2026" : "REFRESH"}
            </button>
          </div>
        }
      />

      {/* Error banner (test looks for /Failed to load health data/) */}
      {healthQuery.isError && (
        <div
          className="font-mono"
          style={{
            border:
              "1px solid color-mix(in srgb, var(--status-warn) 40%, transparent)",
            background:
              "color-mix(in srgb, var(--status-warn) 10%, transparent)",
            color: "var(--status-warn)",
            padding: "10px 14px",
            fontSize: 11,
            borderRadius: 3,
          }}
        >
          Failed to load health data: {(healthQuery.error as Error).message}
        </div>
      )}
      {isAdmin && comprehensiveQuery.isError && (
        <div
          className="font-mono"
          style={{
            border:
              "1px solid color-mix(in srgb, var(--status-warn) 40%, transparent)",
            background:
              "color-mix(in srgb, var(--status-warn) 10%, transparent)",
            color: "var(--status-warn)",
            padding: "10px 14px",
            fontSize: 11,
            borderRadius: 3,
          }}
        >
          Failed to load comprehensive health:{" "}
          {(comprehensiveQuery.error as Error).message}
        </div>
      )}

      {/* Loading skeleton */}
      {healthQuery.isLoading && (
        <WindowPanel title="health" status="LOADING" tone="muted">
          <LoadingSkeletonGroup lines={4} />
        </WindowPanel>
      )}

      {/* Overall + roll-up row */}
      {data && (
        <div
          className="grid"
          style={{ gridTemplateColumns: "1.4fr 1fr", gap: 12 }}
        >
          <WindowPanel
            title="overall status"
            tone={
              overallTone(overallStatus) === "critical"
                ? "accent"
                : (overallTone(overallStatus) as "ok" | "warn")
            }
            actions={
              <MonoBadge tone={overallTone(overallStatus)}>
                {overallStatus.toUpperCase()}
              </MonoBadge>
            }
          >
            <div
              className="flex items-center"
              style={{ gap: 20 }}
              role="status"
              aria-live="polite"
            >
              <BigStat value={totalCount} sub="components monitored" />
              <div className="flex flex-col" style={{ gap: 6, flex: 1 }}>
                <StatBar
                  label="HEALTHY"
                  color="var(--status-ok)"
                  value={healthyCount}
                  max={totalCount || 1}
                />
                <StatBar
                  label="DEGRADED"
                  color="var(--status-warn)"
                  value={degradedCount}
                  max={totalCount || 1}
                />
                <StatBar
                  label="CRITICAL"
                  color="var(--accent)"
                  value={criticalCount}
                  max={totalCount || 1}
                />
              </div>
            </div>
          </WindowPanel>

          <WindowPanel title="signal">
            <BigStat
              value={criticalCount}
              sub={
                criticalCount === 0
                  ? "no critical subsystems"
                  : "components need attention"
              }
            />
          </WindowPanel>
        </div>
      )}

      {/* Subsystem grid (admin) */}
      {isAdmin && comprehensive && subsystems.length > 0 && (
        <>
          <SectionHeader
            icon={"\u25a1"}
            title={`subsystems / ${subsystems.length}`}
            size={16}
          />
          <div
            className="grid"
            style={{
              gridTemplateColumns: "repeat(auto-fill, minmax(320px, 1fr))",
              gap: 12,
            }}
          >
            {subsystems.map((sub) => (
              <SubsystemPanel key={sub.name} subsystem={sub} />
            ))}
          </div>
        </>
      )}

      {/* Core component grid */}
      {checkEntries.length > 0 && (
        <>
          <SectionHeader
            icon={"\u25c7"}
            title={`core components / ${checkEntries.length}`}
            size={16}
          />
          <div
            className="grid"
            style={{
              gridTemplateColumns: "repeat(auto-fill, minmax(320px, 1fr))",
              gap: 12,
            }}
          >
            {checkEntries.map(([name, check]) => (
              <CheckPanel key={name} name={name} check={check} />
            ))}
          </div>
        </>
      )}

      {/* No checks at all */}
      {data && checkEntries.length === 0 && subsystems.length === 0 && (
        <WindowPanel title="status">
          <p
            className="font-mono"
            style={{
              padding: 22,
              textAlign: "center",
              fontSize: 12,
              color: "var(--text-muted)",
            }}
          >
            no health checks reported by the platform.
          </p>
        </WindowPanel>
      )}
    </div>
  );
}
