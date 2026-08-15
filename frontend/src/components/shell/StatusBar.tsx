/**
 * StatusBar -- fixed 24px console strip pinned at the bottom of the
 * authenticated shell.
 *
 * Segments (left -> right):
 *   1. Engine dot + label from GET /health (public endpoint)
 *   2. Queue depth from GET /tasks/queue-depth (admin-only; hidden on 4xx/5xx)
 *   3. Active module (first path segment; "" -> CHAT)
 *   4. ROI %% from GET /cost/roi (hidden on error/permission miss)
 *   5. flex spacer
 *   6. Online/offline (navigator.onLine + online/offline events)
 *   7. Build tag: v<version> <short-sha>
 *   8. HH:MM:SS live clock
 *
 * Motion: the queue-count pulse reuses the existing
 * `.animate-severity-pulse` utility which already opts out under
 * `prefers-reduced-motion: reduce` (see globals.css).
 */
import { useEffect, useState } from "react";
import { useLocation } from "react-router";
import { useQuery } from "@tanstack/react-query";

import { authorizedRequestJson, requestJson } from "@platform/api/http";
import { appVersion, buildSha } from "@platform/config/version";

// ---------------------------------------------------------------------------
// Backend response shapes (mirrored inline; no new module boundary crossings).
// ---------------------------------------------------------------------------

/** Matches `aila.api.schemas.health.HealthCheckResponse.status`. */
type HealthStatus = "healthy" | "degraded" | "unhealthy";

interface HealthCheckResponse {
  status: HealthStatus;
  checks: Record<string, unknown>;
}

interface DataEnvelope<T> {
  data: T;
}

/** GET /tasks/queue-depth returns `{ data: { <status>: count, ... } }`. */
type QueueDepthPayload = Record<string, number>;

/** Matches `aila.api.schemas.cost.ROIResponse`. */
interface ROIResponse {
  period_start: string;
  period_end: string;
  llm_cost_usd: number;
  human_equivalent_cost_usd: number;
  human_equivalent_hours: number;
  roi_percentage: number;
  run_count: number;
}

// ---------------------------------------------------------------------------
// Hooks
// ---------------------------------------------------------------------------

type EngineStatus = "ok" | "degraded" | "offline";

function useEngineStatus(): EngineStatus {
  const query = useQuery({
    queryKey: ["system-status", "health"],
    queryFn: () => requestJson<HealthCheckResponse>("/health"),
    refetchInterval: 10_000,
    staleTime: 5_000,
    retry: 1,
  });

  if (query.isError) return "offline";
  const status = query.data?.status;
  if (status === "degraded") return "degraded";
  if (status === "unhealthy") return "offline";
  // "healthy" or (loading -> optimistic ok, dot renders but with no known-bad state)
  return "ok";
}

/**
 * Sum every status bucket into a single visible queue count. The endpoint
 * returns e.g. `{ queued: 2, running: 1, waiting: 0 }`; UX-wise "queue" here
 * means "backlog of not-yet-terminal tasks", so we sum all buckets that the
 * server chose to report and don't filter -- if the server adds a new state
 * it lands in the total without a frontend change.
 *
 * On any error (non-admin 403, rate-limit 429, network) `null` is returned
 * and the caller hides the segment rather than pretending "0".
 */
function useQueueDepth(): number | null {
  const query = useQuery({
    queryKey: ["system-status", "queue"],
    queryFn: () =>
      authorizedRequestJson<DataEnvelope<QueueDepthPayload>>("/tasks/queue-depth"),
    refetchInterval: 10_000,
    // Admin-only route: retrying a 403 wastes both requests against the
    // 10/minute limiter. One shot per interval, hide on failure.
    retry: false,
  });

  if (query.isError || !query.data) return null;
  const depth = query.data.data ?? {};
  return Object.values(depth).reduce<number>((sum, n) => sum + (Number(n) || 0), 0);
}

/**
 * Fetch platform-wide LLM-vs-human ROI (defaults to trailing 3 months
 * server-side). Aggregated over months of cost records so a fast refetch
 * cadence buys nothing; slow polling is also friendlier to the 120/min
 * limiter on `/cost/roi`. On error/empty the caller hides the segment.
 */
function useROI(): ROIResponse | null {
  const query = useQuery({
    queryKey: ["system-status", "roi"],
    queryFn: () =>
      authorizedRequestJson<DataEnvelope<ROIResponse>>("/cost/roi"),
    refetchInterval: 60_000,
    staleTime: 30_000,
    retry: false,
  });

  if (query.isError || !query.data?.data) return null;
  return query.data.data;
}

function useOnline(): boolean {
  const [online, setOnline] = useState<boolean>(() =>
    typeof navigator !== "undefined" ? navigator.onLine : true,
  );
  useEffect(() => {
    const handleOnline = () => setOnline(true);
    const handleOffline = () => setOnline(false);
    window.addEventListener("online", handleOnline);
    window.addEventListener("offline", handleOffline);
    return () => {
      window.removeEventListener("online", handleOnline);
      window.removeEventListener("offline", handleOffline);
    };
  }, []);
  return online;
}

function useClock(): string {
  const [now, setNow] = useState<Date>(() => new Date());
  useEffect(() => {
    const id = window.setInterval(() => setNow(new Date()), 1000);
    return () => window.clearInterval(id);
  }, []);
  const hh = String(now.getHours()).padStart(2, "0");
  const mm = String(now.getMinutes()).padStart(2, "0");
  const ss = String(now.getSeconds()).padStart(2, "0");
  return `${hh}:${mm}:${ss}`;
}

/**
 * Map the first URL segment to a compact console label. Root -> CHAT
 * (the shell's default landing surface); known modules get a short tag
 * (e.g. "vulnerability" -> "VULN") to keep the bar dense; anything else
 * is uppercased verbatim.
 */
const MODULE_LABELS: Record<string, string> = {
  vulnerability: "VULN",
  hello_world: "HELLO",
};

function useModuleLabel(): string {
  const location = useLocation();
  const seg = location.pathname.split("/").filter(Boolean)[0];
  if (!seg) return "CHAT";
  const mapped = MODULE_LABELS[seg];
  if (mapped) return mapped;
  return seg.toUpperCase().replace(/[-_]/g, " ");
}

// ---------------------------------------------------------------------------
// Palette -- these tokens are guaranteed to exist across every theme block
// in globals.css (see midnight-cloud-8, synthwave, ps1, etc.).
// ---------------------------------------------------------------------------

const ENGINE_COLOR: Record<EngineStatus, string> = {
  ok: "var(--status-completed)",
  degraded: "var(--status-running)",
  offline: "var(--status-failed)",
};

const ENGINE_LABEL: Record<EngineStatus, string> = {
  ok: "ENGINE OK",
  degraded: "DEGRADED",
  offline: "OFFLINE",
};

// ---------------------------------------------------------------------------
// Presentational bits
// ---------------------------------------------------------------------------

function Divider() {
  return (
    <span
      aria-hidden
      style={{
        width: 1,
        alignSelf: "stretch",
        marginBlock: 4,
        background: "var(--color-border)",
        opacity: 0.55,
      }}
    />
  );
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export function StatusBar() {
  const engine = useEngineStatus();
  const queue = useQueueDepth();
  const roi = useROI();
  const online = useOnline();
  const clock = useClock();
  const moduleLabel = useModuleLabel();

  const shortSha =
    !buildSha || buildSha === "dev" ? "" : buildSha.slice(0, 7);
  const buildTag = shortSha ? `v${appVersion} ${shortSha}` : `v${appVersion}`;

  const engineColor = ENGINE_COLOR[engine];
  const engineLabel = ENGINE_LABEL[engine];

  return (
    <footer
      role="status" aria-live="off"
      aria-label="System status"
      data-testid="app-status-bar"
      style={{
        height: "var(--statusbar-h, 24px)",
        flex: "0 0 auto",
        display: "flex",
        alignItems: "center",
        gap: 10,
        padding: "0 10px",
        borderTop: "1px solid var(--color-border-bright)",
        background: "var(--color-chrome)",
        color: "var(--color-text-faint)",
        fontFamily: "var(--font-mono)",
        fontSize: "10.5px",
        letterSpacing: "0.1em",
        textTransform: "uppercase",
        userSelect: "none",
        overflow: "hidden",
        whiteSpace: "nowrap",
      }}
    >
      {/* 1. Engine dot + label */}
      <span
        style={{ display: "inline-flex", alignItems: "center", gap: 6 }}
        title={`Platform health: ${engineLabel.toLowerCase()}`}
      >
        <span
          aria-hidden
          style={{
            width: 8,
            height: 8,
            display: "inline-block",
            background: engineColor,
            boxShadow: engine === "ok" ? `0 0 6px ${engineColor}` : "none",
          }}
        />
        <span>{engineLabel}</span>
      </span>

      {/* 2. Queue depth -- hidden on error so we never fake "0" */}
      {queue !== null && (
        <>
          <Divider />
          <span
            style={{ display: "inline-flex", alignItems: "center", gap: 6 }}
            title={`${queue} task${queue === 1 ? "" : "s"} in queue`}
          >
            <span>QUEUE</span>
            <span
              className={queue > 0 ? "animate-severity-pulse" : undefined}
              style={{
                color:
                  queue > 0
                    ? "var(--color-accent)"
                    : "var(--color-text-muted)",
                fontVariantNumeric: "tabular-nums",
              }}
            >
              {queue}
            </span>
          </span>
        </>
      )}

      {/* 3. Active module / route */}
      <Divider />
      <span>CTX {moduleLabel}</span>

      {/* 4. ROI vs human-equivalent -- hidden on error/permission miss */}
      {roi !== null && (
        <>
          <Divider />
          <span
            style={{ display: "inline-flex", alignItems: "center", gap: 6 }}
            title={
              `ROI over ${roi.period_start} -> ${roi.period_end}: ` +
              `LLM $${roi.llm_cost_usd.toFixed(2)} vs human ` +
              `$${roi.human_equivalent_cost_usd.toFixed(2)} ` +
              `(${roi.human_equivalent_hours.toFixed(1)}h across ${roi.run_count} run${roi.run_count === 1 ? "" : "s"})`
            }
          >
            <span>ROI</span>
            <span
              style={{
                color:
                  roi.roi_percentage > 0
                    ? "var(--status-completed)"
                    : roi.roi_percentage < 0
                      ? "var(--status-failed)"
                      : "var(--color-text-muted)",
                fontVariantNumeric: "tabular-nums",
              }}
            >
              {`${roi.roi_percentage > 0 ? "+" : ""}${roi.roi_percentage.toFixed(0)}%`}
            </span>
          </span>
        </>
      )}

      {/* 5. flex spacer */}
      <span style={{ flex: 1 }} />

      {/* 5. Online / offline */}
      <span
        style={{
          color: online
            ? "var(--color-text-muted)"
            : "var(--status-running)",
        }}
      >
        {online ? "ONLINE" : "OFFLINE"}
      </span>

      {/* 6. Build tag */}
      <Divider />
      <span title="Application version and git SHA">{buildTag}</span>

      {/* 7. Live clock */}
      <Divider />
      <span
        style={{
          color: "color-mix(in srgb, var(--color-text-muted) 60%, transparent)",
          fontVariantNumeric: "tabular-nums",
        }}
      >
        {clock}
      </span>
    </footer>
  );
}
