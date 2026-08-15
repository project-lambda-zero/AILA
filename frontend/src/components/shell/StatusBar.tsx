/**
 * StatusBar -- the 24px OS-frame footer, rebuilt from the design mock.
 *
 * Left mode chip (accent-filled), then a set of live status segments, then a
 * flex spacer, then network state + build tag + live clock, and finally the
 * `aila.sh` sig on the right. Mono uppercase 9.5px, tokens are the mock
 * semantic names (--surface-chrome, --border, --status-*, --text-*).
 *
 * Segments (left -> right):
 *   0. Mode chip -- fills the left cell with --accent (mock's modeChipStyle).
 *   1. Engine dot + label from GET /health.
 *   2. Queue depth from GET /tasks/queue-depth (admin-only; hidden on 4xx/5xx).
 *   3. Context / active module (first path segment; "" -> CONSOLE).
 *   4. ROI %% from GET /cost/roi (hidden on error/permission miss).
 *   5. flex spacer.
 *   6. Online / offline.
 *   7. Build tag: v<version> <short-sha>.
 *   8. HH:MM:SS live clock.
 *   9. `aila.sh` sig cell.
 */
import { useEffect, useState } from "react";
import { useLocation } from "react-router";
import { useQuery } from "@tanstack/react-query";

import { authorizedRequestJson, requestJson } from "@platform/api/http";
import { appVersion, buildSha } from "@platform/config/version";

// ---------------------------------------------------------------------------
// Backend response shapes (mirrored inline; no new module boundary crossings).
// ---------------------------------------------------------------------------

type HealthStatus = "healthy" | "degraded" | "unhealthy";
interface HealthCheckResponse {
  status: HealthStatus;
  checks: Record<string, unknown>;
}
interface DataEnvelope<T> {
  data: T;
}
type QueueDepthPayload = Record<string, number>;
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
  return "ok";
}

/** Sum every status bucket into a single visible queue count. Hide on error
 *  (403 for non-admin, 429, network) so we never fake a "0". */
function useQueueDepth(): number | null {
  const query = useQuery({
    queryKey: ["system-status", "queue"],
    queryFn: () =>
      authorizedRequestJson<DataEnvelope<QueueDepthPayload>>("/tasks/queue-depth"),
    refetchInterval: 10_000,
    retry: false,
  });
  if (query.isError || !query.data) return null;
  const depth = query.data.data ?? {};
  return Object.values(depth).reduce<number>((sum, n) => sum + (Number(n) || 0), 0);
}

/** Trailing-3-month LLM-vs-human ROI. Hidden on error/permission miss. */
function useROI(): ROIResponse | null {
  const query = useQuery({
    queryKey: ["system-status", "roi"],
    queryFn: () => authorizedRequestJson<DataEnvelope<ROIResponse>>("/cost/roi"),
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

// Map the first URL segment to a compact console label. Root -> CONSOLE (the
// mock's home surface); known modules get a short tag to keep the bar dense.
const MODULE_LABELS: Record<string, string> = {
  vulnerability: "VULN",
  hello_world: "HELLO",
};

function useModuleLabel(): string {
  const location = useLocation();
  const seg = location.pathname.split("/").filter(Boolean)[0];
  if (!seg) return "CONSOLE";
  const mapped = MODULE_LABELS[seg];
  if (mapped) return mapped;
  return seg.toUpperCase().replace(/[-_]/g, " ");
}

// ---------------------------------------------------------------------------
// Palette -- mock semantic tokens.
// ---------------------------------------------------------------------------

const ENGINE_COLOR: Record<EngineStatus, string> = {
  ok: "var(--status-ok)",
  degraded: "var(--status-warn)",
  offline: "var(--accent)",
};

const ENGINE_LABEL: Record<EngineStatus, string> = {
  ok: "engine ok",
  degraded: "degraded",
  offline: "offline",
};

// ---------------------------------------------------------------------------
// Presentational bits
// ---------------------------------------------------------------------------

const CELL_BORDER: React.CSSProperties = {
  borderLeft: "1px solid var(--border-soft)",
};

function Cell({
  children,
  style,
  title,
}: {
  children: React.ReactNode;
  style?: React.CSSProperties;
  title?: string;
}) {
  return (
    <div
      className="flex items-center"
      title={title}
      style={{ gap: 6, padding: "0 11px", height: "100%", ...CELL_BORDER, ...style }}
    >
      {children}
    </div>
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

  const shortSha = !buildSha || buildSha === "dev" ? "" : buildSha.slice(0, 7);
  const buildTag = shortSha ? `v${appVersion} ${shortSha}` : `v${appVersion}`;

  const engineColor = ENGINE_COLOR[engine];
  const engineLabel = ENGINE_LABEL[engine];

  return (
    <footer
      role="status"
      aria-live="off"
      aria-label="System status"
      data-testid="app-status-bar"
      style={{
        flex: "0 0 var(--statusbar-h, 24px)",
        height: "var(--statusbar-h, 24px)",
        display: "flex",
        alignItems: "stretch",
        background: "var(--surface-chrome)",
        borderTop: "2px solid var(--border)",
        color: "var(--text-faint)",
        fontFamily: "var(--font-mono)",
        fontSize: 9.5,
        letterSpacing: "0.1em",
        textTransform: "uppercase",
        userSelect: "none",
        overflow: "hidden",
        whiteSpace: "nowrap",
        position: "relative",
        zIndex: 20,
      }}
    >
      {/* Mode chip -- fills the left cell with --accent, mirrors modeChipStyle. */}
      <div
        className="flex items-center"
        style={{
          padding: "0 11px",
          background: "var(--accent)",
          color: "var(--text-on-accent)",
          fontWeight: 700,
          letterSpacing: "0.14em",
        }}
        title="Composer mode"
      >
        basic
      </div>

      {/* 1. Engine dot + label */}
      <Cell style={{ color: "var(--text-muted)" }}>
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
      </Cell>

      {/* 2. Queue depth -- hidden on error so we never fake "0" */}
      {queue !== null && (
        <Cell title={`${queue} task${queue === 1 ? "" : "s"} in queue`}>
          <span>queue</span>
          <span
            className={queue > 0 ? "animate-severity-pulse" : undefined}
            style={{
              color: queue > 0 ? "var(--accent)" : "var(--text-muted)",
              fontVariantNumeric: "tabular-nums",
            }}
          >
            {queue}
          </span>
        </Cell>
      )}

      {/* 3. Active module / route */}
      <Cell>ctx {moduleLabel.toLowerCase()}</Cell>

      {/* 4. ROI vs human-equivalent -- hidden on error/permission miss */}
      {roi !== null && (
        <Cell
          title={
            `ROI over ${roi.period_start} -> ${roi.period_end}: ` +
            `LLM $${roi.llm_cost_usd.toFixed(2)} vs human ` +
            `$${roi.human_equivalent_cost_usd.toFixed(2)} ` +
            `(${roi.human_equivalent_hours.toFixed(1)}h across ${roi.run_count} run${roi.run_count === 1 ? "" : "s"})`
          }
        >
          <span>roi</span>
          <span
            style={{
              color:
                roi.roi_percentage > 0
                  ? "var(--status-ok)"
                  : roi.roi_percentage < 0
                    ? "var(--accent)"
                    : "var(--text-muted)",
              fontVariantNumeric: "tabular-nums",
            }}
          >
            {`${roi.roi_percentage > 0 ? "+" : ""}${roi.roi_percentage.toFixed(0)}%`}
          </span>
        </Cell>
      )}

      {/* flex spacer */}
      <span style={{ flex: 1 }} />

      {/* Online / offline */}
      <Cell
        style={{
          color: online ? "var(--text-muted)" : "var(--status-warn)",
        }}
      >
        {online ? "online" : "offline"}
      </Cell>

      {/* Build tag */}
      <Cell title="Application version and git SHA">{buildTag}</Cell>

      {/* Live clock */}
      <Cell style={{ color: "var(--text-faint)", fontVariantNumeric: "tabular-nums" }}>
        {clock}
      </Cell>

      {/* Sig cell -- matches the mock's `aila.sh` right-most segment. */}
      <Cell style={{ color: "var(--text-muted)", textTransform: "none", letterSpacing: "0.06em" }}>
        aila.sh
      </Cell>
    </footer>
  );
}
