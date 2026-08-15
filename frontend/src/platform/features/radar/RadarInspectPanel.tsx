/**
 * RadarInspectPanel -- mock rebuild.
 *
 * Fixed right-side inspector composed of stacked WindowPanels:
 *  - HEADER card: name / host / distro / STALE badge
 *  - RISK SUMMARY: StatBar distribution + optional pie chart (lazy)
 *  - SERVICES: mono lines with state chip
 *  - PORTS: mono lines
 *  - NETWORK METADATA: KV block
 *  - SYSTEM INFO: KV block (when metadata present)
 */
import * as React from "react";
import { X as CloseIcon } from "@phosphor-icons/react/dist/csr/X";

import { LoadingSkeleton } from "@/components/aila/LoadingSkeleton";
import { MonoBadge, StatBar } from "@/components/aila/mock";
import { WindowPanel } from "@/components/aila/WindowPanel";
import { useThemeChartColors } from "@platform/features/viz/chartColors";
import { formatRelativeTime } from "@platform/features/systems/api";
import type { TopologyNode } from "./types";

const RadarSeverityPieView = React.lazy(() =>
  import("./RadarSeverityPie.view").then((m) => ({
    default: m.RadarSeverityPieView,
  })),
);

interface RadarInspectPanelProps {
  node: TopologyNode | null;
  open: boolean;
  onClose: () => void;
}

interface SeveritySlice {
  name: string;
  value: number;
  fill: string;
}

function buildSeveritySlices(
  counts: TopologyNode["severity_counts"],
  colors: { critical: string; high: string; medium: string; low: string },
): SeveritySlice[] {
  if (!counts) return [];
  return [
    { name: "Critical", value: counts.critical, fill: colors.critical },
    { name: "High", value: counts.high, fill: colors.high },
    { name: "Medium", value: counts.medium, fill: colors.medium },
    { name: "Low", value: counts.low, fill: colors.low },
  ].filter((s) => s.value > 0);
}

export function RadarInspectPanel({ node, open, onClose }: RadarInspectPanelProps) {
  React.useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [open, onClose]);

  const colors = useThemeChartColors();

  if (!open || !node) return null;

  const counts = node.severity_counts;
  const total = counts
    ? counts.critical + counts.high + counts.medium + counts.low
    : 0;
  const slices = buildSeveritySlices(counts, colors);
  const hasSeverityData = slices.length > 0;

  return (
    <>
      <div
        onClick={onClose}
        aria-hidden="true"
        style={{
          position: "fixed",
          inset: 0,
          zIndex: 40,
          background: "color-mix(in srgb, var(--surface-page) 70%, transparent)",
        }}
      />
      <div
        role="complementary"
        aria-label={`System details: ${node.name}`}
        style={{
          position: "fixed",
          top: 0,
          right: 0,
          bottom: 0,
          width: 480,
          maxWidth: "100vw",
          zIndex: 50,
          background: "var(--surface-page)",
          borderLeft: "1px solid var(--border)",
          display: "flex",
          flexDirection: "column",
          padding: 16,
          gap: 12,
          overflow: "hidden",
        }}
      >
        {/* Header */}
        <div
          className="flex items-start justify-between"
          style={{
            gap: 10,
            padding: "10px 12px",
            border: "1px solid var(--border)",
            background: "var(--surface-card)",
            borderRadius: 3,
          }}
        >
          <div className="flex flex-col" style={{ gap: 6, minWidth: 0 }}>
            <span
              className="font-mono uppercase"
              style={{ fontSize: 13, letterSpacing: "0.08em", color: "var(--text-primary)" }}
            >
              {node.name}
            </span>
            <div
              className="flex items-center flex-wrap font-mono"
              style={{ gap: 6, fontSize: 10, color: "var(--text-muted)" }}
            >
              <span>{node.host}</span>
              <span style={{ color: "var(--text-faint)" }}>{"\u00B7"}</span>
              <span>{node.distro}</span>
            </div>
            {node.is_stale && (
              <div style={{ marginTop: 2 }}>
                <MonoBadge tone="warn">STALE -- data may be outdated</MonoBadge>
              </div>
            )}
          </div>
          <button
            type="button"
            onClick={onClose}
            aria-label="Close panel"
            style={{
              width: 24,
              height: 24,
              border: "1px solid var(--border-soft)",
              background: "var(--surface-sunk)",
              color: "var(--text-muted)",
              borderRadius: 3,
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              cursor: "pointer",
            }}
          >
            <CloseIcon size={14} />
          </button>
        </div>

        {/* Scrollable body */}
        <div className="flex flex-col" style={{ gap: 12, overflowY: "auto", flex: 1, minHeight: 0 }}>
          <WindowPanel title="risk summary">
            {counts ? (
              hasSeverityData ? (
                <div className="flex flex-col" style={{ gap: 10 }}>
                  <div className="flex flex-col" style={{ gap: 6 }}>
                    <StatBar label="CRITICAL" color={colors.critical} value={counts.critical} max={total} />
                    <StatBar label="HIGH" color={colors.high} value={counts.high} max={total} />
                    <StatBar label="MEDIUM" color={colors.medium} value={counts.medium} max={total} />
                    <StatBar label="LOW" color={colors.low} value={counts.low} max={total} />
                  </div>
                  <div style={{ height: 140 }}>
                    <React.Suspense
                      fallback={<LoadingSkeleton size="full" width="full" className="h-full" />}
                    >
                      <RadarSeverityPieView slices={slices} />
                    </React.Suspense>
                  </div>
                  <div className="flex items-center justify-center flex-wrap font-mono" style={{ gap: 10, fontSize: 10 }}>
                    <LegendChip label={`C:${counts.critical}`} color={colors.critical} />
                    <LegendChip label={`H:${counts.high}`} color={colors.high} />
                    <LegendChip label={`M:${counts.medium}`} color={colors.medium} />
                    <LegendChip label={`L:${counts.low}`} color={colors.low} />
                    <span style={{ color: "var(--text-faint)" }}>TOTAL: {total}</span>
                  </div>
                </div>
              ) : (
                <MutedLine>No vulnerabilities detected.</MutedLine>
              )
            ) : (
              <MutedLine>No vulnerability scan data yet. Run a vulnerability scan to populate severity data.</MutedLine>
            )}
          </WindowPanel>

          <WindowPanel title={`running services (${node.services.length})`}>
            {node.services.length > 0 ? (
              <div className="flex flex-col" style={{ gap: 4 }}>
                {node.services.slice(0, 10).map((svc, i) => (
                  <div
                    key={i}
                    className="flex items-center justify-between font-mono"
                    style={{
                      gap: 8,
                      padding: "4px 0",
                      borderBottom:
                        i === Math.min(node.services.length, 10) - 1
                          ? "none"
                          : "1px solid var(--border-faint)",
                    }}
                  >
                    <span
                      style={{
                        fontSize: 11,
                        color: "var(--text-primary)",
                        overflow: "hidden",
                        textOverflow: "ellipsis",
                        whiteSpace: "nowrap",
                        flex: 1,
                      }}
                    >
                      {svc.service_name}
                    </span>
                    <span
                      className="uppercase"
                      style={{ fontSize: 9, letterSpacing: "0.12em", color: "var(--text-muted)" }}
                    >
                      {svc.state}/{svc.sub_state}
                    </span>
                  </div>
                ))}
                {node.services.length > 10 && (
                  <p
                    className="font-mono"
                    style={{ fontSize: 10, color: "var(--text-faint)", marginTop: 4 }}
                  >
                    and {node.services.length - 10} more...
                  </p>
                )}
              </div>
            ) : (
              <MutedLine>No service data collected.</MutedLine>
            )}
          </WindowPanel>

          <WindowPanel title={`open ports (${node.ports.length})`}>
            {node.ports.length > 0 ? (
              <div className="flex flex-col" style={{ gap: 4 }}>
                {node.ports.slice(0, 10).map((port, i) => (
                  <div
                    key={i}
                    className="flex items-center font-mono"
                    style={{
                      gap: 10,
                      padding: "4px 0",
                      borderBottom:
                        i === Math.min(node.ports.length, 10) - 1
                          ? "none"
                          : "1px solid var(--border-faint)",
                    }}
                  >
                    <span
                      style={{
                        fontSize: 11,
                        color: "var(--accent)",
                        fontWeight: 600,
                        width: 68,
                        flex: "0 0 auto",
                      }}
                    >
                      {port.port}/{port.protocol}
                    </span>
                    <span
                      style={{
                        fontSize: 10,
                        color: "var(--text-muted)",
                        overflow: "hidden",
                        textOverflow: "ellipsis",
                        whiteSpace: "nowrap",
                      }}
                    >
                      {port.process_name ?? "--"} ({port.local_address})
                    </span>
                  </div>
                ))}
                {node.ports.length > 10 && (
                  <p
                    className="font-mono"
                    style={{ fontSize: 10, color: "var(--text-faint)", marginTop: 4 }}
                  >
                    and {node.ports.length - 10} more...
                  </p>
                )}
              </div>
            ) : (
              <MutedLine>No port data collected.</MutedLine>
            )}
          </WindowPanel>

          <WindowPanel title="network metadata">
            <KeyValueGrid
              rows={[
                ["Subnet", node.subnet ?? "unresolved"],
                ["Groups", node.group_tags.length > 0 ? node.group_tags.join(", ") : "none"],
                ["Last collected", formatRelativeTime(node.last_collected)],
              ]}
            />
          </WindowPanel>

          {node.metadata && <SystemInfoSection metadata={node.metadata} />}
        </div>
      </div>
    </>
  );
}

// ---------------------------------------------------------------------------
// System info section (Phase 176d)
// ---------------------------------------------------------------------------

function SystemInfoSection({
  metadata,
}: {
  metadata: NonNullable<TopologyNode["metadata"]>;
}) {
  const rows: Array<[string, string]> = [];
  if (metadata.gateway_ip) {
    rows.push([
      "Gateway",
      metadata.gateway_interface
        ? `${metadata.gateway_ip} via ${metadata.gateway_interface}`
        : metadata.gateway_ip,
    ]);
  }
  if (metadata.external_ip) rows.push(["External IP", metadata.external_ip]);
  if (metadata.os_pretty_name) rows.push(["OS", metadata.os_pretty_name]);
  if (metadata.kernel) rows.push(["Kernel", metadata.kernel]);
  if (metadata.cpu_cores != null) rows.push(["CPU cores", String(metadata.cpu_cores)]);
  if (metadata.memory_mb != null) rows.push(["Memory", `${metadata.memory_mb} MB`]);
  if (metadata.disk_gb != null) rows.push(["Disk (/)", `${metadata.disk_gb} GB`]);
  if (metadata.uptime_seconds != null) rows.push(["Uptime", formatUptime(metadata.uptime_seconds)]);

  if (rows.length === 0 && !metadata.is_stale) return null;

  return (
    <WindowPanel title="system info">
      {rows.length > 0 && <KeyValueGrid rows={rows} />}
      {metadata.is_stale && (
        <div style={{ marginTop: rows.length > 0 ? 8 : 0 }}>
          <MonoBadge tone="warn">stale -- last scan did not refresh this data</MonoBadge>
        </div>
      )}
    </WindowPanel>
  );
}

// ---------------------------------------------------------------------------
// Shared building blocks
// ---------------------------------------------------------------------------

function KeyValueGrid({ rows }: { rows: Array<[string, string]> }) {
  return (
    <div className="flex flex-col">
      {rows.map(([k, v], i) => (
        <div
          key={k}
          className="flex items-start justify-between font-mono"
          style={{
            gap: 10,
            padding: "6px 0",
            borderBottom: i === rows.length - 1 ? "none" : "1px solid var(--border-faint)",
          }}
        >
          <span
            className="uppercase"
            style={{ fontSize: 9, letterSpacing: "0.14em", color: "var(--text-faint)" }}
          >
            {k}
          </span>
          <span
            style={{
              fontSize: 11,
              color: "var(--text-primary)",
              textAlign: "right",
              wordBreak: "break-all",
              maxWidth: "60%",
            }}
          >
            {v}
          </span>
        </div>
      ))}
    </div>
  );
}

function MutedLine({ children }: { children: React.ReactNode }) {
  return (
    <p
      className="font-mono"
      style={{
        fontSize: 11,
        color: "var(--text-muted)",
        border: "1px solid var(--border-faint)",
        borderRadius: 3,
        padding: 10,
      }}
    >
      {children}
    </p>
  );
}

function LegendChip({ label, color }: { label: string; color: string }) {
  return (
    <span className="flex items-center" style={{ gap: 4 }}>
      <span
        aria-hidden="true"
        style={{ width: 8, height: 8, background: color, borderRadius: 1 }}
      />
      <span style={{ color: "var(--text-primary)" }}>{label}</span>
    </span>
  );
}

function formatUptime(seconds: number): string {
  if (seconds < 60) return `${seconds}s`;
  const days = Math.floor(seconds / 86_400);
  const hours = Math.floor((seconds % 86_400) / 3600);
  const mins = Math.floor((seconds % 3600) / 60);
  if (days > 0) return `${days}d ${hours}h`;
  if (hours > 0) return `${hours}h ${mins}m`;
  return `${mins}m`;
}
