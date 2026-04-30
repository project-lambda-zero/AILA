/**
 * RadarInspectPanel.tsx — Slide-over inspect panel for network topology nodes (Phase 144).
 *
 * Opens when a node is clicked in the RadarGraph. Displays:
 * - System name, host, distro header
 * - Stale warning badge when is_stale=true
 * - Severity distribution pie chart (AilaChart) when severity_counts exists
 * - Running services list
 * - Open ports list
 * - Network metadata (subnet, group tags, last collected)
 *
 * Follows the same fixed-panel pattern as FindingDetailPanel (Phase 143).
 */
import * as React from "react";
import { X as CloseIcon } from "@phosphor-icons/react";
import {
  PieChart,
  Pie,
  Cell,
  Tooltip,
  ResponsiveContainer,
} from "recharts";

import { AilaCard } from "@/components/aila/AilaCard";
import { AilaBadge } from "@/components/aila/AilaBadge";
import { formatRelativeTime } from "@platform/features/systems/api";
import type { TopologyNode } from "./types";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface RadarInspectPanelProps {
  node: TopologyNode | null;
  open: boolean;
  onClose: () => void;
}

// ---------------------------------------------------------------------------
// Severity pie chart data
// ---------------------------------------------------------------------------

interface SeveritySlice {
  name: string;
  value: number;
  fill: string;
}

function buildSeveritySlices(counts: TopologyNode["severity_counts"]): SeveritySlice[] {
  if (!counts) return [];
  return [
    { name: "Critical", value: counts.critical, fill: "var(--color-critical)" },
    { name: "High", value: counts.high, fill: "var(--color-high)" },
    { name: "Medium", value: counts.medium, fill: "var(--color-medium)" },
    { name: "Low", value: counts.low, fill: "var(--color-low)" },
  ].filter((s) => s.value > 0);
}

// ---------------------------------------------------------------------------
// Tooltip style
// ---------------------------------------------------------------------------

const TOOLTIP_STYLE: React.CSSProperties = {
  backgroundColor: "var(--color-elevated)",
  border: "1px solid var(--color-border)",
  borderRadius: "4px",
  fontFamily: "var(--font-mono, monospace)",
  fontSize: "11px",
  color: "var(--color-text)",
};

// ---------------------------------------------------------------------------
// Section heading
// ---------------------------------------------------------------------------

function SectionHeading({ children }: { children: React.ReactNode }) {
  return (
    <p className="font-mono text-[10px] text-muted-foreground uppercase tracking-wider mb-2">
      {children}
    </p>
  );
}

// ---------------------------------------------------------------------------
// Main panel
// ---------------------------------------------------------------------------

export function RadarInspectPanel({ node, open, onClose }: RadarInspectPanelProps) {
  if (!open || !node) return null;

  const severitySlices = buildSeveritySlices(node.severity_counts);
  const hasSeverityData = severitySlices.length > 0;
  const hasSeverityCounts = node.severity_counts !== null;

  const totalFindings = hasSeverityCounts && node.severity_counts
    ? node.severity_counts.critical + node.severity_counts.high + node.severity_counts.medium + node.severity_counts.low
    : 0;

  return (
    <>
      {/* Overlay */}
      <div
        className="fixed inset-0 z-40 bg-black/20"
        onClick={onClose}
        aria-hidden="true"
      />

      {/* Panel */}
      <div
        className="fixed inset-y-0 right-0 z-50 w-[480px] bg-elevated border-l border-border flex flex-col overflow-hidden"
        role="complementary"
        aria-label={`System details: ${node.name}`}
      >
        {/* Header */}
        <div className="flex items-start justify-between p-5 border-b border-border shrink-0">
          <div className="flex flex-col gap-2 min-w-0">
            <span className="font-mono text-base font-semibold truncate">{node.name}</span>
            <div className="flex items-center gap-2 flex-wrap">
              <span className="font-mono text-xs text-muted-foreground">{node.host}</span>
              <span className="text-muted-foreground text-xs">·</span>
              <span className="font-mono text-xs text-muted-foreground">{node.distro}</span>
            </div>
            {node.is_stale && (
              <div className="mt-1">
                <AilaBadge severity="critical" size="sm">
                  STALE — data may be outdated
                </AilaBadge>
              </div>
            )}
          </div>
          <button
            type="button"
            onClick={onClose}
            className="text-muted-foreground hover:text-foreground transition-colors ml-3 shrink-0"
            aria-label="Close panel"
          >
            <CloseIcon size={18} />
          </button>
        </div>

        {/* Scrollable body */}
        <div className="flex-1 overflow-y-auto p-5 flex flex-col gap-4">

          {/* Severity Risk Summary */}
          <div>
            <SectionHeading>Risk Summary</SectionHeading>
            {hasSeverityCounts ? (
              <AilaCard>
                <div className="p-3">
                  {hasSeverityData ? (
                    <>
                      <div className="h-40">
                        <ResponsiveContainer width="100%" height="100%">
                          <PieChart>
                            <Pie
                              data={severitySlices}
                              dataKey="value"
                              nameKey="name"
                              cx="50%"
                              cy="50%"
                              outerRadius="70%"
                              strokeWidth={0}
                            >
                              {severitySlices.map((slice) => (
                                <Cell key={slice.name} fill={slice.fill} />
                              ))}
                            </Pie>
                            <Tooltip contentStyle={TOOLTIP_STYLE} />
                          </PieChart>
                        </ResponsiveContainer>
                      </div>
                      <div className="flex justify-center gap-3 mt-2 font-mono text-[10px]">
                        <span style={{ color: "var(--color-critical)" }}>
                          C:{node.severity_counts!.critical}
                        </span>
                        <span style={{ color: "var(--color-high)" }}>
                          H:{node.severity_counts!.high}
                        </span>
                        <span style={{ color: "var(--color-medium)" }}>
                          M:{node.severity_counts!.medium}
                        </span>
                        <span style={{ color: "var(--color-low)" }}>
                          L:{node.severity_counts!.low}
                        </span>
                        <span className="text-muted-foreground">
                          Total:{totalFindings}
                        </span>
                      </div>
                    </>
                  ) : (
                    <p className="font-mono text-xs text-muted-foreground text-center py-4">
                      No vulnerabilities detected.
                    </p>
                  )}
                </div>
              </AilaCard>
            ) : (
              <AilaCard>
                <div className="p-3">
                  <p className="font-mono text-xs text-muted-foreground">
                    No vulnerability scan data yet. Run a vulnerability scan to populate severity data.
                  </p>
                </div>
              </AilaCard>
            )}
          </div>

          {/* Running Services */}
          <div>
            <SectionHeading>Running Services ({node.services.length})</SectionHeading>
            <AilaCard>
              <div className="p-3">
                {node.services.length > 0 ? (
                  <div className="flex flex-col gap-1">
                    {node.services.slice(0, 10).map((svc, i) => (
                      <div key={i} className="flex items-center justify-between gap-2">
                        <span className="font-mono text-xs truncate flex-1">{svc.service_name}</span>
                        <span className="font-mono text-[10px] text-muted-foreground shrink-0">
                          {svc.state}/{svc.sub_state}
                        </span>
                      </div>
                    ))}
                    {node.services.length > 10 && (
                      <p className="font-mono text-[10px] text-muted-foreground mt-1">
                        and {node.services.length - 10} more...
                      </p>
                    )}
                  </div>
                ) : (
                  <p className="font-mono text-xs text-muted-foreground">
                    No service data collected.
                  </p>
                )}
              </div>
            </AilaCard>
          </div>

          {/* Open Ports */}
          <div>
            <SectionHeading>Open Ports ({node.ports.length})</SectionHeading>
            <AilaCard>
              <div className="p-3">
                {node.ports.length > 0 ? (
                  <div className="flex flex-col gap-1">
                    {node.ports.slice(0, 10).map((port, i) => (
                      <div key={i} className="flex items-center gap-3">
                        <span className="font-mono text-xs font-medium w-16 shrink-0">
                          {port.port}/{port.protocol}
                        </span>
                        <span className="font-mono text-[10px] text-muted-foreground truncate">
                          {port.process_name ?? "—"} ({port.local_address})
                        </span>
                      </div>
                    ))}
                    {node.ports.length > 10 && (
                      <p className="font-mono text-[10px] text-muted-foreground mt-1">
                        and {node.ports.length - 10} more...
                      </p>
                    )}
                  </div>
                ) : (
                  <p className="font-mono text-xs text-muted-foreground">
                    No port data collected.
                  </p>
                )}
              </div>
            </AilaCard>
          </div>

          {/* Network Metadata */}
          <div>
            <SectionHeading>Network Metadata</SectionHeading>
            <AilaCard>
              <div className="p-3 flex flex-col gap-2">
                <div className="flex items-center justify-between">
                  <span className="font-mono text-[10px] text-muted-foreground uppercase">Subnet</span>
                  <span className="font-mono text-xs">{node.subnet ?? "unresolved"}</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="font-mono text-[10px] text-muted-foreground uppercase">Groups</span>
                  <span className="font-mono text-xs">
                    {node.group_tags.length > 0 ? node.group_tags.join(", ") : "none"}
                  </span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="font-mono text-[10px] text-muted-foreground uppercase">Last collected</span>
                  <span className="font-mono text-xs">
                    {formatRelativeTime(node.last_collected)}
                  </span>
                </div>
              </div>
            </AilaCard>
          </div>

          {/* Phase 176d: system info (gateway / external IP / neofetch-like) */}
          {node.metadata && <SystemInfoSection metadata={node.metadata} />}

        </div>
      </div>
    </>
  );
}

// ---------------------------------------------------------------------------
// Phase 176d: System info section
// ---------------------------------------------------------------------------

function SystemInfoSection({
  metadata,
}: {
  metadata: NonNullable<TopologyNode["metadata"]>;
}) {
  const hasNetwork =
    metadata.gateway_ip || metadata.gateway_interface || metadata.external_ip;
  const hasSystem =
    metadata.os_pretty_name ||
    metadata.os_name ||
    metadata.kernel ||
    metadata.cpu_cores != null ||
    metadata.memory_mb != null ||
    metadata.disk_gb != null ||
    metadata.uptime_seconds != null;

  if (!hasNetwork && !hasSystem) return null;

  return (
    <div>
      <SectionHeading>System Info</SectionHeading>
      <AilaCard>
        <div className="p-3 flex flex-col gap-2">
          {hasNetwork && (
            <>
              {metadata.gateway_ip && (
                <InfoRow
                  label="Gateway"
                  value={
                    metadata.gateway_interface
                      ? `${metadata.gateway_ip} via ${metadata.gateway_interface}`
                      : metadata.gateway_ip
                  }
                />
              )}
              {metadata.external_ip && (
                <InfoRow label="External IP" value={metadata.external_ip} />
              )}
            </>
          )}
          {metadata.os_pretty_name && (
            <InfoRow label="OS" value={metadata.os_pretty_name} />
          )}
          {metadata.kernel && <InfoRow label="Kernel" value={metadata.kernel} />}
          {metadata.cpu_cores != null && (
            <InfoRow label="CPU cores" value={String(metadata.cpu_cores)} />
          )}
          {metadata.memory_mb != null && (
            <InfoRow label="Memory" value={`${metadata.memory_mb} MB`} />
          )}
          {metadata.disk_gb != null && (
            <InfoRow label="Disk (/)" value={`${metadata.disk_gb} GB`} />
          )}
          {metadata.uptime_seconds != null && (
            <InfoRow
              label="Uptime"
              value={formatUptime(metadata.uptime_seconds)}
            />
          )}
          {metadata.is_stale && (
            <div className="mt-1">
              <AilaBadge severity="medium" size="sm">
                stale — last scan did not refresh this data
              </AilaBadge>
            </div>
          )}
        </div>
      </AilaCard>
    </div>
  );
}

function InfoRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-center justify-between gap-3">
      <span className="font-mono text-[10px] text-muted-foreground uppercase">
        {label}
      </span>
      <span className="font-mono text-xs truncate max-w-[60%] text-right">
        {value}
      </span>
    </div>
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
