/**
 * TopologyDetailSheet -- mock rebuild.
 *
 * Right-side node inspector rendered as a fixed overlay (matching the
 * Findings detail-panel pattern in the mock). Body is composed of
 * stacked WindowPanels: severity distribution (StatBars), system
 * metadata (KV grid), network, ports (DataGrid), services (DataGrid).
 *
 * Data props unchanged. Backdrop click / ESC closes via onOpenChange.
 */
import * as React from "react";
import { X as CloseIcon } from "@phosphor-icons/react/dist/csr/X";

import { DataGrid, MonoBadge, StatBar } from "@/components/aila/mock";
import { WindowPanel } from "@/components/aila/WindowPanel";
import { formatRelativeTime } from "@platform/features/systems/api";
import type { PortInfo, ServiceInfo, TopologyNode } from "@platform/features/radar/types";
import { humaniseUptime } from "./topologyGraph";

interface TopologyDetailSheetProps {
  node: TopologyNode | null;
  open: boolean;
  onOpenChange(open: boolean): void;
}

export function TopologyDetailSheet({
  node,
  open,
  onOpenChange,
}: TopologyDetailSheetProps) {
  React.useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onOpenChange(false);
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [open, onOpenChange]);

  if (!open || !node) return null;

  return (
    <>
      <div
        onClick={() => onOpenChange(false)}
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
          width: 560,
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
        <SheetHeader node={node} onClose={() => onOpenChange(false)} />
        <div className="flex flex-col" style={{ gap: 12, overflowY: "auto", flex: 1, minHeight: 0 }}>
          <SheetBody node={node} />
        </div>
      </div>
    </>
  );
}

function SheetHeader({ node, onClose }: { node: TopologyNode; onClose: () => void }) {
  return (
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
        <div className="flex items-center flex-wrap" style={{ gap: 8 }}>
          <span
            className="font-mono uppercase"
            style={{ fontSize: 13, letterSpacing: "0.08em", color: "var(--text-primary)" }}
          >
            {node.name}
          </span>
          {node.is_stale && <MonoBadge tone="warn">STALE</MonoBadge>}
        </div>
        <div className="flex items-center flex-wrap font-mono" style={{ gap: 6, fontSize: 10, color: "var(--text-muted)" }}>
          <span>{node.host}</span>
          <span style={{ color: "var(--text-faint)" }}>|</span>
          <span>{node.distro}</span>
          <span style={{ color: "var(--text-faint)" }}>|</span>
          <span>ID {node.id}</span>
        </div>
      </div>
      <button
        type="button"
        onClick={onClose}
        aria-label="Close panel"
        className="font-mono"
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
  );
}

function SheetBody({ node }: { node: TopologyNode }) {
  const counts = node.severity_counts;
  const total = counts
    ? counts.critical + counts.high + counts.medium + counts.low
    : 0;
  const meta = node.metadata ?? null;

  return (
    <>
      <WindowPanel title="severity distribution">
        {counts && total > 0 ? (
          <div className="flex flex-col" style={{ gap: 6 }}>
            <StatBar label="CRITICAL" color="var(--accent)" value={counts.critical} max={total} />
            <StatBar label="HIGH" color="var(--status-warn)" value={counts.high} max={total} />
            <StatBar label="MEDIUM" color="var(--status-info)" value={counts.medium} max={total} />
            <StatBar label="LOW" color="var(--status-ok)" value={counts.low} max={total} />
            <div
              className="flex items-center justify-between font-mono uppercase"
              style={{ fontSize: 9, letterSpacing: "0.14em", color: "var(--text-faint)", paddingTop: 4 }}
            >
              <span>TOTAL</span>
              <span style={{ color: "var(--text-primary)" }}>{total}</span>
            </div>
          </div>
        ) : (
          <MutedLine>No vulnerability data collected yet.</MutedLine>
        )}
      </WindowPanel>

      <WindowPanel title="system metadata">
        <KeyValueGrid
          rows={[
            ["Host", node.host],
            ["Distro", node.distro],
            ["OS name", meta?.os_pretty_name ?? meta?.os_name ?? "--"],
            ["Kernel", meta?.kernel ?? "--"],
            ["CPU cores", meta?.cpu_cores != null ? String(meta.cpu_cores) : "--"],
            ["Memory", meta?.memory_mb != null ? `${meta.memory_mb} MB` : "--"],
            ["Disk (/)", meta?.disk_gb != null ? `${meta.disk_gb} GB` : "--"],
            ["Uptime", humaniseUptime(meta?.uptime_seconds ?? null)],
          ]}
        />
      </WindowPanel>

      <WindowPanel title="network">
        <KeyValueGrid
          rows={[
            ["Subnet", node.subnet ?? "unresolved"],
            ["Gateway", meta?.gateway_ip ?? "--"],
            ["Gateway iface", meta?.gateway_interface ?? "--"],
            ["External IP", meta?.external_ip ?? "--"],
            ["Group tags", node.group_tags.length > 0 ? node.group_tags.join(", ") : "none"],
            ["Last collected", formatRelativeTime(node.last_collected)],
            ["Metadata stale", meta?.is_stale ? "yes" : "no"],
          ]}
        />
      </WindowPanel>

      <WindowPanel title={`open ports (${node.ports.length})`} flush>
        {node.ports.length > 0 ? (
          <PortsGrid ports={node.ports} />
        ) : (
          <div style={{ padding: 12 }}>
            <MutedLine>No open ports collected.</MutedLine>
          </div>
        )}
      </WindowPanel>

      <WindowPanel title={`services (${node.services.length})`} flush>
        {node.services.length > 0 ? (
          <ServicesGrid services={node.services} />
        ) : (
          <div style={{ padding: 12 }}>
            <MutedLine>No service data collected.</MutedLine>
          </div>
        )}
      </WindowPanel>
    </>
  );
}

// ---------------------------------------------------------------------------
// Small stateless building blocks
// ---------------------------------------------------------------------------

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

function PortsGrid({ ports }: { ports: PortInfo[] }) {
  return (
    <DataGrid
      columns={[
        { label: "PORT", width: "60px" },
        { label: "PROTO", width: "60px" },
        { label: "PROCESS", width: "1fr" },
        { label: "ADDRESS", width: "1.2fr" },
      ]}
      rows={ports}
      getKey={(p, i) => `${p.port}-${p.protocol}-${p.local_address}-${i}`}
      renderCells={(p) => [
        <span style={{ color: "var(--accent)", fontWeight: 600 }}>{p.port}</span>,
        <span style={{ color: "var(--text-primary)" }}>{p.protocol}</span>,
        <span style={{ color: "var(--text-primary)" }}>{p.process_name ?? "--"}</span>,
        <span style={{ color: "var(--text-muted)" }}>{p.local_address}</span>,
      ]}
    />
  );
}

function ServicesGrid({ services }: { services: ServiceInfo[] }) {
  return (
    <DataGrid
      columns={[
        { label: "SERVICE", width: "1fr" },
        { label: "STATE", width: "90px" },
        { label: "SUB-STATE", width: "110px" },
      ]}
      rows={services}
      getKey={(s, i) => `${s.service_name}-${i}`}
      renderCells={(s) => [
        <span style={{ color: "var(--text-primary)" }}>{s.service_name}</span>,
        <MonoBadge tone={s.state === "active" ? "ok" : s.state === "failed" ? "critical" : "muted"}>
          {s.state}
        </MonoBadge>,
        <span style={{ color: "var(--text-muted)" }}>{s.sub_state}</span>,
      ]}
    />
  );
}
