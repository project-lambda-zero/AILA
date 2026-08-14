/**
 * TopologyDetailSheet.tsx -- right-side node inspector for the Topology
 * console. Uses the shared ui/sheet primitive so keyboard trap, ESC,
 * backdrop, and focus restoration behave like every other overlay.
 *
 * Renders EVERY field the /topology payload exposes for the node:
 *   host, distro, subnet, group_tags, last_collected, is_stale
 *   ports[]     -> table (port/protocol/process/address)
 *   services[]  -> table (name/state/sub_state)
 *   severity_counts -> per-severity breakdown row
 *   metadata (SystemMetadata) -> gateway_ip, external_ip, os_name,
 *     kernel, cpu_cores, memory_mb, disk_gb, uptime (humanised)
 */
import * as React from "react";

import { AilaBadge } from "@/components/aila/AilaBadge";
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from "@/components/ui/sheet";
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
  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent
        side="right"
        className="w-full sm:max-w-[560px] border-l border-border bg-elevated font-mono"
      >
        {node ? <SheetBody node={node} /> : <EmptySheetBody />}
      </SheetContent>
    </Sheet>
  );
}

function EmptySheetBody() {
  return (
    <>
      <SheetHeader>
        <SheetTitle>No node selected</SheetTitle>
        <SheetDescription>Click a node in the canvas to inspect it.</SheetDescription>
      </SheetHeader>
    </>
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
      <SheetHeader className="border-b border-border">
        <SheetTitle className="flex items-center gap-2 font-mono">
          <span className="truncate">{node.name}</span>
          {node.is_stale && (
            <AilaBadge severity="medium" size="sm">STALE</AilaBadge>
          )}
        </SheetTitle>
        <SheetDescription className="font-mono text-xs">
          {node.host} <span className="text-text-muted">|</span> {node.distro}
          <span className="text-text-muted"> |</span> id {node.id}
        </SheetDescription>
      </SheetHeader>

      <div className="flex-1 overflow-y-auto px-4 pb-6 flex flex-col gap-5 text-xs">
        <Section title="Severity counts">
          {counts ? (
            <div className="grid grid-cols-5 gap-2">
              <SeverityCell label="Critical" value={counts.critical} tone="critical" />
              <SeverityCell label="High" value={counts.high} tone="high" />
              <SeverityCell label="Medium" value={counts.medium} tone="medium" />
              <SeverityCell label="Low" value={counts.low} tone="low" />
              <SeverityCell label="Total" value={total} tone="neutral" />
            </div>
          ) : (
            <MutedLine>No vulnerability data collected yet.</MutedLine>
          )}
        </Section>

        <Section title="System metadata">
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
        </Section>

        <Section title="Network">
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
        </Section>

        <Section title={`Open ports (${node.ports.length})`}>
          {node.ports.length > 0 ? (
            <PortsTable ports={node.ports} />
          ) : (
            <MutedLine>No open ports collected.</MutedLine>
          )}
        </Section>

        <Section title={`Services (${node.services.length})`}>
          {node.services.length > 0 ? (
            <ServicesTable services={node.services} />
          ) : (
            <MutedLine>No service data collected.</MutedLine>
          )}
        </Section>
      </div>
    </>
  );
}

// ---------------------------------------------------------------------------
// Small stateless building blocks
// ---------------------------------------------------------------------------

function Section({
  title,
  children,
}: {
  title: string;
  children: React.ReactNode;
}) {
  return (
    <div className="flex flex-col gap-2">
      <p className="text-[10px] uppercase tracking-wider text-text-muted">
        {title}
      </p>
      {children}
    </div>
  );
}

function MutedLine({ children }: { children: React.ReactNode }) {
  return (
    <p className="text-[11px] text-text-muted border border-border rounded-[2px] p-2">
      {children}
    </p>
  );
}

function SeverityCell({
  label,
  value,
  tone,
}: {
  label: string;
  value: number;
  tone: "critical" | "high" | "medium" | "low" | "neutral";
}) {
  const color =
    tone === "neutral"
      ? "var(--color-text)"
      : `var(--color-${tone})`;
  return (
    <div className="flex flex-col items-center border border-border rounded-[2px] py-1">
      <span className="text-[9px] uppercase text-text-muted">{label}</span>
      <span className="text-sm font-semibold" style={{ color }}>
        {value}
      </span>
    </div>
  );
}

function KeyValueGrid({ rows }: { rows: Array<[string, string]> }) {
  return (
    <div className="grid grid-cols-[minmax(0,120px)_1fr] gap-y-1 gap-x-3 border border-border rounded-[2px] p-2">
      {rows.map(([k, v]) => (
        <React.Fragment key={k}>
          <span className="text-[10px] uppercase text-text-muted self-center">
            {k}
          </span>
          <span className="text-[11px] break-all">{v}</span>
        </React.Fragment>
      ))}
    </div>
  );
}

function PortsTable({ ports }: { ports: PortInfo[] }) {
  return (
    <div className="border border-border rounded-[2px] overflow-hidden">
      <table aria-label="Node ports" className="w-full text-[11px]">
        <thead>
          <tr className="bg-surface text-text-muted uppercase text-[9px]">
            <th className="text-left px-2 py-1">Port</th>
            <th className="text-left px-2 py-1">Proto</th>
            <th className="text-left px-2 py-1">Process</th>
            <th className="text-left px-2 py-1">Address</th>
          </tr>
        </thead>
        <tbody>
          {ports.map((p, i) => (
            <tr key={`${p.port}-${p.protocol}-${p.local_address}-${i}`} className="border-t border-border">
              <td className="px-2 py-1 font-semibold">{p.port}</td>
              <td className="px-2 py-1">{p.protocol}</td>
              <td className="px-2 py-1">{p.process_name ?? "--"}</td>
              <td className="px-2 py-1 text-text-muted">{p.local_address}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function ServicesTable({ services }: { services: ServiceInfo[] }) {
  return (
    <div className="border border-border rounded-[2px] overflow-hidden">
      <table aria-label="Node vulnerabilities" className="w-full text-[11px]">
        <thead>
          <tr className="bg-surface text-text-muted uppercase text-[9px]">
            <th className="text-left px-2 py-1">Service</th>
            <th className="text-left px-2 py-1">State</th>
            <th className="text-left px-2 py-1">Sub-state</th>
          </tr>
        </thead>
        <tbody>
          {services.map((s, i) => (
            <tr key={`${s.service_name}-${i}`} className="border-t border-border">
              <td className="px-2 py-1">{s.service_name}</td>
              <td className="px-2 py-1">{s.state}</td>
              <td className="px-2 py-1 text-text-muted">{s.sub_state}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
