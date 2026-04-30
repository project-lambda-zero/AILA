import { useState } from "react";

import { AilaCard } from "@/components/aila/AilaCard";
import { LoadingSkeleton } from "@/components/aila/LoadingSkeleton";

import { useRegistryAnalysis } from "../queries";

type RegTab =
  | "autoruns"
  | "services"
  | "software"
  | "users"
  | "usb"
  | "recent"
  | "network"
  | "shellbags"
  | "amcache"
  | "shimcache"
  | "bam"
  | "security";

interface RegTabDef {
  id: RegTab;
  label: string;
  icon: string;
}

const REG_TABS: RegTabDef[] = [
  { id: "autoruns", label: "Autoruns", icon: "▶" },
  { id: "services", label: "Services", icon: "⚙" },
  { id: "software", label: "Software", icon: "📦" },
  { id: "users", label: "User Accounts", icon: "👤" },
  { id: "usb", label: "USB History", icon: "🔌" },
  { id: "recent", label: "Recent Docs", icon: "📋" },
  { id: "network", label: "Network", icon: "🌐" },
  { id: "shellbags", label: "ShellBags", icon: "📂" },
  { id: "amcache", label: "AmCache", icon: "💾" },
  { id: "shimcache", label: "ShimCache", icon: "🔄" },
  { id: "bam", label: "BAM", icon: "📊" },
  { id: "security", label: "Security Pkgs", icon: "🔒" },
];

export function RegistryViewer({ projectId }: { projectId: string }) {
  const { data: registry, isLoading, isError } = useRegistryAnalysis(projectId);
  const [activeTab, setActiveTab] = useState<RegTab>("autoruns");

  if (isLoading) return <LoadingSkeleton size="lg" width="full" />;

  if (isError) {
    return (
      <AilaCard className="border-border-danger">
        <p className="text-sm text-text-danger">Failed to load registry analysis.</p>
      </AilaCard>
    );
  }

  if (!registry) return null;

  const dataMap: Record<RegTab, Record<string, unknown>[]> = {
    autoruns: registry.autoruns,
    services: registry.services,
    software: registry.installed_software,
    users: registry.user_accounts,
    usb: registry.usb_history,
    recent: registry.recent_docs,
    network: registry.network_interfaces,
    shellbags: registry.shellbags,
    amcache: registry.amcache,
    shimcache: registry.shimcache,
    bam: registry.bam,
    security: registry.security_packages,
  };

  const totalItems = Object.values(dataMap).reduce((sum, arr) => sum + arr.length, 0);

  if (totalItems === 0) {
    return (
      <AilaCard>
        <p className="text-sm text-text-muted text-center py-8">
          No registry data available. This project may not contain a Windows disk image.
        </p>
      </AilaCard>
    );
  }

  const activeData = dataMap[activeTab];

  return (
    <div className="space-y-0">
      {/* Sub-tab bar */}
      <div className="flex flex-wrap gap-0.5 bg-surface-secondary rounded-t-lg p-1 border border-b-0 border-border">
        {REG_TABS.map((tab) => {
          const count = dataMap[tab.id].length;
          return (
            <button
              key={tab.id}
              type="button"
              onClick={() => setActiveTab(tab.id)}
              className={`flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-md transition-colors ${
                activeTab === tab.id
                  ? "bg-surface text-foreground shadow-sm border border-border"
                  : "text-text-muted hover:text-foreground hover:bg-surface/50"
              }`}
            >
              <span>{tab.icon}</span>
              <span>{tab.label}</span>
              {count > 0 && (
                <span className={`ml-1 px-1.5 py-0.5 rounded-full text-[10px] font-bold ${
                  activeTab === tab.id
                    ? "bg-primary/10 text-primary"
                    : "bg-surface-secondary text-text-muted"
                }`}>
                  {count}
                </span>
              )}
            </button>
          );
        })}
      </div>

      {/* Data display */}
      <div className="border border-border rounded-b-lg">
        {activeData.length === 0 ? (
          <div className="py-12 text-center">
            <p className="text-sm text-text-muted">
              No {REG_TABS.find((t) => t.id === activeTab)?.label.toLowerCase()} data found.
            </p>
          </div>
        ) : (
          <RegistryTable rows={activeData} />
        )}
      </div>
    </div>
  );
}

function RegistryTable({ rows }: { rows: Record<string, unknown>[] }) {
  const [filterText, setFilterText] = useState("");
  const [expandedRow, setExpandedRow] = useState<number | null>(null);

  const columns = Object.keys(rows[0] ?? {}).filter(
    (k) => typeof rows[0][k] !== "object"
  );

  const filtered = filterText
    ? rows.filter((row) =>
        columns.some((col) =>
          String(row[col] ?? "").toLowerCase().includes(filterText.toLowerCase())
        )
      )
    : rows;

  return (
    <div>
      <div className="px-3 py-2 border-b border-border bg-surface-secondary/50">
        <input
          type="text"
          placeholder="Search registry data..."
          value={filterText}
          onChange={(e) => setFilterText(e.target.value)}
          className="w-full max-w-xs px-2.5 py-1 text-xs rounded border border-border bg-surface text-foreground placeholder:text-text-muted focus:outline-none focus:border-primary"
        />
        <span className="ml-3 text-[10px] text-text-muted">
          {filtered.length} of {rows.length} entries
        </span>
      </div>
      <div className="overflow-x-auto max-h-[600px] overflow-y-auto">
        <table className="w-full text-xs">
          <thead className="bg-surface-secondary sticky top-0 z-10">
            <tr>
              <th className="text-left px-3 py-2 text-text-muted font-medium w-8">#</th>
              {columns.map((col) => (
                <th key={col} className="text-left px-3 py-2 text-text-muted font-medium whitespace-nowrap">
                  {col}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {filtered.slice(0, 500).map((row, i) => (
              <>
                <tr
                  key={i}
                  onClick={() => setExpandedRow(expandedRow === i ? null : i)}
                  className="border-t border-border hover:bg-surface-secondary/30 cursor-pointer"
                >
                  <td className="px-3 py-1.5 text-text-muted font-mono">{i + 1}</td>
                  {columns.map((col) => (
                    <td
                      key={col}
                      className="px-3 py-1.5 text-foreground font-mono whitespace-nowrap truncate max-w-xs"
                      title={String(row[col] ?? "")}
                    >
                      {String(row[col] ?? "\u2014")}
                    </td>
                  ))}
                </tr>
                {expandedRow === i && (
                  <tr key={`${i}-detail`} className="border-t border-border/50">
                    <td colSpan={columns.length + 1} className="px-4 py-3 bg-surface-secondary/20">
                      <pre className="text-[10px] font-mono text-foreground whitespace-pre-wrap break-all max-h-48 overflow-y-auto">
                        {JSON.stringify(row, null, 2)}
                      </pre>
                    </td>
                  </tr>
                )}
              </>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
