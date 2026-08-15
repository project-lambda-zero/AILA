import { Fragment, useState } from "react";

import { LoadingSkeleton } from "@/components/aila/LoadingSkeleton";
import { WindowPanel } from "@/components/aila/WindowPanel";
import { DataGrid } from "@/components/aila/mock";

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
}

const REG_TABS: RegTabDef[] = [
  { id: "autoruns", label: "Autoruns" },
  { id: "services", label: "Services" },
  { id: "software", label: "Software" },
  { id: "users", label: "User Accounts" },
  { id: "usb", label: "USB History" },
  { id: "recent", label: "Recent Docs" },
  { id: "network", label: "Network" },
  { id: "shellbags", label: "ShellBags" },
  { id: "amcache", label: "AmCache" },
  { id: "shimcache", label: "ShimCache" },
  { id: "bam", label: "BAM" },
  { id: "security", label: "Security Pkgs" },
];

const INPUT_STYLE: React.CSSProperties = {
  height: 26,
  padding: "0 10px",
  fontSize: 11,
  background: "var(--surface-sunk)",
  border: "1px solid var(--border-soft)",
  color: "var(--text-primary)",
  borderRadius: 3,
  minWidth: 220,
};

export function RegistryViewer({ projectId }: { projectId: string }) {
  const { data: registry, isLoading, isError } = useRegistryAnalysis(projectId);
  const [activeTab, setActiveTab] = useState<RegTab>("autoruns");

  if (isLoading) return <LoadingSkeleton size="lg" width="full" />;

  if (isError) {
    return (
      <WindowPanel
        title="registry"
        tone="warn"
        status="forensics ; registry unavailable"
      >
        <p
          className="font-mono"
          style={{ fontSize: 11, color: "var(--accent)" }}
        >
          Failed to load registry analysis.
        </p>
      </WindowPanel>
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

  const totalItems = Object.values(dataMap).reduce(
    (sum, arr) => sum + arr.length,
    0,
  );

  if (totalItems === 0) {
    return (
      <WindowPanel
        title="registry"
        tone="muted"
        status="forensics ; no windows hive"
      >
        <p
          className="font-mono"
          style={{
            fontSize: 11,
            color: "var(--text-muted)",
            textAlign: "center",
            padding: "24px 0",
          }}
        >
          No registry data available. This project may not contain a Windows
          disk image.
        </p>
      </WindowPanel>
    );
  }

  const activeData = dataMap[activeTab];
  const activeLabel = REG_TABS.find((t) => t.id === activeTab)?.label ?? "";

  return (
    <WindowPanel
      title="registry"
      status={`hives ; ${totalItems} entries across ${REG_TABS.length} views`}
    >
      <div className="space-y-3">
        {/* Sub-tab bar -- mock language chip strip. */}
        <div className="flex flex-wrap" style={{ gap: 4 }}>
          {REG_TABS.map((tab) => {
            const count = dataMap[tab.id].length;
            const active = activeTab === tab.id;
            return (
              <button
                key={tab.id}
                type="button"
                onClick={() => setActiveTab(tab.id)}
                className="font-mono uppercase"
                style={{
                  display: "inline-flex",
                  alignItems: "center",
                  gap: 6,
                  height: 24,
                  padding: "0 10px",
                  fontSize: 9.5,
                  letterSpacing: "0.08em",
                  borderRadius: 3,
                  color: active ? "var(--text-on-accent)" : "var(--text-muted)",
                  background: active
                    ? "var(--accent)"
                    : "var(--surface-sunk)",
                  border: `1px solid ${
                    active ? "var(--accent)" : "var(--border-soft)"
                  }`,
                  cursor: "pointer",
                }}
              >
                <span>{tab.label}</span>
                {count > 0 && (
                  <span
                    style={{
                      padding: "1px 5px",
                      fontSize: 8.5,
                      borderRadius: 2,
                      background: active
                        ? "color-mix(in srgb, var(--text-on-accent) 20%, transparent)"
                        : "var(--surface-card)",
                      color: active
                        ? "var(--text-on-accent)"
                        : "var(--text-faint)",
                      border: active
                        ? "1px solid color-mix(in srgb, var(--text-on-accent) 30%, transparent)"
                        : "1px solid var(--border-faint)",
                    }}
                  >
                    {count}
                  </span>
                )}
              </button>
            );
          })}
        </div>

        {/* Data display */}
        {activeData.length === 0 ? (
          <div
            style={{
              padding: "40px 0",
              textAlign: "center",
            }}
          >
            <p
              className="font-mono"
              style={{ fontSize: 11, color: "var(--text-muted)" }}
            >
              No {activeLabel.toLowerCase()} data found.
            </p>
          </div>
        ) : (
          <RegistryTable rows={activeData} />
        )}
      </div>
    </WindowPanel>
  );
}

interface RegistryRow extends Record<string, unknown> {
  __idx: number;
}

function RegistryTable({ rows }: { rows: Record<string, unknown>[] }) {
  const [filterText, setFilterText] = useState("");
  const [expandedRow, setExpandedRow] = useState<number | null>(null);

  const columns = Object.keys(rows[0] ?? {}).filter(
    (k) => typeof rows[0][k] !== "object",
  );

  const filtered = filterText
    ? rows.filter((row) =>
        columns.some((col) =>
          String(row[col] ?? "")
            .toLowerCase()
            .includes(filterText.toLowerCase()),
        ),
      )
    : rows;

  const gridColumns = [
    { label: "#", width: "40px" },
    ...columns.map((col) => ({
      label: col,
      width: "minmax(0, 1fr)" as const,
    })),
  ];

  const capped: RegistryRow[] = filtered.slice(0, 500).map((row, i) => ({
    ...row,
    __idx: i,
  }));

  return (
    <div className="space-y-2">
      <div className="flex items-center" style={{ gap: 12 }}>
        <input
          aria-label="Search registry data"
          type="text"
          placeholder="search registry data..."
          value={filterText}
          onChange={(e) => setFilterText(e.target.value)}
          className="font-mono"
          style={INPUT_STYLE}
        />
        <span
          className="font-mono"
          style={{ fontSize: 9.5, color: "var(--text-faint)" }}
        >
          {filtered.length} of {rows.length} entries
        </span>
      </div>
      <div
        style={{
          overflowX: "auto",
          overflowY: "auto",
          maxHeight: 600,
        }}
        aria-label="Registry entries"
      >
        <DataGrid<RegistryRow>
          columns={gridColumns}
          rows={capped}
          getKey={(r) => r.__idx}
          onRowClick={(r) =>
            setExpandedRow(expandedRow === r.__idx ? null : r.__idx)
          }
          renderCells={(row) => [
            <span
              key="idx"
              className="font-mono"
              style={{ fontSize: 10, color: "var(--text-faint)" }}
            >
              {row.__idx + 1}
            </span>,
            ...columns.map((col) => (
              <Fragment key={col}>
                {expandedRow === row.__idx ? (
                  <span
                    className="font-mono whitespace-pre-wrap break-all"
                    style={{
                      fontSize: 10,
                      color: "var(--text-primary)",
                    }}
                    title={String(row[col] ?? "")}
                  >
                    {String(row[col] ?? "\u2014")}
                  </span>
                ) : (
                  <span
                    className="font-mono truncate"
                    style={{
                      fontSize: 10,
                      color: "var(--text-primary)",
                      display: "block",
                      whiteSpace: "nowrap",
                      overflow: "hidden",
                      textOverflow: "ellipsis",
                    }}
                    title={String(row[col] ?? "")}
                  >
                    {String(row[col] ?? "\u2014")}
                  </span>
                )}
              </Fragment>
            )),
          ]}
        />
      </div>
      {expandedRow !== null && capped[expandedRow] && (
        <pre
          className="font-mono whitespace-pre-wrap break-all"
          style={{
            padding: 12,
            fontSize: 10,
            lineHeight: 1.5,
            color: "var(--text-muted)",
            background: "var(--surface-sunk)",
            border: "1px solid var(--border-soft)",
            borderRadius: 3,
            maxHeight: 320,
            overflowY: "auto",
            margin: 0,
          }}
        >
          {JSON.stringify(capped[expandedRow], null, 2)}
        </pre>
      )}
    </div>
  );
}
