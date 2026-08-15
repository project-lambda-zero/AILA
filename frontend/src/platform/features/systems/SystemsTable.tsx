import { useMemo, useState } from "react";
import { useNavigate } from "react-router";

import { DataGrid, MonoBadge } from "@/components/aila/mock";
import { ConnectivityBadge } from "./ConnectivityBadge";
import {
  formatRelativeTime,
  type SystemSummaryEnriched,
  type SeverityLevel,
} from "./api";

const SEVERITY_ORDER: Record<SeverityLevel, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
};

type SortKey = "name" | "distro" | "severity" | "last_scan";
type SortDir = "asc" | "desc";

interface SystemsDataGridProps {
  rows: SystemSummaryEnriched[];
  onManageTags?: (systemId: number) => void;
  onRowClick?: (row: SystemSummaryEnriched) => void;
  emptyMessage?: string;
}

/**
 * SystemsDataGrid -- honest bordered mono grid for the systems inventory.
 *
 * Composes DataGrid with the mock language: link-styled host, mono host:port
 * pair, ConnectivityBadge (MonoBadge under the hood), MonoBadge chips for
 * tags and severity, and formatRelativeTime for last-scan metadata. Sort
 * state is local; header cells click through name -> distro -> severity ->
 * last_scan cycles asc/desc. onRowClick defaults to routing to detail.
 */
export function SystemsDataGrid({
  rows,
  onManageTags,
  onRowClick,
  emptyMessage,
}: SystemsDataGridProps) {
  const navigate = useNavigate();
  const [sortKey, setSortKey] = useState<SortKey>("severity");
  const [sortDir, setSortDir] = useState<SortDir>("desc");

  const sorted = useMemo(() => {
    const copy = rows.slice();
    copy.sort((a, b) => {
      let cmp = 0;
      if (sortKey === "name") {
        cmp = a.name.localeCompare(b.name);
      } else if (sortKey === "distro") {
        cmp = (a.distro ?? "").localeCompare(b.distro ?? "");
      } else if (sortKey === "severity") {
        const av = a.top_severity ? SEVERITY_ORDER[a.top_severity] ?? 0 : 0;
        const bv = b.top_severity ? SEVERITY_ORDER[b.top_severity] ?? 0 : 0;
        cmp = av - bv;
      } else if (sortKey === "last_scan") {
        const at = a.last_scan_at ? Date.parse(a.last_scan_at) : 0;
        const bt = b.last_scan_at ? Date.parse(b.last_scan_at) : 0;
        cmp = at - bt;
      }
      return sortDir === "asc" ? cmp : -cmp;
    });
    return copy;
  }, [rows, sortKey, sortDir]);

  function toggleSort(key: SortKey) {
    if (sortKey === key) {
      setSortDir((d) => (d === "asc" ? "desc" : "asc"));
    } else {
      setSortKey(key);
      setSortDir(key === "severity" || key === "last_scan" ? "desc" : "asc");
    }
  }

  function sortLabel(key: SortKey, label: string) {
    const arrow =
      sortKey === key ? (sortDir === "asc" ? "\u2191" : "\u2193") : "";
    return (
      <button
        type="button"
        onClick={() => toggleSort(key)}
        className="font-mono uppercase"
        style={{
          background: "transparent",
          border: 0,
          padding: 0,
          fontSize: 9,
          letterSpacing: "0.14em",
          color: sortKey === key ? "var(--text-primary)" : "var(--text-faint)",
          cursor: "pointer",
        }}
      >
        {label} {arrow}
      </button>
    );
  }

  return (
    <DataGrid<SystemSummaryEnriched>
      columns={[
        { label: sortLabel("name", "host"), width: "minmax(180px, 1.4fr)" },
        { label: "endpoint", width: "minmax(160px, 1fr)" },
        { label: sortLabel("distro", "distro"), width: "120px" },
        { label: "tags", width: "minmax(180px, 1.4fr)" },
        { label: "ssh", width: "110px" },
        { label: sortLabel("severity", "top sev"), width: "90px" },
        { label: sortLabel("last_scan", "last scan"), width: "120px" },
        { label: "\u00a0", width: "60px", align: "right" },
      ]}
      rows={sorted}
      getKey={(r) => r.id}
      onRowClick={
        onRowClick
          ? (r) => onRowClick(r)
          : (r) => navigate(`/systems/${r.id}`)
      }
      empty={
        <div
          className="font-mono"
          style={{
            padding: 34,
            textAlign: "center",
            fontSize: 12,
            color: "var(--text-muted)",
          }}
        >
          {emptyMessage ?? "no systems match the current filters."}
        </div>
      }
      renderCells={(row) => {
        const tags = row.tags ?? [];
        const visible = tags.slice(0, 3);
        const overflow = tags.length - visible.length;
        const sev = row.top_severity;
        return [
          <span
            style={{ color: "var(--accent)", fontWeight: 500, fontSize: 12 }}
          >
            {row.name}
          </span>,
          <span
            className="truncate"
            style={{ color: "var(--text-muted)", fontSize: 11 }}
          >
            {row.username}@{row.host}:{row.port}
          </span>,
          <span style={{ color: "var(--text-primary)", fontSize: 11 }}>
            {row.distro}
          </span>,
          <div
            className="flex flex-wrap items-center"
            style={{ gap: 4 }}
          >
            {visible.length === 0 && (
              <span
                style={{ color: "var(--text-faint)", fontSize: 10 }}
              >
                --
              </span>
            )}
            {visible.map((t) => (
              <MonoBadge key={`${t.tag_key}:${t.tag_value}`} tone="info">
                {t.tag_key}:{t.tag_value}
              </MonoBadge>
            ))}
            {overflow > 0 && (
              <MonoBadge
                tone="muted"
                title={tags
                  .slice(3)
                  .map((t) => `${t.tag_key}:${t.tag_value}`)
                  .join("\n")}
              >
                +{overflow}
              </MonoBadge>
            )}
          </div>,
          <ConnectivityBadge status={row.connectivity_status} />,
          sev ? (
            <MonoBadge tone={sev}>{sev.toUpperCase()}</MonoBadge>
          ) : (
            <span style={{ color: "var(--text-faint)", fontSize: 10 }}>
              N/A
            </span>
          ),
          <span
            style={{ color: "var(--text-muted)", fontSize: 10 }}
            title={row.last_scan_at ?? undefined}
          >
            {formatRelativeTime(row.last_scan_at)}
          </span>,
          onManageTags ? (
            <button
              type="button"
              onClick={(e) => {
                e.stopPropagation();
                onManageTags(row.id);
              }}
              aria-label={`Manage tags for ${row.name}`}
              className="font-mono uppercase"
              style={{
                height: 22,
                padding: "0 8px",
                fontSize: 9,
                letterSpacing: "0.08em",
                border: "1px solid var(--border-soft)",
                background: "var(--surface-sunk)",
                color: "var(--text-muted)",
                borderRadius: 3,
                cursor: "pointer",
              }}
            >
              tags +
            </button>
          ) : (
            <span
              style={{ color: "var(--text-faint)", fontSize: 10 }}
              aria-hidden="true"
            >
              --
            </span>
          ),
        ];
      }}
    />
  );
}
