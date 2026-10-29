/**
 * Network and registry analysis tabs: one multi-section payload per route,
 * a section switcher, optional stats block, and an auto-column table over
 * the selected section's tool-emitted rows.
 */
import type { JSX } from "react";
import { useMemo, useState } from "react";

import { parseStructuredAnalysis, useForensicsQuery } from "../../../../api/forensics";
import { css } from "../../../css";
import { DataTable, DictPanel, Panel, emptyNote, inlineNote, renderValue } from "../panels";
import type { TableColumn } from "../panels";
import type { TabProps } from "./shared";

/** [payload key, section label] pairs in display order. */
type SectionDefs = readonly (readonly [string, string])[];

const NETWORK_SECTIONS: SectionDefs = [
  ["protocol_hierarchy", "protocol hierarchy"],
  ["hosts", "hosts"],
  ["sessions", "sessions"],
  ["dns", "dns"],
  ["suspicious_dns", "suspicious dns"],
  ["http_requests", "http requests"],
  ["http_responses", "http responses"],
  ["tls_client_hellos", "tls client hellos"],
  ["unusual_ports", "unusual ports"],
  ["user_agents", "user agents"],
  ["credentials", "credentials"],
  ["beacons", "beacons"],
  ["anomalies", "anomalies"],
  ["commentary", "commentary"],
];

const REGISTRY_SECTIONS: SectionDefs = [
  ["autoruns", "autoruns"],
  ["services", "services"],
  ["installed_software", "installed software"],
  ["user_accounts", "user accounts"],
  ["usb_history", "usb history"],
  ["recent_docs", "recent docs"],
  ["network_interfaces", "network interfaces"],
  ["shellbags", "shellbags"],
  ["amcache", "amcache"],
  ["shimcache", "shimcache"],
  ["bam", "bam"],
  ["security_packages", "security packages"],
];

export function NetworkAnalysisTab({ projectId }: TabProps): JSX.Element {
  return (
    <StructuredAnalysisTab
      projectId={projectId}
      path={`/forensics/projects/${projectId}/network-analysis`}
      queryKey="network-analysis"
      title="network analysis"
      sections={NETWORK_SECTIONS}
      statsKey="stats"
    />
  );
}

export function RegistryAnalysisTab({ projectId }: TabProps): JSX.Element {
  return (
    <StructuredAnalysisTab
      projectId={projectId}
      path={`/forensics/projects/${projectId}/registry-analysis`}
      queryKey="registry-analysis"
      title="registry analysis"
      sections={REGISTRY_SECTIONS}
      statsKey={null}
    />
  );
}

function StructuredAnalysisTab({
  projectId,
  path,
  queryKey,
  title,
  sections,
  statsKey,
}: {
  projectId: string;
  path: string;
  queryKey: string;
  title: string;
  sections: SectionDefs;
  statsKey: string | null;
}): JSX.Element {
  const q = useForensicsQuery(projectId, [queryKey], path, (raw) =>
    parseStructuredAnalysis(
      raw,
      sections.map(([k]) => k),
      statsKey,
    ),
  );
  const [active, setActive] = useState<string>(sections[0][0]);
  if (q.isLoading) return <div style={emptyNote}>{"loading\u2026"}</div>;
  if (q.isError) {
    const msg = q.error instanceof Error ? q.error.message : "request failed";
    return <div style={emptyNote}>could not load {title} &mdash; {msg}</div>;
  }
  const data = q.data;
  if (!data) return <div style={emptyNote}>no data.</div>;
  const rows = data.sections[active] ?? [];
  const stats = data.stats;

  return (
    <Panel
      title={title}
      tag={`${sections.length} sections`}
      right={
        <div style={css("display:flex;gap:4px;flex-wrap:wrap;")}>
          {sections.map(([k, label]) => {
            const n = data.sections[k]?.length ?? 0;
            return (
              <button
                key={k}
                type="button"
                onClick={() => setActive(k)}
                style={css(
                  `background:${active === k ? "var(--accent)" : "transparent"};color:${active === k ? "var(--text-on-accent)" : "var(--text-muted)"};border:1px solid ${active === k ? "var(--accent)" : "var(--border-soft)"};border-radius:2px;font-family:var(--font-mono);font-size:11px;letter-spacing:0.08em;text-transform:uppercase;padding:2px 7px;cursor:pointer;`,
                )}
              >
                {label} {n ? `\u00b7 ${n}` : ""}
              </button>
            );
          })}
        </div>
      }
    >
      <div style={css("padding:12px;display:flex;flex-direction:column;gap:12px;")}>
        {stats && Object.keys(stats).length ? (
          <div>
            <div style={css("font-size:11px;letter-spacing:0.12em;text-transform:uppercase;color:var(--text-faint);margin-bottom:5px;")}>stats</div>
            <DictPanel data={stats} initialOpen />
          </div>
        ) : null}
        <div>
          <div style={css("font-size:11px;letter-spacing:0.12em;text-transform:uppercase;color:var(--text-faint);margin-bottom:5px;")}>{sections.find(([k]) => k === active)?.[1] ?? active}</div>
          {rows.length === 0 ? <div style={inlineNote}>no rows in this section.</div> : <SectionAutoTable rows={rows} />}
        </div>
      </div>
    </Panel>
  );
}

/** Columns are the first ten keys seen across the first 60 rows; section
 * rows are open-ended tool records, so no fixed schema applies. */
function SectionAutoTable({ rows }: { rows: Record<string, unknown>[] }): JSX.Element {
  const cols = useMemo<TableColumn<Record<string, unknown>>[]>(() => {
    const keys: string[] = [];
    const seen = new Set<string>();
    for (const r of rows.slice(0, 60)) {
      for (const k of Object.keys(r)) {
        if (!seen.has(k)) {
          seen.add(k);
          keys.push(k);
        }
      }
    }
    return keys.slice(0, 10).map((k) => ({
      field: k,
      label: k.replace(/_/g, " "),
      render: (row) => {
        const v = row[k];
        if (v === null || v === undefined) return <span style={css("color:var(--text-faint);")}>{"\u2014"}</span>;
        if (typeof v === "object") return renderValue(v);
        return String(v);
      },
    }));
  }, [rows]);
  return <DataTable rows={rows} columns={cols} />;
}
