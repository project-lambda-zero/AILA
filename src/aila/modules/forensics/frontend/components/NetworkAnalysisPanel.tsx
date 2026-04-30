import { useMemo, useState } from "react";

import { AilaCard } from "@/components/aila/AilaCard";
import { LoadingSkeleton } from "@/components/aila/LoadingSkeleton";

import { useNetworkAnalysis } from "../queries";
import type { NetworkAnalysis, NetworkCommentary } from "../types";

// --- Tab definition ---------------------------------------------------------

type SubTab =
  | "commentary"
  | "overview"
  | "hosts"
  | "sessions"
  | "dns"
  | "suspicious_dns"
  | "http_requests"
  | "http_responses"
  | "tls"
  | "user_agents"
  | "unusual_ports"
  | "credentials"
  | "beacons"
  | "anomalies";

interface ColumnDef<T = Record<string, unknown>> {
  key: string;
  header: string;
  align?: "left" | "right";
  mono?: boolean;
  render?: (row: T) => React.ReactNode;
  width?: string;
}

interface SubTabDef {
  id: SubTab;
  label: string;
  countOf: (a: NetworkAnalysis) => number;
  rowsOf: (a: NetworkAnalysis) => Record<string, unknown>[];
  columns: ColumnDef[];
  emptyHint: string;
}

// --- helpers ---------------------------------------------------------------

const fmtInt = (v: unknown): string => {
  const n = Number(v);
  if (!Number.isFinite(n)) return String(v ?? "");
  return n.toLocaleString();
};

const fmtBytes = (v: unknown): string => {
  const n = Number(v);
  if (!Number.isFinite(n) || n <= 0) return "0";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let i = 0;
  let x = n;
  while (x >= 1024 && i < units.length - 1) {
    x /= 1024;
    i++;
  }
  return `${x.toFixed(x >= 100 ? 0 : 1)} ${units[i]}`;
};

const fmtSec = (v: unknown): string => {
  const n = Number(v);
  if (!Number.isFinite(n)) return "";
  if (n >= 60) {
    const m = Math.floor(n / 60);
    const s = Math.round(n % 60);
    return `${m}m${s}s`;
  }
  return `${n.toFixed(n >= 10 ? 0 : 2)}s`;
};

const ipFlag = (ip: unknown, isInternal: unknown): React.ReactNode => {
  const txt = String(ip ?? "");
  const label = isInternal ? "internal" : "external";
  const cls = isInternal ? "text-emerald-700" : "text-blue-700";
  return (
    <span>
      <span className="font-mono">{txt}</span>
      <span className={`ml-2 text-[10px] uppercase tracking-wide ${cls}`}>{label}</span>
    </span>
  );
};

const classificationBadge = (v: unknown): React.ReactNode => {
  const k = String(v ?? "common");
  const map: Record<string, string> = {
    common: "bg-slate-100 text-slate-700 border-slate-300",
    suspicious: "bg-amber-50 text-amber-800 border-amber-300",
    dga_shape: "bg-rose-50 text-rose-700 border-rose-300",
    empty: "bg-slate-50 text-slate-500 border-slate-200",
  };
  const cls = map[k] ?? map.common;
  return (
    <span className={`inline-block px-2 py-0.5 text-[10px] font-semibold uppercase rounded border ${cls}`}>
      {k}
    </span>
  );
};

const severityBadge = (s: string): React.ReactNode => {
  const map: Record<string, string> = {
    info: "bg-slate-100 text-slate-700 border-slate-300",
    low: "bg-sky-50 text-sky-700 border-sky-300",
    medium: "bg-amber-50 text-amber-800 border-amber-300",
    high: "bg-rose-50 text-rose-700 border-rose-300",
  };
  const cls = map[s] ?? map.info;
  return (
    <span className={`inline-block px-2 py-0.5 text-[10px] font-semibold uppercase rounded border ${cls}`}>
      {s}
    </span>
  );
};

// --- column definitions -----------------------------------------------------

const COLS_HOSTS: ColumnDef[] = [
  { key: "ip", header: "IP", render: (r) => ipFlag(r.ip, r.is_internal) },
  { key: "peer_count", header: "Peers", align: "right", render: (r) => fmtInt(r.peer_count) },
  { key: "flows", header: "Flows", align: "right", render: (r) => fmtInt(r.flows) },
  { key: "packets_sent", header: "Pkts Sent", align: "right", render: (r) => fmtInt(r.packets_sent) },
  { key: "packets_recv", header: "Pkts Recv", align: "right", render: (r) => fmtInt(r.packets_recv) },
  { key: "bytes_sent", header: "Bytes Sent", align: "right", render: (r) => fmtBytes(r.bytes_sent) },
  { key: "bytes_recv", header: "Bytes Recv", align: "right", render: (r) => fmtBytes(r.bytes_recv) },
  { key: "bytes_total", header: "Total", align: "right", render: (r) => fmtBytes(r.bytes_total) },
];

const COLS_SESSIONS: ColumnDef[] = [
  { key: "src", header: "Source", mono: true, render: (r) => `${r.src}:${r.sport}` },
  { key: "dst", header: "Destination", mono: true, render: (r) => `${r.dst}:${r.dport}` },
  { key: "protocol", header: "Proto" },
  { key: "packets", header: "Pkts", align: "right", render: (r) => fmtInt(r.packets) },
  { key: "bytes", header: "Bytes", align: "right", render: (r) => fmtBytes(r.bytes) },
  { key: "duration_s", header: "Duration", align: "right", render: (r) => fmtSec(r.duration_s) },
  { key: "bytes_per_sec", header: "B/s", align: "right", render: (r) => fmtBytes(r.bytes_per_sec) },
  {
    key: "is_long_lived",
    header: "Flag",
    render: (r) => (r.is_long_lived ? <span className="text-amber-700 text-[10px] font-semibold uppercase">long-lived</span> : ""),
  },
];

const COLS_DNS: ColumnDef[] = [
  { key: "qname", header: "Query name", mono: true },
  { key: "count", header: "Count", align: "right", render: (r) => fmtInt(r.count) },
  { key: "qtypes", header: "Types", render: (r) => (Array.isArray(r.qtypes) ? (r.qtypes as string[]).join(",") : "") },
  { key: "answer_count", header: "Answers", align: "right", render: (r) => fmtInt(r.answer_count) },
  { key: "nxdomain_count", header: "NX", align: "right", render: (r) => fmtInt(r.nxdomain_count) },
  { key: "classification", header: "Class", render: (r) => classificationBadge(r.classification) },
  { key: "dga_score", header: "DGA", align: "right", render: (r) => String(r.dga_score ?? "") },
  { key: "tld", header: "TLD", mono: true },
];

const COLS_HTTP_REQ: ColumnDef[] = [
  { key: "ts", header: "Time", mono: true },
  { key: "src", header: "Client", mono: true },
  { key: "method", header: "Method" },
  { key: "host", header: "Host", mono: true },
  { key: "uri", header: "URI", mono: true },
  {
    key: "user_agent",
    header: "User-Agent",
    mono: true,
    render: (r) => {
      const ua = String(r.user_agent ?? "");
      return (
        <span className="truncate inline-block max-w-[360px]" title={ua}>
          {ua || <span className="text-text-muted italic">(empty)</span>}
        </span>
      );
    },
  },
  {
    key: "is_suspicious_ua",
    header: "UA flag",
    render: (r) =>
      r.is_suspicious_ua ? (
        <span className="text-rose-700 text-[10px] font-semibold uppercase">{String(r.ua_tag ?? "sus")}</span>
      ) : (
        ""
      ),
  },
];

const COLS_HTTP_RESP: ColumnDef[] = [
  { key: "ts", header: "Time", mono: true },
  { key: "src", header: "Server", mono: true },
  {
    key: "status",
    header: "Status",
    render: (r) => {
      const s = Number(r.status) || 0;
      const cls = s >= 500 ? "text-rose-700" : s >= 400 ? "text-amber-700" : "text-emerald-700";
      return <span className={`font-mono font-semibold ${cls}`}>{s || "?"}</span>;
    },
  },
  { key: "content_type", header: "Type", mono: true },
  { key: "content_length", header: "Length", align: "right", render: (r) => fmtBytes(r.content_length) },
];

const COLS_TLS: ColumnDef[] = [
  { key: "ts", header: "Time", mono: true },
  { key: "src", header: "Client", mono: true },
  { key: "dst", header: "Server", mono: true, render: (r) => `${r.dst}:${r.dport}` },
  { key: "sni", header: "SNI", mono: true },
  { key: "ja3", header: "JA3", mono: true, render: (r) => String(r.ja3 ?? "").slice(0, 32) },
  { key: "tls_version", header: "Ver", mono: true },
];

const COLS_UA: ColumnDef[] = [
  { key: "user_agent", header: "User-Agent", mono: true },
  { key: "count", header: "Count", align: "right", render: (r) => fmtInt(r.count) },
  {
    key: "is_suspicious",
    header: "Flag",
    render: (r) => (r.is_suspicious ? <span className="text-rose-700 text-[10px] font-semibold uppercase">{String(r.tag ?? "sus")}</span> : ""),
  },
];

const COLS_UNUSUAL: ColumnDef[] = [
  { key: "src", header: "Source", mono: true },
  { key: "dst", header: "Destination", mono: true },
  { key: "dport", header: "Dport", align: "right", mono: true },
];

const COLS_CREDS: ColumnDef[] = [
  { key: "ts", header: "Time", mono: true },
  { key: "src", header: "Client", mono: true },
  { key: "dst", header: "Server", mono: true },
  { key: "kind", header: "Kind" },
  { key: "http_authorization", header: "HTTP Auth", mono: true, render: (r) => String(r.http_authorization ?? "").slice(0, 120) },
  { key: "ftp_command", header: "FTP", mono: true },
  { key: "ftp_arg", header: "FTP arg", mono: true },
  { key: "smtp_command", header: "SMTP", mono: true },
];

const COLS_BEACONS: ColumnDef[] = [
  { key: "src", header: "Source", mono: true },
  { key: "dst", header: "Destination", mono: true, render: (r) => `${r.dst}:${r.dport}` },
  { key: "protocol", header: "Proto" },
  { key: "packet_count", header: "Packets", align: "right", render: (r) => fmtInt(r.packet_count) },
  {
    key: "mean_interval_s",
    header: "Interval",
    align: "right",
    render: (r) => `${Number(r.mean_interval_s ?? 0).toFixed(2)}s ±${Number(r.interval_stdev_s ?? 0).toFixed(2)}`,
  },
  {
    key: "regularity",
    header: "Regularity",
    align: "right",
    render: (r) => {
      const v = Number(r.regularity ?? 0);
      const cls = v >= 0.9 ? "text-rose-700" : v >= 0.75 ? "text-amber-700" : "text-slate-600";
      return <span className={`font-mono font-semibold ${cls}`}>{v.toFixed(3)}</span>;
    },
  },
  {
    key: "constant_size",
    header: "Const size",
    render: (r) => (r.constant_size ? <span className="text-rose-700 text-[10px] font-semibold uppercase">yes</span> : ""),
  },
];

const COLS_ANOMALIES: ColumnDef[] = [
  { key: "kind", header: "Kind" },
  { key: "detail", header: "Detail" },
  { key: "count", header: "Count", align: "right", render: (r) => fmtInt(r.count) },
  {
    key: "examples",
    header: "Examples",
    mono: true,
    render: (r) => {
      const ex = r.examples;
      if (!Array.isArray(ex)) return "";
      return (ex as string[]).slice(0, 3).join(", ");
    },
  },
];

const COLS_PROTO: ColumnDef[] = [
  { key: "protocol", header: "Protocol", render: (r) => <span style={{ paddingLeft: `${(Number(r.depth) || 0) * 12}px` }} className="font-mono">{String(r.protocol ?? "")}</span> },
  { key: "packets", header: "Packets", align: "right", render: (r) => fmtInt(r.packets) },
  { key: "bytes", header: "Bytes", align: "right", render: (r) => fmtBytes(r.bytes) },
  { key: "percent", header: "%", align: "right", render: (r) => `${Number(r.percent ?? 0).toFixed(1)}%` },
];

const SUB_TABS: SubTabDef[] = [
  {
    id: "commentary",
    label: "AI Commentary",
    countOf: (a) => a.commentary.length,
    rowsOf: () => [],
    columns: [],
    emptyHint: "No commentary generated (LLM disabled or capture had nothing notable).",
  },
  {
    id: "overview",
    label: "Overview",
    countOf: (a) => a.protocol_hierarchy.length,
    rowsOf: (a) => a.protocol_hierarchy,
    columns: COLS_PROTO,
    emptyHint: "No protocol hierarchy recorded.",
  },
  {
    id: "hosts",
    label: "Hosts",
    countOf: (a) => a.hosts.length,
    rowsOf: (a) => a.hosts,
    columns: COLS_HOSTS,
    emptyHint: "No host talker data.",
  },
  {
    id: "sessions",
    label: "Sessions",
    countOf: (a) => a.sessions.length,
    rowsOf: (a) => a.sessions,
    columns: COLS_SESSIONS,
    emptyHint: "No TCP/UDP conversations parsed.",
  },
  {
    id: "dns",
    label: "DNS",
    countOf: (a) => a.dns.length,
    rowsOf: (a) => a.dns,
    columns: COLS_DNS,
    emptyHint: "No DNS queries in this capture.",
  },
  {
    id: "suspicious_dns",
    label: "Suspicious DNS",
    countOf: (a) => a.suspicious_dns.length,
    rowsOf: (a) => a.suspicious_dns,
    columns: COLS_DNS,
    emptyHint: "No names on abuse-heavy TLDs and no DGA-shaped names.",
  },
  {
    id: "http_requests",
    label: "HTTP requests",
    countOf: (a) => a.http_requests.length,
    rowsOf: (a) => a.http_requests,
    columns: COLS_HTTP_REQ,
    emptyHint: "No HTTP requests extracted.",
  },
  {
    id: "http_responses",
    label: "HTTP responses",
    countOf: (a) => a.http_responses.length,
    rowsOf: (a) => a.http_responses,
    columns: COLS_HTTP_RESP,
    emptyHint: "No HTTP responses extracted.",
  },
  {
    id: "tls",
    label: "TLS / SNI",
    countOf: (a) => a.tls_client_hellos.length,
    rowsOf: (a) => a.tls_client_hellos,
    columns: COLS_TLS,
    emptyHint: "No TLS Client Hellos observed.",
  },
  {
    id: "user_agents",
    label: "User agents",
    countOf: (a) => a.user_agents.length,
    rowsOf: (a) => a.user_agents,
    columns: COLS_UA,
    emptyHint: "No HTTP User-Agent headers seen.",
  },
  {
    id: "unusual_ports",
    label: "Unusual ports",
    countOf: (a) => a.unusual_ports.length,
    rowsOf: (a) => a.unusual_ports,
    columns: COLS_UNUSUAL,
    emptyHint: "No unusual destination ports.",
  },
  {
    id: "credentials",
    label: "Credentials",
    countOf: (a) => a.credentials.length,
    rowsOf: (a) => a.credentials,
    columns: COLS_CREDS,
    emptyHint: "No plaintext credential traffic observed.",
  },
  {
    id: "beacons",
    label: "Beacons",
    countOf: (a) => a.beacons.length,
    rowsOf: (a) => a.beacons,
    columns: COLS_BEACONS,
    emptyHint: "No beacon candidates (no flow showed regular inter-arrival intervals).",
  },
  {
    id: "anomalies",
    label: "Anomalies",
    countOf: (a) => a.anomalies.length,
    rowsOf: (a) => a.anomalies,
    columns: COLS_ANOMALIES,
    emptyHint: "No anomalies flagged.",
  },
];

// --- components ------------------------------------------------------------

function StatsBar({ stats }: { stats: NetworkAnalysis["stats"] }) {
  const items = [
    { label: "Packets", value: fmtInt(stats.packet_count ?? 0) },
    { label: "Bytes", value: fmtBytes(stats.byte_count ?? 0) },
    { label: "Duration", value: stats.duration_s ? fmtSec(stats.duration_s) : "—" },
  ];
  return (
    <div className="flex gap-6 border border-border rounded-md px-4 py-3 bg-surface-secondary/40 mb-3">
      {items.map((it) => (
        <div key={it.label}>
          <div className="text-[10px] uppercase tracking-wide text-text-muted font-medium">{it.label}</div>
          <div className="font-mono text-sm font-semibold text-foreground">{it.value}</div>
        </div>
      ))}
    </div>
  );
}

function CommentaryPanel({ items }: { items: NetworkCommentary[] }) {
  if (!items || items.length === 0) {
    return (
      <div className="py-12 text-center">
        <p className="text-sm text-text-muted">
          No AI commentary was generated for this capture. Either the LLM is disabled or the capture had nothing notable to narrate.
        </p>
      </div>
    );
  }
  const order = ["overall", "hosts", "dns", "http", "tls", "beacons", "anomalies"];
  const sorted = [...items].sort(
    (a, b) => order.indexOf(a.subject) - order.indexOf(b.subject),
  );
  return (
    <div className="divide-y divide-border">
      {sorted.map((c, i) => (
        <div key={`${c.subject}-${i}`} className="px-4 py-4">
          <div className="flex items-center gap-2 mb-2">
            <span className="text-sm font-semibold text-foreground uppercase tracking-wide">
              {c.subject}
            </span>
            {severityBadge(String(c.severity))}
          </div>
          <p className="text-sm leading-relaxed text-foreground whitespace-pre-wrap">
            {c.narrative}
          </p>
        </div>
      ))}
    </div>
  );
}

function DataTable({
  rows,
  columns,
  emptyHint,
}: {
  rows: Record<string, unknown>[];
  columns: ColumnDef[];
  emptyHint: string;
}) {
  const [sortCol, setSortCol] = useState<string | null>(null);
  const [sortAsc, setSortAsc] = useState(false);
  const [filterText, setFilterText] = useState("");

  const filtered = useMemo(() => {
    if (!filterText) return rows;
    const needle = filterText.toLowerCase();
    return rows.filter((row) =>
      columns.some((col) => {
        const v = row[col.key];
        return String(v ?? "").toLowerCase().includes(needle);
      }),
    );
  }, [rows, columns, filterText]);

  const sorted = useMemo(() => {
    if (!sortCol) return filtered;
    return [...filtered].sort((a, b) => {
      const va = a[sortCol];
      const vb = b[sortCol];
      const na = Number(va);
      const nb = Number(vb);
      if (Number.isFinite(na) && Number.isFinite(nb)) {
        return sortAsc ? na - nb : nb - na;
      }
      const sa = String(va ?? "");
      const sb = String(vb ?? "");
      return sortAsc ? sa.localeCompare(sb) : sb.localeCompare(sa);
    });
  }, [filtered, sortCol, sortAsc]);

  if (rows.length === 0) {
    return (
      <div className="py-12 text-center">
        <p className="text-sm text-text-muted">{emptyHint}</p>
      </div>
    );
  }

  const handleSort = (col: string) => {
    if (sortCol === col) setSortAsc(!sortAsc);
    else {
      setSortCol(col);
      setSortAsc(false);
    }
  };

  return (
    <div>
      <div className="px-3 py-2 border-b border-border bg-surface-secondary/50 flex items-center gap-3">
        <input
          type="text"
          placeholder="Filter rows..."
          value={filterText}
          onChange={(e) => setFilterText(e.target.value)}
          className="w-full max-w-xs px-2.5 py-1 text-xs rounded border border-border bg-surface text-foreground placeholder:text-text-muted focus:outline-none focus:border-primary"
        />
        <span className="text-[10px] text-text-muted">
          {sorted.length} of {rows.length} rows
        </span>
      </div>
      <div className="overflow-x-auto max-h-[600px] overflow-y-auto">
        <table className="w-full text-xs">
          <thead className="bg-surface-secondary sticky top-0 z-10">
            <tr>
              <th className="text-left px-3 py-2 text-text-muted font-medium w-8">#</th>
              {columns.map((c) => (
                <th
                  key={c.key}
                  onClick={() => handleSort(c.key)}
                  className={`px-3 py-2 text-text-muted font-medium whitespace-nowrap cursor-pointer hover:text-foreground select-none ${c.align === "right" ? "text-right" : "text-left"}`}
                  style={c.width ? { width: c.width } : undefined}
                >
                  {c.header}
                  {sortCol === c.key && <span className="ml-1">{sortAsc ? "▲" : "▼"}</span>}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {sorted.slice(0, 1000).map((row, i) => (
              <tr key={i} className="border-t border-border hover:bg-surface-secondary/30">
                <td className="px-3 py-1.5 text-text-muted font-mono">{i + 1}</td>
                {columns.map((c) => {
                  const raw = row[c.key];
                  const rendered: React.ReactNode = c.render
                    ? c.render(row)
                    : raw === undefined || raw === null
                      ? ""
                      : String(raw);
                  const isEmpty =
                    rendered === "" || rendered === undefined || rendered === null;
                  return (
                    <td
                      key={c.key}
                      className={`px-3 py-1.5 text-foreground whitespace-nowrap ${c.mono ? "font-mono" : ""} ${c.align === "right" ? "text-right" : ""}`}
                    >
                      {isEmpty ? <span className="text-text-muted">—</span> : rendered}
                    </td>
                  );
                })}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {sorted.length > 1000 && (
        <div className="px-3 py-2 text-[10px] text-text-muted border-t border-border bg-surface-secondary/50">
          Showing 1000 of {sorted.length} rows. Filter to narrow.
        </div>
      )}
    </div>
  );
}

// --- top-level panel -------------------------------------------------------

export function NetworkAnalysisPanel({ projectId }: { projectId: string }) {
  const { data: analysis, isLoading, isError } = useNetworkAnalysis(projectId);
  const [activeSubTab, setActiveSubTab] = useState<SubTab>("commentary");

  if (isLoading) return <LoadingSkeleton size="lg" width="full" />;
  if (isError) {
    return (
      <AilaCard className="border-border-danger">
        <p className="text-sm text-text-danger">Failed to load network analysis.</p>
      </AilaCard>
    );
  }
  if (!analysis) return null;

  const hasAnyData =
    analysis.commentary.length +
      analysis.hosts.length +
      analysis.sessions.length +
      analysis.dns.length +
      analysis.http_requests.length +
      analysis.http_responses.length +
      analysis.tls_client_hellos.length +
      analysis.beacons.length +
      analysis.anomalies.length +
      analysis.protocol_hierarchy.length >
    0;

  if (!hasAnyData) {
    return (
      <AilaCard>
        <p className="text-sm text-text-muted text-center py-8">
          No network analysis data available. This project may not contain PCAP evidence.
        </p>
      </AilaCard>
    );
  }

  const active = SUB_TABS.find((t) => t.id === activeSubTab) ?? SUB_TABS[0];

  return (
    <div className="space-y-0">
      <StatsBar stats={analysis.stats} />

      <div className="flex flex-wrap gap-0.5 bg-surface-secondary rounded-t-lg p-1 border border-b-0 border-border">
        {SUB_TABS.map((tab) => {
          const count = tab.countOf(analysis);
          const isActive = activeSubTab === tab.id;
          return (
            <button
              key={tab.id}
              type="button"
              onClick={() => setActiveSubTab(tab.id)}
              className={`flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-md transition-colors ${
                isActive
                  ? "bg-surface text-foreground shadow-sm border border-border"
                  : "text-text-muted hover:text-foreground hover:bg-surface/50"
              }`}
            >
              <span>{tab.label}</span>
              {count > 0 && (
                <span
                  className={`ml-1 px-1.5 py-0.5 rounded-full text-[10px] font-bold ${
                    isActive ? "bg-primary/10 text-primary" : "bg-surface-secondary text-text-muted"
                  }`}
                >
                  {count}
                </span>
              )}
            </button>
          );
        })}
      </div>

      <div className="border border-border rounded-b-lg bg-surface">
        {active.id === "commentary" ? (
          <CommentaryPanel items={analysis.commentary} />
        ) : (
          <DataTable rows={active.rowsOf(analysis)} columns={active.columns} emptyHint={active.emptyHint} />
        )}
      </div>
    </div>
  );
}
