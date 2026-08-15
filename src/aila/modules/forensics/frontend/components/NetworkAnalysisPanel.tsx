import { useState } from "react";

import { EmptyState } from "@/components/aila/EmptyState";
import { LoadingSkeleton } from "@/components/aila/LoadingSkeleton";
import { WindowPanel } from "@/components/aila/WindowPanel";
import {
  BigStat,
  DataGrid,
  MonoBadge,
  Segmented,
  type GridColumn,
} from "@/components/aila/mock";

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

// D24 exception: `render` is a cell-formatter slot tied to the column's
// placement constraints (header, alignment, width, mono-font) -- not a
// public render-prop API. ColumnDef is module-internal; the only
// exported surface here is <NetworkAnalysisPanel projectId>.
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
  const color = isInternal ? "var(--status-ok)" : "var(--status-info)";
  return (
    <span>
      <span className="font-mono">{txt}</span>
      <span
        className="ml-2 uppercase"
        style={{ fontSize: 9, letterSpacing: "0.08em", color }}
      >
        {label}
      </span>
    </span>
  );
};

const classificationBadge = (v: unknown): React.ReactNode => {
  const k = String(v ?? "common");
  const toneMap: Record<string, string> = {
    common: "muted",
    suspicious: "high",
    dga_shape: "critical",
    empty: "muted",
  };
  return <MonoBadge tone={toneMap[k] ?? "muted"}>{k}</MonoBadge>;
};

const severityBadge = (s: string): React.ReactNode => {
  const toneMap: Record<string, string> = {
    info: "info",
    low: "low",
    medium: "medium",
    high: "high",
  };
  return <MonoBadge tone={toneMap[s] ?? "info"}>{s}</MonoBadge>;
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
    render: (r) =>
      r.is_long_lived ? (
        <span
          className="uppercase"
          style={{ fontSize: 9, color: "var(--status-warn)", letterSpacing: "0.08em" }}
        >
          long-lived
        </span>
      ) : (
        ""
      ),
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
        <span className="truncate inline-block" style={{ maxWidth: 360 }} title={ua}>
          {ua || (
            <span style={{ color: "var(--text-muted)", fontStyle: "italic" }}>
              (empty)
            </span>
          )}
        </span>
      );
    },
  },
  {
    key: "is_suspicious_ua",
    header: "UA flag",
    render: (r) =>
      r.is_suspicious_ua ? (
        <span
          className="uppercase"
          style={{ color: "var(--accent)", fontSize: 9, letterSpacing: "0.08em" }}
        >
          {String(r.ua_tag ?? "sus")}
        </span>
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
      const color = s >= 500 ? "var(--accent)" : s >= 400 ? "var(--status-warn)" : "var(--status-ok)";
      return <span className="font-mono font-semibold" style={{ color }}>{s || "?"}</span>;
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
    render: (r) =>
      r.is_suspicious ? (
        <span
          className="uppercase"
          style={{ color: "var(--accent)", fontSize: 9, letterSpacing: "0.08em" }}
        >
          {String(r.tag ?? "sus")}
        </span>
      ) : (
        ""
      ),
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
      const color = v >= 0.9 ? "var(--accent)" : v >= 0.75 ? "var(--status-warn)" : "var(--text-muted)";
      return <span className="font-mono font-semibold" style={{ color }}>{v.toFixed(3)}</span>;
    },
  },
  {
    key: "constant_size",
    header: "Const size",
    render: (r) =>
      r.constant_size ? (
        <span
          className="uppercase"
          style={{ color: "var(--accent)", fontSize: 9, letterSpacing: "0.08em" }}
        >
          yes
        </span>
      ) : (
        ""
      ),
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

// --- sub-components --------------------------------------------------------

function StatsBar({ analysis }: { analysis: NetworkAnalysis }) {
  const stats = analysis.stats;
  const packets = Number(stats.packet_count ?? 0);
  const bytes = Number(stats.byte_count ?? 0);
  const sessions = analysis.sessions.length;
  const dnsCount = analysis.dns.length;
  const susDns = analysis.suspicious_dns.length;
  const httpReq = analysis.http_requests.length;
  const httpResp = analysis.http_responses.length;
  return (
    <div className="grid grid-cols-2 md:grid-cols-4 gap-2">
      <WindowPanel title="packets" tone="info">
        <div className="flex items-center justify-between">
          <BigStat value={fmtInt(packets)} sub={fmtBytes(bytes)} />
          <MonoBadge tone="info">PCAP</MonoBadge>
        </div>
      </WindowPanel>
      <WindowPanel title="sessions" tone="info">
        <div className="flex items-center justify-between">
          <BigStat value={fmtInt(sessions)} sub="flows" />
          <MonoBadge tone="muted">TCP/UDP</MonoBadge>
        </div>
      </WindowPanel>
      <WindowPanel title="dns" tone="info">
        <div className="flex items-center justify-between">
          <BigStat value={fmtInt(dnsCount)} sub={`${susDns} suspicious`} />
          <MonoBadge tone={susDns > 0 ? "high" : "muted"}>
            {susDns > 0 ? "SUS" : "OK"}
          </MonoBadge>
        </div>
      </WindowPanel>
      <WindowPanel title="http" tone="info">
        <div className="flex items-center justify-between">
          <BigStat value={fmtInt(httpReq + httpResp)} sub={`${httpReq} req / ${httpResp} resp`} />
          <MonoBadge tone="muted">L7</MonoBadge>
        </div>
      </WindowPanel>
    </div>
  );
}

function CommentaryPanel({ items }: { items: NetworkCommentary[] }) {
  if (!items || items.length === 0) {
    return (
      <WindowPanel title="commentary" tone="muted" status="capture ; nothing notable narrated">
        <p
          className="font-mono"
          style={{ fontSize: 11, color: "var(--text-muted)", padding: "18px 4px", textAlign: "center" }}
        >
          No AI commentary was generated for this capture. Either the LLM is
          disabled or the capture had nothing notable to narrate.
        </p>
      </WindowPanel>
    );
  }
  const order = ["overall", "hosts", "dns", "http", "tls", "beacons", "anomalies"];
  const sorted = [...items].sort(
    (a, b) => order.indexOf(a.subject) - order.indexOf(b.subject),
  );
  return (
    <WindowPanel title="commentary" tone="info" status={`${items.length} narratives`}>
      <div className="space-y-2">
        {sorted.map((c, i) => (
          <div
            key={`${c.subject}-${i}`}
            style={{
              padding: "10px 12px",
              border: "1px solid var(--border-faint)",
              background: "var(--surface-sunk)",
              borderRadius: 3,
            }}
          >
            <div className="flex items-center gap-2" style={{ marginBottom: 6 }}>
              <MonoBadge tone={severityToTone(String(c.severity))}>
                {String(c.severity)}
              </MonoBadge>
              <span
                className="font-mono uppercase"
                style={{
                  fontSize: 10,
                  letterSpacing: "0.1em",
                  color: "var(--text-primary)",
                }}
              >
                {c.subject}
              </span>
            </div>
            <p
              className="whitespace-pre-wrap"
              style={{ fontSize: 12, lineHeight: 1.55, color: "var(--text-primary)" }}
            >
              {c.narrative}
            </p>
          </div>
        ))}
      </div>
    </WindowPanel>
  );
}

function severityToTone(s: string): string {
  switch (s) {
    case "high":
      return "high";
    case "medium":
      return "medium";
    case "low":
      return "low";
    default:
      return "info";
  }
}

// Known "identifier"-ish columns get a bit more room; everything else stretches.
const WIDE_KEYS: Record<string, true> = {
  src: true,
  dst: true,
  qname: true,
  host: true,
  uri: true,
  user_agent: true,
  sni: true,
  ja3: true,
  detail: true,
};

function columnWidth(c: ColumnDef): string {
  if (c.width) return c.width;
  if (c.align === "right") return "110px";
  if (WIDE_KEYS[c.key]) return "minmax(140px, 1.6fr)";
  return "minmax(90px, 1fr)";
}

function GridForTab({
  tab,
  analysis,
}: {
  tab: SubTabDef;
  analysis: NetworkAnalysis;
}) {
  const rows = tab.rowsOf(analysis).slice(0, 1000);
  if (rows.length === 0) {
    return (
      <WindowPanel tone="muted" status={`${tab.label.toLowerCase()} ; no rows`}>
        <p
          className="font-mono"
          style={{ fontSize: 11, color: "var(--text-muted)", padding: "18px 4px", textAlign: "center" }}
        >
          {tab.emptyHint}
        </p>
      </WindowPanel>
    );
  }
  const columns: GridColumn[] = tab.columns.map((c) => ({
    label: c.header.toUpperCase(),
    width: columnWidth(c),
    align: c.align,
  }));
  const renderCells = (row: Record<string, unknown>) =>
    tab.columns.map((c) => {
      const raw = row[c.key];
      const rendered: React.ReactNode = c.render
        ? c.render(row)
        : raw === undefined || raw === null
          ? ""
          : String(raw);
      const isEmpty =
        rendered === "" || rendered === undefined || rendered === null;
      if (isEmpty) {
        return <span style={{ color: "var(--text-faint)" }}>--</span>;
      }
      if (c.mono && typeof rendered === "string") {
        return (
          <span className="font-mono truncate" title={rendered}>
            {rendered}
          </span>
        );
      }
      return rendered;
    });
  return (
    <DataGrid
      columns={columns}
      rows={rows}
      renderCells={renderCells}
      getKey={(_r, i) => i}
    />
  );
}

// --- top-level panel -------------------------------------------------------

export function NetworkAnalysisPanel({ projectId }: { projectId: string }) {
  const { data: analysis, isLoading, isError } = useNetworkAnalysis(projectId);
  const [sub, setSub] = useState<SubTab>("commentary");

  if (isLoading) return <LoadingSkeleton size="lg" width="full" />;
  if (isError) {
    return (
      <WindowPanel title="load error" tone="warn" status="network analysis ; unavailable">
        <p className="font-mono" style={{ fontSize: 12, color: "var(--accent)" }}>
          Failed to load network analysis.
        </p>
      </WindowPanel>
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
      <EmptyState
        title="No network analysis"
        description="This project may not contain PCAP evidence."
      />
    );
  }

  const stats = analysis.stats;
  const packets = Number(stats.packet_count ?? 0);
  const sessions = analysis.sessions.length;

  const active = SUB_TABS.find((t) => t.id === sub) ?? SUB_TABS[0];

  return (
    <WindowPanel
      title="network analysis"
      tone="accent"
      status={`${fmtInt(packets)} packets ; ${fmtInt(sessions)} sessions`}
    >
      <div className="space-y-3">
        <Segmented<SubTab>
          options={SUB_TABS.map((t) => ({ value: t.id, label: t.label.toUpperCase() }))}
          value={sub}
          onChange={setSub}
        />
        <StatsBar analysis={analysis} />
        {active.id === "commentary" ? (
          <CommentaryPanel items={analysis.commentary} />
        ) : (
          <GridForTab tab={active} analysis={analysis} />
        )}
      </div>
    </WindowPanel>
  );
}
