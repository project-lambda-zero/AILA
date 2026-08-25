/**
 * AdminDashboardPage -- bespoke platform dashboard (req 42).
 *
 * Renders the real values `GET /dashboard` already computes
 * (`api/routers/dashboard.py`): total systems + finding severity distribution
 * + a weighted risk score with the arithmetic shown, the per-module dashboard
 * contributions the platform collects via `dashboard_providers()`, and the
 * 30-day workflow-closure count. One operator+ read call, no mutation.
 *
 * Honesty: the backend sets `online_systems == total_systems` (no live ping),
 * so there is deliberately no "online" card here -- surfacing one would imply a
 * probe that does not run. Every number rendered is a field the backend
 * returned; nothing is derived or trended.
 */

import { useQuery } from "@tanstack/react-query";
import type { CSSProperties, JSX } from "react";

import { ApiError, apiFetchEnvelope } from "../../api/client";
import type { ModulePageProps } from "../contract";
import { css } from "../css";
import { ConsoleWindow } from "../window";
import StructuredValue from "./StructuredValue";

/* ------------------------------- types ----------------------------------- */

interface FleetStats {
  total_systems: number;
  online_systems: number;
  total_findings: number;
  critical_findings: number;
  high_findings: number;
  medium_findings: number;
  low_findings: number;
}

interface DashboardData {
  risk_score: number;
  fleet_stats: FleetStats;
  module_data: Record<string, unknown>;
  generated_at: string;
}

interface DashboardEnvelope {
  data: DashboardData;
  meta?: { closed_last_30d?: number };
}

/* ------------------------- severity color language ----------------------- */

// A four-hue ramp drawn from the existing globals.css semantic tokens (the
// same palette badges.tsx `severity` reads: status-err / status-warn /
// status-signal / status-info). The bar segments and the legend swatches both
// read this one map, so they agree by construction.
const SEV: { key: keyof FleetStats; label: string; color: string }[] = [
  { key: "critical_findings", label: "critical", color: "var(--status-err, #d64545)" },
  { key: "high_findings", label: "high", color: "var(--status-warn)" },
  { key: "medium_findings", label: "medium", color: "var(--status-signal)" },
  { key: "low_findings", label: "low", color: "var(--status-info)" },
];

/* ------------------------------- styles ---------------------------------- */

const scroll: CSSProperties = css("flex:1;min-height:0;overflow:auto;");
const body: CSSProperties = css("display:flex;flex-direction:column;gap:16px;padding:14px 16px;");
const sectionTitle: CSSProperties = css(
  "font-family:var(--font-mono);font-size:9px;letter-spacing:0.16em;text-transform:uppercase;color:var(--text-faint);",
);
const cardGrid: CSSProperties = css(
  "display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:10px;",
);
const card: CSSProperties = css(
  "display:flex;flex-direction:column;gap:5px;padding:12px 14px;border:1px solid var(--border-soft);border-radius:3px;background:color-mix(in srgb,var(--surface-card) 84%,transparent);min-width:0;",
);
const cardLabel: CSSProperties = css(
  "font-family:var(--font-mono);font-size:8.5px;letter-spacing:0.14em;text-transform:uppercase;color:var(--text-faint);",
);
const bigNumber: CSSProperties = css(
  "font-family:var(--font-display);font-size:30px;line-height:1;color:var(--text-primary);font-variant-numeric:tabular-nums;",
);
const caption: CSSProperties = css(
  "font-family:var(--font-mono);font-size:9px;line-height:1.5;color:var(--text-faint);",
);
const panel: CSSProperties = css(
  "display:flex;flex-direction:column;gap:10px;padding:12px 14px;border:1px solid var(--border-soft);border-radius:3px;background:color-mix(in srgb,var(--surface-card) 84%,transparent);",
);
const barTrack: CSSProperties = css(
  "display:flex;width:100%;height:18px;border:1px solid var(--border-soft);border-radius:2px;overflow:hidden;background:var(--surface-sunk);",
);
const legendRow: CSSProperties = css("display:flex;flex-wrap:wrap;gap:14px;");
const legendItem: CSSProperties = css(
  "display:inline-flex;align-items:center;gap:6px;font-family:var(--font-mono);font-size:10px;color:var(--text-muted);",
);
const swatch: CSSProperties = css("width:9px;height:9px;border-radius:1px;flex:0 0 auto;");
const legendCount: CSSProperties = css("color:var(--text-primary);font-variant-numeric:tabular-nums;");
const moduleGrid: CSSProperties = css(
  "display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:10px;",
);
const moduleGroupTitle: CSSProperties = css(
  "font-family:var(--font-mono);font-size:10px;letter-spacing:0.1em;text-transform:uppercase;color:var(--text-muted);",
);
const providerCardTitle: CSSProperties = css(
  "font-family:var(--font-mono);font-size:9px;letter-spacing:0.06em;color:var(--text-faint);margin-bottom:6px;word-break:break-word;",
);
const emptyNote: CSSProperties = css(
  "font-family:var(--font-mono);font-size:10.5px;color:var(--text-faint);letter-spacing:0.03em;",
);
const footerLine: CSSProperties = css(
  "font-family:var(--font-mono);font-size:9px;line-height:1.6;color:var(--text-faint);letter-spacing:0.03em;border-top:1px solid var(--border-faint);padding-top:10px;",
);
const refreshBtn: CSSProperties = css(
  "padding:4px 11px;border:1px solid var(--border-soft);border-radius:2px;background:transparent;color:var(--text-muted);font-family:var(--font-mono);font-size:9px;letter-spacing:0.1em;text-transform:uppercase;cursor:pointer;",
);
const stateNote: CSSProperties = css(
  "flex:1;display:flex;align-items:center;justify-content:center;padding:24px;font-family:var(--font-mono);font-size:11px;color:var(--text-faint);letter-spacing:0.04em;text-align:center;",
);

/* ------------------------------ helpers ---------------------------------- */

function apiErrMessage(err: unknown): string {
  if (err instanceof ApiError) {
    // The backend HTTPException detail arrives as a `{"detail": "..."}` body;
    // surface the detail verbatim (spec: 403 shows the backend detail).
    try {
      const parsed: unknown = JSON.parse(err.message);
      if (parsed && typeof parsed === "object" && "detail" in parsed) {
        const detail = parsed.detail;
        if (typeof detail === "string" && detail.trim() !== "") return detail;
      }
    } catch {
      /* body was not JSON -- fall through to the raw message */
    }
    return err.message || `HTTP ${err.status}`;
  }
  if (err instanceof Error) return err.message;
  return String(err);
}

function fmtInt(n: number): string {
  return Number.isFinite(n) ? Math.trunc(n).toLocaleString() : "\u2014";
}

// Band the 0-10 risk score into the same semantic hues the severity ramp uses.
// This colors the computed score; it does not alter or invent it.
function riskColor(score: number): string {
  if (score >= 7) return "var(--status-err, #d64545)";
  if (score >= 4) return "var(--status-warn)";
  return "var(--status-ok)";
}

/* ---------------------------- sub-renderers ------------------------------ */

function SeverityDistribution({ stats }: { stats: FleetStats }): JSX.Element {
  const segTotal = SEV.reduce((sum, s) => sum + Math.max(0, Number(stats[s.key]) || 0), 0);
  return (
    <div style={panel}>
      <span style={sectionTitle}>severity distribution</span>
      {segTotal === 0 ? (
        <div style={emptyNote}>no findings recorded across registered modules.</div>
      ) : (
        <>
          <div style={barTrack} role="img" aria-label={`Findings by severity: ${SEV.map((s) => `${s.label} ${Number(stats[s.key]) || 0}`).join(", ")}`}>
            {SEV.map((s) => {
              const count = Math.max(0, Number(stats[s.key]) || 0);
              if (count === 0) return null;
              return (
                <div
                  key={s.key}
                  title={`${s.label}: ${count}`}
                  style={{ width: `${(count / segTotal) * 100}%`, background: s.color, height: "100%" }}
                />
              );
            })}
          </div>
          <div style={legendRow}>
            {SEV.map((s) => (
              <span key={s.key} style={legendItem}>
                <span style={{ ...swatch, background: s.color }} />
                {s.label} <span style={legendCount}>{fmtInt(Number(stats[s.key]) || 0)}</span>
              </span>
            ))}
          </div>
        </>
      )}
    </div>
  );
}

function ModuleContributions({ moduleData }: { moduleData: Record<string, unknown> }): JSX.Element {
  const entries = Object.entries(moduleData);
  if (entries.length === 0) {
    return (
      <div style={panel}>
        <span style={sectionTitle}>module contributions</span>
        <div style={emptyNote}>no module dashboard providers reported this run.</div>
      </div>
    );
  }
  // Group `{module_id}.{provider}` keys under their module_id.
  const groups = new Map<string, { provider: string; value: unknown }[]>();
  for (const [key, value] of entries) {
    const dot = key.indexOf(".");
    const moduleId = dot >= 0 ? key.slice(0, dot) : key;
    const provider = dot >= 0 ? key.slice(dot + 1) : key;
    const list = groups.get(moduleId) ?? [];
    list.push({ provider, value });
    groups.set(moduleId, list);
  }
  return (
    <div style={css("display:flex;flex-direction:column;gap:14px;")}>
      <span style={sectionTitle}>module contributions</span>
      {[...groups.entries()].map(([moduleId, providers]) => (
        <div key={moduleId} style={css("display:flex;flex-direction:column;gap:8px;")}>
          <span style={moduleGroupTitle}>{moduleId}</span>
          <div style={moduleGrid}>
            {providers.map(({ provider, value }) => (
              <div key={provider} style={card}>
                <div style={providerCardTitle}>{provider}</div>
                <StructuredValue value={value} />
              </div>
            ))}
          </div>
        </div>
      ))}
    </div>
  );
}

/* --------------------------------- page ---------------------------------- */

export default function AdminDashboardPage(props: ModulePageProps): JSX.Element {
  const { windowId, title, isFocused, onFocus, onBack, onMinimize, isFullscreen, onToggleFullscreen } = props;
  const q = useQuery({
    queryKey: ["admin", "dashboard"],
    queryFn: () => apiFetchEnvelope<DashboardEnvelope>("/dashboard"),
    retry: false,
  });

  const statusStrip = (
    <>
      <span
        style={{
          display: "flex",
          alignItems: "center",
          padding: "0 11px",
          background: "var(--status-ok)",
          color: "var(--text-on-accent)",
          fontWeight: 700,
          letterSpacing: "0.14em",
        }}
      >
        admin &middot; platform
      </span>
      <span
        style={{
          display: "flex",
          alignItems: "center",
          padding: "0 11px",
          textTransform: "none",
          letterSpacing: "0.03em",
          color: "var(--text-muted)",
        }}
      >
        GET /dashboard
      </span>
      <span style={{ flex: 1 }} />
    </>
  );

  let content: JSX.Element;
  if (q.isLoading && q.data === undefined) {
    content = <div style={stateNote}>loading /dashboard&#8230;</div>;
  } else if (q.isError) {
    content = (
      <div style={{ ...stateNote, color: "var(--status-warn)" }}>
        could not load the dashboard &mdash; {apiErrMessage(q.error)}
      </div>
    );
  } else if (!q.data) {
    content = <div style={stateNote}>no dashboard data returned.</div>;
  } else {
    const data = q.data.data;
    const stats = data.fleet_stats;
    const closed = q.data.meta?.closed_last_30d ?? 0;
    const c = stats.critical_findings;
    const h = stats.high_findings;
    const m = stats.medium_findings;
    const l = stats.low_findings;
    const riskArith =
      stats.total_findings > 0
        ? `(${c}\u00d710 + ${h}\u00d77 + ${m}\u00d74 + ${l}\u00d71) / ${stats.total_findings}`
        : "no findings \u2014 score is 0";
    const gen = new Date(data.generated_at);
    const generatedLabel = Number.isNaN(gen.getTime()) ? data.generated_at : gen.toLocaleString();
    content = (
      <div style={scroll}>
        <div style={body}>
          <div style={cardGrid}>
            <div style={card}>
              <span style={cardLabel}>systems</span>
              <span style={bigNumber}>{fmtInt(stats.total_systems)}</span>
              <span style={caption}>registered managed systems</span>
            </div>
            <div style={card}>
              <span style={cardLabel}>findings</span>
              <span style={bigNumber}>{fmtInt(stats.total_findings)}</span>
              <span style={caption}>across registered modules</span>
            </div>
            <div style={card} title={riskArith}>
              <span style={cardLabel}>risk score</span>
              <span style={{ ...bigNumber, color: riskColor(data.risk_score) }}>{data.risk_score}</span>
              <span style={caption}>weighted from severity distribution</span>
              <span style={css("font-family:var(--font-mono);font-size:8.5px;color:var(--text-faint);word-break:break-word;")}>
                {riskArith}
              </span>
            </div>
            <div style={card}>
              <span style={cardLabel}>closed (30d)</span>
              <span style={bigNumber}>{fmtInt(closed)}</span>
              <span style={caption}>closed via workflow (last 30 days)</span>
            </div>
          </div>

          <SeverityDistribution stats={stats} />

          <ModuleContributions moduleData={data.module_data} />

          <div style={footerLine}>
            generated {generatedLabel} &middot; closed_last_30d: {fmtInt(closed)} (closed via workflow, last 30
            days)
          </div>
        </div>
      </div>
    );
  }

  return (
    <ConsoleWindow
      id={windowId}
      kind="page"
      title={title}
      isFullscreen={isFullscreen}
      isFocused={isFocused}
      onFocus={onFocus}
      onClose={onBack}
      onMinimize={onMinimize}
      onToggleFullscreen={onToggleFullscreen}
      footerExtras={statusStrip}
    >
      <header
        style={{
          flex: "0 0 auto",
          display: "flex",
          alignItems: "center",
          gap: 10,
          padding: "8px 14px",
          background: "var(--surface-chrome)",
          borderBottom: "1px solid var(--border)",
          fontSize: 10.5,
          letterSpacing: "0.12em",
          textTransform: "uppercase",
          color: "var(--text-muted)",
        }}
      >
        <span
          style={{
            width: 9,
            height: 9,
            borderRadius: 1,
            background: "var(--accent)",
            boxShadow: "0 0 7px var(--accent)",
          }}
        />
        <span style={{ fontFamily: "var(--font-display)", color: "var(--text-primary)", fontWeight: 400, letterSpacing: "0.16em" }}>
          admin &middot; dashboard
        </span>
        <span style={{ color: "var(--text-faint)", textTransform: "none", letterSpacing: "0.04em" }}>
          fleet posture &mdash; systems, findings, risk, module contributions
        </span>
        <span style={{ flex: 1 }} />
        <button type="button" onClick={() => void q.refetch()} disabled={q.isFetching} style={refreshBtn}>
          {q.isFetching ? "refreshing\u2026" : "refresh"}
        </button>
      </header>

      <main style={{ flex: 1, minHeight: 0, display: "flex", flexDirection: "column" }}>{content}</main>
    </ConsoleWindow>
  );
}
