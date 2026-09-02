/**
 * Shared kit for the bespoke `admin:cost` page (req 47): cross-segment types,
 * inline styles (CSS-var driven, mirroring the console design system), format
 * helpers, and the reusable chart primitives (SVG spend chart, DOM breakdown
 * bars, stat cards). The three segment components (overview / detail / configs)
 * and the page shell all import their contracts from here so nothing drifts.
 *
 * SVG note: CSS custom properties do NOT resolve inside SVG `fill`/`stroke`,
 * so the spend chart uses the literal `CHART` hex palette. Every other surface
 * is DOM and reads the design tokens directly.
 */
import type { CSSProperties, JSX } from "react";

import { css } from "../../css";

/* -------------------------------- types ---------------------------------- */

export type Segment = "overview" | "detail" | "configs";
export const SEGMENTS: Segment[] = ["overview", "detail", "configs"];

export type DimKind = "model" | "task_type" | "module";

/** A breakdown drill-in: the dimension the operator clicked in the overview.
 *  `taskTypes` carries the concrete task_type set a module/task_type slice maps
 *  to, so the detail segment can filter server-side on exact task_type values. */
export interface Dim {
  kind: DimKind;
  value: string;
  taskTypes: string[];
}

/** The detail segment's applied filters. `taskType` is an exact-value list
 *  (a module drill-in expands to its task_types); the rest are scalars that
 *  map 1:1 to /admin/llm-log query params. */
export interface DetailFilters {
  model: string; // comma-OR text
  taskType: string[]; // exact task_type values
  userId: string;
  status: string; // comma-OR text
  since: string; // yyyy-mm-dd
  until: string; // yyyy-mm-dd
  costMin: string;
  costMax: string;
}

export const EMPTY_DETAIL_FILTERS: DetailFilters = {
  model: "",
  taskType: [],
  userId: "",
  status: "",
  since: "",
  until: "",
  costMin: "",
  costMax: "",
};

export interface CostOverviewProps {
  dim: Dim | null;
  onDim: (d: Dim | null) => void;
}

export interface CostDetailProps {
  filters: DetailFilters;
  onFilters: (f: DetailFilters) => void;
}

/* ------------------------------- helpers --------------------------------- */

export function fmtUsd(n: number): string {
  const a = Math.abs(n);
  const dp = a > 0 && a < 1 ? 4 : 2;
  return "$" + n.toLocaleString(undefined, { minimumFractionDigits: dp, maximumFractionDigits: dp });
}

export function fmtInt(n: number): string {
  return n.toLocaleString();
}

export function fmtPct(n: number): string {
  return `${n.toFixed(1)}%`;
}

/** Derive the module bucket from a task_type via its leading token (the
 *  documented "task_type prefix" heuristic). Split on `.`/`_`/`-`. */
export function moduleOf(taskType: string): string {
  const t = (taskType ?? "").trim();
  if (!t) return "unknown";
  return t.split(/[._-]/)[0] || t;
}

/** Short month label: "2026-04" -> "26-04". */
export function monthShort(ym: string): string {
  return ym.length >= 7 ? ym.slice(2) : ym;
}

export function apiErrMessage(err: unknown): string {
  if (err instanceof Error && err.message) return err.message;
  return "request failed";
}

/* -------------------------------- colors --------------------------------- */

const H_WARN = "#ffb85f";

/** Literal hex for SVG (CSS vars do not resolve in fill/stroke). `accent`
 *  matches the `--accent` token value. */
export const CHART = {
  accent: "#ff5f87",
  grid: "#2a2a2a",
  axis: "#7a7a7a",
} as const;

/* -------------------------------- styles --------------------------------- */

export const panelBox: CSSProperties = css(
  "min-height:0;display:flex;flex-direction:column;border:1px solid var(--border);border-radius:var(--radius-md,3px);background:color-mix(in srgb,var(--surface-card) 84%,transparent);overflow:hidden;box-shadow:var(--bevel-raised,inset 1px 1px 0 rgba(255,255,255,0.03));",
);
export const panelTitle: CSSProperties = css(
  "flex:0 0 auto;display:flex;align-items:center;gap:10px;height:var(--panel-title-h,27px);padding:0 12px;background:var(--surface-chrome);border-bottom:1px solid var(--border);font-family:var(--font-mono);font-size:9.5px;text-transform:uppercase;letter-spacing:0.14em;color:var(--text-muted);",
);
export const dot: CSSProperties = css(
  "width:8px;height:8px;border-radius:1px;background:var(--accent);box-shadow:0 0 6px var(--accent);flex:0 0 auto;",
);
export const scroll: CSSProperties = css("flex:1;min-height:0;overflow:auto;");
export const pad: CSSProperties = css("padding:12px 14px;");
export const stack: CSSProperties = css("display:flex;flex-direction:column;gap:12px;");
export const prose: CSSProperties = css(
  "font-family:var(--font-mono);font-size:11px;line-height:1.6;color:var(--text-muted);",
);
export const emptyNote: CSSProperties = css(
  "flex:1;display:flex;align-items:center;justify-content:center;padding:20px;font-family:var(--font-mono);font-size:11px;color:var(--text-faint);letter-spacing:0.04em;text-align:center;",
);
export const inputStyle: CSSProperties = css(
  "background:var(--surface-sunk);border:1px solid var(--border-soft);border-radius:2px;color:var(--text-primary);font-family:var(--font-mono);font-size:11px;padding:6px 9px;min-width:0;outline:none;width:100%;",
);
export const inputDisabled: CSSProperties = css(
  "background:var(--surface-chrome);border:1px solid var(--border-faint);border-radius:2px;color:var(--text-faint);font-family:var(--font-mono);font-size:11px;padding:6px 9px;min-width:0;outline:none;width:100%;cursor:not-allowed;",
);
export const btnPrimary: CSSProperties = css(
  "padding:6px 14px;border:1px solid var(--accent);border-radius:2px;background:color-mix(in srgb,var(--accent) 10%,transparent);color:var(--accent);font-family:var(--font-mono);font-size:10px;letter-spacing:0.1em;text-transform:uppercase;cursor:pointer;",
);
export const btnPrimaryDisabled: CSSProperties = css(
  "padding:6px 14px;border:1px solid var(--border-faint);border-radius:2px;background:transparent;color:var(--text-faint);font-family:var(--font-mono);font-size:10px;letter-spacing:0.1em;text-transform:uppercase;cursor:not-allowed;",
);
export const btnGhost: CSSProperties = css(
  "padding:5px 11px;border:1px solid var(--border-soft);border-radius:2px;background:transparent;color:var(--text-muted);font-family:var(--font-mono);font-size:10px;letter-spacing:0.1em;text-transform:uppercase;cursor:pointer;",
);
export const chipOk: CSSProperties = css(
  "display:inline-block;padding:1px 7px;border:1px solid color-mix(in srgb,var(--status-ok) 55%,transparent);border-radius:2px;font-family:var(--font-mono);font-size:9px;line-height:1.6;letter-spacing:0.1em;text-transform:uppercase;color:var(--status-ok);background:color-mix(in srgb,var(--status-ok) 10%,transparent);",
);
export const chipFaint: CSSProperties = css(
  "display:inline-block;padding:1px 7px;border:1px solid var(--border-faint);border-radius:2px;font-family:var(--font-mono);font-size:9px;line-height:1.6;letter-spacing:0.1em;text-transform:uppercase;color:var(--text-faint);background:transparent;",
);
export const chipWarn: CSSProperties = css(
  `display:inline-block;padding:1px 7px;border:1px solid color-mix(in srgb,${H_WARN} 55%,transparent);border-radius:2px;font-family:var(--font-mono);font-size:9px;line-height:1.6;letter-spacing:0.1em;text-transform:uppercase;color:${H_WARN};background:color-mix(in srgb,${H_WARN} 12%,transparent);`,
);
export const label: CSSProperties = css(
  "display:flex;flex-direction:column;gap:4px;font-family:var(--font-mono);font-size:9.5px;letter-spacing:0.08em;text-transform:uppercase;color:var(--text-muted);",
);
export const warnText: CSSProperties = css(
  `font-family:var(--font-mono);font-size:10.5px;color:${H_WARN};line-height:1.5;`,
);
export const okText: CSSProperties = css(
  "font-family:var(--font-mono);font-size:10.5px;color:var(--status-ok);",
);

/** Segment strip button (shell). */
export function segButton(active: boolean): CSSProperties {
  return css(
    active
      ? "padding:5px 14px;border:1px solid var(--accent);border-radius:2px;background:color-mix(in srgb,var(--accent) 14%,transparent);color:var(--accent);font-family:var(--font-mono);font-size:10px;letter-spacing:0.12em;text-transform:uppercase;cursor:pointer;"
      : "padding:5px 14px;border:1px solid var(--border-soft);border-radius:2px;background:transparent;color:var(--text-muted);font-family:var(--font-mono);font-size:10px;letter-spacing:0.12em;text-transform:uppercase;cursor:pointer;",
  );
}

/* --------------------------------- table --------------------------------- */

export const th: CSSProperties = css(
  "text-align:left;padding:6px 9px;font-family:var(--font-mono);font-size:9px;letter-spacing:0.1em;text-transform:uppercase;color:var(--text-faint);border-bottom:1px solid var(--border);position:sticky;top:0;background:var(--surface-chrome);white-space:nowrap;",
);
export const td: CSSProperties = css(
  "padding:6px 9px;font-family:var(--font-mono);font-size:11px;color:var(--text-primary);border-bottom:1px solid var(--border-faint);white-space:nowrap;",
);

/* ------------------------------- stat card ------------------------------- */

const statCard: CSSProperties = css(
  "flex:1;min-width:120px;display:flex;flex-direction:column;gap:5px;padding:11px 13px;border:1px solid var(--border);border-radius:var(--radius-md,3px);background:color-mix(in srgb,var(--surface-card) 84%,transparent);",
);
const statLabel: CSSProperties = css(
  "font-family:var(--font-mono);font-size:9px;letter-spacing:0.12em;text-transform:uppercase;color:var(--text-faint);",
);
const statValue: CSSProperties = css(
  "font-family:var(--font-display,var(--font-mono));font-size:22px;line-height:1.1;letter-spacing:0.01em;",
);
const statSub: CSSProperties = css(
  "font-family:var(--font-mono);font-size:9.5px;color:var(--text-muted);letter-spacing:0.03em;",
);

export function StatCard(props: {
  label: string;
  value: string;
  sub?: string;
  tone?: "accent" | "ok" | "warn" | "muted";
}): JSX.Element {
  const color =
    props.tone === "ok"
      ? "var(--status-ok)"
      : props.tone === "warn"
        ? H_WARN
        : props.tone === "accent"
          ? "var(--accent)"
          : "var(--text-primary)";
  return (
    <div style={statCard}>
      <div style={statLabel}>{props.label}</div>
      <div style={{ ...statValue, color }}>{props.value}</div>
      {props.sub ? <div style={statSub}>{props.sub}</div> : null}
    </div>
  );
}

/* ------------------------------ spend chart ------------------------------ */

/** Inline-SVG spend-over-time bar chart. Uniform scale (preserveAspectRatio
 *  meet) so bars + labels never distort. Empty -> honest note. */
export function SpendChart(props: {
  points: { label: string; value: number }[];
  height?: number;
}): JSX.Element {
  const points = props.points;
  const H = props.height ?? 160;
  const W = 560;
  if (points.length === 0) {
    return <div style={{ ...emptyNote, minHeight: H }}>no spend recorded in this window</div>;
  }
  const padL = 6;
  const padR = 6;
  const padB = 20;
  const padT = 10;
  const max = Math.max(1e-9, ...points.map((p) => p.value));
  const n = points.length;
  const bandW = (W - padL - padR) / n;
  const barW = Math.max(2, Math.min(bandW * 0.62, 46));
  return (
    <svg
      viewBox={`0 0 ${W} ${H}`}
      style={{ width: "100%", height: "auto", display: "block" }}
      preserveAspectRatio="xMidYMid meet"
      role="img"
      aria-label="spend over time"
    >
      <line x1={padL} y1={H - padB} x2={W - padR} y2={H - padB} stroke={CHART.grid} strokeWidth={1} />
      {points.map((p, i) => {
        const h = (p.value / max) * (H - padB - padT);
        const x = padL + i * bandW + (bandW - barW) / 2;
        const y = H - padB - h;
        return (
          <g key={`${p.label}-${i}`}>
            <rect x={x} y={y} width={barW} height={Math.max(0, h)} fill={CHART.accent} rx={1}>
              <title>{`${p.label}: ${fmtUsd(p.value)}`}</title>
            </rect>
            <text
              x={padL + i * bandW + bandW / 2}
              y={H - padB + 12}
              fill={CHART.axis}
              fontSize={8}
              fontFamily="monospace"
              textAnchor="middle"
            >
              {p.label}
            </text>
          </g>
        );
      })}
    </svg>
  );
}

/* ---------------------------- breakdown bars ----------------------------- */

export interface BreakdownItem {
  key: string;
  label: string;
  value: number;
  count?: number;
}

const barRowBase =
  "display:grid;grid-template-columns:minmax(90px,150px) 1fr minmax(90px,auto);gap:9px;align-items:center;width:100%;text-align:left;padding:5px 6px;border:1px solid transparent;border-radius:2px;background:transparent;";
const barLabel: CSSProperties = css(
  "font-family:var(--font-mono);font-size:10.5px;color:var(--text-primary);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;",
);
const barTrack: CSSProperties = css(
  "height:9px;border-radius:2px;background:var(--surface-sunk);overflow:hidden;",
);
const barFill: CSSProperties = css(
  "display:block;height:100%;background:color-mix(in srgb,var(--accent) 70%,transparent);",
);
const barVal: CSSProperties = css(
  "font-family:var(--font-mono);font-size:9.5px;color:var(--text-muted);text-align:right;white-space:nowrap;",
);
const footNoteStyle: CSSProperties = css(
  "padding-top:8px;font-family:var(--font-mono);font-size:9px;color:var(--text-faint);letter-spacing:0.03em;",
);

function barRow(active: boolean, clickable: boolean): CSSProperties {
  const base = css(barRowBase);
  return {
    ...base,
    cursor: clickable ? "pointer" : "default",
    borderColor: active ? "var(--accent)" : "transparent",
    background: active ? "color-mix(in srgb,var(--accent) 8%,transparent)" : "transparent",
  };
}

/** DOM horizontal-bar breakdown panel. Each row is a drill-in button when
 *  `onPick` is set; `activeKey` marks the selected dimension. */
export function BreakdownBars(props: {
  title: string;
  items: BreakdownItem[];
  activeKey?: string | null;
  onPick?: (key: string) => void;
  empty?: string;
  foot?: string;
}): JSX.Element {
  const items = props.items;
  const max = Math.max(1e-9, ...items.map((i) => i.value));
  return (
    <div style={panelBox}>
      <div style={panelTitle}>
        <span style={dot} />
        <span style={css("color:var(--text-primary);")}>{props.title}</span>
      </div>
      {items.length === 0 ? (
        <div style={emptyNote}>{props.empty ?? "no data in this window"}</div>
      ) : (
        <div style={pad}>
          {items.map((it) => {
            const pct = (it.value / max) * 100;
            const active = props.activeKey === it.key;
            return (
              <button
                key={it.key}
                type="button"
                disabled={!props.onPick}
                onClick={() => props.onPick?.(it.key)}
                aria-pressed={active}
                style={barRow(active, !!props.onPick)}
              >
                <span style={barLabel} title={it.label}>
                  {it.label}
                </span>
                <span style={barTrack}>
                  <span style={{ ...barFill, width: `${pct}%` }} />
                </span>
                <span style={barVal}>
                  {fmtUsd(it.value)}
                  {it.count != null ? ` \u00b7 ${fmtInt(it.count)}` : ""}
                </span>
              </button>
            );
          })}
          {props.foot ? <div style={footNoteStyle}>{props.foot}</div> : null}
        </div>
      )}
    </div>
  );
}
