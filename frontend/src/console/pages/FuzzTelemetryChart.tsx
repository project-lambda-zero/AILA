/**
 * Time-series chart for one fuzz campaign's telemetry
 * (GET /vr/fuzz/campaigns/{id}/telemetry). One metric at a time, picked from
 * a segmented control; inline SVG polyline with HTML axis labels so text never
 * scales with the stretched viewBox. SVG stroke/fill do not resolve CSS
 * var(), so the line color is read from the computed theme custom property.
 */

import { useState } from "react";
import type { CSSProperties, JSX } from "react";

import { useFuzzTelemetry, type FuzzTelemetryPoint } from "../../api/fuzz";
import { css } from "../css";

type MetricKey = "execs_per_sec" | "coverage_pct" | "corpus_size" | "crashes_found" | "total_execs";

interface MetricSpec {
  label: string;
  /** Theme custom property the line is drawn in. */
  colorVar: string;
  format: (v: number) => string;
}

const compact = new Intl.NumberFormat(undefined, { notation: "compact", maximumFractionDigits: 1 });

const METRICS = {
  execs_per_sec: { label: "exec/s", colorVar: "--status-info", format: (v) => compact.format(v) },
  coverage_pct: { label: "coverage %", colorVar: "--status-ok", format: (v) => `${v.toFixed(2)}%` },
  corpus_size: { label: "corpus", colorVar: "--status-signal", format: (v) => compact.format(v) },
  crashes_found: { label: "crashes", colorVar: "--accent", format: (v) => compact.format(v) },
  total_execs: { label: "total execs", colorVar: "--status-warn", format: (v) => compact.format(v) },
} satisfies Record<MetricKey, MetricSpec>;

const METRIC_KEYS: MetricKey[] = ["execs_per_sec", "coverage_pct", "corpus_size", "crashes_found", "total_execs"];

const VIEW_W = 600;
const VIEW_H = 160;

const LABEL_CSS: CSSProperties = css("font-family:var(--font-mono);font-size:11px;color:var(--text-faint);");

const SEG_BTN_CSS = (active: boolean): CSSProperties =>
  css(
    `min-height:28px;padding:0 10px;border:1px solid ${active ? "var(--accent)" : "var(--border-faint)"};background:${active ? "var(--surface-2)" : "var(--surface-0)"};color:${active ? "var(--text-primary)" : "var(--text-muted)"};font-family:var(--font-mono);font-size:11px;cursor:pointer;border-radius:2px;`,
  );

/** Resolve a theme custom property to a concrete color string for SVG. */
function themeColor(name: string): string {
  const v = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  return v || "currentColor";
}

function series(points: FuzzTelemetryPoint[], key: MetricKey): { t: number; v: number }[] {
  const out: { t: number; v: number }[] = [];
  for (const p of points) {
    const v = p[key];
    const t = Date.parse(p.measured_at);
    if (v !== null && Number.isFinite(t)) out.push({ t, v });
  }
  return out;
}

const TIME_FMT = new Intl.DateTimeFormat(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });

export interface FuzzTelemetryChartProps {
  campaignId: string;
  /** Poll for new samples (the campaign is running). */
  live: boolean;
}

export default function FuzzTelemetryChart({ campaignId, live }: FuzzTelemetryChartProps): JSX.Element {
  const [metric, setMetric] = useState<MetricKey>("execs_per_sec");
  const q = useFuzzTelemetry(campaignId, live);

  if (q.isLoading) return <div style={LABEL_CSS}>loading telemetry&#8230;</div>;
  if (q.isError) {
    return (
      <div style={css("font-family:var(--font-mono);font-size:11px;color:var(--status-warn);")}>
        could not load telemetry &mdash; {q.error.message}
      </div>
    );
  }
  const points = q.data ?? [];
  if (points.length === 0) {
    return <div style={LABEL_CSS}>no telemetry samples recorded for this campaign yet.</div>;
  }

  const spec: MetricSpec = METRICS[metric];
  const data = series(points, metric);
  const latest = data.length > 0 ? data[data.length - 1] : null;

  let plot: JSX.Element;
  if (data.length === 0) {
    plot = <div style={LABEL_CSS}>no {spec.label} values in the recorded samples.</div>;
  } else {
    const t0 = data[0].t;
    const t1 = data[data.length - 1].t;
    let vMin = Math.min(...data.map((d) => d.v));
    let vMax = Math.max(...data.map((d) => d.v));
    if (vMin === vMax) {
      vMin -= 1;
      vMax += 1;
    }
    const x = (t: number): number => (t1 === t0 ? VIEW_W / 2 : ((t - t0) / (t1 - t0)) * VIEW_W);
    const y = (v: number): number => VIEW_H - ((v - vMin) / (vMax - vMin)) * VIEW_H;
    const pts = data.map((d) => `${x(d.t).toFixed(1)},${y(d.v).toFixed(1)}`).join(" ");
    const stroke = themeColor(spec.colorVar);
    const grid = themeColor("--border-faint");
    plot = (
      <div style={css("display:grid;grid-template-columns:auto 1fr;gap:4px 8px;min-width:0;")}>
        <div style={css("display:flex;flex-direction:column;justify-content:space-between;text-align:right;font-family:var(--font-mono);font-size:11px;color:var(--text-faint);")}>
          <span>{spec.format(vMax)}</span>
          <span>{spec.format(vMin)}</span>
        </div>
        <svg
          viewBox={`0 0 ${VIEW_W} ${VIEW_H}`}
          preserveAspectRatio="none"
          role="img"
          aria-label={`${spec.label} over time`}
          style={{ width: "100%", height: 160, display: "block" }}
        >
          {[0, 0.5, 1].map((f) => (
            <line
              key={f}
              x1={0}
              x2={VIEW_W}
              y1={f * VIEW_H}
              y2={f * VIEW_H}
              stroke={grid}
              strokeWidth={1}
              vectorEffect="non-scaling-stroke"
            />
          ))}
          {data.length === 1 ? (
            <circle cx={x(data[0].t)} cy={y(data[0].v)} r={3} fill={stroke} />
          ) : (
            <polyline
              points={pts}
              fill="none"
              stroke={stroke}
              strokeWidth={2}
              vectorEffect="non-scaling-stroke"
              strokeLinejoin="round"
            />
          )}
        </svg>
        <span />
        <div style={css("display:flex;justify-content:space-between;font-family:var(--font-mono);font-size:11px;color:var(--text-faint);")}>
          <span>{TIME_FMT.format(t0)}</span>
          <span>{TIME_FMT.format(t1)}</span>
        </div>
      </div>
    );
  }

  return (
    <div style={css("display:flex;flex-direction:column;gap:8px;min-width:0;")}>
      <div style={css("display:flex;flex-wrap:wrap;align-items:center;gap:6px;")}>
        {METRIC_KEYS.map((k) => (
          <button
            key={k}
            type="button"
            aria-pressed={metric === k}
            onClick={() => setMetric(k)}
            style={SEG_BTN_CSS(metric === k)}
          >
            {METRICS[k].label}
          </button>
        ))}
        <span style={css("flex:1;")} />
        <span style={LABEL_CSS}>
          {points.length} samples
          {latest ? ` · latest ${spec.format(latest.v)}` : ""}
          {live ? ` · live` : ""}
          {q.isFetching ? ` · refreshing` : ""}
        </span>
      </div>
      {plot}
    </div>
  );
}
