import type { ReactNode } from "react";

import { css } from "../css";

/**
 * Shared status / severity badge rendering for DataPage columns and bespoke
 * pages. One color + label map so the whole console reads state the same way:
 * green for healthy, amber for attention, red for bad, muted for neutral.
 * Never derive "high"/"medium" severity from unrelated fields (see XRay's
 * fabricated-severity fix); these maps only label what the row actually says.
 */

type Tone = "ok" | "warn" | "err" | "muted" | "info";

const TONE_COLOR: Record<Tone, string> = {
  ok: "var(--status-ok)",
  warn: "var(--status-warn, #e6b84c)",
  err: "var(--status-err, #d64545)",
  muted: "var(--text-faint)",
  info: "var(--accent)",
};

const STATUS_TONE: Record<string, Tone> = {
  // running / active states
  running: "ok",
  active: "ok",
  created: "info",
  queued: "info",
  waiting: "info",
  paused: "warn",
  stalled: "warn",
  // terminal states
  completed: "ok",
  done: "ok",
  success: "ok",
  succeeded: "ok",
  failed: "err",
  error: "err",
  crashed: "err",
  canceled: "muted",
  cancelled: "muted",
  revoked: "muted",
  archived: "muted",
  disabled: "muted",
  inactive: "muted",
  abandoned: "muted",
  rejected: "err",
  // default
  pending: "warn",
};

const SEVERITY_TONE: Record<string, Tone> = {
  critical: "err",
  high: "err",
  medium: "warn",
  moderate: "warn",
  low: "info",
  none: "muted",
  unknown: "muted",
};

function toneFor(map: Record<string, Tone>, raw: unknown): Tone {
  const key = String(raw ?? "").trim().toLowerCase();
  return map[key] ?? "muted";
}

export function StatusBadge({ value, tone }: { value: unknown; tone?: Tone }): ReactNode {
  const t = tone ?? toneFor(STATUS_TONE, value);
  const label = String(value ?? "");
  const color = TONE_COLOR[t];
  return (
    <span
      style={css(`display:inline-flex;align-items:center;gap:5px;padding:1px 6px;border:1px solid ${color}55;border-radius:2px;font-size:9px;letter-spacing:0.08em;text-transform:uppercase;color:${color};background:color-mix(in srgb,${color} 8%,transparent);white-space:nowrap;`)}
    >
      <span style={css(`width:5px;height:5px;border-radius:1px;background:${color};flex:0 0 auto;`)} />
      {label}
    </span>
  );
}

export function SeverityBadge({ value }: { value: unknown }): ReactNode {
  return <StatusBadge value={value} tone={toneFor(SEVERITY_TONE, value)} />;
}

/** Semantic cell renderers for PageColumn. Register a column `kind` to get the
 * shared treatment (status/severity/timestamp/cost) instead of raw text. */
export type ColumnKind = "status" | "severity" | "time" | "cost";

export function semanticCell(kind: ColumnKind, value: unknown): ReactNode {
  if (value === null || value === undefined) return "\u2014";
  switch (kind) {
    case "status":
      return <StatusBadge value={value} />;
    case "severity":
      return <SeverityBadge value={value} />;
    case "time": {
      if (typeof value === "number") {
        const d = new Date(value * 1000);
        return Number.isNaN(d.getTime()) ? String(value) : d.toISOString().slice(0, 19).replace("T", " ");
      }
      if (typeof value === "string") {
        const d = new Date(value);
        return Number.isNaN(d.getTime()) ? value : d.toISOString().slice(0, 19).replace("T", " ");
      }
      return String(value);
    }
    case "cost": {
      const n = typeof value === "number" ? value : Number(value);
      if (Number.isNaN(n)) return String(value);
      return `$${n.toFixed(4)}`;
    }
    default:
      return String(value);
  }
}
