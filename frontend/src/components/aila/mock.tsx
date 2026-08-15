/**
 * AILA mock design-system kit.
 *
 * Dense monospace terminal primitives taken verbatim from the design mockups
 * (Console / VR X-Ray / Vulnerability .dc.html). Every rebuilt page composes
 * THESE plus WindowPanel / PixelIcon -- never shadcn cards/tables. All sizing
 * is inline (Tailwind v4 does not generate arbitrary px utilities); colours use
 * the mock semantic tokens declared in globals.css (--accent, --surface-card,
 * --border-soft, --text-primary, ...).
 */
import * as React from "react";

// Severity / state / signal tone -> mock colour. Accepts a tone key or a raw
// CSS colour string (passed through).
const TONE: Record<string, string> = {
  critical: "var(--accent)",
  high: "var(--status-warn)",
  medium: "var(--status-info)",
  low: "var(--status-ok)",
  accent: "var(--accent)",
  ok: "var(--status-ok)",
  info: "var(--status-info)",
  warn: "var(--status-warn)",
  signal: "var(--status-signal)",
  muted: "var(--text-faint)",
};

export function toneColor(tone: string): string {
  return TONE[tone] ?? tone;
}

// ---------------------------------------------------------------------------
// SectionHeader -- icon badge + Apoc display title + optional right actions.
// ---------------------------------------------------------------------------
export function SectionHeader({
  icon = "\u25ce",
  title,
  actions,
  size = 23,
}: {
  icon?: React.ReactNode;
  title: React.ReactNode;
  actions?: React.ReactNode;
  size?: number;
}) {
  return (
    <div className="flex items-center" style={{ gap: 11 }}>
      <span
        className="flex items-center justify-center"
        aria-hidden="true"
        style={{
          width: 30,
          height: 30,
          flex: "0 0 auto",
          border: "1px solid var(--accent)",
          background: "color-mix(in srgb, var(--accent) 12%, transparent)",
          borderRadius: 4,
          color: "var(--accent)",
          fontSize: 15,
        }}
      >
        {icon}
      </span>
      <span
        style={{
          fontFamily: "var(--font-display)",
          fontWeight: 300,
          fontSize: size,
          letterSpacing: "-0.01em",
          color: "var(--text-primary)",
        }}
      >
        {title}
      </span>
      {actions ? (
        <>
          <span style={{ flex: 1 }} />
          {actions}
        </>
      ) : null}
    </div>
  );
}

// ---------------------------------------------------------------------------
// MonoBadge -- sev / state / kev chip. Alpha border + fill from the tone.
// ---------------------------------------------------------------------------
export function MonoBadge({
  tone = "muted",
  children,
  title,
}: {
  tone?: string;
  children: React.ReactNode;
  title?: string;
}) {
  const c = toneColor(tone);
  return (
    <span
      title={title}
      className="inline-flex items-center justify-center font-mono uppercase"
      style={{
        height: 19,
        padding: "0 7px",
        fontSize: 8.5,
        letterSpacing: "0.08em",
        borderRadius: 2,
        color: c,
        border: `1px solid color-mix(in srgb, ${c} 35%, transparent)`,
        background: `color-mix(in srgb, ${c} 11%, transparent)`,
        whiteSpace: "nowrap",
      }}
    >
      {children}
    </span>
  );
}

// ---------------------------------------------------------------------------
// FilterChip -- toggle chip (severity / kev filters).
// ---------------------------------------------------------------------------
export function FilterChip({
  active,
  color = "var(--accent)",
  onClick,
  children,
}: {
  active: boolean;
  color?: string;
  onClick?: () => void;
  children: React.ReactNode;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className="font-mono uppercase"
      style={{
        height: 26,
        padding: "0 10px",
        fontSize: 9.5,
        letterSpacing: "0.08em",
        borderRadius: 3,
        cursor: "pointer",
        color: active ? color : "var(--text-faint)",
        border: `1px solid ${active ? color : "var(--border-soft)"}`,
        background: active ? `color-mix(in srgb, ${color} 11%, transparent)` : "transparent",
      }}
    >
      {children}
    </button>
  );
}

// ---------------------------------------------------------------------------
// Segmented -- table / kanban style toggle (filled active segment).
// ---------------------------------------------------------------------------
export function Segmented<T extends string>({
  options,
  value,
  onChange,
}: {
  options: { value: T; label: React.ReactNode }[];
  value: T;
  onChange: (value: T) => void;
}) {
  return (
    <div className="flex" style={{ border: "1px solid var(--border-soft)", borderRadius: 3, overflow: "hidden" }}>
      {options.map((o, i) => {
        const active = o.value === value;
        return (
          <button
            key={o.value}
            type="button"
            onClick={() => onChange(o.value)}
            className="font-mono"
            style={{
              padding: "0 11px",
              height: 26,
              fontSize: 10,
              letterSpacing: "0.06em",
              color: active ? "var(--text-on-accent)" : "var(--text-muted)",
              background: active ? "var(--accent)" : "var(--surface-sunk)",
              border: 0,
              borderLeft: i ? "1px solid var(--border-soft)" : 0,
              cursor: "pointer",
            }}
          >
            {o.label}
          </button>
        );
      })}
    </div>
  );
}

// ---------------------------------------------------------------------------
// StatBar -- one horizontal distribution bar row (label | bar | count).
// ---------------------------------------------------------------------------
export function StatBar({
  label,
  color,
  value,
  max,
}: {
  label: React.ReactNode;
  color: string;
  value: number;
  max: number;
}) {
  const pct = max > 0 ? (value / max) * 100 : 0;
  return (
    <div className="flex items-center" style={{ gap: 10 }}>
      <span
        className="font-mono uppercase"
        style={{ flex: "0 0 66px", fontSize: 9.5, letterSpacing: "0.1em", color }}
      >
        {label}
      </span>
      <span
        style={{
          flex: 1,
          height: 12,
          background: "var(--surface-sunk)",
          border: "1px solid var(--border-soft)",
          borderRadius: 2,
          overflow: "hidden",
        }}
      >
        <span style={{ display: "block", height: "100%", width: `${pct}%`, background: color }} />
      </span>
      <span
        className="font-mono"
        style={{ flex: "0 0 26px", textAlign: "right", fontSize: 11, color: "var(--text-primary)" }}
      >
        {value}
      </span>
    </div>
  );
}

// ---------------------------------------------------------------------------
// BigStat -- oversized accent number with a mono sub-label (KEV panel etc).
// ---------------------------------------------------------------------------
export function BigStat({ value, sub }: { value: React.ReactNode; sub?: React.ReactNode }) {
  return (
    <div>
      <div className="font-mono" style={{ fontSize: 34, color: "var(--accent)", letterSpacing: "-0.02em" }}>
        {value}
      </div>
      {sub ? (
        <div
          className="font-mono"
          style={{ marginTop: 4, fontSize: 9.5, color: "var(--text-faint)", letterSpacing: "0.04em" }}
        >
          {sub}
        </div>
      ) : null}
    </div>
  );
}

// ---------------------------------------------------------------------------
// DataGrid -- honest bordered mono grid (the brand's "honest grid" table).
// Header row + body rows share one grid-template. Generic over the row type.
// ---------------------------------------------------------------------------
export interface GridColumn {
  label: React.ReactNode;
  /** CSS grid track, e.g. "150px" or "1fr". */
  width: string;
  align?: "left" | "right" | "center";
}

export function DataGrid<T>({
  columns,
  rows,
  renderCells,
  getKey,
  onRowClick,
  empty,
}: {
  columns: GridColumn[];
  rows: T[];
  renderCells: (row: T, index: number) => React.ReactNode[];
  getKey?: (row: T, index: number) => React.Key;
  onRowClick?: (row: T, index: number) => void;
  empty?: React.ReactNode;
}) {
  const template = columns.map((c) => c.width).join(" ");
  return (
    <div>
      <div
        className="grid font-mono uppercase"
        style={{
          gridTemplateColumns: template,
          gap: 10,
          padding: "8px 12px",
          background: "var(--surface-sunk)",
          border: "1px solid var(--border-soft)",
          borderBottom: 0,
          borderRadius: "4px 4px 0 0",
          fontSize: 9,
          letterSpacing: "0.14em",
          color: "var(--text-faint)",
        }}
      >
        {columns.map((c, i) => (
          <span key={i} style={{ textAlign: c.align }}>
            {c.label}
          </span>
        ))}
      </div>
      <div style={{ border: "1px solid var(--border-soft)", borderRadius: "0 0 4px 4px", overflow: "hidden" }}>
        {rows.length === 0
          ? empty ?? (
              <div
                className="font-mono"
                style={{ padding: 34, textAlign: "center", fontSize: 12, color: "var(--text-muted)" }}
              >
                no rows match the current filters.
              </div>
            )
          : rows.map((r, ri) => (
              <div
                key={getKey ? getKey(r, ri) : ri}
                onClick={onRowClick ? () => onRowClick(r, ri) : undefined}
                className="grid font-mono"
                style={{
                  gridTemplateColumns: template,
                  gap: 10,
                  padding: "8px 12px",
                  borderBottom: "1px solid var(--border-faint)",
                  background: "var(--surface-card)",
                  alignItems: "center",
                  cursor: onRowClick ? "pointer" : undefined,
                }}
              >
                {renderCells(r, ri).map((cell, ci) => (
                  <span key={ci} style={{ minWidth: 0, textAlign: columns[ci]?.align }}>
                    {cell}
                  </span>
                ))}
              </div>
            ))}
      </div>
    </div>
  );
}
