import { useMemo, useState } from "react";

import { useThemeChartColors } from "@platform/features/viz/chartColors";

import type { TimelineEntry } from "../types";

export interface TimelineTrackProps {
  entries: readonly TimelineEntry[];
  /** Optional -- when set, dots for this source are emphasized. */
  activeSource?: string | null;
  /** Called when the operator clicks a legend chip. */
  onSourceClick?: (source: string) => void;
}

interface Positioned {
  entry: TimelineEntry;
  /** Original index into the entries array (stable key). */
  idx: number;
  ms: number;
  /** Normalized 0..1 along the horizontal axis. */
  x: number;
  /** Row index for vertical stacking to avoid dot overlap. */
  row: number;
  color: string;
}

/**
 * Parse a TimelineEntry timestamp string into ms since epoch.
 * Returns NaN on malformed input; callers filter those out so
 * the visual track ignores rows the backend could not parse.
 */
function parseTs(raw: string): number {
  const n = Date.parse(raw);
  return Number.isFinite(n) ? n : NaN;
}

/**
 * Layout the entries left->right along [min, max] and stack near-neighbors
 * into rows so dots don't overlap. Two entries share a row only if their
 * pixel-normalized positions are >= MIN_SEP apart. The naive per-row
 * scan is O(n*rows) but rows stays small in practice.
 */
function layoutEntries(
  entries: readonly TimelineEntry[],
  colorForSource: (source: string) => string,
  width: number,
): { rows: Positioned[][]; min: number; max: number } {
  const scored = entries
    .map((entry, idx) => ({ entry, idx, ms: parseTs(entry.timestamp) }))
    .filter((s) => Number.isFinite(s.ms))
    .sort((a, b) => a.ms - b.ms);

  if (scored.length === 0) return { rows: [], min: 0, max: 0 };

  const min = scored[0].ms;
  const max = scored[scored.length - 1].ms;
  const span = Math.max(1, max - min);
  // ~10px minimum separation between dot centers at the default width;
  // scale relative to the target width so denser data still spreads.
  const MIN_SEP_PX = 10;
  const minSepNorm = MIN_SEP_PX / Math.max(1, width);

  // Row occupancy: rows[r] holds the last placed dot's normalized x.
  const rowsLastX: number[] = [];
  const rows: Positioned[][] = [];

  for (const s of scored) {
    const x = (s.ms - min) / span;
    let placedRow = -1;
    for (let r = 0; r < rowsLastX.length; r += 1) {
      if (x - rowsLastX[r] >= minSepNorm) {
        placedRow = r;
        break;
      }
    }
    if (placedRow === -1) {
      placedRow = rowsLastX.length;
      rowsLastX.push(x);
      rows.push([]);
    } else {
      rowsLastX[placedRow] = x;
    }
    rows[placedRow].push({
      entry: s.entry,
      idx: s.idx,
      ms: s.ms,
      x,
      row: placedRow,
      color: colorForSource(s.entry.source),
    });
  }
  return { rows, min, max };
}

function formatIsoShort(ms: number): string {
  if (!Number.isFinite(ms)) return "";
  const d = new Date(ms);
  // 2024-01-15 09:42Z -- readable, timezone-explicit, no seconds.
  const iso = d.toISOString();
  return `${iso.slice(0, 10)} ${iso.slice(11, 16)}Z`;
}

const PANEL_STYLE: React.CSSProperties = {
  border: "1px solid var(--border-soft)",
  background: "var(--surface-card)",
  borderRadius: 3,
  padding: 10,
};

/**
 * Visual, time-positioned track for TimelineEntry[]. Dots plot along a
 * shared horizontal time axis, color-coded by source, and click to
 * surface the entry detail beneath the track. Legend chips echo any
 * `activeSource` selection driven from the parent so this component
 * stays a controlled visual and the filter model stays in TimelineViewer.
 */
export function TimelineTrack({
  entries,
  activeSource,
  onSourceClick,
}: TimelineTrackProps) {
  const theme = useThemeChartColors();
  const [selected, setSelected] = useState<number | null>(null);

  // Deterministic per-source color assignment. Sort sources first so
  // colors stay stable across renders even if the entries array is
  // resorted upstream.
  const sourceColor = useMemo(() => {
    const palette = [
      theme.accent,
      theme.critical,
      theme.high,
      theme.medium,
      theme.low,
    ];
    const uniq = Array.from(new Set(entries.map((e) => e.source))).sort();
    const map = new Map<string, string>();
    uniq.forEach((src, i) => {
      map.set(src, palette[i % palette.length]);
    });
    return (source: string) => map.get(source) ?? theme.textMuted;
  }, [
    entries,
    theme.accent,
    theme.critical,
    theme.high,
    theme.medium,
    theme.low,
    theme.textMuted,
  ]);

  const VIEW_W = 1000; // logical viewBox width; SVG scales to container
  const layout = useMemo(
    () => layoutEntries(entries, sourceColor, VIEW_W),
    [entries, sourceColor],
  );

  const uniqueSources = useMemo(
    () => Array.from(new Set(entries.map((e) => e.source))).sort(),
    [entries],
  );

  if (layout.rows.length === 0) {
    return (
      <div
        style={{
          ...PANEL_STYLE,
          borderStyle: "dashed",
          background: "var(--surface-sunk)",
        }}
      >
        <p
          className="font-mono"
          style={{ fontSize: 10.5, color: "var(--text-muted)" }}
        >
          No parseable timestamps -- visual track is empty. Check the list
          below for rows whose timestamp field the backend could not parse.
        </p>
      </div>
    );
  }

  const ROW_H = 14;
  const AXIS_H = 22;
  const TOP_PAD = 8;
  const svgH = TOP_PAD + Math.max(1, layout.rows.length) * ROW_H + AXIS_H;

  // Five evenly spaced axis ticks -- start, quartiles, end.
  const axisTicks = Array.from({ length: 5 }, (_, i) => {
    const t = i / 4;
    const ms = layout.min + (layout.max - layout.min) * t;
    return { t, ms };
  });

  const selectedEntry =
    selected !== null ? entries.find((_, i) => i === selected) : null;

  return (
    <div className="space-y-2">
      <div
        style={PANEL_STYLE}
        role="group"
        aria-label="Visual timeline track"
      >
        <svg
          viewBox={`0 0 ${VIEW_W} ${svgH}`}
          preserveAspectRatio="none"
          width="100%"
          style={{ height: svgH, display: "block" }}
        >
          <title>Timeline of {entries.length} events plotted by time</title>
          {/* Axis baseline */}
          <line
            x1={0}
            x2={VIEW_W}
            y1={svgH - AXIS_H}
            y2={svgH - AXIS_H}
            stroke={theme.border}
            strokeWidth={1}
          />
          {/* Row guides -- subtle, per row so eye can track a dot's y */}
          {layout.rows.map((_, r) => (
            <line
              key={`guide-${r}`}
              x1={0}
              x2={VIEW_W}
              y1={TOP_PAD + r * ROW_H + ROW_H / 2}
              y2={TOP_PAD + r * ROW_H + ROW_H / 2}
              stroke={theme.border}
              strokeOpacity={0.25}
              strokeWidth={1}
              strokeDasharray="2 4"
            />
          ))}
          {/* Axis ticks */}
          {axisTicks.map((tk) => (
            <g key={`tick-${tk.t}`}>
              <line
                x1={tk.t * VIEW_W}
                x2={tk.t * VIEW_W}
                y1={svgH - AXIS_H}
                y2={svgH - AXIS_H + 4}
                stroke={theme.border}
              />
              <text
                x={tk.t * VIEW_W}
                y={svgH - 6}
                fill={theme.textMuted}
                fontSize={10}
                fontFamily="ui-monospace, SFMono-Regular, Menlo, monospace"
                textAnchor={
                  tk.t === 0 ? "start" : tk.t === 1 ? "end" : "middle"
                }
              >
                {formatIsoShort(tk.ms)}
              </text>
            </g>
          ))}
          {/* Dots */}
          {layout.rows.flat().map((p) => {
            const cx = p.x * VIEW_W;
            const cy = TOP_PAD + p.row * ROW_H + ROW_H / 2;
            const emphasized = !activeSource || activeSource === p.entry.source;
            const isSel = selected === p.idx;
            return (
              <g
                key={`dot-${p.idx}`}
                style={{ cursor: "pointer" }}
                onClick={() =>
                  setSelected((cur) => (cur === p.idx ? null : p.idx))
                }
              >
                <title>
                  {formatIsoShort(p.ms)} {"\u00b7"} {p.entry.source} {"\u00b7"}{" "}
                  {p.entry.event_type}
                  {"\n"}
                  {p.entry.description}
                </title>
                <circle
                  cx={cx}
                  cy={cy}
                  r={isSel ? 5.5 : 3.5}
                  fill={p.color}
                  fillOpacity={emphasized ? 1 : 0.25}
                  stroke={isSel ? theme.accent : "none"}
                  strokeWidth={isSel ? 1.5 : 0}
                />
              </g>
            );
          })}
        </svg>
        {/* Legend */}
        <div
          className="flex flex-wrap"
          style={{ marginTop: 8, gap: 6 }}
        >
          {uniqueSources.map((src) => {
            const isActive = activeSource === src;
            const chipColor = sourceColor(src);
            return (
              <button
                key={`legend-${src}`}
                type="button"
                onClick={() => onSourceClick?.(src)}
                aria-pressed={isActive}
                className="font-mono uppercase inline-flex items-center"
                style={{
                  gap: 5,
                  padding: "2px 8px",
                  fontSize: 9,
                  letterSpacing: "0.08em",
                  borderRadius: 3,
                  color: isActive ? chipColor : "var(--text-faint)",
                  background: isActive
                    ? `color-mix(in srgb, ${chipColor} 12%, transparent)`
                    : "var(--surface-sunk)",
                  border: `1px solid ${
                    isActive ? chipColor : "var(--border-soft)"
                  }`,
                  cursor: "pointer",
                }}
              >
                <span
                  aria-hidden="true"
                  className="inline-block"
                  style={{
                    width: 8,
                    height: 8,
                    borderRadius: 2,
                    backgroundColor: chipColor,
                  }}
                />
                {src}
              </button>
            );
          })}
        </div>
      </div>
      {selectedEntry && (
        <div
          style={PANEL_STYLE}
          role="region"
          aria-label="Selected timeline entry"
        >
          <div className="flex items-baseline justify-between" style={{ gap: 12 }}>
            <div
              className="font-mono"
              style={{ fontSize: 10.5, color: "var(--text-muted)" }}
            >
              {selectedEntry.timestamp}
              <span
                style={{
                  margin: "0 8px",
                  color: "var(--border)",
                }}
              >
                {"\u00b7"}
              </span>
              <span
                className="inline-block align-middle"
                style={{
                  width: 8,
                  height: 8,
                  borderRadius: 2,
                  backgroundColor: sourceColor(selectedEntry.source),
                }}
              />
              <span style={{ marginLeft: 4 }}>{selectedEntry.source}</span>
              <span
                style={{ margin: "0 8px", color: "var(--border)" }}
              >
                {"\u00b7"}
              </span>
              <span>{selectedEntry.event_type}</span>
            </div>
            <button
              type="button"
              onClick={() => setSelected(null)}
              className="font-mono uppercase"
              aria-label="Close selected entry"
              style={{
                padding: "2px 6px",
                fontSize: 9,
                letterSpacing: "0.08em",
                color: "var(--text-faint)",
                background: "transparent",
                border: 0,
                cursor: "pointer",
                textDecoration: "underline dotted",
              }}
            >
              close
            </button>
          </div>
          <p
            className="font-mono break-words"
            style={{
              marginTop: 8,
              fontSize: 11,
              color: "var(--text-primary)",
              lineHeight: 1.55,
            }}
          >
            {selectedEntry.description}
          </p>
        </div>
      )}
      {/* SR-only mirror -- keeps a11y parity with the visual track. */}
      <table className="sr-only">
        <caption>
          Timeline entries plotted on the visual track ({entries.length} total).
        </caption>
        <thead>
          <tr>
            <th>Timestamp</th>
            <th>Source</th>
            <th>Type</th>
            <th>Description</th>
          </tr>
        </thead>
        <tbody>
          {entries.map((e, i) => (
            // eslint-disable-next-line react/no-array-index-key
            <tr key={`sr-${i}`}>
              <td>{e.timestamp}</td>
              <td>{e.source}</td>
              <td>{e.event_type}</td>
              <td>{e.description}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
