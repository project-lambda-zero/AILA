import { useMemo } from "react";

import { AilaChart } from "@/components/aila/AilaChart";
import { WindowPanel } from "@/components/aila/WindowPanel";
import { useThemeChartColors } from "@platform/features/viz/chartColors";

import type { TimelineEntry } from "../types";

export interface TimelineDistributionProps {
  entries: readonly TimelineEntry[];
  /** Cap on distinct event-type bars so the second chart stays readable. */
  topN?: number;
}

// Index signature so the bucket array is assignable to
// AilaChart's ``data: Array<Record<string, unknown>>`` prop without
// a cast at each callsite.
type Bucket = { name: string; count: number } & Record<string, unknown>;

/**
 * Group entries by a string key and return the descending-count buckets,
 * capped at ``limit`` when set. Uses a Map for the running tally so
 * distinct keys stay in insertion order until the final sort.
 */
function bucketBy(
  entries: readonly TimelineEntry[],
  keyFn: (e: TimelineEntry) => string,
  limit?: number,
): Bucket[] {
  const counts = new Map<string, number>();
  for (const e of entries) {
    const k = keyFn(e) || "(unknown)";
    counts.set(k, (counts.get(k) ?? 0) + 1);
  }
  const out: Bucket[] = Array.from(counts, ([name, count]) => ({ name, count }));
  out.sort((a, b) => b.count - a.count);
  return typeof limit === "number" ? out.slice(0, limit) : out;
}

/**
 * Additive analytics for the forensics timeline. Renders two AilaChart
 * bar charts side-by-side: distribution of entries by source (parity
 * with the visual track's legend colors) and distribution by event type
 * capped to the top ``topN`` (default 10). Bucketing is entirely
 * client-side over the already-loaded ``entries`` -- no extra fetches.
 */
export function TimelineDistribution({
  entries,
  topN = 10,
}: TimelineDistributionProps) {
  const theme = useThemeChartColors();

  // Palette shared with TimelineTrack -- accent-first, then severity ramp.
  // Recharts consumes hex strings; CSS `var(--…)` does not resolve inside
  // SVG presentation attributes (see chartColors.ts docstring).
  const palette = useMemo(
    () => [theme.accent, theme.critical, theme.high, theme.medium, theme.low],
    [theme.accent, theme.critical, theme.high, theme.medium, theme.low],
  );

  const bySource = useMemo(() => bucketBy(entries, (e) => e.source), [entries]);
  const byType = useMemo(
    () => bucketBy(entries, (e) => e.event_type, topN),
    [entries, topN],
  );

  const hasSources = bySource.length > 0;
  const hasTypes = byType.length > 0;

  return (
    <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">
      <WindowPanel title="events by source">
        {hasSources ? (
          <>
            <AilaChart
              type="bar"
              data={bySource}
              dataKey="count"
              xKey="name"
              colors={palette}
              size="sm"
              ariaLabel="Timeline events grouped by source tool"
            />
            <p className="mt-1 text-3xs text-text-muted font-mono">
              {bySource.length} source{bySource.length === 1 ? "" : "s"} ·{" "}
              {entries.length} event{entries.length === 1 ? "" : "s"}
            </p>
          </>
        ) : (
          <p className="text-xs text-text-muted py-2">No source data.</p>
        )}
        <table className="sr-only">
          <caption>Timeline event counts grouped by source.</caption>
          <thead>
            <tr>
              <th>Source</th>
              <th>Count</th>
            </tr>
          </thead>
          <tbody>
            {bySource.map((row) => (
              <tr key={`src-${row.name}`}>
                <td>{row.name}</td>
                <td>{row.count}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </WindowPanel>

      <WindowPanel title="top event types">
        {hasTypes ? (
          <>
            <AilaChart
              type="bar"
              data={byType}
              dataKey="count"
              xKey="name"
              colors={palette}
              size="sm"
              ariaLabel="Top timeline event types by count"
            />
            <p className="mt-1 text-3xs text-text-muted font-mono">
              top {byType.length} of {new Set(entries.map((e) => e.event_type)).size}
            </p>
          </>
        ) : (
          <p className="text-xs text-text-muted py-2">No event-type data.</p>
        )}
        <table className="sr-only">
          <caption>Top timeline event types by count.</caption>
          <thead>
            <tr>
              <th>Event type</th>
              <th>Count</th>
            </tr>
          </thead>
          <tbody>
            {byType.map((row) => (
              <tr key={`type-${row.name}`}>
                <td>{row.name}</td>
                <td>{row.count}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </WindowPanel>
    </div>
  );
}
