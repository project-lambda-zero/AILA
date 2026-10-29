/** The knowledge CORPUS STATS panel: GET /platform/knowledge/stats with the
 * headline figures and the per-dimension bucket bars. */

import { useMemo } from "react";
import type { JSX } from "react";

import { useKnowledgeStats } from "../../../api/knowledge";
import type { KnowledgeBucket } from "../../../api/knowledge";
import { css } from "../../css";
import { fmtInt } from "./helpers";
import {
  barTrack,
  bucketCountCell,
  bucketLabelCell,
  bucketRow,
  dot,
  emptyNote,
  H_WARN,
  pad,
  panelBox,
  panelTitle,
  scroll,
  statFigure,
  statLabel,
  statValue,
} from "./styles";

export function StatsPanel(): JSX.Element {
  const stats = useKnowledgeStats();

  return (
    <div style={panelBox}>
      <div style={panelTitle}>
        <span style={dot} />
        <span style={css("color:var(--text-primary);")}>corpus stats</span>
        <span style={css("flex:1;")} />
      </div>
      <div style={{ ...scroll, ...pad }}>
        {stats.isLoading ? (
          <div style={emptyNote}>loading corpus stats&#8230;</div>
        ) : stats.isError ? (
          <div style={{ ...emptyNote, color: H_WARN }}>
            could not load /platform/knowledge/stats &mdash;{" "}
            {stats.error instanceof Error ? stats.error.message : "request failed"}
          </div>
        ) : !stats.data ? (
          <div style={emptyNote}>no stats returned.</div>
        ) : (
          <div style={css("display:flex;flex-direction:column;gap:14px;min-width:0;")}>
            <div style={css("display:grid;grid-template-columns:1fr 1fr;gap:10px;")}>
              <div style={statFigure}>
                <span style={statValue}>{fmtInt(stats.data.total_entries)}</span>
                <span style={statLabel}>total entries</span>
              </div>
              <div style={statFigure}>
                <span style={statValue}>{fmtInt(stats.data.edge_count)}</span>
                <span style={statLabel}>knowledge edges</span>
              </div>
            </div>
            <BucketPanel label="by namespace" buckets={stats.data.by_namespace} />
            <BucketPanel label="by source type" buckets={stats.data.by_source_type} />
            <BucketPanel label="by model" buckets={stats.data.by_model} />
          </div>
        )}
      </div>
    </div>
  );
}

function BucketPanel({ label, buckets }: { label: string; buckets: KnowledgeBucket[] }): JSX.Element {
  const max = useMemo(() => buckets.reduce((m, b) => (b.count > m ? b.count : m), 0), [buckets]);
  return (
    <div style={css("display:flex;flex-direction:column;gap:5px;min-width:0;")}>
      <div style={css("font-family:var(--font-mono);font-size:11px;letter-spacing:0.14em;text-transform:uppercase;color:var(--text-faint);")}>
        {label}
      </div>
      {buckets.length === 0 ? (
        <div style={css("font-family:var(--font-mono);font-size:11px;color:var(--text-faint);letter-spacing:0.04em;")}>
          &mdash; empty &mdash;
        </div>
      ) : (
        <div>
          {buckets.map((b) => {
            const pct = max > 0 ? Math.max(2, Math.round((b.count / max) * 100)) : 0;
            return (
              <div key={b.key} style={bucketRow}>
                <span style={bucketLabelCell} title={b.key}>{b.key || "\u2014"}</span>
                <span style={bucketCountCell}>{fmtInt(b.count)}</span>
                <div style={barTrack} aria-hidden="true">
                  <div
                    style={{
                      position: "absolute",
                      left: 0,
                      top: 0,
                      bottom: 0,
                      width: `${pct}%`,
                      background: "color-mix(in srgb,var(--accent) 55%,transparent)",
                    }}
                  />
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
