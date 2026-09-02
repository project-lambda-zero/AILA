import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import type { JSX } from "react";

import { apiFetch } from "../../api/client";
import { css } from "../css";

/** One row of GET /admin/workflows/runs/{run_id}/transitions
 * (schemas/transitions.py TransitionView). `input_hash`/`output_hash` are
 * audit-internal and never exposed; `error_message` is pre-redacted at write
 * time and passed through verbatim. */
interface Transition {
  run_id: string;
  seq: number;
  from_state: string | null;
  to_state: string;
  event: string;
  duration_ms: number | null;
  error_class: string | null;
  error_message: string | null;
  happened_at: string;
  task_id: string | null;
}

// The detail panel body is a `140px 1fr` CSS grid (DataPage.tsx ~1158); a
// bespoke detail body must span both tracks or it collapses into the 140px
// label column. Mirrors the grid-column span TeamCrossDetail / WorkspaceTargets
// use.
const SPAN = "grid-column:1/-1;";
const FAINT = "color:var(--text-faint);";
const MONO = "font-family:var(--font-mono);";

/** A collapsed timeline segment: a single transition, or a run of >=2
 * consecutive transitions sharing the same `to_state` (repeat retries into the
 * same state), which AC4 collapses into one expandable row. */
interface Segment {
  key: string;
  items: Transition[];
}

/** Group consecutive transitions by equal `to_state`. Order-preserving: a
 * segment holds one item unless the next transition lands in the same state. */
function collapse(rows: Transition[]): Segment[] {
  const segs: Segment[] = [];
  for (const r of rows) {
    const last = segs[segs.length - 1];
    if (last && last.items[last.items.length - 1].to_state === r.to_state) {
      last.items.push(r);
    } else {
      segs.push({ key: `${r.run_id}:${r.seq}`, items: [r] });
    }
  }
  return segs;
}

function fmtDuration(ms: number | null): string {
  if (ms == null) return "";
  if (ms < 1000) return `${ms}ms`;
  return `${(ms / 1000).toFixed(1)}s`;
}

/** One transition rendered as a card: seq gutter, from -> to, timestamp, the
 * triggering event, duration, and (when present) the redacted error class +
 * message. */
function TransitionCard({ t }: { t: Transition }): JSX.Element {
  return (
    <div style={css("border:1px solid var(--border-soft);border-radius:2px;padding:6px 8px;display:flex;flex-direction:column;gap:3px;min-width:0;")}>
      <div style={css("display:flex;align-items:baseline;gap:8px;min-width:0;")}>
        <span style={css(MONO + "font-size:9px;flex:0 0 auto;" + FAINT)}>#{t.seq}</span>
        <span style={css(MONO + "font-size:11px;color:var(--text-primary);min-width:0;word-break:break-word;")}>
          {t.from_state ?? "\u2205"} {"\u2192"} {t.to_state}
        </span>
        <span style={css("flex:1;")} />
        <span style={css(MONO + "font-size:9px;flex:0 0 auto;" + FAINT)}>{t.happened_at}</span>
      </div>
      <div style={css("display:flex;align-items:center;gap:8px;flex-wrap:wrap;font-size:10px;")}>
        <span style={css(FAINT)}>event</span>
        <span style={css(MONO + "color:var(--text-muted);")}>{t.event}</span>
        {t.duration_ms != null ? (
          <>
            <span style={css(FAINT)}>took</span>
            <span style={css(MONO + "color:var(--text-muted);")}>{fmtDuration(t.duration_ms)}</span>
          </>
        ) : null}
        {t.error_class ? (
          <span style={css(MONO + "color:var(--status-warn);")}>{t.error_class}</span>
        ) : null}
      </div>
      {t.error_message ? (
        <div style={css(MONO + "font-size:10px;color:var(--status-warn);white-space:pre-wrap;word-break:break-word;border-radius:2px;padding:4px 6px;background:color-mix(in srgb,var(--status-warn) 8%,transparent);")}>
          {t.error_message}
        </div>
      ) : null}
    </div>
  );
}

/** A timeline segment. Single-item segments render the card directly; a run of
 * repeat retries into the same state renders one expandable header showing the
 * seq range + count, revealing the individual cards on expand. */
function SegmentRow({ seg }: { seg: Segment }): JSX.Element {
  const [open, setOpen] = useState(false);
  if (seg.items.length === 1) return <TransitionCard t={seg.items[0]} />;
  const first = seg.items[0];
  const last = seg.items[seg.items.length - 1];
  return (
    <div style={css("display:flex;flex-direction:column;gap:4px;min-width:0;")}>
      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        aria-expanded={open}
        style={css("text-align:left;border:1px dashed var(--border-soft);border-radius:2px;padding:6px 8px;background:transparent;cursor:pointer;display:flex;align-items:baseline;gap:8px;min-width:0;")}
      >
        <span style={css(MONO + "font-size:9px;flex:0 0 auto;" + FAINT)}>
          {open ? "\u25be" : "\u25b8"} #{first.seq}{"\u2013"}{last.seq}
        </span>
        <span style={css(MONO + "font-size:11px;color:var(--text-primary);min-width:0;word-break:break-word;")}>
          {first.from_state ?? "\u2205"} {"\u2192"} {first.to_state}
        </span>
        <span style={css("flex:1;")} />
        <span style={css(MONO + "font-size:9px;color:var(--accent);flex:0 0 auto;")}>{"\u00d7"}{seg.items.length}</span>
      </button>
      {open ? (
        <div style={css("display:flex;flex-direction:column;gap:4px;padding-left:10px;margin-left:4px;border-left:1px solid var(--border-soft);")}>
          {seg.items.map((t) => (
            <TransitionCard key={`${t.run_id}:${t.seq}`} t={t} />
          ))}
        </div>
      ) : null}
    </div>
  );
}

/** Row-detail body for `admin:workflows` (req 38): drills a cursor row into its
 * full transition history from GET /admin/workflows/runs/{run_id}/transitions,
 * shown as an ordered timeline beneath the six cursor fields. Because DataPage
 * renders `detailBody` INSTEAD of the generic field grid (DataPage.tsx ~1159),
 * this component owns both the cursor-field header and the timeline. Inspection
 * only -- the admin_workflows router is read-only. */
export function WorkflowTransitionsDetail({ row }: { row: Record<string, unknown> }): JSX.Element {
  const runId = String(row["run_id"] ?? "");
  const q = useQuery<Transition[]>({
    queryKey: ["admin-workflow-transitions", runId],
    queryFn: () => apiFetch<Transition[]>(`/admin/workflows/runs/${encodeURIComponent(runId)}/transitions`),
    enabled: runId !== "",
    retry: false,
    refetchOnWindowFocus: false,
  });

  const rows = q.data ?? [];

  let body: JSX.Element;
  if (q.isLoading) {
    body = <div style={css(FAINT + MONO + "font-size:10px;")}>loading transitions{"\u2026"}</div>;
  } else if (q.error) {
    body = (
      <div style={css("color:var(--status-warn);font-size:10px;" + MONO)}>
        could not load transitions {"\u2014"} {(q.error as Error).message}
      </div>
    );
  } else if (rows.length === 0) {
    body = <div style={css(FAINT + MONO + "font-size:11px;")}>no transitions recorded</div>;
  } else {
    body = (
      <div style={css("display:flex;flex-direction:column;gap:4px;")}>
        {collapse(rows).map((s) => (
          <SegmentRow key={s.key} seg={s} />
        ))}
      </div>
    );
  }

  return (
    <div style={css(SPAN + "display:flex;flex-direction:column;gap:12px;min-width:0;")}>
      <div style={css("display:grid;grid-template-columns:110px 1fr;gap:5px 12px;font-size:11.5px;align-items:center;")}>
        <span style={css(FAINT)}>run</span>
        <span style={css("color:var(--text-primary);word-break:break-all;" + MONO)}>{runId || "\u2014"}</span>
        <span style={css(FAINT)}>state</span>
        <span style={css("color:var(--text-primary);word-break:break-word;")}>{String(row["current_state"] ?? "\u2014")}</span>
        <span style={css(FAINT)}>definition</span>
        <span style={css("color:var(--text-primary);" + MONO)}>
          {String(row["definition_id"] ?? "\u2014")} {"\u00b7"} v{String(row["version"] ?? "?")}
        </span>
        <span style={css(FAINT)}>retries</span>
        <span style={css("color:var(--text-primary);")}>{String(row["retries_in_state"] ?? "0")}</span>
        <span style={css(FAINT)}>updated</span>
        <span style={css("color:var(--text-primary);" + MONO)}>{String(row["updated_at"] ?? "\u2014")}</span>
      </div>
      <div style={css("display:flex;flex-direction:column;gap:6px;")}>
        <div style={css(MONO + "font-size:9px;letter-spacing:0.14em;text-transform:uppercase;" + FAINT)}>
          transitions{rows.length > 0 ? ` (${rows.length})` : ""}
        </div>
        {body}
      </div>
    </div>
  );
}
