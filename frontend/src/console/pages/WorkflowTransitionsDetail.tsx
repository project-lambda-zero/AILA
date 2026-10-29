import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import type { JSX } from "react";

import { useWorkflowTransition } from "../../api/admin";
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
function TransitionCard({ t, selected, onSelect }: { t: Transition; selected?: boolean; onSelect?: (t: Transition) => void }): JSX.Element {
  return (
    <div
      onClick={onSelect ? () => onSelect(t) : undefined}
      style={css(
        `border:1px solid ${selected ? "var(--accent)" : "var(--border-soft)"};border-radius:2px;padding:6px 8px;display:flex;flex-direction:column;gap:3px;min-width:0;${onSelect ? "cursor:pointer;" : ""}${selected ? "background:color-mix(in srgb,var(--accent) 8%,transparent);" : ""}`,
      )}
    >
      <div style={css("display:flex;align-items:baseline;gap:8px;min-width:0;")}>
        <span style={css(MONO + "font-size:11px;flex:0 0 auto;" + FAINT)}>#{t.seq}</span>
        <span style={css(MONO + "font-size:11px;color:var(--text-primary);min-width:0;word-break:break-word;")}>
          {t.from_state ?? "\u2205"} {"\u2192"} {t.to_state}
        </span>
        <span style={css("flex:1;")} />
        <span style={css(MONO + "font-size:11px;flex:0 0 auto;" + FAINT)}>{t.happened_at}</span>
      </div>
      <div style={css("display:flex;align-items:center;gap:8px;flex-wrap:wrap;font-size:11px;")}>
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
        <div style={css(MONO + "font-size:11px;color:var(--status-warn);white-space:pre-wrap;word-break:break-word;border-radius:2px;padding:4px 6px;background:color-mix(in srgb,var(--status-warn) 8%,transparent);")}>
          {t.error_message}
        </div>
      ) : null}
    </div>
  );
}

/** A timeline segment. Single-item segments render the card directly; a run of
 * repeat retries into the same state renders one expandable header showing the
 * seq range + count, revealing the individual cards on expand. */
function SegmentRow({ seg, selectedSeq, onSelect }: { seg: Segment; selectedSeq: number | null; onSelect: (t: Transition) => void }): JSX.Element {
  const [open, setOpen] = useState(false);
  if (seg.items.length === 1) return <TransitionCard t={seg.items[0]} selected={seg.items[0].seq === selectedSeq} onSelect={onSelect} />;
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
        <span style={css(MONO + "font-size:11px;flex:0 0 auto;" + FAINT)}>
          {open ? "\u25be" : "\u25b8"} #{first.seq}{"\u2013"}{last.seq}
        </span>
        <span style={css(MONO + "font-size:11px;color:var(--text-primary);min-width:0;word-break:break-word;")}>
          {first.from_state ?? "\u2205"} {"\u2192"} {first.to_state}
        </span>
        <span style={css("flex:1;")} />
        <span style={css(MONO + "font-size:11px;color:var(--accent);flex:0 0 auto;")}>{"\u00d7"}{seg.items.length}</span>
      </button>
      {open ? (
        <div style={css("display:flex;flex-direction:column;gap:4px;padding-left:10px;margin-left:4px;border-left:1px solid var(--border-soft);")}>
          {seg.items.map((t) => (
            <TransitionCard key={`${t.run_id}:${t.seq}`} t={t} selected={t.seq === selectedSeq} onSelect={onSelect} />
          ))}
        </div>
      ) : null}
    </div>
  );
}

/** Observed state machine derived from the transition rows: unique states as
 * nodes (first-appearance order), one edge per distinct from -> to pair with
 * the observed count folded in. Rendered as an inline SVG below the timeline. */
interface StateNode {
  state: string;
  y: number;
}

interface StateEdge {
  from: string;
  to: string;
  count: number;
}

function buildStateMachine(rows: Transition[]): { nodes: StateNode[]; edges: StateEdge[] } {
  const order: string[] = [];
  const edgeCounts = new Map<string, StateEdge>();
  for (const r of rows) {
    const from = r.from_state ?? "∅";
    for (const s of [from, r.to_state]) {
      if (!order.includes(s)) order.push(s);
    }
    const key = `${from}→${r.to_state}`;
    const edge = edgeCounts.get(key) ?? { from, to: r.to_state, count: 0 };
    edge.count += 1;
    edgeCounts.set(key, edge);
  }
  const nodes = order.map((state, i) => ({ state, y: 30 + i * 56 }));
  return { nodes, edges: [...edgeCounts.values()] };
}

const NODE_W = 150;
const NODE_H = 30;
const DIAGRAM_W = 480;
const NODE_X = 24;

function StateMachineDiagram({ rows }: { rows: Transition[] }): JSX.Element {
  const { nodes, edges } = buildStateMachine(rows);
  const yOf = new Map(nodes.map((n) => [n.state, n.y]));
  const maxCount = Math.max(1, ...edges.map((e) => e.count));
  const height = nodes.length * 56 + 12;
  const edgeColor = "var(--accent)";

  return (
    <svg
      role="img"
      aria-label="observed state machine"
      width={DIAGRAM_W}
      height={height}
      style={{ maxWidth: "100%", display: "block" }}
    >
      <defs>
        <marker id="wfd-arrow" markerWidth="7" markerHeight="7" refX="6" refY="3.5" orient="auto">
          <path d="M0,0 L7,3.5 L0,7 Z" style={{ fill: edgeColor }} />
        </marker>
      </defs>
      {edges.map((e) => {
        const y1 = yOf.get(e.from) ?? 0;
        const y2 = yOf.get(e.to) ?? 0;
        const strokeW = 1 + (e.count / maxCount) * 3;
        if (e.from === e.to) {
          const cx = NODE_X + NODE_W + 28;
          return (
            <g key={`${e.from}→${e.to}`}>
              <path
                d={`M ${NODE_X + NODE_W} ${y1} C ${cx + 26} ${y1 - 22}, ${cx + 26} ${y1 + 22}, ${NODE_X + NODE_W} ${y1 + 4}`}
                fill="none"
                style={{ stroke: edgeColor }}
                strokeWidth={strokeW}
                opacity={0.75}
                markerEnd="url(#wfd-arrow)"
              />
              <text x={cx + 30} y={y1 + 4} fontSize={9} style={{ fill: "var(--text-muted)" }} fontFamily="var(--font-mono)">
                {"×"}{e.count}
              </text>
            </g>
          );
        }
        const forward = y2 > y1;
        const bend = Math.min(90, Math.abs(y2 - y1) * 0.6 + 30);
        const x1 = NODE_X + NODE_W;
        const x2 = NODE_X + NODE_W + bend;
        const midY = (y1 + y2) / 2;
        return (
          <g key={`${e.from}→${e.to}`}>
            <path
              d={
                forward
                  ? `M ${x1} ${y1} C ${x2} ${y1}, ${x2} ${y2}, ${x1} ${y2}`
                  : `M ${x1} ${y1} C ${x2 + 30} ${y1}, ${x2 + 30} ${y2}, ${x1} ${y2}`
              }
              fill="none"
              style={{ stroke: edgeColor }}
              strokeWidth={strokeW}
              opacity={0.75}
              markerEnd="url(#wfd-arrow)"
            />
            <text x={x2 + (forward ? 8 : 38)} y={midY + 3} fontSize={9} style={{ fill: "var(--text-muted)" }} fontFamily="var(--font-mono)">
              {"×"}{e.count}
            </text>
          </g>
        );
      })}
      {nodes.map((n) => (
        <g key={n.state}>
          <rect x={NODE_X} y={n.y - NODE_H / 2} width={NODE_W} height={NODE_H} rx={2} style={{ fill: "var(--surface-card)", stroke: "var(--border)" }} />
          <text x={NODE_X + 8} y={n.y + 3.5} fontSize={10} style={{ fill: "var(--text-primary)" }} fontFamily="var(--font-mono)">
            {n.state}
          </text>
        </g>
      ))}
    </svg>
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
  const [selectedSeq, setSelectedSeq] = useState<number | null>(null);
  const q = useQuery<Transition[]>({
    queryKey: ["admin-workflow-transitions", runId],
    queryFn: () => apiFetch<Transition[]>(`/admin/workflows/runs/${encodeURIComponent(runId)}/transitions`),
    enabled: runId !== "",
    retry: false,
    refetchOnWindowFocus: false,
  });
  const seqQ = useWorkflowTransition(runId, selectedSeq);

  const rows = q.data ?? [];

  const onSelect = (t: Transition): void => setSelectedSeq((cur) => (cur === t.seq ? null : t.seq));

  let body: JSX.Element;
  if (q.isLoading) {
    body = <div style={css(FAINT + MONO + "font-size:11px;")}>loading transitions{"\u2026"}</div>;
  } else if (q.error) {
    body = (
      <div style={css("color:var(--status-warn);font-size:11px;" + MONO)}>
        could not load transitions {"\u2014"} {(q.error as Error).message}
      </div>
    );
  } else if (rows.length === 0) {
    body = <div style={css(FAINT + MONO + "font-size:11px;")}>no transitions recorded</div>;
  } else {
    body = (
      <div style={css("display:flex;flex-direction:column;gap:4px;")}>
        {collapse(rows).map((s) => (
          <SegmentRow key={s.key} seg={s} selectedSeq={selectedSeq} onSelect={onSelect} />
        ))}
      </div>
    );
  }

  const selected = seqQ.data ?? null;

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
        <div style={css(MONO + "font-size:11px;letter-spacing:0.14em;text-transform:uppercase;" + FAINT)}>
          transitions{rows.length > 0 ? ` (${rows.length})` : ""}
        </div>
        {body}
      </div>
      {selectedSeq !== null ? (
        <div style={css("display:flex;flex-direction:column;gap:6px;")}>
          <div style={css(MONO + "font-size:11px;letter-spacing:0.14em;text-transform:uppercase;" + FAINT)}>
            transition #{selectedSeq}
          </div>
          {seqQ.isLoading ? (
            <div style={css(FAINT + MONO + "font-size:11px;")}>loading{"\u2026"}</div>
          ) : seqQ.error ? (
            <div style={css("color:var(--status-warn);font-size:11px;" + MONO)}>
              could not load transition {"\u2014"} {(seqQ.error as Error).message}
            </div>
          ) : selected ? (
            <div style={css("display:grid;grid-template-columns:110px 1fr;gap:5px 12px;font-size:11.5px;align-items:baseline;")}>
              <span style={css(FAINT)}>from</span>
              <span style={css("color:var(--text-primary);" + MONO)}>{selected.from_state ?? "\u2205"}</span>
              <span style={css(FAINT)}>to</span>
              <span style={css("color:var(--text-primary);" + MONO)}>{selected.to_state}</span>
              <span style={css(FAINT)}>event</span>
              <span style={css("color:var(--text-primary);" + MONO)}>{selected.event}</span>
              <span style={css(FAINT)}>duration</span>
              <span style={css("color:var(--text-primary);" + MONO)}>{fmtDuration(selected.duration_ms) || "\u2014"}</span>
              <span style={css(FAINT)}>task</span>
              <span style={css("color:var(--text-primary);word-break:break-all;" + MONO)}>{selected.task_id ?? "\u2014"}</span>
              <span style={css(FAINT)}>happened</span>
              <span style={css("color:var(--text-primary);" + MONO)}>{selected.happened_at}</span>
              {selected.error_class ? (
                <>
                  <span style={css(FAINT)}>error</span>
                  <span style={css("color:var(--status-warn);" + MONO)}>{selected.error_class}</span>
                </>
              ) : null}
              {selected.error_message ? (
                <>
                  <span style={css(FAINT)}>detail</span>
                  <span style={css("color:var(--status-warn);white-space:pre-wrap;word-break:break-word;" + MONO)}>{selected.error_message}</span>
                </>
              ) : null}
            </div>
          ) : null}
        </div>
      ) : null}
      {rows.length > 0 ? (
        <div style={css("display:flex;flex-direction:column;gap:6px;")}>
          <div style={css(MONO + "font-size:11px;letter-spacing:0.14em;text-transform:uppercase;" + FAINT)}>state machine</div>
          <StateMachineDiagram rows={rows} />
        </div>
      ) : null}
    </div>
  );
}
