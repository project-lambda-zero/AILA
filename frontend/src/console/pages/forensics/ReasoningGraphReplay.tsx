/**
 * Reasoning-graph replay for one forensics investigation. A step scrubber
 * (prev/next, range slider, per-step chips) selects one durable
 * ReasoningGraphSnapshot and lists its nodes and edges; a diff block compares
 * two chosen steps through GET .../reasoning-graphs/diff (added/removed nodes
 * and edges) and lists nodes/edges present in both steps whose label, kind,
 * or attributes changed, compared from the two loaded snapshots.
 */
import type { JSX, ReactNode } from "react";
import { useMemo, useState } from "react";

import { useReasoningGraphDiff, useReasoningGraphs } from "../../../api/forensicsReasoning";
import type { ReasoningGraphEdge, ReasoningGraphNode, ReasoningSnapshot } from "../../../api/forensicsReasoning";
import { css } from "../../css";
import { Select } from "./formControls";
import { DictPanel, H, Panel, emptyNote } from "./panels";

const btn = (on: boolean): string =>
  `height:28px;min-width:28px;padding:0 10px;font-family:var(--font-mono);font-size:11px;letter-spacing:0.06em;border-radius:2px;cursor:pointer;border:1px solid ${on ? "var(--accent)" : "var(--border-soft)"};background:${on ? "var(--accent)" : "transparent"};color:${on ? "var(--text-on-accent)" : "var(--text-muted)"};`;

const caption = css("font-size:11px;letter-spacing:0.1em;text-transform:uppercase;color:var(--text-faint);");

const edgeKey = (e: ReasoningGraphEdge): string => `${e.source}\u0000${e.target}\u0000${e.kind}`;

export function ReasoningGraphReplay({ projectId, investigationId }: { projectId: string; investigationId: string }): JSX.Element {
  const graphs = useReasoningGraphs(projectId, investigationId);
  const snapshots = graphs.data ?? [];
  const [selStep, setSelStep] = useState<number | null>(null);
  const [diffFrom, setDiffFrom] = useState<number | null>(null);
  const [diffTo, setDiffTo] = useState<number | null>(null);

  if (graphs.isLoading) return <div style={emptyNote}>{"loading\u2026"}</div>;
  if (graphs.isError) {
    return (
      <div style={emptyNote}>
        could not load reasoning-graphs &mdash; {graphs.error instanceof Error ? graphs.error.message : "request failed"}
      </div>
    );
  }
  if (snapshots.length === 0) return <div style={emptyNote}>no reasoning graphs recorded.</div>;

  const foundIdx = snapshots.findIndex((s) => s.step_number === selStep);
  const idx = foundIdx === -1 ? snapshots.length - 1 : foundIdx;
  const cur = snapshots[idx];
  const toStep = diffTo ?? cur.step_number;
  const fromStep = diffFrom ?? snapshots[Math.max(0, idx - 1)].step_number;
  const stepOptions = snapshots.map((s) => ({ value: String(s.step_number), label: `step ${s.step_number}` }));

  return (
    <div style={css("flex:1;min-height:0;overflow:auto;display:flex;flex-direction:column;gap:10px;")}>
      <Panel title="reasoning graph replay" tag={`step ${cur.step_number} \u00b7 ${idx + 1} of ${snapshots.length}`}>
        <div style={css("padding:10px 12px;display:flex;flex-direction:column;gap:10px;")}>
          <div style={css("display:flex;align-items:center;gap:8px;")}>
            <button type="button" style={css(btn(false))} disabled={idx === 0} onClick={() => setSelStep(snapshots[idx - 1].step_number)}>
              {"\u25c0 prev"}
            </button>
            <input
              type="range"
              min={0}
              max={snapshots.length - 1}
              value={idx}
              onChange={(e) => setSelStep(snapshots[Number(e.target.value)].step_number)}
              aria-label="reasoning graph step"
              style={css("flex:1;height:28px;accent-color:var(--accent);")}
            />
            <button
              type="button"
              style={css(btn(false))}
              disabled={idx === snapshots.length - 1}
              onClick={() => setSelStep(snapshots[idx + 1].step_number)}
            >
              {"next \u25b6"}
            </button>
          </div>
          <div style={css("display:flex;gap:4px;overflow-x:auto;padding-bottom:2px;")}>
            {snapshots.map((s, i) => (
              <button key={s.id} type="button" title={s.strategy_family} style={css(btn(i === idx))} onClick={() => setSelStep(s.step_number)}>
                {s.step_number}
              </button>
            ))}
          </div>
          <div style={css("display:flex;flex-wrap:wrap;gap:14px;font-family:var(--font-mono);font-size:11px;color:var(--text-muted);")}>
            <span>
              strategy <span style={css("color:var(--text-primary);")}>{cur.strategy_family || "\u2014"}</span>
            </span>
            <span>
              nodes <span style={css("color:var(--text-primary);")}>{cur.nodes.length}</span>
            </span>
            <span>
              edges <span style={css("color:var(--text-primary);")}>{cur.edges.length}</span>
            </span>
            <span style={css("flex:1;")} />
            <span style={css("color:var(--text-faint);")}>{cur.updated_at ?? cur.created_at ?? ""}</span>
          </div>
          <GraphLists snapshot={cur} />
        </div>
      </Panel>

      <Panel title="step diff" tag={`${fromStep} \u2192 ${toStep}`}>
        <div style={css("padding:10px 12px;display:flex;flex-direction:column;gap:10px;")}>
          <div style={css("display:flex;align-items:center;gap:10px;font-size:11px;color:var(--text-muted);")}>
            <span style={caption}>from</span>
            <div style={css("width:150px;")}>
              <Select value={String(fromStep)} onChange={(v) => setDiffFrom(Number(v))} options={stepOptions} />
            </div>
            <span style={caption}>to</span>
            <div style={css("width:150px;")}>
              <Select value={String(toStep)} onChange={(v) => setDiffTo(Number(v))} options={stepOptions} />
            </div>
          </div>
          {fromStep === toStep ? (
            <div style={emptyNote}>pick two different steps to compare.</div>
          ) : (
            <StepDiff
              projectId={projectId}
              investigationId={investigationId}
              from={snapshots.find((s) => s.step_number === fromStep)}
              to={snapshots.find((s) => s.step_number === toStep)}
              fromStep={fromStep}
              toStep={toStep}
            />
          )}
        </div>
      </Panel>
    </div>
  );
}

function GraphLists({ snapshot }: { snapshot: ReasoningSnapshot }): JSX.Element {
  const labels = useMemo(() => new Map(snapshot.nodes.map((n) => [n.id, n.label || n.id])), [snapshot]);
  return (
    <div style={css("display:grid;grid-template-columns:1fr 1fr;gap:10px;")}>
      <div style={css("display:flex;flex-direction:column;gap:5px;min-width:0;")}>
        <span style={caption}>nodes</span>
        {snapshot.nodes.length === 0 ? <div style={emptyNote}>no nodes.</div> : <NodeList nodes={snapshot.nodes} />}
      </div>
      <div style={css("display:flex;flex-direction:column;gap:5px;min-width:0;")}>
        <span style={caption}>edges</span>
        {snapshot.edges.length === 0 ? <div style={emptyNote}>no edges.</div> : <EdgeList edges={snapshot.edges} labels={labels} />}
      </div>
    </div>
  );
}

function NodeList({ nodes, tone }: { nodes: ReasoningGraphNode[]; tone?: string }): JSX.Element {
  const [openId, setOpenId] = useState<string | null>(null);
  return (
    <div style={css("display:flex;flex-direction:column;gap:3px;")}>
      {nodes.map((n) => {
        const open = openId === n.id;
        const attrCount = Object.keys(n.attributes).length;
        return (
          <div key={n.id} style={css("border:1px solid var(--border-soft);border-radius:2px;background:var(--surface-sunk);")}>
            <button
              type="button"
              onClick={() => setOpenId(open ? null : n.id)}
              disabled={attrCount === 0}
              style={css(
                `width:100%;min-height:28px;display:flex;align-items:center;gap:8px;padding:4px 8px;background:transparent;border:0;text-align:left;font-family:var(--font-mono);font-size:11px;color:var(--text-primary);cursor:${attrCount ? "pointer" : "default"};`,
              )}
            >
              <span style={css(`color:${tone ?? "var(--accent)"};text-transform:uppercase;letter-spacing:0.06em;min-width:90px;`)}>{n.kind}</span>
              <span style={css("flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;")}>{n.label || n.id}</span>
              <span style={css("color:var(--text-faint);")}>{attrCount ? `${attrCount} attr ${open ? "\u25be" : "\u25b8"}` : n.id.slice(0, 12)}</span>
            </button>
            {open ? (
              <div style={css("padding:0 8px 8px;")}>
                <DictPanel data={n.attributes} initialOpen />
              </div>
            ) : null}
          </div>
        );
      })}
    </div>
  );
}

function EdgeList({ edges, labels, tone }: { edges: ReasoningGraphEdge[]; labels: Map<string, string>; tone?: string }): JSX.Element {
  return (
    <div style={css("display:flex;flex-direction:column;gap:3px;")}>
      {edges.map((e) => (
        <div
          key={edgeKey(e)}
          style={css(
            "display:flex;align-items:center;gap:7px;min-height:28px;padding:4px 8px;border:1px solid var(--border-soft);border-radius:2px;background:var(--surface-sunk);font-family:var(--font-mono);font-size:11px;color:var(--text-primary);",
          )}
        >
          <span style={css("flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;text-align:right;")}>{labels.get(e.source) ?? e.source}</span>
          <span style={css(`flex:0 0 auto;color:${tone ?? "var(--accent)"};letter-spacing:0.04em;`)}>{`\u2014${e.kind}\u2192`}</span>
          <span style={css("flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;")}>{labels.get(e.target) ?? e.target}</span>
        </div>
      ))}
    </div>
  );
}

function StepDiff({
  projectId,
  investigationId,
  from,
  to,
  fromStep,
  toStep,
}: {
  projectId: string;
  investigationId: string;
  from: ReasoningSnapshot | undefined;
  to: ReasoningSnapshot | undefined;
  fromStep: number;
  toStep: number;
}): JSX.Element {
  const diff = useReasoningGraphDiff(projectId, investigationId, fromStep, toStep);

  const { labels, changedNodes, changedEdges } = useMemo(() => {
    const fromNodes = new Map((from?.nodes ?? []).map((n) => [n.id, n]));
    const fromEdges = new Map((from?.edges ?? []).map((e) => [edgeKey(e), e]));
    const toNodes = to?.nodes ?? [];
    const nodeLabels = new Map<string, string>();
    for (const n of [...(from?.nodes ?? []), ...toNodes]) nodeLabels.set(n.id, n.label || n.id);
    return {
      labels: nodeLabels,
      changedNodes: toNodes.filter((n) => {
        const before = fromNodes.get(n.id);
        return before !== undefined && JSON.stringify(before) !== JSON.stringify(n);
      }),
      changedEdges: (to?.edges ?? []).filter((e) => {
        const before = fromEdges.get(edgeKey(e));
        return before !== undefined && JSON.stringify(before.attributes) !== JSON.stringify(e.attributes);
      }),
    };
  }, [from, to]);

  if (diff.isLoading) return <div style={emptyNote}>{"loading diff\u2026"}</div>;
  if (diff.isError) {
    return <div style={emptyNote}>could not load diff &mdash; {diff.error instanceof Error ? diff.error.message : "request failed"}</div>;
  }
  const d = diff.data;
  if (!d) return <div style={emptyNote}>no diff.</div>;

  return (
    <div style={css("display:grid;grid-template-columns:1fr 1fr;gap:10px;")}>
      <DiffBlock label="added nodes" tone={H.mint} count={d.added_nodes.length}>
        <NodeList nodes={d.added_nodes} tone={H.mint} />
      </DiffBlock>
      <DiffBlock label="added edges" tone={H.mint} count={d.added_edges.length}>
        <EdgeList edges={d.added_edges} labels={labels} tone={H.mint} />
      </DiffBlock>
      <DiffBlock label="removed nodes" tone={H.danger} count={d.removed_nodes.length}>
        <NodeList nodes={d.removed_nodes} tone={H.danger} />
      </DiffBlock>
      <DiffBlock label="removed edges" tone={H.danger} count={d.removed_edges.length}>
        <EdgeList edges={d.removed_edges} labels={labels} tone={H.danger} />
      </DiffBlock>
      <DiffBlock label="changed nodes" tone={H.amber} count={changedNodes.length}>
        <NodeList nodes={changedNodes} tone={H.amber} />
      </DiffBlock>
      <DiffBlock label="changed edges" tone={H.amber} count={changedEdges.length}>
        <EdgeList edges={changedEdges} labels={labels} tone={H.amber} />
      </DiffBlock>
    </div>
  );
}

function DiffBlock({ label, tone, count, children }: { label: string; tone: string; count: number; children: ReactNode }): JSX.Element {
  return (
    <div style={css("display:flex;flex-direction:column;gap:5px;min-width:0;")}>
      <span style={css(`font-size:11px;letter-spacing:0.1em;text-transform:uppercase;color:${tone};`)}>
        {label} {"\u00b7"} {count}
      </span>
      {count === 0 ? <div style={css("font-size:11px;color:var(--text-faint);")}>none.</div> : children}
    </div>
  );
}
