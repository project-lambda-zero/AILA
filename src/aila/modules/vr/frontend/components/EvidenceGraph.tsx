import "@xyflow/react/dist/style.css";

import {
  Background,
  Controls,
  type Edge,
  MarkerType,
  type Node,
  ReactFlow,
} from "@xyflow/react";
import { useMemo, useState } from "react";

import { AilaBadge } from "@/components/aila/AilaBadge";

/** EvidenceGraph — first-class evidence rendering surface from
 *  08_FRONTEND_UX.md §1.9 / §3.
 *
 *  Six node types, five edge types. Node tones come from AILA design
 *  tokens (passed via inline `style.background` because ReactFlow
 *  needs concrete colours and CSS vars don't resolve inside SVG fills
 *  on the edges layer — same gotcha as Recharts, per CLAUDE.md
 *  mistake #4).
 *
 *  v0.5 backend gap: the platform doesn't expose a project-evidence-
 *  graph endpoint yet. Callers pass `nodes` + `edges` directly so this
 *  component is shippable now and the endpoint can backfill later. */

export type GraphNodeKind =
  | "hypothesis"
  | "evidence"
  | "crash"
  | "exploit"
  | "advisory"
  | "obligation";

export type GraphEdgeKind =
  | "supports"
  | "refutes"
  | "found_by"
  | "exploits"
  | "derived_from";

export interface GraphNodeInput {
  id: string;
  kind: GraphNodeKind;
  label: string;
  state?: string;
  meta?: Record<string, unknown>;
}

export interface GraphEdgeInput {
  id: string;
  source: string;
  target: string;
  kind: GraphEdgeKind;
}

const NODE_TONE: Record<
  GraphNodeKind,
  { bg: string; border: string; tone: "info" | "low" | "medium" | "high" | "critical" }
> = {
  hypothesis: { bg: "#1e3a8a", border: "#3b82f6", tone: "info" },     // blue
  evidence:   { bg: "#14532d", border: "#22c55e", tone: "low" },      // green
  crash:      { bg: "#7f1d1d", border: "#ef4444", tone: "critical" }, // red
  exploit:    { bg: "#7c2d12", border: "#f97316", tone: "high" },     // orange
  advisory:   { bg: "#581c87", border: "#a855f7", tone: "medium" },   // purple
  obligation: { bg: "#374151", border: "#9ca3af", tone: "info" },     // gray
};

const EDGE_STYLE: Record<
  GraphEdgeKind,
  { stroke: string; dashed?: boolean; label: string }
> = {
  supports:     { stroke: "#22c55e", label: "supports" },
  refutes:      { stroke: "#ef4444", label: "refutes" },
  found_by:     { stroke: "#9ca3af", label: "found_by" },
  exploits:     { stroke: "#f97316", label: "exploits" },
  derived_from: { stroke: "#9ca3af", dashed: true, label: "derived_from" },
};

/** Lay out nodes in concentric tiers by kind. Cheap dagre alternative
 *  that works without an extra dep — hypotheses ring inside, evidence
 *  outside, crashes/exploits/advisories on the perimeter, obligations
 *  off to one side. */
function layout(nodes: GraphNodeInput[]): Map<string, { x: number; y: number }> {
  const tiers: Record<GraphNodeKind, GraphNodeInput[]> = {
    hypothesis: [],
    evidence: [],
    crash: [],
    exploit: [],
    advisory: [],
    obligation: [],
  };
  for (const n of nodes) tiers[n.kind].push(n);

  const positions = new Map<string, { x: number; y: number }>();

  const rings: Array<{ kind: GraphNodeKind; radius: number }> = [
    { kind: "hypothesis", radius: 0 },
    { kind: "evidence", radius: 200 },
    { kind: "crash", radius: 400 },
    { kind: "exploit", radius: 400 },
    { kind: "advisory", radius: 400 },
    { kind: "obligation", radius: 600 },
  ];

  for (const ring of rings) {
    const items = tiers[ring.kind];
    if (items.length === 0) continue;
    if (ring.radius === 0) {
      // Stack hypotheses in a column at the origin
      items.forEach((n, i) =>
        positions.set(n.id, { x: 0, y: i * 110 - ((items.length - 1) * 110) / 2 }),
      );
      continue;
    }
    items.forEach((n, i) => {
      const angle = (2 * Math.PI * i) / Math.max(items.length, 1);
      positions.set(n.id, {
        x: ring.radius * Math.cos(angle),
        y: ring.radius * Math.sin(angle),
      });
    });
  }
  return positions;
}

type GraphFilter = "all" | "confirmed" | "rejected" | "unresolved" | "tainted";

export function EvidenceGraph({
  nodes: rawNodes,
  edges: rawEdges,
  height = 600,
  onNodeClick,
  showLabels = true,
}: {
  nodes: GraphNodeInput[];
  edges: GraphEdgeInput[];
  height?: number;
  onNodeClick?: (node: GraphNodeInput) => void;
  showLabels?: boolean;
}) {
  const [filter, setFilter] = useState<GraphFilter>("all");
  const [searchText, setSearchText] = useState("");
  const [edgeLabels, setEdgeLabels] = useState(showLabels);

  // Apply filter
  const { filteredNodes, filteredEdges } = useMemo(() => {
    const search = searchText.trim().toLowerCase();
    let nodes = rawNodes;
    if (search) {
      const matchIds = new Set(
        nodes
          .filter((n) => n.label.toLowerCase().includes(search))
          .map((n) => n.id),
      );
      // include directly-connected neighbours
      for (const e of rawEdges) {
        if (matchIds.has(e.source)) matchIds.add(e.target);
        if (matchIds.has(e.target)) matchIds.add(e.source);
      }
      nodes = nodes.filter((n) => matchIds.has(n.id));
    }
    switch (filter) {
      case "confirmed":
        nodes = nodes.filter(
          (n) =>
            (n.kind === "hypothesis" && n.state === "confirmed") ||
            (n.kind === "evidence" && hasRelated(rawEdges, n.id, "hypothesis", rawNodes, "confirmed")),
        );
        break;
      case "rejected":
        nodes = nodes.filter(
          (n) =>
            (n.kind === "hypothesis" && (n.state === "refuted" || n.state === "tainted")) ||
            (n.kind === "evidence" && hasRelated(rawEdges, n.id, "hypothesis", rawNodes, "refuted")),
        );
        break;
      case "unresolved":
        nodes = nodes.filter(
          (n) =>
            (n.kind === "hypothesis" && (!n.state || n.state === "open")) ||
            (n.kind === "obligation" && (!n.state || n.state === "open")),
        );
        break;
      case "tainted":
        // Show nodes downstream of a tainted hypothesis
        nodes = nodes.filter(
          (n) =>
            n.state === "tainted" ||
            downstreamOf(rawEdges, n.id).some((id) => {
              const t = rawNodes.find((x) => x.id === id);
              return t?.state === "tainted";
            }),
        );
        break;
    }
    const ids = new Set(nodes.map((n) => n.id));
    const edges = rawEdges.filter((e) => ids.has(e.source) && ids.has(e.target));
    return { filteredNodes: nodes, filteredEdges: edges };
  }, [rawNodes, rawEdges, filter, searchText]);

  const positions = useMemo(() => layout(filteredNodes), [filteredNodes]);

  const flowNodes: Node[] = useMemo(
    () =>
      filteredNodes.map((n) => {
        const tone = NODE_TONE[n.kind];
        const p = positions.get(n.id) ?? { x: 0, y: 0 };
        return {
          id: n.id,
          position: p,
          data: {
            label: (
              <div className="text-left" style={{ color: "white" }}>
                <div className="text-[10px] uppercase opacity-70">{n.kind}</div>
                <div className="text-xs font-mono truncate max-w-[180px]">
                  {n.label}
                </div>
                {n.state && (
                  <div className="text-[10px] opacity-80 mt-1">{n.state}</div>
                )}
              </div>
            ),
          },
          style: {
            background: tone.bg,
            border: `2px ${n.kind === "obligation" && n.state === "open" ? "dashed" : "solid"} ${tone.border}`,
            borderRadius:
              n.kind === "crash" || n.kind === "exploit" ? 999 : 6,
            padding: 6,
            width: 210,
            color: "white",
          },
        };
      }),
    [filteredNodes, positions],
  );

  const flowEdges: Edge[] = useMemo(
    () =>
      filteredEdges.map((e) => {
        const s = EDGE_STYLE[e.kind];
        return {
          id: e.id,
          source: e.source,
          target: e.target,
          label: edgeLabels ? s.label : undefined,
          labelStyle: { fontSize: 10, fill: "#9ca3af" },
          labelBgStyle: { fill: "#1f2937" },
          style: {
            stroke: s.stroke,
            strokeWidth: 1.5,
            strokeDasharray: s.dashed ? "4 4" : undefined,
          },
          markerEnd: {
            type: MarkerType.ArrowClosed,
            color: s.stroke,
            width: 12,
            height: 12,
          },
        };
      }),
    [filteredEdges, edgeLabels],
  );

  return (
    <div className="space-y-2">
      {/* Toolbar */}
      <div className="flex items-center gap-2 flex-wrap text-xs">
        <span className="text-text-muted">View:</span>
        {(
          [
            "all",
            "confirmed",
            "rejected",
            "unresolved",
            "tainted",
          ] as GraphFilter[]
        ).map((f) => (
          <button
            key={f}
            type="button"
            onClick={() => setFilter(f)}
            className={
              "px-2 py-0.5 rounded font-mono " +
              (filter === f
                ? "bg-accent text-white"
                : "bg-surface border border-border-default text-text-muted hover:bg-surface-hover")
            }
          >
            {f}
          </button>
        ))}
        <input
          type="text"
          value={searchText}
          onChange={(e) => setSearchText(e.target.value)}
          placeholder="search labels…"
          className="ml-auto px-2 py-0.5 text-xs font-mono rounded bg-surface border border-border-default"
        />
        <button
          type="button"
          onClick={() => setEdgeLabels((v) => !v)}
          className="px-2 py-0.5 text-xs font-mono rounded bg-surface border border-border-default hover:bg-surface-hover"
          title="Edge labels become unreadable past ~40 nodes"
        >
          {edgeLabels ? "Labels: on" : "Labels: off"}
        </button>
      </div>

      <div
        className="border border-border-default rounded-md overflow-hidden bg-surface/30"
        style={{ height }}
      >
        {filteredNodes.length === 0 ? (
          <div className="h-full flex items-center justify-center text-xs text-text-muted">
            No nodes match the current filter.
          </div>
        ) : (
          <ReactFlow
            nodes={flowNodes}
            edges={flowEdges}
            fitView
            onNodeClick={(_, node) => {
              const raw = rawNodes.find((n) => n.id === node.id);
              if (raw && onNodeClick) onNodeClick(raw);
            }}
            proOptions={{ hideAttribution: true }}
          >
            <Background gap={20} color="#374151" />
            <Controls position="bottom-right" showInteractive={false} />
          </ReactFlow>
        )}
      </div>

      {/* Legend */}
      <div className="flex items-center gap-2 flex-wrap text-[10px] text-text-muted">
        <span>Legend:</span>
        {(Object.keys(NODE_TONE) as GraphNodeKind[]).map((k) => {
          const tone = NODE_TONE[k];
          return (
            <span key={k} className="inline-flex items-center gap-1">
              <span
                className="w-2 h-2 rounded-sm inline-block"
                style={{ background: tone.bg, border: `1px solid ${tone.border}` }}
              />
              {k}
            </span>
          );
        })}
        <span className="ml-2">|</span>
        {(Object.keys(EDGE_STYLE) as GraphEdgeKind[]).map((k) => {
          const s = EDGE_STYLE[k];
          return (
            <span key={k} className="inline-flex items-center gap-1">
              <span
                className="inline-block w-3 h-0.5"
                style={{
                  background: s.stroke,
                  borderTop: s.dashed ? `2px dashed ${s.stroke}` : undefined,
                  height: s.dashed ? 0 : 2,
                }}
              />
              {s.label}
            </span>
          );
        })}
        <span className="ml-auto text-text-muted">
          <AilaBadge severity="info" size="sm">
            {filteredNodes.length} / {rawNodes.length} nodes
          </AilaBadge>
        </span>
      </div>
    </div>
  );
}

function hasRelated(
  edges: GraphEdgeInput[],
  nodeId: string,
  targetKind: GraphNodeKind,
  nodes: GraphNodeInput[],
  targetState: string,
): boolean {
  for (const e of edges) {
    if (e.source !== nodeId) continue;
    const t = nodes.find((n) => n.id === e.target);
    if (t?.kind === targetKind && t.state === targetState) return true;
  }
  return false;
}

function downstreamOf(edges: GraphEdgeInput[], nodeId: string): string[] {
  const out: string[] = [];
  const visited = new Set<string>([nodeId]);
  const stack = [nodeId];
  while (stack.length) {
    const cur = stack.pop()!;
    for (const e of edges) {
      if (e.source === cur && !visited.has(e.target)) {
        visited.add(e.target);
        stack.push(e.target);
        out.push(e.target);
      }
    }
  }
  return out;
}
