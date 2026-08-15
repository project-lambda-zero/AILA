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

/** EvidenceGraph -- first-class evidence rendering surface from
 *  08_FRONTEND_UX.md §1.9 / §3.
 *
 *  Six node types, five edge types. Node tones come from AILA design
 *  tokens (passed via inline `style.background` because ReactFlow
 *  needs concrete colours and CSS vars don't resolve inside SVG fills
 *  on the edges layer -- same gotcha as Recharts, per CLAUDE.md
 *  mistake #4).
 *
 *  Server-side layout is now authoritative: callers can pass
 *  `serverPositions` (from `useEvidenceGraph` → `EvidenceGraphSnapshot`)
 *  and the component will honour the server-computed x/y. The
 *  client-side concentric layout below kicks in only when the snapshot
 *  is unavailable (e.g. ephemeral cards built from local data). */

export type GraphNodeKind =
  | "investigation"
  | "branch"
  | "hypothesis"
  | "evidence"
  | "crash"
  | "exploit"
  | "advisory"
  | "obligation"
  | "outcome"
  | "finding";

export type GraphEdgeKind =
  | "supports"
  | "refutes"
  | "found_by"
  | "exploits"
  | "derived_from"
  | "spawned"
  | "produced"
  | "raises"
  | "rejects"
  | "resolves"
  | "linked"
  | "produced_finding";

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
  investigation: { bg: "color-mix(in srgb, var(--color-peach) 16%, var(--color-base))", border: "var(--color-peach)", tone: "info" },     // signal root
  branch:     { bg: "color-mix(in srgb, var(--color-lavender) 16%, var(--color-base))", border: "var(--color-lavender)", tone: "info" },         // lavender persona-thread
  hypothesis: { bg: "color-mix(in srgb, var(--color-medium) 16%, var(--color-base))", border: "var(--color-medium)", tone: "info" },         // medium -- thinking
  evidence:   { bg: "color-mix(in srgb, var(--color-mint) 16%, var(--color-base))", border: "var(--color-mint)", tone: "low" },          // mint -- fact
  crash:      { bg: "color-mix(in srgb, var(--color-accent) 16%, var(--color-base))", border: "var(--color-accent)", tone: "critical" },     // critical
  exploit:    { bg: "color-mix(in srgb, var(--color-amber) 16%, var(--color-base))", border: "var(--color-amber)", tone: "high" },         // amber runtime proof
  advisory:   { bg: "color-mix(in srgb, var(--color-lavender) 16%, var(--color-base))", border: "var(--color-lavender)", tone: "medium" },       // lavender doc
  obligation: { bg: "color-mix(in srgb, var(--color-text-muted) 16%, var(--color-base))", border: "var(--color-text-muted)", tone: "info" },         // muted
  outcome:    { bg: "color-mix(in srgb, var(--color-accent) 16%, var(--color-base))", border: "var(--color-accent)", tone: "medium" },       // accent terminal artifact
  finding:    { bg: "color-mix(in srgb, var(--color-medium) 16%, var(--color-base))", border: "var(--color-medium)", tone: "medium" },       // medium dispatched finding
};

const EDGE_STYLE: Record<
  GraphEdgeKind,
  { stroke: string; dashed?: boolean; label: string }
> = {
  supports:         { stroke: "var(--color-mint)", label: "supports" },
  refutes:          { stroke: "var(--color-accent)", label: "refutes" },
  found_by:         { stroke: "var(--color-text-muted)", label: "found_by" },
  exploits:         { stroke: "var(--color-amber)", label: "exploits" },
  derived_from:     { stroke: "var(--color-text-muted)", dashed: true, label: "derived_from" },
  spawned:          { stroke: "var(--color-lavender)", label: "spawned" },
  produced:         { stroke: "var(--color-amber)", label: "produced" },
  raises:           { stroke: "var(--color-medium)", label: "raises" },
  rejects:          { stroke: "var(--color-accent)", dashed: true, label: "rejects" },
  resolves:         { stroke: "var(--color-mint)", dashed: true, label: "resolves" },
  linked:           { stroke: "var(--color-medium)", dashed: true, label: "linked" },
  produced_finding: { stroke: "var(--color-medium)", label: "produced_finding" },
};

/** Lay out nodes in concentric tiers by kind. Cheap dagre alternative
 *  that works without an extra dep -- hypotheses ring inside, evidence
 *  outside, crashes/exploits/advisories on the perimeter, obligations
 *  off to one side. */
function layout(nodes: GraphNodeInput[]): Map<string, { x: number; y: number }> {
  const tiers: Record<GraphNodeKind, GraphNodeInput[]> = {
    investigation: [],
    branch: [],
    hypothesis: [],
    evidence: [],
    crash: [],
    exploit: [],
    advisory: [],
    obligation: [],
    outcome: [],
    finding: [],
  };
  for (const n of nodes) tiers[n.kind].push(n);

  const positions = new Map<string, { x: number; y: number }>();

  const rings: Array<{ kind: GraphNodeKind; radius: number }> = [
    { kind: "investigation", radius: 0 },
    { kind: "branch", radius: 220 },
    { kind: "hypothesis", radius: 310 },
    { kind: "evidence", radius: 310 },
    { kind: "outcome", radius: 400 },
    { kind: "crash", radius: 400 },
    { kind: "exploit", radius: 400 },
    { kind: "advisory", radius: 400 },
    { kind: "finding", radius: 520 },
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


type LayoutAlgo = "concentric" | "radial" | "grid";

function layoutGrid(nodes: GraphNodeInput[]): Map<string, { x: number; y: number }> {
  // Group by kind, render each kind in a row with even spacing.
  const tiers: Record<GraphNodeKind, GraphNodeInput[]> = {
    investigation: [],
    branch: [],
    hypothesis: [],
    evidence: [],
    crash: [],
    exploit: [],
    advisory: [],
    obligation: [],
    outcome: [],
    finding: [],
  };
  for (const n of nodes) tiers[n.kind].push(n);
  const positions = new Map<string, { x: number; y: number }>();
  const colW = 260;
  const rowH = 120;
  let rowIdx = 0;
  for (const kind of Object.keys(tiers) as GraphNodeKind[]) {
    tiers[kind].forEach((n, i) => {
      positions.set(n.id, { x: i * colW, y: rowIdx * rowH });
    });
    if (tiers[kind].length > 0) rowIdx++;
  }
  return positions;
}

function layoutRadial(nodes: GraphNodeInput[]): Map<string, { x: number; y: number }> {
  // Single concentric ring, all nodes equally spaced.
  const positions = new Map<string, { x: number; y: number }>();
  const r = Math.max(200, nodes.length * 15);
  nodes.forEach((n, i) => {
    const angle = (2 * Math.PI * i) / Math.max(nodes.length, 1);
    positions.set(n.id, {
      x: r * Math.cos(angle),
      y: r * Math.sin(angle),
    });
  });
  return positions;
}
type GraphFilter = "all" | "confirmed" | "rejected" | "unresolved" | "tainted";

export function EvidenceGraph({
  nodes: rawNodes,
  edges: rawEdges,
  height = 600,
  onNodeClick,
  showLabels = true,
  serverPositions,
}: {
  nodes: GraphNodeInput[];
  edges: GraphEdgeInput[];
  height?: number;
  /** Called with the raw node and the click event so callers can branch
   *  on cmd/ctrl-click (open in new tab per §3.6) vs primary-click. */
  onNodeClick?: (node: GraphNodeInput, event: React.MouseEvent) => void;
  showLabels?: boolean;
  /** Server-computed x/y per node-id. When present, overrides the
   *  client-side layout algorithms (08_FRONTEND_UX.md §1.9). The
   *  layout picker is hidden when serverPositions is in effect since
   *  the server is the authority. */
  serverPositions?: Map<string, { x: number; y: number }>;
}) {
  const [filter, setFilter] = useState<GraphFilter>("all");
  const [searchText, setSearchText] = useState("");
  const [edgeLabels, setEdgeLabels] = useState(showLabels);
  const [layoutAlgo, setLayoutAlgo] = useState<LayoutAlgo>("concentric");

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

  const positions = useMemo(() => {
    // Server-side authoritative layout takes precedence when
    // supplied. Falls back to local algorithms when the snapshot
    // is missing or empty (08_FRONTEND_UX.md §1.9).
    if (serverPositions && serverPositions.size > 0) {
      // Server coords are id-keyed against the original rawNodes
      // -- clip to the filtered subset to honour search/filter
      // without re-running the layout client-side.
      const filtered = new Map<string, { x: number; y: number }>();
      for (const n of filteredNodes) {
        const p = serverPositions.get(n.id);
        if (p) filtered.set(n.id, p);
      }
      // If the server snapshot doesn't cover every node (e.g. the
      // client synthesised extra nodes the backend doesn't model),
      // fall back to layout() for the orphans.
      if (filtered.size < filteredNodes.length) {
        const fallback = layout(filteredNodes);
        for (const n of filteredNodes) {
          if (!filtered.has(n.id)) {
            const p = fallback.get(n.id);
            if (p) filtered.set(n.id, p);
          }
        }
      }
      return filtered;
    }
    if (layoutAlgo === "grid") return layoutGrid(filteredNodes);
    if (layoutAlgo === "radial") return layoutRadial(filteredNodes);
    return layout(filteredNodes);
  }, [filteredNodes, layoutAlgo, serverPositions]);

  const flowNodes: Node[] = useMemo(
    () =>
      filteredNodes.map((n) => {
        const tone = NODE_TONE[n.kind];
        const p = positions.get(n.id) ?? { x: 0, y: 0 };
        return {
          id: n.id,
          position: p,
          ariaLabel: `${n.kind} ${n.label}${n.state ? ` (${n.state})` : ""}`,
          data: {
            label: (
              <div
                className="text-left"
                style={{ color: "var(--color-text)" }}
                aria-label={`${n.kind} ${n.label}${n.state ? ` (${n.state})` : ""}`}
                role="article"
              >
                <div className="text-3xs uppercase opacity-70">{n.kind}</div>
                <div className="text-xs font-mono truncate" style={{ maxWidth: 180 }}>
                  {n.label}
                </div>
                {n.state && (
                  <div className="text-3xs opacity-80 mt-1">{n.state}</div>
                )}
              </div>
            ),
          },
          style: {
            background: tone.bg,
            border: `2px ${n.kind === "obligation" && n.state === "open" ? "dashed" : "solid"} ${tone.border}`,
            borderRadius: 4,
            padding: 6,
            width: 210,
            color: "var(--color-text)",
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
          labelStyle: { fontSize: 10, fill: "var(--color-text-muted)" },
          labelBgStyle: { fill: "var(--color-elevated)" },
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
                ? "bg-accent text-background"
                : "bg-surface border border-border text-text-muted hover:bg-elevated")
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
          aria-label="Search evidence graph"
          className="ml-auto px-2 py-0.5 text-xs font-mono rounded bg-surface border border-border"
        />
        <button
          type="button"
          onClick={() => setEdgeLabels((v) => !v)}
          className="px-2 py-0.5 text-xs font-mono rounded bg-surface border border-border hover:bg-elevated"
          title="Edge labels become unreadable past ~40 nodes"
        >
          {edgeLabels ? "Labels: on" : "Labels: off"}
        </button>
        <select
          value={layoutAlgo}
          onChange={(e) => setLayoutAlgo(e.target.value as LayoutAlgo)}
          className="px-2 py-0.5 text-xs font-mono rounded bg-surface border border-border"
          aria-label="Layout algorithm"
          title="Layout algorithm -- concentric tiers, single radial ring, or kind-grouped grid"
        >
          <option value="concentric">layout: concentric</option>
          <option value="radial">layout: radial</option>
          <option value="grid">layout: grid</option>
        </select>
      </div>

      <div
        className="border border-border rounded-md overflow-hidden bg-surface/30"
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
            onNodeClick={(event, node) => {
              const raw = rawNodes.find((n) => n.id === node.id);
              if (raw && onNodeClick) onNodeClick(raw, event as unknown as React.MouseEvent);
            }}
            proOptions={{ hideAttribution: true }}
          >
            <Background gap={20} color="var(--color-border)" />
            <Controls position="bottom-right" showInteractive={false} />
          </ReactFlow>
        )}
      </div>

      {/* Legend */}
      <div className="flex items-center gap-2 flex-wrap text-3xs text-text-muted">
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
