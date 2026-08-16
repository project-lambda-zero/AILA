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

import { WindowPanel } from "@/components/aila/WindowPanel";
import { FilterChip, MonoBadge, Segmented } from "@/components/aila/mock";

/** EvidenceGraph -- first-class evidence rendering surface from
 *  08_FRONTEND_UX.md §1.9 / §3.
 *
 *  Ten node kinds, twelve edge kinds. Node fills/borders come from the
 *  mock semantic tokens (`--accent`, `--status-*`, `--text-*`) passed
 *  inline via `style.background`/`style.stroke` because ReactFlow needs
 *  concrete colours -- CSS vars still resolve at render time inside the
 *  DOM `style` attribute, but not inside SVG `fill` shorthand in older
 *  chrome. Same gotcha as Recharts, per CLAUDE.md mistake #4.
 *
 *  Server-side layout is authoritative: callers pass `serverPositions`
 *  from `useEvidenceGraph` and the component honours the snapshot; the
 *  client-side concentric/radial/grid algorithms kick in only when the
 *  snapshot is unavailable (ephemeral cards built from local data). */

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

// Mock-token hue per node kind. investigation=accent, branch=status-info,
// hypothesis=status-signal, evidence=text-faint, crash=status-warn,
// exploit=accent, advisory=text-muted, obligation=status-info,
// outcome=status-ok, finding=accent.
const NODE_HUE: Record<GraphNodeKind, string> = {
  investigation: "var(--accent)",
  branch: "var(--status-info)",
  hypothesis: "var(--status-signal)",
  evidence: "var(--text-faint)",
  crash: "var(--status-warn)",
  exploit: "var(--accent)",
  advisory: "var(--text-muted)",
  obligation: "var(--status-info)",
  outcome: "var(--status-ok)",
  finding: "var(--accent)",
};

// Mock-token stroke per edge kind. supports=status-ok, refutes=accent,
// everything else defaults to text-muted.
const EDGE_STROKE: Record<GraphEdgeKind, string> = {
  supports: "var(--status-ok)",
  refutes: "var(--accent)",
  found_by: "var(--text-muted)",
  exploits: "var(--text-muted)",
  derived_from: "var(--text-muted)",
  spawned: "var(--text-muted)",
  produced: "var(--text-muted)",
  raises: "var(--text-muted)",
  rejects: "var(--text-muted)",
  resolves: "var(--text-muted)",
  linked: "var(--text-muted)",
  produced_finding: "var(--text-muted)",
};

const EDGE_DASHED: Partial<Record<GraphEdgeKind, boolean>> = {
  derived_from: true,
  rejects: true,
  resolves: true,
  linked: true,
};

const EDGE_LABEL: Record<GraphEdgeKind, string> = {
  supports: "supports",
  refutes: "refutes",
  found_by: "found_by",
  exploits: "exploits",
  derived_from: "derived_from",
  spawned: "spawned",
  produced: "produced",
  raises: "raises",
  rejects: "rejects",
  resolves: "resolves",
  linked: "linked",
  produced_finding: "produced_finding",
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
  wrap = true,
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
  /** Wrap in a `<WindowPanel title="evidence graph" flush>`. Defaults on.
   *  Pass `false` when the caller already provides an outer panel. */
  wrap?: boolean;
}) {
  const [filter, setFilter] = useState<GraphFilter>("all");
  const [searchText, setSearchText] = useState("");
  const [edgeLabels, setEdgeLabels] = useState(showLabels);
  const [layoutAlgo, setLayoutAlgo] = useState<LayoutAlgo>("concentric");

  const { filteredNodes, filteredEdges } = useMemo(() => {
    const search = searchText.trim().toLowerCase();
    let nodes = rawNodes;
    if (search) {
      const matchIds = new Set(
        nodes.filter((n) => n.label.toLowerCase().includes(search)).map((n) => n.id),
      );
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
            (n.kind === "evidence" &&
              hasRelated(rawEdges, n.id, "hypothesis", rawNodes, "confirmed")),
        );
        break;
      case "rejected":
        nodes = nodes.filter(
          (n) =>
            (n.kind === "hypothesis" &&
              (n.state === "refuted" || n.state === "tainted")) ||
            (n.kind === "evidence" &&
              hasRelated(rawEdges, n.id, "hypothesis", rawNodes, "refuted")),
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
    if (serverPositions && serverPositions.size > 0) {
      const filtered = new Map<string, { x: number; y: number }>();
      for (const n of filteredNodes) {
        const p = serverPositions.get(n.id);
        if (p) filtered.set(n.id, p);
      }
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
        const hue = NODE_HUE[n.kind];
        const p = positions.get(n.id) ?? { x: 0, y: 0 };
        return {
          id: n.id,
          position: p,
          ariaLabel: `${n.kind} ${n.label}${n.state ? ` (${n.state})` : ""}`,
          data: {
            label: (
              <div
                className="font-mono"
                style={{ textAlign: "left", color: "var(--text-primary)" }}
                aria-label={`${n.kind} ${n.label}${n.state ? ` (${n.state})` : ""}`}
                role="article"
              >
                <div
                  style={{
                    fontSize: 9,
                    textTransform: "uppercase",
                    letterSpacing: "0.1em",
                    color: hue,
                  }}
                >
                  {n.kind}
                </div>
                <div
                  style={{
                    fontSize: 11,
                    marginTop: 2,
                    overflow: "hidden",
                    textOverflow: "ellipsis",
                    whiteSpace: "nowrap",
                    maxWidth: 180,
                    color: "var(--text-primary)",
                  }}
                >
                  {n.label}
                </div>
                {n.state && (
                  <div
                    style={{
                      fontSize: 9,
                      marginTop: 3,
                      color: "var(--text-muted)",
                      letterSpacing: "0.06em",
                    }}
                  >
                    {n.state}
                  </div>
                )}
              </div>
            ),
          },
          style: {
            background: `color-mix(in srgb, ${hue} 12%, var(--surface-sunk))`,
            border: `${
              n.kind === "obligation" && n.state === "open" ? "1px dashed" : "1px solid"
            } ${hue}`,
            borderRadius: 3,
            padding: 6,
            width: 210,
            color: "var(--text-primary)",
          },
        };
      }),
    [filteredNodes, positions],
  );

  const flowEdges: Edge[] = useMemo(
    () =>
      filteredEdges.map((e) => {
        const stroke = EDGE_STROKE[e.kind];
        const dashed = EDGE_DASHED[e.kind];
        return {
          id: e.id,
          source: e.source,
          target: e.target,
          label: edgeLabels ? EDGE_LABEL[e.kind] : undefined,
          labelStyle: {
            fontSize: 9,
            fill: "var(--text-muted)",
            fontFamily: "var(--font-mono)",
          },
          labelBgStyle: { fill: "var(--surface-chrome)" },
          style: {
            stroke,
            strokeWidth: 1.25,
            strokeDasharray: dashed ? "4 4" : undefined,
          },
          markerEnd: {
            type: MarkerType.ArrowClosed,
            color: stroke,
            width: 12,
            height: 12,
          },
        };
      }),
    [filteredEdges, edgeLabels],
  );

  const filters: GraphFilter[] = ["all", "confirmed", "rejected", "unresolved", "tainted"];

  const body = (
    <div style={{ display: "flex", flexDirection: "column", gap: 8, padding: wrap ? 8 : 0 }}>
      {/* Toolbar */}
      <div className="flex items-center flex-wrap" style={{ gap: 6 }}>
        <span
          className="font-mono uppercase"
          style={{ fontSize: 9, color: "var(--text-faint)", letterSpacing: "0.1em" }}
        >
          view
        </span>
        {filters.map((f) => (
          <FilterChip key={f} active={filter === f} onClick={() => setFilter(f)}>
            {f}
          </FilterChip>
        ))}
        <span style={{ flex: 1 }} />
        <input
          type="text"
          value={searchText}
          onChange={(e) => setSearchText(e.target.value)}
          placeholder="search labels…"
          aria-label="Search evidence graph"
          className="font-mono"
          style={{
            height: 26,
            padding: "0 8px",
            fontSize: 10,
            width: 180,
            background: "var(--surface-sunk)",
            border: "1px solid var(--border-soft)",
            color: "var(--text-primary)",
            borderRadius: 2,
            outline: "none",
          }}
        />
        <button
          type="button"
          onClick={() => setEdgeLabels((v) => !v)}
          className="font-mono uppercase"
          title="Edge labels become unreadable past ~40 nodes"
          style={{
            height: 26,
            padding: "0 10px",
            fontSize: 9.5,
            letterSpacing: "0.08em",
            color: edgeLabels ? "var(--accent)" : "var(--text-faint)",
            border: `1px solid ${edgeLabels ? "var(--accent)" : "var(--border-soft)"}`,
            background: edgeLabels
              ? "color-mix(in srgb, var(--accent) 11%, transparent)"
              : "transparent",
            borderRadius: 2,
            cursor: "pointer",
          }}
        >
          labels {edgeLabels ? "on" : "off"}
        </button>
        {!serverPositions && (
          <Segmented<LayoutAlgo>
            options={[
              { value: "concentric", label: "CONCENTRIC" },
              { value: "radial", label: "RADIAL" },
              { value: "grid", label: "GRID" },
            ]}
            value={layoutAlgo}
            onChange={setLayoutAlgo}
          />
        )}
      </div>

      <div
        style={{
          border: "1px solid var(--border-soft)",
          background: "var(--surface-sunk)",
          overflow: "hidden",
          height,
        }}
      >
        {filteredNodes.length === 0 ? (
          <div
            className="font-mono"
            style={{
              height: "100%",
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              fontSize: 10.5,
              color: "var(--text-faint)",
              letterSpacing: "0.06em",
            }}
          >
            no nodes match the current filter
          </div>
        ) : (
          <ReactFlow
            nodes={flowNodes}
            edges={flowEdges}
            fitView
            onNodeClick={(event, node) => {
              const raw = rawNodes.find((n) => n.id === node.id);
              if (raw && onNodeClick)
                onNodeClick(raw, event as unknown as React.MouseEvent);
            }}
            proOptions={{ hideAttribution: true }}
          >
            <Background gap={20} color="var(--border-faint)" />
            <Controls position="bottom-right" showInteractive={false} />
          </ReactFlow>
        )}
      </div>

      {/* Legend */}
      <div
        className="flex items-center flex-wrap font-mono"
        style={{
          gap: 8,
          fontSize: 9,
          color: "var(--text-faint)",
          letterSpacing: "0.06em",
        }}
      >
        <span>legend</span>
        {(Object.keys(NODE_HUE) as GraphNodeKind[]).map((k) => {
          const hue = NODE_HUE[k];
          return (
            <span key={k} className="inline-flex items-center" style={{ gap: 4 }}>
              <span
                style={{
                  width: 8,
                  height: 8,
                  display: "inline-block",
                  background: `color-mix(in srgb, ${hue} 25%, var(--surface-sunk))`,
                  border: `1px solid ${hue}`,
                }}
              />
              {k}
            </span>
          );
        })}
        <span style={{ opacity: 0.6 }}>|</span>
        {(Object.keys(EDGE_STROKE) as GraphEdgeKind[]).map((k) => {
          const stroke = EDGE_STROKE[k];
          const dashed = EDGE_DASHED[k];
          return (
            <span key={k} className="inline-flex items-center" style={{ gap: 4 }}>
              <span
                style={{
                  display: "inline-block",
                  width: 14,
                  height: 0,
                  borderTop: `${dashed ? "1.5px dashed" : "1.5px solid"} ${stroke}`,
                }}
              />
              {EDGE_LABEL[k]}
            </span>
          );
        })}
        <span style={{ flex: 1 }} />
        <MonoBadge tone="info">
          {filteredNodes.length}/{rawNodes.length} nodes
        </MonoBadge>
      </div>
    </div>
  );

  if (!wrap) return body;
  return (
    <WindowPanel title="evidence graph" tone="info" flush>
      {body}
    </WindowPanel>
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
