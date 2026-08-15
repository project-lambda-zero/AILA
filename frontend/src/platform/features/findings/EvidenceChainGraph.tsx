import { useMemo } from "react";
import {
  ReactFlow,
  Background,
  Controls,
  MiniMap,
  type Node,
  type Edge,
  BackgroundVariant,
  Position,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";

import { MonoBadge } from "@/components/aila/mock";
import { WindowPanel } from "@/components/aila/WindowPanel";
import { LoadingSkeletonGroup } from "@/components/aila/LoadingSkeleton";
import { useEvidenceChain, type EvidenceNode, type EvidenceEdge } from "./api";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

type NodeType = "scan_session" | "advisory" | "cvss" | "epss" | "finding" | "triage";

// ---------------------------------------------------------------------------
// Layout constants -- top-to-bottom layers
// ---------------------------------------------------------------------------

const LAYER_Y: Record<string, number> = {
  scan_session: 0,
  advisory: 120,
  finding: 260,
  cvss: 400,
  epss: 400,
  triage: 540,
};

const NODE_X: Record<string, number> = {
  scan_session: 300,
  advisory: 300,
  finding: 300,
  cvss: 160,
  epss: 440,
  triage: 300,
};

const TYPE_TONE: Record<string, string> = {
  scan_session: "var(--accent)",
  advisory: "var(--status-info)",
  finding: "var(--accent)",
  cvss: "var(--status-warn)",
  epss: "var(--status-ok)",
  triage: "var(--text-muted)",
};

const LEGEND: Array<{ type: NodeType; label: string; tone: "accent" | "info" | "warn" | "ok" | "muted" }> = [
  { type: "scan_session", label: "SCAN", tone: "accent" },
  { type: "advisory", label: "ADVISORY", tone: "info" },
  { type: "finding", label: "FINDING", tone: "accent" },
  { type: "cvss", label: "CVSS", tone: "warn" },
  { type: "epss", label: "EPSS", tone: "ok" },
  { type: "triage", label: "TRIAGE", tone: "muted" },
];

// ---------------------------------------------------------------------------
// Node style by type
// ---------------------------------------------------------------------------

function nodeStyle(type: string, available: boolean): React.CSSProperties {
  return {
    padding: "10px 14px",
    borderRadius: 3,
    fontSize: 11,
    fontFamily: "var(--font-mono)",
    border: available ? "1px solid" : "1px dashed",
    borderColor: available ? (TYPE_TONE[type] ?? "var(--border)") : "var(--border)",
    minWidth: 160,
    maxWidth: 200,
    background: "var(--surface-card)",
    color: "var(--text-primary)",
    opacity: available ? 1 : 0.5,
  };
}

// ---------------------------------------------------------------------------
// Build ReactFlow nodes and edges from API data
// ---------------------------------------------------------------------------

function buildFlowNode(node: EvidenceNode): Node {
  const available = node.metadata.available !== false;
  const type = node.type as NodeType;

  const metaLines = Object.entries(node.metadata)
    .filter(([k]) => k !== "available")
    .slice(0, 4)
    .map(([k, v]) => `${k}: ${v}`)
    .join("\n");

  return {
    id: node.id,
    position: {
      x: NODE_X[type] ?? 300,
      y: LAYER_Y[type] ?? 200,
    },
    data: {
      label: (
        <div>
          <div
            style={{
              fontSize: 9,
              textTransform: "uppercase",
              letterSpacing: "0.12em",
              color: "var(--text-muted)",
              marginBottom: 4,
            }}
          >
            {node.type.replace(/_/g, " ")}
          </div>
          <div style={{ fontWeight: 600, marginBottom: available ? 6 : 0 }}>
            {node.label}
          </div>
          {available && metaLines && (
            <div
              style={{
                fontSize: 9,
                color: "var(--text-muted)",
                whiteSpace: "pre-line",
                lineHeight: 1.4,
              }}
            >
              {metaLines}
            </div>
          )}
          {!available && (
            <div style={{ fontSize: 9, color: "var(--text-faint)", fontStyle: "italic" }}>
              Not available
            </div>
          )}
        </div>
      ),
    },
    style: nodeStyle(node.type, available),
    sourcePosition: Position.Bottom,
    targetPosition: Position.Top,
  };
}

function buildFlowEdge(edge: EvidenceEdge, index: number): Edge {
  return {
    id: `edge-${index}`,
    source: edge.from_id,
    target: edge.to_id,
    label: edge.label,
    labelStyle: {
      fontSize: 9,
      fontFamily: "var(--font-mono)",
      fill: "var(--text-muted)",
    },
    style: { stroke: "var(--border)", strokeWidth: 1.5 },
    animated: edge.from_id === "scan_session",
  };
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

interface EvidenceChainGraphProps {
  findingId: number;
}

/**
 * EvidenceChainGraph -- ReactFlow graph showing finding evidence provenance (UX-05).
 *
 * Layers (top to bottom):
 *   Scan Session → Advisory → Finding → CVSS + EPSS → Triage Decision
 *
 * Nodes with unavailable data are shown with dashed borders and muted text.
 */
export function EvidenceChainGraph({ findingId }: EvidenceChainGraphProps) {
  const { data, isLoading, isError, error } = useEvidenceChain(findingId);

  const { nodes, edges } = useMemo(() => {
    const chain = data?.data;
    if (!chain) return { nodes: [] as Node[], edges: [] as Edge[] };
    return {
      nodes: chain.nodes.map(buildFlowNode),
      edges: chain.edges.map(buildFlowEdge),
    };
  }, [data]);

  const legend = (
    <div className="flex flex-wrap items-center" style={{ gap: 6 }}>
      {LEGEND.map((entry) => (
        <MonoBadge key={entry.type} tone={entry.tone}>
          {entry.label}
        </MonoBadge>
      ))}
    </div>
  );

  if (isLoading) {
    return (
      <WindowPanel title="evidence chain" status="LOADING" tone="muted">
        <LoadingSkeletonGroup lines={6} />
      </WindowPanel>
    );
  }

  if (isError) {
    return (
      <WindowPanel title="evidence chain" tone="warn">
        <div
          className="font-mono"
          style={{
            border: "1px solid color-mix(in srgb, var(--status-warn) 40%, transparent)",
            background: "color-mix(in srgb, var(--status-warn) 10%, transparent)",
            color: "var(--status-warn)",
            padding: "8px 12px",
            fontSize: 11,
            borderRadius: 3,
          }}
        >
          Failed to load evidence chain: {(error as Error).message}
        </div>
      </WindowPanel>
    );
  }

  if (nodes.length === 0) {
    return (
      <WindowPanel title="evidence chain" tone="muted" actions={legend}>
        <p
          className="font-mono"
          style={{ fontSize: 11, color: "var(--text-muted)", padding: "6px 0" }}
        >
          No evidence chain data available for this finding.
        </p>
      </WindowPanel>
    );
  }

  return (
    <WindowPanel title="evidence chain" tone="info" actions={legend} flush>
      <div style={{ height: 600, width: "100%" }}>
        <ReactFlow
          nodes={nodes}
          edges={edges}
          fitView
          fitViewOptions={{ padding: 0.2 }}
          nodesDraggable
          nodesConnectable={false}
          elementsSelectable
          proOptions={{ hideAttribution: true }}
        >
          <Background variant={BackgroundVariant.Dots} gap={16} size={1} color="var(--border-faint)" />
          <MiniMap
            nodeColor={() => "var(--accent)"}
            style={{
              background: "var(--surface-sunk)",
              border: "1px solid var(--border-soft)",
            }}
          />
          <Controls />
        </ReactFlow>
      </div>
    </WindowPanel>
  );
}
