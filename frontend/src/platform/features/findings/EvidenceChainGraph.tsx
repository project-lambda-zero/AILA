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

// ---------------------------------------------------------------------------
// Node color by type
// ---------------------------------------------------------------------------

function nodeStyle(type: string, available: boolean): React.CSSProperties {
  const base: React.CSSProperties = {
    padding: "10px 14px",
    borderRadius: 4,
    fontSize: 11,
    fontFamily: "JetBrains Mono, monospace",
    border: available ? "1px solid" : "1px dashed",
    minWidth: 160,
    maxWidth: 200,
    background: "var(--color-surface)",
    color: "var(--color-text)",
  };

  const borderColors: Record<string, string> = {
    scan_session: "var(--color-accent)",
    advisory: "var(--color-lavender)",
    finding: "var(--color-critical)",
    cvss: "var(--color-medium)",
    epss: "var(--color-mint)",
    triage: "var(--color-border)",
  };

  return {
    ...base,
    borderColor: available
      ? (borderColors[type] ?? "var(--color-border)")
      : "var(--color-border)",
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
          <div style={{ fontSize: 9, textTransform: "uppercase", opacity: 0.6, marginBottom: 4 }}>
            {node.type.replace(/_/g, " ")}
          </div>
          <div style={{ fontWeight: 600, marginBottom: available ? 6 : 0 }}>
            {node.label}
          </div>
          {available && metaLines && (
            <div style={{ fontSize: 9, opacity: 0.7, whiteSpace: "pre-line", lineHeight: 1.4 }}>
              {metaLines}
            </div>
          )}
          {!available && (
            <div style={{ fontSize: 9, opacity: 0.5, fontStyle: "italic" }}>
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
      fontFamily: "JetBrains Mono, monospace",
      fill: "var(--color-text-muted)",
    },
    style: { stroke: "var(--color-border)", strokeWidth: 1.5 },
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
    if (!chain) return { nodes: [], edges: [] };

    return {
      nodes: chain.nodes.map(buildFlowNode),
      edges: chain.edges.map(buildFlowEdge),
    };
  }, [data]);

  if (isLoading) {
    return (
      <div className="p-4">
        <LoadingSkeletonGroup lines={6} />
      </div>
    );
  }

  if (isError) {
    return (
      <div className="rounded-[2px] border border-destructive bg-destructive/10 p-4 font-mono text-xs text-destructive">
        Failed to load evidence chain: {(error as Error).message}
      </div>
    );
  }

  if (nodes.length === 0) {
    return (
      <div className="p-4 font-mono text-xs text-text-muted">
        No evidence chain data available for this finding.
      </div>
    );
  }

  return (
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
        <Background variant={BackgroundVariant.Dots} gap={16} size={1} color="var(--color-border)" />
        <MiniMap
          nodeColor={(node) => {
            const type = (node.data as { label: React.ReactNode })
              ? "var(--color-accent)"
              : "var(--color-border)";
            return type;
          }}
          style={{ background: "var(--color-surface)", border: "1px solid var(--color-border)" }}
        />
        <Controls />
      </ReactFlow>
    </div>
  );
}
