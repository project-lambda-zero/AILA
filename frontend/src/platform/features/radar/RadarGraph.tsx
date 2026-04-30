/**
 * RadarGraph.tsx — ReactFlow canvas for the Network Radar (Phase 144).
 *
 * Renders the topology graph with:
 * - Custom RadarNode nodes (SVG circles, severity colored)
 * - Animated/dashed edges with port/protocol labels
 * - Subnet group node clustering via ReactFlow group type
 * - Background dot grid, Controls, and MiniMap
 * - Auto-fit on data load
 *
 * Per D-03: filtering and colorBy are applied in-memory; no additional API calls.
 */
import "@xyflow/react/dist/style.css";

import * as React from "react";
import {
  ReactFlow,
  ReactFlowProvider,
  Background,
  BackgroundVariant,
  Controls,
  MiniMap,
  useNodesState,
  useEdgesState,
  useReactFlow,
  type Node,
  type Edge,
  type NodeMouseHandler,
} from "@xyflow/react";

import { RadarNode } from "./RadarNode";
import { buildFlowNodes, buildFlowEdges, filterNodes } from "./topologyUtils";
import type { ColorByMode, RadarFilter, SubnetGroup, TopologyEdge, TopologyNode } from "./types";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface RadarGraphProps {
  nodes: TopologyNode[];
  edges: TopologyEdge[];
  subnets: SubnetGroup[];
  colorBy: ColorByMode;
  filter: RadarFilter;
  subnetGrouping: boolean;
  onNodeClick: (node: TopologyNode) => void;
}

// Custom node types — memoized to prevent ReactFlow re-registration
const NODE_TYPES = { radarNode: RadarNode } as const;

// ---------------------------------------------------------------------------
// Inner graph (must be inside ReactFlowProvider)
// ---------------------------------------------------------------------------

function RadarGraphInner({
  nodes: topologyNodes,
  edges: topologyEdges,
  colorBy,
  filter,
  subnetGrouping,
  onNodeClick,
}: RadarGraphProps) {
  const { fitView } = useReactFlow();

  // Derive filtered nodes
  const filteredNodes = React.useMemo(
    () => filterNodes(topologyNodes, filter),
    [topologyNodes, filter],
  );

  // Build ReactFlow nodes/edges from filtered topology data
  const initialFlowNodes = React.useMemo(
    () => buildFlowNodes(filteredNodes, colorBy, subnetGrouping),
    [filteredNodes, colorBy, subnetGrouping],
  );

  const initialFlowEdges = React.useMemo(() => {
    const visibleIds = new Set(filteredNodes.map((n) => String(n.id)));
    return buildFlowEdges(topologyEdges, visibleIds);
  }, [filteredNodes, topologyEdges]);

  const [flowNodes, setFlowNodes, onNodesChange] = useNodesState<Node>(initialFlowNodes);
  const [flowEdges, setFlowEdges, onEdgesChange] = useEdgesState<Edge>(initialFlowEdges);

  // Sync ReactFlow state when topology data or filters change
  React.useEffect(() => {
    setFlowNodes(initialFlowNodes);
    setFlowEdges(initialFlowEdges);
    // Fit view after a short delay to allow layout to settle
    const timer = setTimeout(() => {
      void fitView({ padding: 0.2, duration: 400 });
    }, 100);
    return () => clearTimeout(timer);
  }, [initialFlowNodes, initialFlowEdges, setFlowNodes, setFlowEdges, fitView]);

  // Handle node click — extract TopologyNode from ReactFlow node data
  const handleNodeClick: NodeMouseHandler = React.useCallback(
    (_event, rfNode) => {
      const nodeData = rfNode.data as { node?: TopologyNode };
      if (nodeData.node) {
        onNodeClick(nodeData.node);
      }
    },
    [onNodeClick],
  );

  // Empty state when no nodes match filters
  if (filteredNodes.length === 0) {
    return (
      <div className="flex items-center justify-center h-full text-muted-foreground">
        <div className="text-center font-mono text-sm">
          {topologyNodes.length === 0
            ? "No network data collected yet.\nRun a discovery scan from the Systems page."
            : "No systems match the current filters."}
        </div>
      </div>
    );
  }

  return (
    <ReactFlow
      nodes={flowNodes}
      edges={flowEdges}
      onNodesChange={onNodesChange}
      onEdgesChange={onEdgesChange}
      onNodeClick={handleNodeClick}
      nodeTypes={NODE_TYPES}
      fitView
      fitViewOptions={{ padding: 0.2 }}
      minZoom={0.1}
      maxZoom={2}
      proOptions={{ hideAttribution: true }}
      style={{ background: "var(--color-base)" }}
    >
      <Background
        variant={BackgroundVariant.Dots}
        gap={20}
        color="var(--color-border)"
      />
      <Controls
        style={{
          background: "var(--color-elevated)",
          border: "1px solid var(--color-border)",
        }}
      />
      <MiniMap
        nodeColor={(n) => {
          const d = n.data as { fillColor?: string };
          return d.fillColor ?? "var(--color-border)";
        }}
        style={{
          background: "var(--color-elevated)",
          border: "1px solid var(--color-border)",
        }}
      />
    </ReactFlow>
  );
}

// ---------------------------------------------------------------------------
// Public export — wraps inner graph with ReactFlowProvider
// ---------------------------------------------------------------------------

export function RadarGraph(props: RadarGraphProps) {
  return (
    <ReactFlowProvider>
      <RadarGraphInner {...props} />
    </ReactFlowProvider>
  );
}
