/**
 * RadarGraph -- ReactFlow canvas for Network Radar.
 *
 * Physics/layout builders + filtering unchanged; only visual chrome
 * (background/controls/minimap/empty state) retokenized to the mock.
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
import type {
  ColorByMode,
  RadarFilter,
  SubnetGroup,
  TopologyEdge,
  TopologyNode,
} from "./types";

interface RadarGraphProps {
  nodes: TopologyNode[];
  edges: TopologyEdge[];
  subnets: SubnetGroup[];
  colorBy: ColorByMode;
  filter: RadarFilter;
  subnetGrouping: boolean;
  onNodeClick: (node: TopologyNode) => void;
}

const NODE_TYPES = { radarNode: RadarNode } as const;

function RadarGraphInner({
  nodes: topologyNodes,
  edges: topologyEdges,
  colorBy,
  filter,
  subnetGrouping,
  onNodeClick,
}: RadarGraphProps) {
  const { fitView } = useReactFlow();

  const filteredNodes = React.useMemo(
    () => filterNodes(topologyNodes, filter),
    [topologyNodes, filter],
  );

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

  React.useEffect(() => {
    setFlowNodes(initialFlowNodes);
    setFlowEdges(initialFlowEdges);
    const timer = setTimeout(() => {
      void fitView({ padding: 0.2, duration: 400 });
    }, 100);
    return () => clearTimeout(timer);
  }, [initialFlowNodes, initialFlowEdges, setFlowNodes, setFlowEdges, fitView]);

  const handleNodeClick: NodeMouseHandler = React.useCallback(
    (_event, rfNode) => {
      const nodeData = rfNode.data as { node?: TopologyNode };
      if (nodeData.node) {
        onNodeClick(nodeData.node);
      }
    },
    [onNodeClick],
  );

  if (filteredNodes.length === 0) {
    return (
      <div
        className="flex items-center justify-center font-mono uppercase"
        style={{
          height: "100%",
          padding: 24,
          fontSize: 11,
          letterSpacing: "0.14em",
          color: "var(--text-muted)",
          textAlign: "center",
        }}
      >
        {topologyNodes.length === 0
          ? "no network data collected yet"
          : "no systems match the current filters"}
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
      style={{ background: "var(--surface-sunk)" }}
    >
      <Background
        variant={BackgroundVariant.Dots}
        gap={20}
        color="color-mix(in srgb, var(--border) 70%, transparent)"
      />
      <Controls
        style={{
          background: "var(--surface-card)",
          border: "1px solid var(--border-soft)",
          color: "var(--text-primary)",
          borderRadius: 3,
        }}
      />
      <MiniMap
        nodeColor={(n) => {
          const d = n.data as { fillColor?: string };
          return d.fillColor ?? "var(--border)";
        }}
        maskColor="color-mix(in srgb, var(--surface-page) 78%, transparent)"
        style={{
          background: "var(--surface-card)",
          border: "1px solid var(--border-soft)",
          borderRadius: 3,
        }}
      />
    </ReactFlow>
  );
}

export function RadarGraph(props: RadarGraphProps) {
  return (
    <ReactFlowProvider>
      <RadarGraphInner {...props} />
    </ReactFlowProvider>
  );
}
