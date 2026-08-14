/**
 * TopologyCanvas.tsx -- xyflow surface for the Topology console.
 *
 * Wraps the ReactFlow instance in its provider (fitView + node lookups
 * require the provider context) and hoists the imperative focus API so
 * the parent page can zoom into a subnet on sidebar click.
 *
 * Reduced-motion: xyflow's own zoom/pan animations obey the caller's
 * `duration` argument, so we set duration=0 when the user prefers
 * reduced motion. The dot background is static either way.
 */
import "@xyflow/react/dist/style.css";

import * as React from "react";
import {
  Background,
  BackgroundVariant,
  Controls,
  MiniMap,
  ReactFlow,
  ReactFlowProvider,
  useEdgesState,
  useNodesState,
  useReactFlow,
  type Edge,
  type Node,
  type NodeMouseHandler,
  type ReactFlowInstance,
} from "@xyflow/react";

import { useReducedMotion } from "@/hooks/useReducedMotion";
import type {
  SubnetGroup,
  TopologyEdge,
  TopologyNode,
} from "@platform/features/radar/types";
import { TopologyGraphNode } from "./TopologyGraphNode";
import {
  buildEdges,
  buildNodes,
  type TopologyOverlays,
} from "./topologyGraph";

const NODE_TYPES = { topologyNode: TopologyGraphNode } as const;

export interface TopologyCanvasHandle {
  focusSubnet(subnet: string | null, subnets: SubnetGroup[]): void;
}

interface TopologyCanvasProps {
  nodes: TopologyNode[];
  edges: TopologyEdge[];
  overlays: TopologyOverlays;
  focusedSubnet: string | null;
  onNodeClick(node: TopologyNode): void;
}

function TopologyCanvasInner(
  { nodes, edges, overlays, focusedSubnet, onNodeClick }: TopologyCanvasProps,
  ref: React.Ref<TopologyCanvasHandle>,
) {
  const prefersReducedMotion = useReducedMotion();
  const instanceRef = React.useRef<ReactFlowInstance | null>(null);

  const nodesById = React.useMemo(() => {
    const map = new Map<string, TopologyNode>();
    for (const n of nodes) map.set(String(n.id), n);
    return map;
  }, [nodes]);

  const initialFlowNodes = React.useMemo(
    () => buildNodes(nodes, overlays, focusedSubnet),
    [nodes, overlays, focusedSubnet],
  );

  const initialFlowEdges = React.useMemo(() => {
    const visible = new Set(nodes.map((n) => String(n.id)));
    return buildEdges(edges, visible, focusedSubnet, nodesById);
  }, [edges, nodes, nodesById, focusedSubnet]);

  const [flowNodes, setFlowNodes, onNodesChange] =
    useNodesState<Node>(initialFlowNodes);
  const [flowEdges, setFlowEdges, onEdgesChange] =
    useEdgesState<Edge>(initialFlowEdges);

  React.useEffect(() => {
    setFlowNodes(initialFlowNodes);
    setFlowEdges(initialFlowEdges);
  }, [initialFlowNodes, initialFlowEdges, setFlowNodes, setFlowEdges]);

  const { fitView, setCenter, getNode } = useReactFlow();

  React.useImperativeHandle(
    ref,
    () => ({
      focusSubnet(subnet, subnets) {
        const duration = prefersReducedMotion ? 0 : 500;
        if (subnet === null) {
          void fitView({ padding: 0.2, duration });
          return;
        }
        const target = subnets.find((s) => s.subnet_prefix === subnet);
        if (!target || target.system_ids.length === 0) return;
        const positions = target.system_ids
          .map((id) => getNode(String(id)))
          .filter((n): n is Node => n !== undefined)
          .map((n) => n.position);
        if (positions.length === 0) {
          void fitView({ padding: 0.3, duration });
          return;
        }
        const xs = positions.map((p) => p.x);
        const ys = positions.map((p) => p.y);
        const cx = (Math.min(...xs) + Math.max(...xs)) / 2 + 70;
        const cy = (Math.min(...ys) + Math.max(...ys)) / 2 + 55;
        void setCenter(cx, cy, { zoom: 1, duration });
      },
    }),
    [fitView, getNode, setCenter, prefersReducedMotion],
  );

  const handleNodeClick: NodeMouseHandler = React.useCallback(
    (_event, rfNode) => {
      if (rfNode.type !== "topologyNode") return;
      const data = rfNode.data as { node?: TopologyNode };
      if (data.node) onNodeClick(data.node);
    },
    [onNodeClick],
  );

  return (
    <ReactFlow
      nodes={flowNodes}
      edges={flowEdges}
      onInit={(instance) => {
        instanceRef.current = instance;
      }}
      onNodesChange={onNodesChange}
      onEdgesChange={onEdgesChange}
      onNodeClick={handleNodeClick}
      nodeTypes={NODE_TYPES}
      fitView
      fitViewOptions={{ padding: 0.2, duration: prefersReducedMotion ? 0 : 400 }}
      minZoom={0.1}
      maxZoom={2.5}
      proOptions={{ hideAttribution: true }}
      style={{ background: "var(--color-base)" }}
      nodesDraggable
      nodesConnectable={false}
    >
      <Background
        variant={BackgroundVariant.Dots}
        gap={22}
        size={1}
        color="color-mix(in srgb, var(--color-border) 70%, transparent)"
      />
      <Controls
        showInteractive={false}
        style={{
          background: "var(--color-elevated)",
          border: "1px solid var(--color-border)",
          borderRadius: 4,
        }}
      />
      <MiniMap
        pannable
        zoomable
        nodeColor={(n) => {
          const d = n.data as { fill?: string };
          return d.fill ?? "var(--color-border)";
        }}
        maskColor="color-mix(in srgb, var(--color-base) 80%, transparent)"
        style={{
          background: "var(--color-elevated)",
          border: "1px solid var(--color-border)",
          borderRadius: 4,
        }}
      />
    </ReactFlow>
  );
}

const TopologyCanvasInnerFwd = React.forwardRef(TopologyCanvasInner);

export const TopologyCanvas = React.forwardRef<
  TopologyCanvasHandle,
  TopologyCanvasProps
>(function TopologyCanvas(props, ref) {
  return (
    <ReactFlowProvider>
      <TopologyCanvasInnerFwd {...props} ref={ref} />
    </ReactFlowProvider>
  );
});
