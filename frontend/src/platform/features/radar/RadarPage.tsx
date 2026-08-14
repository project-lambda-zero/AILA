/**
 * RadarPage.tsx -- Network Radar page at /radar (Phase 144).
 *
 * Assembles the ReactFlow topology graph with toolbar and inspect panel.
 * Operator+ role required (enforced in router.tsx and by the backend).
 *
 * State:
 * - colorBy: active color-by mode (local state)
 * - filter: search + severity filters (local state)
 * - subnetGrouping: whether to group nodes by /24 subnet (local state)
 * - selectedNode: clicked topology node (local state)
 * - inspectOpen: inspect panel visibility (local state)
 */
import * as React from "react";

import { AilaCard } from "@/components/aila/AilaCard";
import { LoadingSkeleton } from "@/components/aila/LoadingSkeleton";
import { EmptyState } from "@/components/aila/EmptyState";
import { GlobeHemisphereEast } from "@phosphor-icons/react/dist/csr/GlobeHemisphereEast";
import { WifiSlash } from "@phosphor-icons/react/dist/csr/WifiSlash";
import { FeatureBoundary } from "@app/FeatureBoundary";
import { RadarGraph } from "./RadarGraph";
import { RadarInspectPanel } from "./RadarInspectPanel";
import { RadarToolbar } from "./RadarToolbar";
import { useTopology } from "./useTopology";
import { filterNodes } from "./topologyUtils";
import type { ColorByMode, RadarFilter, TopologyNode } from "./types";

export function RadarPage() {
  const [colorBy, setColorBy] = React.useState<ColorByMode>("vulnerabilities");
  const [filter, setFilter] = React.useState<RadarFilter>({ search: "", severities: [] });
  const [subnetGrouping, setSubnetGrouping] = React.useState(true);
  const [selectedNode, setSelectedNode] = React.useState<TopologyNode | null>(null);
  const [inspectOpen, setInspectOpen] = React.useState(false);

  const { data: topology, isLoading, isError, error, refetch } = useTopology();

  const handleNodeClick = React.useCallback((node: TopologyNode) => {
    setSelectedNode(node);
    setInspectOpen(true);
  }, []);

  const handleInspectClose = React.useCallback(() => {
    setInspectOpen(false);
  }, []);

  // Compute filtered count for toolbar
  const filteredCount = React.useMemo(() => {
    if (!topology) return 0;
    return filterNodes(topology.nodes, filter).length;
  }, [topology, filter]);

  // Loading state
  if (isLoading) {
    return (
      <div className="flex flex-col p-4 gap-3" style={{ height: "70vh" }}>
        <LoadingSkeleton size="md" width="quarter" />
        <LoadingSkeleton size="full" width="full" />
      </div>
    );
  }

  // Error state
  if (isError) {
    return (
      <div className="flex items-center justify-center p-4" style={{ height: "70vh" }}>
        <div className="max-w-md w-full">
          <EmptyState
            icon={<WifiSlash className="h-10 w-10" />}
            title="Failed to load network topology"
            description={
              (error instanceof Error ? error.message : "Unknown error occurred.") +
              " Ensure you have operator or admin role. The topology endpoint requires operator+ access."
            }
            action={{ label: "Try again", onClick: () => void refetch() }}
          />
        </div>
      </div>
    );
  }

  // Empty state (API returned successfully but no systems registered)
  if (!topology || topology.nodes.length === 0) {
    return (
      <div className="flex items-center justify-center p-4" style={{ height: "70vh" }}>
        <div className="max-w-md w-full">
          <EmptyState
            icon={<GlobeHemisphereEast className="h-10 w-10" />}
            title="No network data yet"
            description="No systems have been discovered. Add systems on the Systems page and run a discovery scan to populate the radar."
            action={{ label: "Go to Systems", href: "/systems" }}
          />
        </div>
      </div>
    );
  }

  return (
    <div className="flex flex-col h-full">
      <RadarToolbar
        colorBy={colorBy}
        onColorByChange={setColorBy}
        filter={filter}
        onFilterChange={setFilter}
        subnetGrouping={subnetGrouping}
        onSubnetGroupingChange={setSubnetGrouping}
        nodeCount={topology.nodes.length}
        filteredCount={filteredCount}
      />

      <div className="relative w-full" style={{ height: "70vh" }}>
        <FeatureBoundary
          label="Network radar graph"
          resetKeys={[topology.nodes.length, colorBy, subnetGrouping]}
          onReset={() => void refetch()}
        >
          <RadarGraph
            nodes={topology.nodes}
            edges={topology.edges}
            subnets={topology.subnets}
            colorBy={colorBy}
            filter={filter}
            subnetGrouping={subnetGrouping}
            onNodeClick={handleNodeClick}
          />
        </FeatureBoundary>
      </div>

      <RadarInspectPanel
        node={selectedNode}
        open={inspectOpen}
        onClose={handleInspectClose}
      />
    </div>
  );
}
