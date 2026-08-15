/**
 * RadarPage -- mock rebuild.
 *
 * SectionHeader('network radar') + RadarToolbar (FilterChip row +
 * Segmented colorBy + count) + WindowPanel(title='radar', flush)
 * hosting RadarGraph. RadarInspectPanel is a right-side WindowPanel
 * shown on node click. Data hooks + physics engine unchanged.
 */
import * as React from "react";

import { LoadingSkeleton } from "@/components/aila/LoadingSkeleton";
import { GlobeHemisphereEast } from "@phosphor-icons/react/dist/csr/GlobeHemisphereEast";
import { WifiSlash } from "@phosphor-icons/react/dist/csr/WifiSlash";
import { FeatureBoundary } from "@app/FeatureBoundary";

import { SectionHeader } from "@/components/aila/mock";
import { WindowPanel } from "@/components/aila/WindowPanel";

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

  const filteredCount = React.useMemo(() => {
    if (!topology) return 0;
    return filterNodes(topology.nodes, filter).length;
  }, [topology, filter]);

  return (
    <div className="flex flex-col" style={{ gap: 16, padding: 20, height: "100%", minHeight: 0 }}>
      <SectionHeader icon={"\u25CE"} title="network radar" />

      <RadarToolbar
        colorBy={colorBy}
        onColorByChange={setColorBy}
        filter={filter}
        onFilterChange={setFilter}
        subnetGrouping={subnetGrouping}
        onSubnetGroupingChange={setSubnetGrouping}
        nodeCount={topology?.nodes.length ?? 0}
        filteredCount={filteredCount}
      />

      <WindowPanel title="radar" flush className="flex flex-col" style={{ flex: 1, minHeight: 0 }}>
        {isLoading ? (
          <div className="flex flex-col" style={{ padding: 16, gap: 10, flex: 1 }}>
            <LoadingSkeleton size="md" width="quarter" />
            <LoadingSkeleton size="full" width="full" className="h-full" />
          </div>
        ) : isError ? (
          <RadarEmpty
            icon={<WifiSlash size={28} />}
            title="failed to load network topology"
            detail={
              (error instanceof Error ? error.message : "unknown error occurred.") +
              " ensure you have operator or admin role."
            }
            action={{ label: "try again", onClick: () => void refetch() }}
          />
        ) : !topology || topology.nodes.length === 0 ? (
          <RadarEmpty
            icon={<GlobeHemisphereEast size={28} />}
            title="no network data yet"
            detail="no systems have been discovered. add systems on the Systems page and run a discovery scan."
          />
        ) : (
          <div style={{ position: "relative", width: "100%", flex: 1, minHeight: 0 }}>
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
        )}
      </WindowPanel>

      <RadarInspectPanel
        node={selectedNode}
        open={inspectOpen}
        onClose={handleInspectClose}
      />
    </div>
  );
}

function RadarEmpty({
  icon,
  title,
  detail,
  action,
}: {
  icon: React.ReactNode;
  title: string;
  detail: string;
  action?: { label: string; onClick: () => void };
}) {
  return (
    <div
      className="flex flex-col items-center justify-center font-mono"
      style={{ flex: 1, gap: 10, padding: 32, color: "var(--text-muted)" }}
    >
      <span style={{ color: "var(--text-faint)" }}>{icon}</span>
      <span
        className="uppercase"
        style={{ fontSize: 11, letterSpacing: "0.14em", color: "var(--text-primary)" }}
      >
        {title}
      </span>
      <span style={{ fontSize: 11, textAlign: "center", maxWidth: 480 }}>{detail}</span>
      {action && (
        <button
          type="button"
          onClick={action.onClick}
          className="font-mono uppercase"
          style={{
            height: 26,
            fontSize: 9.5,
            letterSpacing: "0.08em",
            border: "1px solid var(--border-soft)",
            background: "var(--surface-sunk)",
            color: "var(--text-primary)",
            padding: "0 11px",
            borderRadius: 3,
            cursor: "pointer",
            marginTop: 6,
          }}
        >
          {action.label}
        </button>
      )}
    </div>
  );
}
