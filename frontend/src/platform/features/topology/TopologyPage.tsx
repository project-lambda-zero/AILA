/**
 * TopologyPage.tsx -- full network-topology console (issue #212).
 *
 * Wires the two /topology endpoints together and lays out the console:
 *
 *   +------------------+---------------------------------+
 *   | subnet sidebar   | overlay toolbar                 |
 *   |  (subnets query) +---------------------------------+
 *   |                  | xyflow canvas (full topology)   |
 *   |                  |                                 |
 *   +------------------+---------------------------------+
 *
 * The page returns bare content -- protectPage wraps it in <PageFrame>,
 * so wrapping our own <PageShell> would double the header (rule #16).
 *
 * Endpoints wired:
 *   GET /topology          -- nodes + edges + subnets (payload rendered)
 *   GET /topology/subnets  -- sidebar counts (independent cache)
 *
 * Graph lib: @xyflow/react (vendor-xyflow chunk already shipped).
 * Console aesthetic: mono, sharp 2-4px radii, midnight-cloud-8 palette.
 * Motion: pan/zoom on subnet focus honours prefers-reduced-motion.
 */
import * as React from "react";
import { ArrowsClockwise } from "@phosphor-icons/react/dist/csr/ArrowsClockwise";
import { Broadcast } from "@phosphor-icons/react/dist/csr/Broadcast";
import { CirclesThreePlus } from "@phosphor-icons/react/dist/csr/CirclesThreePlus";
import { HardDrives } from "@phosphor-icons/react/dist/csr/HardDrives";
import { LineSegments } from "@phosphor-icons/react/dist/csr/LineSegments";
import { TreeStructure } from "@phosphor-icons/react/dist/csr/TreeStructure";
import { Warning } from "@phosphor-icons/react/dist/csr/Warning";

import { AilaBadge } from "@/components/aila/AilaBadge";
import { AilaCard } from "@/components/aila/AilaCard";
import { EmptyState } from "@/components/aila/EmptyState";
import { KpiTile } from "@/components/aila/KpiTile";
import { LoadingSkeleton } from "@/components/aila/LoadingSkeleton";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";
import { FeatureBoundary } from "@app/FeatureBoundary";
import type { UseQueryResult } from "@tanstack/react-query";

import type {
  SubnetGroup,
  TopologyNode,
  TopologyResponse,
} from "@platform/features/radar/types";
import {
  TopologyCanvas,
  type TopologyCanvasHandle,
} from "./TopologyCanvas";
import { TopologyDetailSheet } from "./TopologyDetailSheet";
import {
  DEFAULT_OVERLAYS,
  type TopologyOverlays,
} from "./topologyGraph";
import { useTopologyFull, useTopologySubnets } from "./useTopologyData";

export function TopologyPage() {
  const full = useTopologyFull();
  const subnetsQuery = useTopologySubnets();

  const [overlays, setOverlays] = React.useState<TopologyOverlays>(DEFAULT_OVERLAYS);
  const [focusedSubnet, setFocusedSubnet] = React.useState<string | null>(null);
  const [selectedNode, setSelectedNode] = React.useState<TopologyNode | null>(null);
  const [sheetOpen, setSheetOpen] = React.useState(false);

  const canvasRef = React.useRef<TopologyCanvasHandle | null>(null);

  const handleNodeClick = React.useCallback((node: TopologyNode) => {
    setSelectedNode(node);
    setSheetOpen(true);
  }, []);

  // Prefer live subnets from /topology/subnets; fall back to the copy
  // embedded in the full response so the sidebar renders even if the
  // secondary query hasn't returned yet.
  const sidebarSubnets: SubnetGroup[] =
    subnetsQuery.data ?? full.data?.subnets ?? [];

  const handleSubnetPick = React.useCallback(
    (subnet: string | null) => {
      setFocusedSubnet(subnet);
      canvasRef.current?.focusSubnet(subnet, sidebarSubnets);
    },
    [sidebarSubnets],
  );

  return (
    <div className="flex flex-col gap-3 h-full min-h-0">
      <TopologyHeader
        overlays={overlays}
        onOverlaysChange={setOverlays}
        onRefresh={() => {
          void full.refetch();
          void subnetsQuery.refetch();
        }}
        refreshing={full.isFetching || subnetsQuery.isFetching}
        nodeCount={full.data?.nodes.length ?? 0}
        edgeCount={full.data?.edges.length ?? 0}
        subnetCount={sidebarSubnets.length}
        staleCount={
          full.data?.nodes.filter((n) => n.is_stale).length ?? 0
        }
      />

      {/* Sidebar + canvas each get their own boundary: a subnet-query
          render fault only kills the sidebar; a canvas render fault
          only kills the graph. */}
      <div className="flex-1 grid gap-3 min-h-0" style={{ gridTemplateColumns: "260px 1fr" }}>
        <FeatureBoundary
          label="Subnet sidebar"
          resetKeys={[subnetsQuery.dataUpdatedAt, sidebarSubnets.length]}
          onReset={() => void subnetsQuery.refetch()}
        >
          <SubnetSidebar
            subnets={sidebarSubnets}
            nodes={full.data?.nodes ?? []}
            focused={focusedSubnet}
            onFocus={handleSubnetPick}
            loading={subnetsQuery.isLoading && !subnetsQuery.data}
          />
        </FeatureBoundary>
        <FeatureBoundary
          label="Topology graph"
          resetKeys={[full.dataUpdatedAt, focusedSubnet]}
          onReset={() => void full.refetch()}
        >
          <AilaCard
            padding="none"
            className="flex flex-col min-h-0 overflow-hidden"
           
          >
            <TopologyBody
              full={full}
              overlays={overlays}
              focusedSubnet={focusedSubnet}
              onNodeClick={handleNodeClick}
              canvasRef={canvasRef}
            />
          </AilaCard>
        </FeatureBoundary>
      </div>

      <TopologyDetailSheet
        node={selectedNode}
        open={sheetOpen}
        onOpenChange={setSheetOpen}
      />
    </div>
  );
}

// ---------------------------------------------------------------------------
// Header: KPIs + overlay toggles + refresh
// ---------------------------------------------------------------------------

function TopologyHeader({
  overlays,
  onOverlaysChange,
  onRefresh,
  refreshing,
  nodeCount,
  edgeCount,
  subnetCount,
  staleCount,
}: {
  overlays: TopologyOverlays;
  onOverlaysChange(next: TopologyOverlays): void;
  onRefresh(): void;
  refreshing: boolean;
  nodeCount: number;
  edgeCount: number;
  subnetCount: number;
  staleCount: number;
}) {
  return (
    <div className="flex items-center justify-between gap-3 flex-wrap">
      <div className="flex gap-2 flex-wrap">
        <KpiTile label="Systems" value={nodeCount} icon={<HardDrives />} tone="accent" />
        <KpiTile label="Edges" value={edgeCount} icon={<LineSegments />} />
        <KpiTile
          label="Subnets"
          value={subnetCount}
          icon={<CirclesThreePlus />}
        />
        <KpiTile
          label="Stale"
          value={staleCount}
          icon={<Warning />}
          tone={staleCount > 0 ? "warn" : "neutral"}
        />
      </div>
      <div className="flex items-center gap-2 flex-wrap">
        <OverlayToggle
          active={overlays.severityHeat}
          onClick={() =>
            onOverlaysChange({ ...overlays, severityHeat: !overlays.severityHeat })
          }
          label="Severity heat"
        />
        <OverlayToggle
          active={overlays.staleOnly}
          onClick={() =>
            onOverlaysChange({ ...overlays, staleOnly: !overlays.staleOnly })
          }
          label="Stale only"
        />
        <OverlayToggle
          active={overlays.groupBySubnet}
          onClick={() =>
            onOverlaysChange({ ...overlays, groupBySubnet: !overlays.groupBySubnet })
          }
          label="Group by subnet"
        />
        <Button
          variant="outline"
          size="sm"
          onClick={onRefresh}
          disabled={refreshing}
          className="font-mono text-xs"
        >
          <ArrowsClockwise
            size={14}
            className={cn(refreshing && "animate-spin motion-reduce:animate-none")}
          />
          <span className="ml-1">Refresh</span>
        </Button>
      </div>
    </div>
  );
}

function OverlayToggle({
  active,
  onClick,
  label,
}: {
  active: boolean;
  onClick(): void;
  label: string;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      aria-pressed={active}
      className={cn(
        "font-mono text-xs uppercase tracking-wider px-3 py-1.5 rounded-[2px] border transition-colors duration-150",
        active
          ? "bg-accent text-badge-text border-accent"
          : "bg-surface text-text-muted border-border hover:border-accent hover:text-text",
      )}
    >
      {label}
    </button>
  );
}

// ---------------------------------------------------------------------------
// Subnet sidebar
// ---------------------------------------------------------------------------

function SubnetSidebar({
  subnets,
  nodes,
  focused,
  onFocus,
  loading,
}: {
  subnets: SubnetGroup[];
  nodes: TopologyNode[];
  focused: string | null;
  onFocus(subnet: string | null): void;
  loading: boolean;
}) {
  const staleBySubnet = React.useMemo(() => {
    const map = new Map<string, number>();
    for (const n of nodes) {
      if (!n.is_stale) continue;
      const key = n.subnet ?? "unresolved";
      map.set(key, (map.get(key) ?? 0) + 1);
    }
    return map;
  }, [nodes]);

  return (
    <AilaCard
      padding="none"
      className="flex flex-col min-h-0 overflow-hidden"
     
    >
      <div className="flex items-center justify-between px-3 py-2 border-b border-border">
        <span className="font-mono text-[10px] uppercase tracking-wider text-text-muted">
          Subnets
        </span>
        <button
          type="button"
          onClick={() => onFocus(null)}
          className={cn(
            "font-mono text-[10px] uppercase tracking-wider px-2 py-0.5 rounded-[2px] border",
            focused === null
              ? "bg-accent text-badge-text border-accent"
              : "border-border text-text-muted hover:text-text hover:border-accent",
          )}
        >
          All
        </button>
      </div>
      <div className="flex-1 overflow-y-auto">
        {loading && subnets.length === 0 ? (
          <div className="p-3 flex flex-col gap-2">
            <LoadingSkeleton size="lg" width="full" />
            <LoadingSkeleton size="lg" width="full" />
            <LoadingSkeleton size="lg" width="full" />
          </div>
        ) : subnets.length === 0 ? (
          <p className="p-3 font-mono text-[11px] text-text-muted">
            No subnets discovered.
          </p>
        ) : (
          subnets.map((s) => {
            const isFocused = focused === s.subnet_prefix;
            const stale = staleBySubnet.get(s.subnet_prefix) ?? 0;
            return (
              <button
                key={s.subnet_prefix}
                type="button"
                onClick={() => onFocus(isFocused ? null : s.subnet_prefix)}
                className={cn(
                  "w-full flex items-center justify-between gap-2 px-3 py-2 border-b border-border/60 text-left transition-colors duration-100 font-mono",
                  isFocused
                    ? "bg-surface text-accent"
                    : "text-text hover:bg-surface/60",
                )}
              >
                <span className="text-xs truncate">{s.subnet_prefix}</span>
                <span className="flex items-center gap-1 shrink-0">
                  {stale > 0 && (
                    <AilaBadge severity="medium" size="sm">
                      {`${stale} stale`}
                    </AilaBadge>
                  )}
                  <span className="text-[10px] text-text-muted">
                    {s.system_ids.length}
                  </span>
                </span>
              </button>
            );
          })
        )}
      </div>
    </AilaCard>
  );
}

// ---------------------------------------------------------------------------
// Canvas body -- handles loading/error/empty gates
// ---------------------------------------------------------------------------

function TopologyBody({
  full,
  overlays,
  focusedSubnet,
  onNodeClick,
  canvasRef,
}: {
  full: UseQueryResult<TopologyResponse, Error>;
  overlays: TopologyOverlays;
  focusedSubnet: string | null;
  onNodeClick(node: TopologyNode): void;
  canvasRef: React.MutableRefObject<TopologyCanvasHandle | null>;
}) {
  if (full.isLoading) {
    return (
      <div className="flex-1 grid place-items-center p-6">
        <LoadingSkeleton size="full" width="full" className="h-full" />
      </div>
    );
  }
  if (full.isError) {
    return (
      <EmptyState
        icon={<Warning size={32} />}
        title="Topology unavailable"
        description={
          full.error instanceof Error
            ? full.error.message
            : "The /topology endpoint returned an error."
        }
      />
    );
  }
  if (!full.data || full.data.nodes.length === 0) {
    return (
      <EmptyState
        icon={<Broadcast size={32} />}
        title="No systems registered"
        description="Run a discovery scan or register systems to populate the topology."
      />
    );
  }
  return (
    <div className="flex-1 min-h-0">
      <TopologyCanvas
        ref={canvasRef}
        nodes={full.data.nodes}
        edges={full.data.edges}
        overlays={overlays}
        focusedSubnet={focusedSubnet}
        onNodeClick={onNodeClick}
      />
    </div>
  );
}

// re-exported so router.tsx can use TreeStructure as the page icon.
export const TopologyPageIcon = TreeStructure;
