/**
 * TopologyPage -- mock rebuild (dense mono terminal).
 *
 * SectionHeader + FilterChip toolbar (overlays + refresh) + 2-col grid:
 *   left  = WindowPanel(title='subnets', flush)   -- subnet picker
 *   right = WindowPanel(title='topology graph', flush) -- reactflow canvas
 *
 * TopologyDetailSheet stays a fixed right sheet (composed of WindowPanel)
 * shown when a node is clicked. Data hooks + reactflow engine unchanged.
 */
import * as React from "react";
import { ArrowsClockwise } from "@phosphor-icons/react/dist/csr/ArrowsClockwise";
import { Broadcast } from "@phosphor-icons/react/dist/csr/Broadcast";
import { TreeStructure } from "@phosphor-icons/react/dist/csr/TreeStructure";
import { Warning } from "@phosphor-icons/react/dist/csr/Warning";

import { LoadingSkeleton } from "@/components/aila/LoadingSkeleton";
import { FeatureBoundary } from "@app/FeatureBoundary";
import type { UseQueryResult } from "@tanstack/react-query";

import { FilterChip, MonoBadge, SectionHeader, StatBar } from "@/components/aila/mock";
import { WindowPanel } from "@/components/aila/WindowPanel";

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

  const sidebarSubnets: SubnetGroup[] =
    subnetsQuery.data ?? full.data?.subnets ?? [];

  const handleSubnetPick = React.useCallback(
    (subnet: string | null) => {
      setFocusedSubnet(subnet);
      canvasRef.current?.focusSubnet(subnet, sidebarSubnets);
    },
    [sidebarSubnets],
  );

  const nodes = full.data?.nodes ?? [];
  const edges = full.data?.edges ?? [];
  const staleCount = nodes.filter((n) => n.is_stale).length;
  const refreshing = full.isFetching || subnetsQuery.isFetching;

  return (
    <div className="flex flex-col" style={{ gap: 16, padding: 20, height: "100%", minHeight: 0 }}>
      <SectionHeader
        icon={"\u25CE"}
        title="topology"
        actions={
          <div className="flex items-center" style={{ gap: 8 }}>
            <span className="font-mono uppercase" style={{ fontSize: 9, letterSpacing: "0.14em", color: "var(--text-faint)" }}>
              {nodes.length} nodes
            </span>
            <span className="font-mono uppercase" style={{ fontSize: 9, letterSpacing: "0.14em", color: "var(--text-faint)" }}>
              {edges.length} edges
            </span>
            <span className="font-mono uppercase" style={{ fontSize: 9, letterSpacing: "0.14em", color: "var(--text-faint)" }}>
              {sidebarSubnets.length} subnets
            </span>
            {staleCount > 0 && (
              <MonoBadge tone="warn">{`${staleCount} stale`}</MonoBadge>
            )}
            <button
              type="button"
              onClick={() => {
                void full.refetch();
                void subnetsQuery.refetch();
              }}
              disabled={refreshing}
              className="font-mono uppercase flex items-center"
              style={{
                gap: 6,
                height: 26,
                fontSize: 9.5,
                letterSpacing: "0.08em",
                border: "1px solid var(--border-soft)",
                background: "var(--surface-sunk)",
                color: "var(--text-primary)",
                padding: "0 11px",
                borderRadius: 3,
                cursor: refreshing ? "wait" : "pointer",
                opacity: refreshing ? 0.6 : 1,
              }}
            >
              <ArrowsClockwise size={12} />
              refresh
            </button>
          </div>
        }
      />

      {/* Overlay filter chip row */}
      <div className="flex items-center flex-wrap" style={{ gap: 8 }}>
        <FilterChip
          active={overlays.severityHeat}
          color="var(--accent)"
          onClick={() => setOverlays({ ...overlays, severityHeat: !overlays.severityHeat })}
        >
          severity heat
        </FilterChip>
        <FilterChip
          active={overlays.staleOnly}
          color="var(--status-warn)"
          onClick={() => setOverlays({ ...overlays, staleOnly: !overlays.staleOnly })}
        >
          stale only
        </FilterChip>
        <FilterChip
          active={overlays.groupBySubnet}
          color="var(--status-info)"
          onClick={() => setOverlays({ ...overlays, groupBySubnet: !overlays.groupBySubnet })}
        >
          group by subnet
        </FilterChip>
      </div>

      {/* Main = subnet sidebar + graph canvas */}
      <div className="grid" style={{ gap: 12, gridTemplateColumns: "260px 1fr", flex: 1, minHeight: 0 }}>
        <FeatureBoundary
          label="Subnet sidebar"
          resetKeys={[subnetsQuery.dataUpdatedAt, sidebarSubnets.length]}
          onReset={() => void subnetsQuery.refetch()}
        >
          <SubnetSidebar
            subnets={sidebarSubnets}
            nodes={nodes}
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
          <WindowPanel title="topology graph" flush className="flex flex-col" style={{ minHeight: 0 }}>
            <TopologyBody
              full={full}
              overlays={overlays}
              focusedSubnet={focusedSubnet}
              onNodeClick={handleNodeClick}
              canvasRef={canvasRef}
            />
          </WindowPanel>
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
// Subnet sidebar -- WindowPanel with a list of chips
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

  const maxCount = subnets.reduce((m, s) => Math.max(m, s.system_ids.length), 0) || 1;

  return (
    <WindowPanel
      title="subnets"
      flush
      className="flex flex-col"
      style={{ minHeight: 0 }}
      actions={
        <button
          type="button"
          onClick={() => onFocus(null)}
          className="font-mono uppercase"
          style={{
            height: 20,
            fontSize: 9,
            letterSpacing: "0.1em",
            padding: "0 8px",
            border: focused === null ? "1px solid var(--accent)" : "1px solid var(--border-soft)",
            background: focused === null ? "color-mix(in srgb, var(--accent) 18%, transparent)" : "var(--surface-sunk)",
            color: focused === null ? "var(--accent)" : "var(--text-muted)",
            borderRadius: 3,
            cursor: "pointer",
          }}
        >
          all
        </button>
      }
    >
      <div style={{ overflowY: "auto", flex: 1, minHeight: 0 }}>
        {loading && subnets.length === 0 ? (
          <div className="flex flex-col" style={{ padding: 10, gap: 6 }}>
            <LoadingSkeleton size="lg" width="full" />
            <LoadingSkeleton size="lg" width="full" />
            <LoadingSkeleton size="lg" width="full" />
          </div>
        ) : subnets.length === 0 ? (
          <p className="font-mono" style={{ padding: 12, fontSize: 11, color: "var(--text-muted)" }}>
            no subnets discovered.
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
                className="w-full font-mono text-left"
                style={{
                  display: "flex",
                  flexDirection: "column",
                  gap: 4,
                  padding: "8px 12px",
                  borderBottom: "1px solid var(--border-faint)",
                  background: isFocused ? "var(--surface-hover)" : "transparent",
                  color: isFocused ? "var(--accent)" : "var(--text-primary)",
                  cursor: "pointer",
                }}
              >
                <div className="flex items-center justify-between" style={{ gap: 6 }}>
                  <span style={{ fontSize: 11, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                    {s.subnet_prefix}
                  </span>
                  <span className="flex items-center" style={{ gap: 6 }}>
                    {stale > 0 && <MonoBadge tone="warn">{`${stale} STALE`}</MonoBadge>}
                    <span style={{ fontSize: 9, color: "var(--text-faint)", letterSpacing: "0.1em" }}>
                      {s.system_ids.length}
                    </span>
                  </span>
                </div>
                <StatBar
                  label=""
                  color={isFocused ? "var(--accent)" : "var(--border)"}
                  value={s.system_ids.length}
                  max={maxCount}
                />
              </button>
            );
          })
        )}
      </div>
    </WindowPanel>
  );
}

// ---------------------------------------------------------------------------
// Canvas body -- loading / error / empty gates
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
      <div className="flex items-center justify-center" style={{ flex: 1, padding: 24 }}>
        <LoadingSkeleton size="full" width="full" className="h-full" />
      </div>
    );
  }
  if (full.isError) {
    return (
      <EmptyPanel
        icon={<Warning size={28} />}
        title="topology unavailable"
        detail={
          full.error instanceof Error
            ? full.error.message
            : "the /topology endpoint returned an error."
        }
      />
    );
  }
  if (!full.data || full.data.nodes.length === 0) {
    return (
      <EmptyPanel
        icon={<Broadcast size={28} />}
        title="no systems registered"
        detail="run a discovery scan or register systems to populate the topology."
      />
    );
  }
  return (
    <div style={{ flex: 1, minHeight: 0 }}>
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

function EmptyPanel({ icon, title, detail }: { icon: React.ReactNode; title: string; detail: string }) {
  return (
    <div
      className="flex flex-col items-center justify-center font-mono"
      style={{ flex: 1, gap: 10, padding: 32, color: "var(--text-muted)" }}
    >
      <span style={{ color: "var(--text-faint)" }}>{icon}</span>
      <span className="uppercase" style={{ fontSize: 11, letterSpacing: "0.14em", color: "var(--text-primary)" }}>
        {title}
      </span>
      <span style={{ fontSize: 11, textAlign: "center", maxWidth: 420 }}>{detail}</span>
    </div>
  );
}

// re-exported so router.tsx can use TreeStructure as the page icon.
export const TopologyPageIcon = TreeStructure;
