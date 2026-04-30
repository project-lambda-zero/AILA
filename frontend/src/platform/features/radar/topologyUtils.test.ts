/**
 * topologyUtils.test.ts — unit tests for radar topology pure functions.
 *
 * All functions under test are pure (no React, no DOM, no network).
 * Tests run in the jsdom environment but do not require it.
 */
import { describe, it, expect } from "vitest";

import {
  dominantSeverity,
  nodeColor,
  filterNodes,
  buildFlowNodes,
  buildFlowEdges,
} from "./topologyUtils";
import type { TopologyNode, TopologyEdge } from "./types";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

function makeNode(overrides: Partial<TopologyNode> = {}): TopologyNode {
  return {
    id: 1,
    name: "test-host",
    host: "192.168.1.1",
    distro: "ubuntu",
    services: [],
    ports: [],
    group_tags: [],
    severity_counts: { critical: 0, high: 0, medium: 0, low: 0 },
    is_stale: false,
    subnet: "192.168.1.0/24",
    last_collected: null,
    ...overrides,
  };
}

function makeEdge(overrides: Partial<TopologyEdge> = {}): TopologyEdge {
  return {
    source_system_id: 1,
    dest_system_id: 2,
    dest_port: 443,
    protocol: "tcp",
    state: "ESTABLISHED",
    is_stale: false,
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// dominantSeverity
// ---------------------------------------------------------------------------

describe("dominantSeverity", () => {
  it("returns 'none' for null counts", () => {
    expect(dominantSeverity(null)).toBe("none");
  });

  it("returns 'none' when all counts are zero", () => {
    expect(dominantSeverity({ critical: 0, high: 0, medium: 0, low: 0 })).toBe("none");
  });

  it("returns 'critical' when critical > 0 (even if others are also > 0)", () => {
    expect(dominantSeverity({ critical: 2, high: 5, medium: 3, low: 1 })).toBe("critical");
  });

  it("returns 'high' when critical=0 but high > 0", () => {
    expect(dominantSeverity({ critical: 0, high: 3, medium: 2, low: 1 })).toBe("high");
  });

  it("returns 'medium' when critical=0 and high=0 but medium > 0", () => {
    expect(dominantSeverity({ critical: 0, high: 0, medium: 1, low: 4 })).toBe("medium");
  });

  it("returns 'low' when only low > 0", () => {
    expect(dominantSeverity({ critical: 0, high: 0, medium: 0, low: 7 })).toBe("low");
  });
});

// ---------------------------------------------------------------------------
// nodeColor
// ---------------------------------------------------------------------------

describe("nodeColor", () => {
  it("returns critical color for vulnerabilities mode with critical-dominant node", () => {
    const node = makeNode({ severity_counts: { critical: 1, high: 0, medium: 0, low: 0 } });
    const color = nodeColor(node, "vulnerabilities");
    expect(color).toBe("var(--color-critical)");
  });

  it("returns high color for vulnerabilities mode with high-dominant node", () => {
    const node = makeNode({ severity_counts: { critical: 0, high: 2, medium: 0, low: 0 } });
    const color = nodeColor(node, "vulnerabilities");
    expect(color).toBe("var(--color-high)");
  });

  it("returns border color for vulnerabilities mode with no findings", () => {
    const node = makeNode({ severity_counts: { critical: 0, high: 0, medium: 0, low: 0 } });
    const color = nodeColor(node, "vulnerabilities");
    expect(color).toBe("var(--color-border)");
  });

  it("returns border color for distro mode with unknown distro", () => {
    const node = makeNode({ distro: "freebsd" });
    const color = nodeColor(node, "distro");
    expect(color).toBe("var(--color-border)");
  });

  it("returns lavender color for distro mode with ubuntu", () => {
    const node = makeNode({ distro: "ubuntu" });
    const color = nodeColor(node, "distro");
    expect(color).toBe("var(--color-lavender, #7c3aed)");
  });

  it("returns mint color for connectivity mode when node is not stale", () => {
    const node = makeNode({ is_stale: false });
    const color = nodeColor(node, "connectivity");
    expect(color).toBe("var(--color-mint, #059669)");
  });

  it("returns critical color for connectivity mode when node is stale", () => {
    const node = makeNode({ is_stale: true });
    const color = nodeColor(node, "connectivity");
    expect(color).toBe("var(--color-critical)");
  });

  it("returns border color for services mode with no services", () => {
    const node = makeNode({ services: [] });
    const color = nodeColor(node, "services");
    expect(color).toBe("var(--color-border)");
  });
});

// ---------------------------------------------------------------------------
// filterNodes
// ---------------------------------------------------------------------------

describe("filterNodes", () => {
  const nodes = [
    makeNode({ id: 1, name: "web-server", host: "10.0.0.1", severity_counts: { critical: 1, high: 0, medium: 0, low: 0 } }),
    makeNode({ id: 2, name: "db-server", host: "10.0.0.2", severity_counts: { critical: 0, high: 2, medium: 0, low: 0 } }),
    makeNode({ id: 3, name: "mail-relay", host: "10.0.1.1", severity_counts: { critical: 0, high: 0, medium: 0, low: 0 } }),
  ];

  it("returns all nodes when filter is empty (no search, no severity)", () => {
    const result = filterNodes(nodes, { search: "", severities: [] });
    expect(result).toHaveLength(3);
  });

  it("filters by search query matching node name", () => {
    const result = filterNodes(nodes, { search: "web", severities: [] });
    expect(result).toHaveLength(1);
    expect(result[0].name).toBe("web-server");
  });

  it("filters by search query matching node host", () => {
    const result = filterNodes(nodes, { search: "10.0.1", severities: [] });
    expect(result).toHaveLength(1);
    expect(result[0].name).toBe("mail-relay");
  });

  it("filters by search is case-insensitive", () => {
    const result = filterNodes(nodes, { search: "DB-SERVER", severities: [] });
    expect(result).toHaveLength(1);
    expect(result[0].name).toBe("db-server");
  });

  it("filters by severity array — returns only critical nodes", () => {
    const result = filterNodes(nodes, { search: "", severities: ["critical"] });
    expect(result).toHaveLength(1);
    expect(result[0].id).toBe(1);
  });

  it("filters by severity array — multiple severities act as OR", () => {
    const result = filterNodes(nodes, { search: "", severities: ["critical", "high"] });
    expect(result).toHaveLength(2);
  });

  it("returns empty array when no nodes match severity", () => {
    const result = filterNodes(nodes, { search: "", severities: ["medium"] });
    expect(result).toHaveLength(0);
  });

  it("returns empty array when search matches no nodes", () => {
    const result = filterNodes(nodes, { search: "nonexistent-xyz", severities: [] });
    expect(result).toHaveLength(0);
  });

  it("applies both search and severity when both are set", () => {
    // "web" matches web-server which is critical — should appear
    const result = filterNodes(nodes, { search: "web", severities: ["critical"] });
    expect(result).toHaveLength(1);
    expect(result[0].name).toBe("web-server");
  });
});

// ---------------------------------------------------------------------------
// buildFlowNodes
// ---------------------------------------------------------------------------

describe("buildFlowNodes", () => {
  const nodes = [
    makeNode({ id: 1, name: "host-a", subnet: "10.0.0.0/24" }),
    makeNode({ id: 2, name: "host-b", subnet: "10.0.0.0/24" }),
    makeNode({ id: 3, name: "host-c", subnet: "10.0.1.0/24" }),
  ];

  it("returns correct count of flow nodes for non-grouped case", () => {
    const flowNodes = buildFlowNodes(nodes, "vulnerabilities", false);
    // One ReactFlow node per topology node, no group nodes
    expect(flowNodes).toHaveLength(3);
  });

  it("assigns correct node type 'radarNode' to each node", () => {
    const flowNodes = buildFlowNodes(nodes, "vulnerabilities", false);
    expect(flowNodes.every((n) => n.type === "radarNode")).toBe(true);
  });

  it("uses string IDs matching topology node IDs", () => {
    const flowNodes = buildFlowNodes(nodes, "vulnerabilities", false);
    const ids = flowNodes.map((n) => n.id);
    expect(ids).toContain("1");
    expect(ids).toContain("2");
    expect(ids).toContain("3");
  });

  it("includes subnet group nodes when subnetGrouping=true", () => {
    const flowNodes = buildFlowNodes(nodes, "vulnerabilities", true);
    // 3 host nodes + 2 subnet group nodes (10.0.0.0/24, 10.0.1.0/24)
    expect(flowNodes.length).toBeGreaterThan(3);
    const groupNodes = flowNodes.filter((n) => n.type === "group");
    expect(groupNodes).toHaveLength(2);
  });

  it("assigns parentId to child nodes when subnetGrouping=true", () => {
    const flowNodes = buildFlowNodes(nodes, "vulnerabilities", true);
    const childNodes = flowNodes.filter((n) => n.type === "radarNode");
    expect(childNodes.every((n) => n.parentId !== undefined)).toBe(true);
  });

  it("does not assign parentId when subnetGrouping=false", () => {
    const flowNodes = buildFlowNodes(nodes, "vulnerabilities", false);
    expect(flowNodes.every((n) => n.parentId === undefined)).toBe(true);
  });

  it("handles empty node array without error", () => {
    const flowNodes = buildFlowNodes([], "vulnerabilities", false);
    expect(flowNodes).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// buildFlowEdges
// ---------------------------------------------------------------------------

describe("buildFlowEdges", () => {
  const edges = [
    makeEdge({ source_system_id: 1, dest_system_id: 2, dest_port: 443, is_stale: false }),
    makeEdge({ source_system_id: 2, dest_system_id: 3, dest_port: 22, is_stale: true }),
    makeEdge({ source_system_id: 1, dest_system_id: 99, dest_port: 80, is_stale: false }), // dest not visible
  ];

  const visibleIds = new Set(["1", "2", "3"]);

  it("filters out edges where destination node is not visible", () => {
    const flowEdges = buildFlowEdges(edges, visibleIds);
    // Edge to node 99 should be filtered out
    expect(flowEdges.every((e) => !e.id.includes("99"))).toBe(true);
    expect(flowEdges).toHaveLength(2);
  });

  it("includes edges where both source and dest are visible", () => {
    const flowEdges = buildFlowEdges(edges, visibleIds);
    expect(flowEdges.some((e) => e.source === "1" && e.target === "2")).toBe(true);
    expect(flowEdges.some((e) => e.source === "2" && e.target === "3")).toBe(true);
  });

  it("returns animated=true for non-stale edges", () => {
    const flowEdges = buildFlowEdges(edges, visibleIds);
    const liveEdge = flowEdges.find((e) => e.source === "1" && e.target === "2");
    expect(liveEdge?.animated).toBe(true);
  });

  it("returns animated=false for stale edges", () => {
    const flowEdges = buildFlowEdges(edges, visibleIds);
    const staleEdge = flowEdges.find((e) => e.source === "2" && e.target === "3");
    expect(staleEdge?.animated).toBe(false);
  });

  it("generates unique edge IDs with source, dest, and port", () => {
    const flowEdges = buildFlowEdges(edges, visibleIds);
    const ids = flowEdges.map((e) => e.id);
    expect(new Set(ids).size).toBe(ids.length); // all unique
  });

  it("returns empty array when no edges have visible endpoints", () => {
    const result = buildFlowEdges(edges, new Set(["99"]));
    expect(result).toHaveLength(0);
  });

  it("returns empty array when edge list is empty", () => {
    const result = buildFlowEdges([], visibleIds);
    expect(result).toHaveLength(0);
  });
});
