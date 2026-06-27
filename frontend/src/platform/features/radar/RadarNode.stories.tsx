/**
 * RadarNode.stories.tsx -- Storybook stories for the RadarNode custom ReactFlow node.
 *
 * Stories render the node inside a ReactFlowProvider with a fixed container
 * so the handles and SVG display correctly without a full ReactFlow canvas.
 */
import type { Meta, StoryObj } from "@storybook/react";
import { ReactFlowProvider } from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import * as React from "react";

import { RadarNode } from "./RadarNode";
import type { TopologyNode } from "./types";

// ---------------------------------------------------------------------------
// Mock data
// ---------------------------------------------------------------------------

const mockNode: TopologyNode = {
  id: 1,
  name: "web-server-01",
  host: "192.168.1.10",
  distro: "ubuntu",
  subnet: "192.168.1",
  group_tags: ["production", "web-tier"],
  ports: [
    { port: 80, protocol: "tcp", local_address: "0.0.0.0", process_name: "nginx" },
    { port: 443, protocol: "tcp", local_address: "0.0.0.0", process_name: "nginx" },
    { port: 22, protocol: "tcp", local_address: "0.0.0.0", process_name: "sshd" },
  ],
  services: [
    { service_name: "nginx", state: "active", sub_state: "running" },
    { service_name: "postgresql", state: "active", sub_state: "running" },
  ],
  severity_counts: { critical: 2, high: 5, medium: 3, low: 1 },
  last_collected: new Date().toISOString(),
  is_stale: false,
};

// Minimal NodeProps shape matching @xyflow/react v12
const baseNodeProps = {
  id: "1",
  type: "radarNode" as const,
  selected: false,
  dragging: false,
  zIndex: 0,
  selectable: true,
  deletable: true,
  draggable: true,
  isConnectable: true,
  positionAbsoluteX: 0,
  positionAbsoluteY: 0,
  width: 120,
  height: 120,
  sourcePosition: undefined,
  targetPosition: undefined,
  dragHandle: undefined,
  parentId: undefined,
};

// ---------------------------------------------------------------------------
// Meta
// ---------------------------------------------------------------------------

const meta: Meta<typeof RadarNode> = {
  title: "Platform/Radar/RadarNode",
  component: RadarNode,
  decorators: [
    (Story) => (
      <ReactFlowProvider>
        <div
          style={{
            width: 200,
            height: 200,
            position: "relative",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            background: "var(--color-base)",
          }}
        >
          <Story />
        </div>
      </ReactFlowProvider>
    ),
  ],
  parameters: {
    layout: "centered",
  },
};

export default meta;
type Story = StoryObj<typeof RadarNode>;

// ---------------------------------------------------------------------------
// Stories
// ---------------------------------------------------------------------------

export const Critical: Story = {
  args: {
    ...baseNodeProps,
    data: {
      node: mockNode,
      fillColor: "var(--color-critical)",
      dominantSeverity: "critical",
    },
  },
};

export const High: Story = {
  args: {
    ...baseNodeProps,
    data: {
      node: {
        ...mockNode,
        name: "db-server-02",
        severity_counts: { critical: 0, high: 7, medium: 2, low: 4 },
      },
      fillColor: "var(--color-high)",
      dominantSeverity: "high",
    },
  },
};

export const Clean: Story = {
  args: {
    ...baseNodeProps,
    data: {
      node: {
        ...mockNode,
        name: "bastion-01",
        severity_counts: null,
      },
      fillColor: "var(--color-border)",
      dominantSeverity: "none",
    },
  },
};

export const Stale: Story = {
  args: {
    ...baseNodeProps,
    data: {
      node: {
        ...mockNode,
        name: "offline-host",
        is_stale: true,
        severity_counts: null,
      },
      fillColor: "var(--color-border)",
      dominantSeverity: "none",
    },
  },
};

export const Selected: Story = {
  args: {
    ...baseNodeProps,
    selected: true,
    data: {
      node: mockNode,
      fillColor: "var(--color-high)",
      dominantSeverity: "high",
    },
  },
};
