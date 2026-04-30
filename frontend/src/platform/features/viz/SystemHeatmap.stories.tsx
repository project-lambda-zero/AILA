/**
 * SystemHeatmap.stories.tsx — Storybook stories for VIZ-03.
 *
 * Uses a mock QueryClient to simulate loaded/empty states
 * without needing a live backend.
 */
import type { Meta, StoryObj } from "@storybook/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import * as React from "react";

import { SystemHeatmap } from "./SystemHeatmap";

function MockedQueryProvider({
  children,
  mockData,
}: {
  children: React.ReactNode;
  mockData: unknown;
}) {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  queryClient.setQueryData(["platform", "topology"], mockData);
  return <QueryClientProvider client={queryClient}>{children}</QueryClientProvider>;
}

const meta: Meta<typeof SystemHeatmap> = {
  title: "Platform/Viz/SystemHeatmap",
  component: SystemHeatmap,
  parameters: {
    layout: "centered",
  },
};

export default meta;
type Story = StoryObj<typeof SystemHeatmap>;

const mockTopologyWithData = {
  nodes: [
    {
      id: 1,
      name: "web-01",
      host: "192.168.1.10",
      distro: "Ubuntu 22.04",
      subnet: "192.168.1.0/24",
      group_tags: [],
      ports: [],
      services: [],
      severity_counts: { critical: 3, high: 12, medium: 25, low: 8 },
      last_collected: "2026-04-09T10:00:00Z",
      is_stale: false,
    },
    {
      id: 2,
      name: "db-primary",
      host: "192.168.1.20",
      distro: "Debian 12",
      subnet: "192.168.1.0/24",
      group_tags: [],
      ports: [],
      services: [],
      severity_counts: { critical: 0, high: 4, medium: 11, low: 2 },
      last_collected: "2026-04-09T10:00:00Z",
      is_stale: false,
    },
    {
      id: 3,
      name: "monitor",
      host: "192.168.1.30",
      distro: "Alpine 3.18",
      subnet: "192.168.1.0/24",
      group_tags: [],
      ports: [],
      services: [],
      severity_counts: { critical: 0, high: 0, medium: 2, low: 5 },
      last_collected: "2026-04-08T10:00:00Z",
      is_stale: true,
    },
  ],
  edges: [],
  subnets: [],
};

export const WithData: Story = {
  decorators: [
    (Story) => (
      <MockedQueryProvider mockData={mockTopologyWithData}>
        <div style={{ width: 600 }}>
          <Story />
        </div>
      </MockedQueryProvider>
    ),
  ],
};

export const EmptyNoNodes: Story = {
  decorators: [
    (Story) => (
      <MockedQueryProvider mockData={{ nodes: [], edges: [], subnets: [] }}>
        <div style={{ width: 600 }}>
          <Story />
        </div>
      </MockedQueryProvider>
    ),
  ],
};

export const NoSeverityData: Story = {
  decorators: [
    (Story) => (
      <MockedQueryProvider
        mockData={{
          nodes: [
            {
              id: 1,
              name: "web-01",
              host: "192.168.1.10",
              distro: "Ubuntu 22.04",
              subnet: null,
              group_tags: [],
              ports: [],
              services: [],
              severity_counts: null,
              last_collected: null,
              is_stale: false,
            },
          ],
          edges: [],
          subnets: [],
        }}
      >
        <div style={{ width: 600 }}>
          <Story />
        </div>
      </MockedQueryProvider>
    ),
  ],
};
