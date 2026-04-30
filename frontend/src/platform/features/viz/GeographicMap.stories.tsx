/**
 * GeographicMap.stories.tsx — Storybook stories for VIZ-04.
 *
 * Note: Leaflet requires a DOM with CSS loaded. The map will render correctly
 * in Storybook only when leaflet/dist/leaflet.css is included in the preview.
 * Add it to .storybook/preview.ts if needed:
 *   import "leaflet/dist/leaflet.css";
 *
 * The EmptyState story does NOT render a Leaflet map container and is always safe.
 */
import type { Meta, StoryObj } from "@storybook/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import * as React from "react";

import { GeographicMap } from "./GeographicMap";

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

const meta: Meta<typeof GeographicMap> = {
  title: "Platform/Viz/GeographicMap",
  component: GeographicMap,
  parameters: {
    layout: "centered",
  },
};

export default meta;
type Story = StoryObj<typeof GeographicMap>;

/** Most common state — no nodes have lat/lng tags. Safe to render anywhere. */
export const EmptyState: Story = {
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

/** Nodes with lat/lng tags — renders a Leaflet map. Requires leaflet.css in Storybook preview. */
export const WithGeoNodes: Story = {
  decorators: [
    (Story) => (
      <MockedQueryProvider
        mockData={{
          nodes: [
            {
              id: 1,
              name: "berlin-01",
              host: "10.0.1.10",
              distro: "Ubuntu 22.04",
              subnet: null,
              group_tags: ["lat:52.5200", "lng:13.4050"],
              ports: [],
              services: [],
              severity_counts: { critical: 2, high: 5, medium: 8, low: 1 },
              last_collected: "2026-04-09T10:00:00Z",
              is_stale: false,
            },
            {
              id: 2,
              name: "london-proxy",
              host: "10.0.2.10",
              distro: "Debian 12",
              subnet: null,
              group_tags: ["lat:51.5074", "lng:-0.1278"],
              ports: [],
              services: [],
              severity_counts: { critical: 0, high: 1, medium: 3, low: 7 },
              last_collected: "2026-04-09T10:00:00Z",
              is_stale: false,
            },
          ],
          edges: [],
          subnets: [],
        }}
      >
        <div style={{ width: 700, height: 500 }}>
          <Story />
        </div>
      </MockedQueryProvider>
    ),
  ],
};

/** Node with no valid geo tags — falls through to empty state. */
export const NoValidGeoTags: Story = {
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
              group_tags: ["env:production", "team:infra"],
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
