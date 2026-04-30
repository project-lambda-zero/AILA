import type { Meta, StoryObj } from "@storybook/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

import { SeverityChartWidget } from "./SeverityChartWidget";

// ---------------------------------------------------------------------------
// Mock data factories
// ---------------------------------------------------------------------------

interface FacetsPayload {
  severity: Record<string, number>;
}

function makeFacets(critical: number, high: number, medium: number, low: number): FacetsPayload {
  return {
    severity: {
      Critical: critical,
      High: high,
      Medium: medium,
      Low: low,
    },
  };
}

function makeQueryClient(facets?: FacetsPayload): QueryClient {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false, staleTime: Infinity } },
  });
  if (facets) {
    // useFindingsFacets resolves to `{ severity }` via the same query key.
    client.setQueryData(["platform", "findings-facets"], facets);
  }
  return client;
}

// ---------------------------------------------------------------------------
// Meta
// ---------------------------------------------------------------------------

const meta = {
  title: "Dashboard/Widgets/SeverityChartWidget",
  component: SeverityChartWidget,
  tags: ["autodocs"],
  parameters: {
    layout: "padded",
    docs: {
      description: {
        component:
          "Pie/donut chart showing finding count by severity level using AilaChart. Zero-count severities are filtered out. Data from GET /vulnerability/findings/facets via useFindingsFacets().",
      },
    },
  },
  decorators: [
    (Story: React.ComponentType, context: { parameters: { queryClient?: QueryClient } }) => (
      <QueryClientProvider client={context.parameters.queryClient ?? makeQueryClient()}>
        <div style={{ width: 360, height: 260, border: "1px solid var(--color-border)", borderRadius: 4 }}>
          <Story />
        </div>
      </QueryClientProvider>
    ),
  ],
} satisfies Meta<typeof SeverityChartWidget>;

export default meta;
type Story = StoryObj<typeof meta>;

// ---------------------------------------------------------------------------
// Stories
// ---------------------------------------------------------------------------

export const Default: Story = {
  name: "Default (mixed severities)",
  parameters: {
    queryClient: makeQueryClient(makeFacets(5, 12, 28, 45)),
  },
};

export const CriticalHeavy: Story = {
  name: "Critical-heavy distribution",
  parameters: {
    queryClient: makeQueryClient(makeFacets(22, 8, 4, 1)),
  },
};

export const NoneFound: Story = {
  name: "No findings (all zeros)",
  parameters: {
    queryClient: makeQueryClient(makeFacets(0, 0, 0, 0)),
  },
};
