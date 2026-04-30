import type { Meta, StoryObj } from "@storybook/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

import { RiskScoreWidget } from "./RiskScoreWidget";
import type { DashboardEnvelope } from "../hooks/useDashboardData";

// ---------------------------------------------------------------------------
// Mock data factories
// ---------------------------------------------------------------------------

function makeMockEnvelope(risk_score: number): DashboardEnvelope {
  return {
    data: {
      risk_score,
      fleet_stats: {
        total_systems: 12,
        online_systems: 10,
        total_findings: 90,
        critical_findings: 5,
        high_findings: 12,
        medium_findings: 28,
        low_findings: 45,
      },
      module_data: {},
      generated_at: new Date().toISOString(),
    },
    meta: { closed_last_30d: 7 },
  };
}

function makeQueryClient(envelope?: DashboardEnvelope): QueryClient {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false, staleTime: Infinity } },
  });
  if (envelope) {
    client.setQueryData(["dashboard", "stats"], envelope);
  }
  return client;
}

// ---------------------------------------------------------------------------
// Meta
// ---------------------------------------------------------------------------

const meta = {
  title: "Dashboard/Widgets/RiskScoreWidget",
  component: RiskScoreWidget,
  tags: ["autodocs"],
  parameters: {
    layout: "padded",
    docs: {
      description: {
        component:
          "Circular SVG gauge showing composite risk score (0-10). Arc color transitions amber → orange → red as severity increases. Data from GET /dashboard via useDashboardData().",
      },
    },
  },
  decorators: [
    (Story: React.ComponentType, context: { parameters: { queryClient?: QueryClient } }) => (
      <QueryClientProvider client={context.parameters.queryClient ?? makeQueryClient()}>
        <div style={{ width: 240, height: 200, border: "1px solid var(--color-border)", borderRadius: 4 }}>
          <Story />
        </div>
      </QueryClientProvider>
    ),
  ],
} satisfies Meta<typeof RiskScoreWidget>;

export default meta;
type Story = StoryObj<typeof meta>;

// ---------------------------------------------------------------------------
// Stories
// ---------------------------------------------------------------------------

export const Default: Story = {
  name: "Default (moderate risk 6.4)",
  parameters: {
    queryClient: makeQueryClient(makeMockEnvelope(6.4)),
  },
};

export const CriticalScore: Story = {
  name: "Critical Score (9.2)",
  parameters: {
    queryClient: makeQueryClient(makeMockEnvelope(9.2)),
  },
};

export const LowScore: Story = {
  name: "Low Score (2.1)",
  parameters: {
    queryClient: makeQueryClient(makeMockEnvelope(2.1)),
  },
};

export const Loading: Story = {
  name: "Loading state",
  parameters: {
    queryClient: makeQueryClient(), // no data set → query stays loading
  },
};
