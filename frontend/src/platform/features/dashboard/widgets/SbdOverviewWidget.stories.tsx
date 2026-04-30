import type { Meta, StoryObj } from "@storybook/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

import { SbdOverviewWidget } from "./SbdOverviewWidget";
import type { DashboardEnvelope } from "../hooks/useDashboardData";

// ---------------------------------------------------------------------------
// Mock data factories
// ---------------------------------------------------------------------------

interface SbdOverviewPayload {
  active_sessions: number;
  pending_reviews: number;
  recent_completions: number;
}

function makeMockEnvelope(sbdOverview?: SbdOverviewPayload): DashboardEnvelope {
  return {
    data: {
      risk_score: 4.2,
      fleet_stats: {
        total_systems: 8,
        online_systems: 7,
        total_findings: 42,
        critical_findings: 2,
        high_findings: 8,
        medium_findings: 18,
        low_findings: 14,
      },
      module_data: sbdOverview
        ? { "sbd_nfr.overview": sbdOverview }
        : {},
      generated_at: new Date().toISOString(),
    },
    meta: { closed_last_30d: 5 },
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
  title: "Dashboard/Widgets/SbdOverviewWidget",
  component: SbdOverviewWidget,
  tags: ["autodocs"],
  parameters: {
    layout: "padded",
    docs: {
      description: {
        component:
          "SbD NFR module overview widget. Shows active sessions, pending reviews, and recent completions. Reads module_data['sbd_nfr.overview']. Shows empty state when module is not loaded.",
      },
    },
  },
  decorators: [
    (Story: React.ComponentType, context: { parameters: { queryClient?: QueryClient } }) => (
      <QueryClientProvider client={context.parameters.queryClient ?? makeQueryClient()}>
        <div style={{ width: 300, height: 200, border: "1px solid var(--color-border)", borderRadius: 4 }}>
          <Story />
        </div>
      </QueryClientProvider>
    ),
  ],
} satisfies Meta<typeof SbdOverviewWidget>;

export default meta;
type Story = StoryObj<typeof meta>;

// ---------------------------------------------------------------------------
// Stories
// ---------------------------------------------------------------------------

export const Default: Story = {
  name: "Default (module loaded)",
  parameters: {
    queryClient: makeQueryClient(
      makeMockEnvelope({ active_sessions: 3, pending_reviews: 2, recent_completions: 7 }),
    ),
  },
};

export const HighActivity: Story = {
  name: "High activity",
  parameters: {
    queryClient: makeQueryClient(
      makeMockEnvelope({ active_sessions: 12, pending_reviews: 8, recent_completions: 31 }),
    ),
  },
};

export const ModuleNotLoaded: Story = {
  name: "Module not loaded (empty state)",
  parameters: {
    queryClient: makeQueryClient(makeMockEnvelope()),
  },
};
