/**
 * SeverityDonutChart.stories.tsx — Storybook stories for VIZ-01.
 *
 * Stories use a mock QueryClient to simulate loaded/empty states
 * without needing a live backend.
 */
import type { Meta, StoryObj } from "@storybook/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import * as React from "react";

import { SeverityDonutChart } from "./SeverityDonutChart";

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
  queryClient.setQueryData(["platform", "findings-facets"], mockData);
  return <QueryClientProvider client={queryClient}>{children}</QueryClientProvider>;
}

const meta: Meta<typeof SeverityDonutChart> = {
  title: "Platform/Viz/SeverityDonutChart",
  component: SeverityDonutChart,
  parameters: {
    layout: "centered",
  },
};

export default meta;
type Story = StoryObj<typeof SeverityDonutChart>;

export const WithData: Story = {
  decorators: [
    (Story) => (
      <MockedQueryProvider
        mockData={{
          severity: { CRITICAL: 12, HIGH: 28, MEDIUM: 45, LOW: 15 },
        }}
      >
        <div style={{ width: 360 }}>
          <Story />
        </div>
      </MockedQueryProvider>
    ),
  ],
};

export const EmptyState: Story = {
  decorators: [
    (Story) => (
      <MockedQueryProvider mockData={{ severity: {} }}>
        <div style={{ width: 360 }}>
          <Story />
        </div>
      </MockedQueryProvider>
    ),
  ],
};

export const CriticalHeavy: Story = {
  decorators: [
    (Story) => (
      <MockedQueryProvider
        mockData={{
          severity: { CRITICAL: 47, HIGH: 12, MEDIUM: 3, LOW: 1 },
        }}
      >
        <div style={{ width: 360 }}>
          <Story />
        </div>
      </MockedQueryProvider>
    ),
  ],
};
