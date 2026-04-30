import type { Meta, StoryObj } from "@storybook/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

import { TopFindingsWidget } from "./TopFindingsWidget";

// ---------------------------------------------------------------------------
// Mock data
// ---------------------------------------------------------------------------

interface FindingRow {
  id: number;
  cve_id: string | null;
  severity: string | null;
  host: string | null;
  package: string | null;
  is_kev: boolean;
}

interface FindingsListResponse {
  data: {
    total: number;
    page: number;
    page_size: number;
    pages: number;
    items: FindingRow[];
  };
}

const SAMPLE_FINDINGS: FindingRow[] = [
  { id: 1, cve_id: "CVE-2024-1234", severity: "critical", host: "arch-vm-01", package: "openssl", is_kev: true },
  { id: 2, cve_id: "CVE-2024-5678", severity: "critical", host: "ubuntu-prod", package: "curl", is_kev: false },
  { id: 3, cve_id: "CVE-2023-9876", severity: "high", host: "debian-lab", package: "glibc", is_kev: false },
  { id: 4, cve_id: "CVE-2024-2468", severity: "high", host: "arch-vm-02", package: "nginx", is_kev: false },
  { id: 5, cve_id: "CVE-2023-1357", severity: "medium", host: "alpine-srv", package: "busybox", is_kev: false },
];

function makeResponse(items: FindingRow[]): FindingsListResponse {
  return {
    data: {
      total: items.length,
      page: 1,
      page_size: 25,
      pages: 1,
      items,
    },
  };
}

function makeQueryClient(items?: FindingRow[]): QueryClient {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false, staleTime: Infinity } },
  });
  if (items) {
    client.setQueryData(["vulnerability", "findings", "top-5"], makeResponse(items));
  }
  return client;
}

// ---------------------------------------------------------------------------
// Meta
// ---------------------------------------------------------------------------

const meta = {
  title: "Dashboard/Widgets/TopFindingsWidget",
  component: TopFindingsWidget,
  tags: ["autodocs"],
  parameters: {
    layout: "padded",
    docs: {
      description: {
        component:
          "Compact table showing top-5 most critical findings with CVE ID, severity badge (AilaBadge), and system name. Fetches GET /vulnerability/findings and re-sorts client-side so legacy criticality vocabulary (Immediate, Moderate, Planned) ranks correctly. Shows empty state when no findings exist.",
      },
    },
  },
  decorators: [
    (Story: React.ComponentType, context: { parameters: { queryClient?: QueryClient } }) => (
      <QueryClientProvider client={context.parameters.queryClient ?? makeQueryClient()}>
        <div style={{ width: 400, height: 240, border: "1px solid var(--color-border)", borderRadius: 4 }}>
          <Story />
        </div>
      </QueryClientProvider>
    ),
  ],
} satisfies Meta<typeof TopFindingsWidget>;

export default meta;
type Story = StoryObj<typeof meta>;

// ---------------------------------------------------------------------------
// Stories
// ---------------------------------------------------------------------------

export const Default: Story = {
  name: "Default (5 findings)",
  parameters: {
    queryClient: makeQueryClient(SAMPLE_FINDINGS),
  },
};

export const SingleFinding: Story = {
  name: "Single finding",
  parameters: {
    queryClient: makeQueryClient([SAMPLE_FINDINGS[0]]),
  },
};

export const NoData: Story = {
  name: "No findings (empty state)",
  parameters: {
    queryClient: makeQueryClient([]),
  },
};
