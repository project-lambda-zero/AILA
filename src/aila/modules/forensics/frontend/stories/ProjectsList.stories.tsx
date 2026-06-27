import type { Meta, StoryObj } from "@storybook/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router";

import { ProjectsPage } from "../screens/ProjectsPage";
import type { PaginatedResponse, ProjectSummary } from "../types";

// ---------------------------------------------------------------------------
// Mock data
// ---------------------------------------------------------------------------

function makeProject(overrides: Partial<ProjectSummary> = {}): ProjectSummary {
  return {
    id: crypto.randomUUID(),
    name: "Case 001 Windows Analysis",
    description: "Analysis of compromised Windows endpoint",
    system_id: 1,
    system_name: "analyzer-01",
    evidence_directory: "/evidence/case-001",
    analyzer_os: "linux",
    project_kind: "disk_evidence",
    status: "ready",
    evidence_count: 4,
    artifact_count: 312,
    lead_count: 7,
    investigation_count: 3,
    created_at: "2026-04-10T08:00:00Z",
    updated_at: "2026-04-10T10:00:00Z",
    ...overrides,
  };
}

function makePage(items: ProjectSummary[]): PaginatedResponse<ProjectSummary> {
  return { total: items.length, page: 1, page_size: 20, pages: 1, items };
}

function makeQC(data?: PaginatedResponse<ProjectSummary>): QueryClient {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: Infinity } } });
  if (data) qc.setQueryData(["forensics", "projects", 1, 20], data);
  return qc;
}

// ---------------------------------------------------------------------------
// Meta
// ---------------------------------------------------------------------------

const meta = {
  title: "Forensics/ProjectsList",
  component: ProjectsPage,
  tags: ["autodocs"],
  parameters: { layout: "padded" },
  decorators: [
    (Story: React.ComponentType, ctx: { parameters: { queryClient?: QueryClient } }) => (
      <QueryClientProvider client={ctx.parameters.queryClient ?? makeQC()}>
        <MemoryRouter initialEntries={["/forensics"]}>
          <div className="p-6 max-w-5xl">
            <Story />
          </div>
        </MemoryRouter>
      </QueryClientProvider>
    ),
  ],
} satisfies Meta<typeof ProjectsPage>;

export default meta;
type Story = StoryObj<typeof meta>;

// ---------------------------------------------------------------------------
// Stories
// ---------------------------------------------------------------------------

export const EmptyState: Story = {
  name: "Empty State -- no projects yet",
  parameters: { queryClient: makeQC(makePage([])) },
};

export const LoadingSkeleton: Story = {
  name: "Loading Skeleton",
  parameters: { queryClient: makeQC() }, // no data → stays loading
};

export const PopulatedList: Story = {
  name: "Populated -- 3 projects",
  parameters: {
    queryClient: makeQC(makePage([
      makeProject({ name: "Case 001 Windows Analysis", status: "ready", investigation_count: 3 }),
      makeProject({ name: "Case 002 Memory Forensics", status: "analyzing", system_name: "analyzer-02", evidence_directory: "/evidence/case-002", artifact_count: 88, investigation_count: 1 }),
      makeProject({ name: "Case 003 Linux Incident", status: "completed", system_name: "analyzer-01", evidence_directory: "/evidence/case-003", artifact_count: 512, lead_count: 14, investigation_count: 6 }),
    ])),
  },
};

export const WithFailedProject: Story = {
  name: "With Failed Project",
  parameters: {
    queryClient: makeQC(makePage([
      makeProject({ name: "Case 001 Windows Analysis", status: "ready" }),
      makeProject({ name: "Case 004 Disk Image", status: "failed", artifact_count: 0, lead_count: 0, investigation_count: 0 }),
    ])),
  },
};
