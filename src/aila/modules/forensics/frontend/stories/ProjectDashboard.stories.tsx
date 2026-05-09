import type { Meta, StoryObj } from "@storybook/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter, Route, Routes } from "react-router";

import { ProjectDashboardPage } from "../screens/ProjectDashboardPage";
import type { InvestigationSummary, ProjectSummary } from "../types";

// ---------------------------------------------------------------------------
// Mock data
// ---------------------------------------------------------------------------

const PROJECT_ID = "proj-demo-001";

function makeProject(overrides: Partial<ProjectSummary> = {}): ProjectSummary {
  return {
    id: PROJECT_ID,
    name: "Case 001 Windows Analysis",
    description: "Compromised Windows endpoint",
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

function makeInvestigation(overrides: Partial<InvestigationSummary> = {}): InvestigationSummary {
  return {
    id: crypto.randomUUID(),
    project_id: PROJECT_ID,
    question: "What processes were executed at logon?",
    status: "completed",
    attempts_used: 3,
    max_attempts: 5,
    final_answer: "explorer.exe, userinit.exe, and a suspicious cmd.exe spawned from winlogon.exe",
    confidence: "high",
    ...overrides,
  };
}

function makeQC(project?: ProjectSummary, investigations?: InvestigationSummary[], leads?: unknown[]): QueryClient {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: Infinity } } });
  if (project) qc.setQueryData(["forensics", "project", PROJECT_ID], project);
  if (investigations) qc.setQueryData(["forensics", "investigations", PROJECT_ID], investigations);
  if (leads) qc.setQueryData(["forensics", "leads", PROJECT_ID, 20], leads);
  return qc;
}

function DashboardWrapper({ queryClient }: { queryClient: QueryClient }) {
  return (
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={[`/forensics/projects/${PROJECT_ID}`]}>
        <Routes>
          <Route path="/forensics/projects/:projectId" element={<ProjectDashboardPage />} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>
  );
}

// ---------------------------------------------------------------------------
// Meta
// ---------------------------------------------------------------------------

const meta = {
  title: "Forensics/ProjectDashboard",
  component: ProjectDashboardPage,
  tags: ["autodocs"],
  parameters: { layout: "padded" },
} satisfies Meta<typeof ProjectDashboardPage>;

export default meta;
type Story = StoryObj<typeof meta>;

// ---------------------------------------------------------------------------
// Stories
// ---------------------------------------------------------------------------

export const NoInvestigations: Story = {
  name: "No Investigations Yet",
  render: () => (
    <DashboardWrapper queryClient={makeQC(makeProject(), [], [])} />
  ),
};

export const OneRunning: Story = {
  name: "One Running Investigation",
  render: () => (
    <DashboardWrapper
      queryClient={makeQC(
        makeProject({ investigation_count: 1 }),
        [makeInvestigation({ status: "running", final_answer: null, confidence: null, attempts_used: 1 })],
        [],
      )}
    />
  ),
};

export const OneCompleted: Story = {
  name: "One Completed Investigation",
  render: () => (
    <DashboardWrapper
      queryClient={makeQC(
        makeProject({ investigation_count: 1 }),
        [makeInvestigation({ status: "completed" })],
        [],
      )}
    />
  ),
};

export const OneFailed: Story = {
  name: "One Failed Investigation",
  render: () => (
    <DashboardWrapper
      queryClient={makeQC(
        makeProject({ investigation_count: 1 }),
        [makeInvestigation({ status: "failed", final_answer: null, confidence: null, attempts_used: 5 })],
        [],
      )}
    />
  ),
};

export const MixedInvestigations: Story = {
  name: "Mixed — running + completed + failed",
  render: () => (
    <DashboardWrapper
      queryClient={makeQC(
        makeProject({ investigation_count: 3 }),
        [
          makeInvestigation({ question: "What processes ran at logon?", status: "completed" }),
          makeInvestigation({ question: "Is there evidence of lateral movement?", status: "running", final_answer: null, confidence: null, attempts_used: 2 }),
          makeInvestigation({ question: "Was there data exfiltration via USB?", status: "failed", final_answer: null, confidence: null, attempts_used: 5 }),
        ],
        [],
      )}
    />
  ),
};
