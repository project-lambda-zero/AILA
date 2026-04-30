/**
 * ForensicsJourney.stories.tsx
 *
 * SB-09: Composite user journey — new project → readiness check → dashboard →
 * start investigation → view detail with steps and answers.
 *
 * Uses a single QueryClient pre-seeded with data for the whole journey.
 * Navigation is driven by MemoryRouter with all routes wired up.
 */
import type { Meta, StoryObj } from "@storybook/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { expect, userEvent, within } from "storybook/test";

import { InvestigationDetailPage } from "../screens/InvestigationDetailPage";
import { NewProjectPage } from "../screens/NewProjectPage";
import { ProjectDashboardPage } from "../screens/ProjectDashboardPage";
import { ProjectsPage } from "../screens/ProjectsPage";
import type {
  AgentStep,
  AnswerCandidate,
  InvestigationDetail,
  InvestigationSummary,
  MachineReadinessResult,
  PaginatedResponse,
  ProjectSummary,
  RegisteredSystem,
} from "../types";

// ---------------------------------------------------------------------------
// Seed data
// ---------------------------------------------------------------------------

const PROJECT_ID = "proj-journey-001";
const INV_ID = "inv-journey-001";

const SYSTEMS: RegisteredSystem[] = [
  { id: 1, name: "analyzer-01", host: "192.168.1.50", username: "analyst", port: 22 },
];

const PROJECT: ProjectSummary = {
  id: PROJECT_ID,
  name: "Case 001 Windows Analysis",
  description: "Compromised endpoint investigation",
  system_id: 1,
  system_name: "analyzer-01",
  evidence_directory: "/evidence/case-001",
  analyzer_os: "linux",
  project_kind: "disk_evidence",
  status: "ready",
  evidence_count: 4,
  artifact_count: 312,
  lead_count: 7,
  investigation_count: 1,
  created_at: "2026-04-10T08:00:00Z",
  updated_at: "2026-04-10T10:00:00Z",
};

const PROJECTS_PAGE: PaginatedResponse<ProjectSummary> = {
  total: 1,
  page: 1,
  page_size: 20,
  pages: 1,
  items: [PROJECT],
};

const READINESS: MachineReadinessResult = {
  ready: true,
  system_id: 1,
  system_name: "analyzer-01",
  analyzer_os: "linux",
  message: "All required tools are installed.",
  tools: [
    { tool_name: "volatility3", required: true, status: "installed", version: "2.4.0", message: null },
    { tool_name: "zeek", required: true, status: "installed", version: "6.0.2", message: null },
  ],
};

const INVESTIGATION_SUMMARY: InvestigationSummary = {
  id: INV_ID,
  project_id: PROJECT_ID,
  question: "What processes were executed at logon?",
  status: "completed",
  attempts_used: 3,
  max_attempts: 5,
  final_answer: "explorer.exe and a suspicious cmd.exe spawned from winlogon.exe",
  confidence: "high",
};

const STEPS: AgentStep[] = [
  {
    id: "step-1",
    step_number: 1,
    action: "check_processes.py",
    command: "python3 /tools/check_processes.py /evidence/case-001/memory.raw",
    script_content: "#!/usr/bin/env python3\nimport volatility3\n# Enumerate running processes\nctx = volatility3.framework.contexts.Context()\n",
    stdout: "[*] Loading memory image...\n[+] Found 52 processes\n[+] Suspicious: cmd.exe (PID 4892) parent: winlogon.exe",
    stderr: "",
    exit_code: 0,
    reasoning: "Enumerate running processes to identify anomalous parent-child relationships.",
    created_at: "2026-04-10T09:00:00Z",
  },
  {
    id: "step-2",
    step_number: 2,
    action: "check_autoruns.py",
    command: "python3 /tools/check_autoruns.py /evidence/case-001/registry/",
    script_content: "#!/usr/bin/env python3\nimport regripper\n# Parse registry hives for autorun entries\n",
    stdout: "[*] Parsing NTUSER.DAT...\n[+] Found autorun: HKCU\\Run\\Updater → C:\\Users\\Public\\svchost32.exe",
    stderr: "",
    exit_code: 0,
    reasoning: "Check registry autoruns for persistence mechanisms.",
    created_at: "2026-04-10T09:02:00Z",
  },
  {
    id: "step-3",
    step_number: 3,
    action: "summarize_findings.py",
    command: "python3 /tools/summarize.py",
    script_content: "#!/usr/bin/env python3\n# Summarize all findings into final answer\n",
    stdout: "[*] Generating final answer...\n[+] Confidence: high",
    stderr: "",
    exit_code: 0,
    reasoning: "Consolidate findings from steps 1-2 into a conclusive answer.",
    created_at: "2026-04-10T09:04:00Z",
  },
];

const INVESTIGATION_DETAIL: InvestigationDetail = {
  ...INVESTIGATION_SUMMARY,
  max_attempts: INVESTIGATION_SUMMARY.max_attempts ?? 5,
  steps: STEPS,
};

const ANSWERS: AnswerCandidate[] = [
  {
    id: "ans-001",
    project_id: PROJECT_ID,
    investigation_id: INV_ID,
    question_text: "What processes were executed at logon?",
    answer_text: "explorer.exe, userinit.exe ran normally. Suspicious cmd.exe (PID 4892) was spawned by winlogon.exe, which in turn launched svchost32.exe from C:\\Users\\Public\\.",
    confidence: "high",
    primary_artifact_id: "art-pslist-001",
    corroboration: ["art-autoruns-002"],
    format_hint: "text",
    created_at: "2026-04-10T09:15:00Z",
  },
];

function makeJourneyQC(): QueryClient {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: Infinity } } });
  qc.setQueryData(["platform", "systems"], SYSTEMS);
  qc.setQueryData(["forensics", "projects", 1, 20], PROJECTS_PAGE);
  qc.setQueryData(["forensics", "project", PROJECT_ID], PROJECT);
  qc.setQueryData(["forensics", "investigations", PROJECT_ID], [INVESTIGATION_SUMMARY]);
  qc.setQueryData(["forensics", "investigation", PROJECT_ID, INV_ID], INVESTIGATION_DETAIL);
  qc.setQueryData(["forensics", "answers", PROJECT_ID], ANSWERS);
  qc.setQueryData(["forensics", "leads", PROJECT_ID, 20], []);
  qc.setQueryData(["forensics", "readiness", PROJECT_ID], READINESS);
  return qc;
}

// ---------------------------------------------------------------------------
// Journey app — all routes wired
// ---------------------------------------------------------------------------

function JourneyApp({ queryClient }: { queryClient: QueryClient }) {
  return (
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={["/forensics"]}>
        <div className="p-4 min-h-screen">
          <Routes>
            <Route path="/forensics" element={<ProjectsPage />} />
            <Route path="/forensics/projects/new" element={<NewProjectPage />} />
            <Route path="/forensics/projects/:projectId" element={<ProjectDashboardPage />} />
            <Route
              path="/forensics/projects/:projectId/investigations/:investigationId"
              element={<InvestigationDetailPage />}
            />
          </Routes>
        </div>
      </MemoryRouter>
    </QueryClientProvider>
  );
}

// ---------------------------------------------------------------------------
// Meta
// ---------------------------------------------------------------------------

const meta = {
  title: "Forensics/ForensicsJourney",
  component: JourneyApp,
  tags: ["autodocs"],
  parameters: {
    layout: "fullscreen",
    docs: {
      description: {
        component:
          "Composite user journey covering the full forensics workflow: projects list → new project → readiness check → dashboard → start investigation → investigation detail with steps and answers.",
      },
    },
  },
} satisfies Meta<typeof JourneyApp>;

export default meta;
type Story = StoryObj<typeof meta>;

// ---------------------------------------------------------------------------
// Stories
// ---------------------------------------------------------------------------

export const ProjectsListView: Story = {
  name: "1. Projects List — populated",
  args: { queryClient: makeJourneyQC() },
};

export const NewProjectFormView: Story = {
  name: "2. New Project Form",
  args: { queryClient: makeJourneyQC() },
  render: ({ queryClient }) => (
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={["/forensics/projects/new"]}>
        <div className="p-4 max-w-2xl">
          <Routes>
            <Route path="/forensics/projects/new" element={<NewProjectPage />} />
            <Route path="/forensics" element={<ProjectsPage />} />
          </Routes>
        </div>
      </MemoryRouter>
    </QueryClientProvider>
  ),
};

export const DashboardWithInvestigation: Story = {
  name: "3. Project Dashboard — investigation complete",
  args: { queryClient: makeJourneyQC() },
  render: ({ queryClient }) => (
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={[`/forensics/projects/${PROJECT_ID}`]}>
        <div className="p-4">
          <Routes>
            <Route path="/forensics/projects/:projectId" element={<ProjectDashboardPage />} />
            <Route
              path="/forensics/projects/:projectId/investigations/:investigationId"
              element={<InvestigationDetailPage />}
            />
            <Route path="/forensics" element={<ProjectsPage />} />
          </Routes>
        </div>
      </MemoryRouter>
    </QueryClientProvider>
  ),
};

export const InvestigationDetailView: Story = {
  name: "4. Investigation Detail — steps + answers",
  args: { queryClient: makeJourneyQC() },
  render: ({ queryClient }) => (
    <QueryClientProvider client={queryClient}>
      <MemoryRouter
        initialEntries={[`/forensics/projects/${PROJECT_ID}/investigations/${INV_ID}`]}
      >
        <div className="p-4">
          <Routes>
            <Route
              path="/forensics/projects/:projectId/investigations/:investigationId"
              element={<InvestigationDetailPage />}
            />
            <Route path="/forensics/projects/:projectId" element={<ProjectDashboardPage />} />
          </Routes>
        </div>
      </MemoryRouter>
    </QueryClientProvider>
  ),
};

export const FullJourneyPlay: Story = {
  name: "5. Full Journey (interactive play)",
  args: { queryClient: makeJourneyQC() },
  play: async ({ canvasElement }) => {
    const canvas = within(canvasElement);

    // Step 1: Projects list shows Case 001
    const projectCard = await canvas.findByText("Case 001 Windows Analysis");
    expect(projectCard).toBeInTheDocument();

    // Step 2: Navigate to project dashboard
    await userEvent.click(projectCard);

    // Step 3: Dashboard shows the completed investigation
    const invQuestion = await canvas.findByText("What processes were executed at logon?");
    expect(invQuestion).toBeInTheDocument();

    // Step 4: Click into investigation detail
    await userEvent.click(invQuestion);

    // Step 5: Detail shows final answer
    const answer = await canvas.findByText(/explorer\.exe/);
    expect(answer).toBeInTheDocument();
  },
};
