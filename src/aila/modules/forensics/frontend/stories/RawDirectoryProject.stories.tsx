import type { Meta, StoryObj } from "@storybook/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter, Route, Routes } from "react-router-dom";

import { FetchRawFilePanel } from "../components/FetchRawFilePanel";
import { NewProjectPage } from "../screens/NewProjectPage";
import { ProjectDashboardPage } from "../screens/ProjectDashboardPage";
import type {
  EvidenceItem,
  InvestigationSummary,
  ProjectSummary,
  RegisteredSystem,
} from "../types";

// ---------------------------------------------------------------------------
// Mock data — a raw_directory project pointing at a Linux rootfs copy
// ---------------------------------------------------------------------------

const PROJECT_ID = "proj-raw-001";

const SYSTEMS: RegisteredSystem[] = [
  { id: 1, name: "analyzer-01", host: "192.168.1.50", username: "analyst", port: 22 },
];

const RAW_PROJECT: ProjectSummary = {
  id: PROJECT_ID,
  name: "Dropbox rootfs — CASE-2203",
  description:
    "A loose rootfs copy exported from the victim laptop. Intake only — no disk image, no dissect.",
  system_id: 1,
  system_name: "analyzer-01",
  evidence_directory: "/mnt/case/rootfs",
  analyzer_os: "linux",
  project_kind: "raw_directory",
  status: "ready",
  evidence_count: 6,
  artifact_count: 0,
  lead_count: 0,
  investigation_count: 0,
  created_at: "2026-04-18T09:00:00Z",
  updated_at: "2026-04-18T09:05:00Z",
};

const RAW_EVIDENCE: EvidenceItem[] = [
  {
    id: "ev-1",
    file_path: "/mnt/case/rootfs/etc/passwd",
    evidence_type: "text_file",
    file_hash_sha256: null,
    size_bytes: 2840,
  },
  {
    id: "ev-2",
    file_path: "/mnt/case/rootfs/etc/shadow",
    evidence_type: "text_file",
    file_hash_sha256: null,
    size_bytes: 1230,
  },
  {
    id: "ev-3",
    file_path: "/mnt/case/rootfs/var/log/auth.log",
    evidence_type: "log_file",
    file_hash_sha256: null,
    size_bytes: 148_992,
  },
  {
    id: "ev-4",
    file_path: "/mnt/case/rootfs/home/alice/.bash_history",
    evidence_type: "text_file",
    file_hash_sha256: null,
    size_bytes: 4812,
  },
  {
    id: "ev-5",
    file_path: "/mnt/case/rootfs/home/alice/notes.txt",
    evidence_type: "text_file",
    file_hash_sha256: null,
    size_bytes: 512,
  },
  {
    id: "ev-6",
    file_path: "/mnt/case/rootfs/opt/dropbox-client",
    evidence_type: "raw_file",
    file_hash_sha256: null,
    size_bytes: 12_884_000,
  },
];

const RAW_INVESTIGATION: InvestigationSummary = {
  id: "inv-raw-1",
  project_id: PROJECT_ID,
  question: "List every non-system user in /etc/passwd with uid >= 1000.",
  status: "running",
  attempts_used: 1,
  max_attempts: 5,
  final_answer: null,
  confidence: null,
};

// ---------------------------------------------------------------------------
// QueryClient factories
// ---------------------------------------------------------------------------

function makeQC({
  project,
  evidence,
  investigations,
  systems,
}: {
  project?: ProjectSummary;
  evidence?: EvidenceItem[];
  investigations?: InvestigationSummary[];
  systems?: RegisteredSystem[];
}): QueryClient {
  const qc = new QueryClient({
    defaultOptions: { queries: { retry: false, staleTime: Infinity } },
  });
  if (project) qc.setQueryData(["forensics", "project", PROJECT_ID], project);
  if (evidence) qc.setQueryData(["forensics", "evidence", PROJECT_ID], evidence);
  if (investigations)
    qc.setQueryData(["forensics", "investigations", PROJECT_ID], investigations);
  if (systems) qc.setQueryData(["platform", "systems"], systems);
  return qc;
}

// ---------------------------------------------------------------------------
// Wizard story — the user toggles the new "Raw Directory" kind
// ---------------------------------------------------------------------------

const wizardMeta = {
  title: "Forensics/RawDirectory",
  component: NewProjectPage,
  tags: ["autodocs"],
  parameters: { layout: "padded" },
  decorators: [
    (Story: React.ComponentType, ctx: { parameters: { queryClient?: QueryClient } }) => (
      <QueryClientProvider client={ctx.parameters.queryClient ?? makeQC({ systems: SYSTEMS })}>
        <MemoryRouter initialEntries={["/forensics/projects/new"]}>
          <div className="p-6 max-w-2xl">
            <Story />
          </div>
        </MemoryRouter>
      </QueryClientProvider>
    ),
  ],
} satisfies Meta<typeof NewProjectPage>;

export default wizardMeta;

type WizardStory = StoryObj<typeof wizardMeta>;

export const NewProjectRawDirectoryToggle: WizardStory = {
  name: "Wizard — Raw Directory toggle available",
  parameters: { queryClient: makeQC({ systems: SYSTEMS }) },
};

// ---------------------------------------------------------------------------
// Dashboard story — no full-analysis button, FetchRawFilePanel in its place
// ---------------------------------------------------------------------------

function DashboardWrapper({ queryClient }: { queryClient: QueryClient }) {
  return (
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={[`/forensics/projects/${PROJECT_ID}`]}>
        <Routes>
          <Route
            path="/forensics/projects/:projectId"
            element={<ProjectDashboardPage />}
          />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>
  );
}

export const DashboardIntakeOnly: StoryObj = {
  name: "Dashboard — intake only, no full-analysis button",
  render: () => (
    <DashboardWrapper
      queryClient={makeQC({
        project: RAW_PROJECT,
        evidence: RAW_EVIDENCE,
        investigations: [],
      })}
    />
  ),
};

export const DashboardWithRunningQuery: StoryObj = {
  name: "Dashboard — investigation running against raw files",
  render: () => (
    <DashboardWrapper
      queryClient={makeQC({
        project: { ...RAW_PROJECT, investigation_count: 1 },
        evidence: RAW_EVIDENCE,
        investigations: [RAW_INVESTIGATION],
      })}
    />
  ),
};

// ---------------------------------------------------------------------------
// Fetch-raw panel in isolation — file vs directory selection
// ---------------------------------------------------------------------------

export const FetchPanelFileList: StoryObj = {
  name: "FetchRawFilePanel — listing evidence",
  render: () => (
    <QueryClientProvider client={makeQC({ evidence: RAW_EVIDENCE })}>
      <div className="max-w-xl">
        <FetchRawFilePanel projectId={PROJECT_ID} />
      </div>
    </QueryClientProvider>
  ),
};

export const FetchPanelEmpty: StoryObj = {
  name: "FetchRawFilePanel — no files catalogued yet",
  render: () => (
    <QueryClientProvider client={makeQC({ evidence: [] })}>
      <div className="max-w-xl">
        <FetchRawFilePanel projectId={PROJECT_ID} />
      </div>
    </QueryClientProvider>
  ),
};
