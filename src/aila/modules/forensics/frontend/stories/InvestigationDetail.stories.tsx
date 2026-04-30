import type { Meta, StoryObj } from "@storybook/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter, Route, Routes } from "react-router-dom";

import { InvestigationDetailPage } from "../screens/InvestigationDetailPage";
import type { AgentStep, AnswerCandidate, InvestigationDetail } from "../types";

// ---------------------------------------------------------------------------
// Mock data
// ---------------------------------------------------------------------------

const PROJECT_ID = "proj-001";
const INV_ID = "inv-001";

function makeStep(n: number, overrides: Partial<AgentStep> = {}): AgentStep {
  return {
    id: `step-${n}`,
    step_number: n,
    action: `check_processes_step${n}.py`,
    command: `python3 /tools/check_processes_step${n}.py /evidence/case-001/memory.raw`,
    script_content: `#!/usr/bin/env python3\nimport volatility3\n\ndef main():\n    ctx = volatility3.framework.contexts.Context()\n    # step ${n} analysis\n    print("Running step ${n}")\n\nif __name__ == "__main__":\n    main()`,
    stdout: `[*] Loading memory image...\n[*] Running plugin pslist\n[*] Found 52 processes\n[+] Suspicious: cmd.exe (PID 4892) parent: winlogon.exe`,
    stderr: "",
    exit_code: 0,
    reasoning: `Step ${n}: Enumerating running processes to identify anomalous parent-child relationships.`,
    created_at: "2026-04-10T09:00:00Z",
    ...overrides,
  };
}

function makeFailedStep(n: number): AgentStep {
  return makeStep(n, {
    action: `extract_registry_step${n}.py`,
    stdout: "",
    stderr: `FileNotFoundError: /evidence/case-001/registry/SYSTEM not found\nEnsure the evidence directory contains extracted registry hives.`,
    exit_code: 1,
    reasoning: `Step ${n}: Attempting to parse SYSTEM registry hive for autorun entries.`,
  });
}

function makeInvestigation(steps: AgentStep[], overrides: Partial<InvestigationDetail> = {}): InvestigationDetail {
  return {
    id: INV_ID,
    project_id: PROJECT_ID,
    question: "What processes were executed at logon? Is there evidence of persistence?",
    status: "completed",
    attempts_used: steps.length,
    max_attempts: 10,
    final_answer: "explorer.exe and userinit.exe ran normally. A suspicious cmd.exe was spawned from winlogon.exe (PID 4892). Registry autoruns contain an entry pointing to C:\\Users\\Public\\svchost32.exe — likely persistence mechanism.",
    confidence: "high",
    steps,
    ...overrides,
  };
}

const ANSWERS: AnswerCandidate[] = [
  {
    id: "ans-001",
    project_id: PROJECT_ID,
    investigation_id: INV_ID,
    question_text: "What processes were executed at logon?",
    answer_text: "explorer.exe, userinit.exe, and a suspicious cmd.exe spawned from winlogon.exe (PID 4892)",
    confidence: "high",
    primary_artifact_id: "art-pslist-001",
    corroboration: ["art-autoruns-002", "art-shimcache-003"],
    format_hint: "process_list",
    created_at: "2026-04-10T09:15:00Z",
  },
  {
    id: "ans-002",
    project_id: PROJECT_ID,
    investigation_id: INV_ID,
    question_text: "Is there evidence of persistence?",
    answer_text: "Yes. Registry Run key at HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run contains entry for svchost32.exe in C:\\Users\\Public\\.",
    confidence: "high",
    primary_artifact_id: "art-autoruns-002",
    corroboration: ["art-amcache-004"],
    format_hint: "text",
    created_at: "2026-04-10T09:16:00Z",
  },
];

function makeQC(investigation: InvestigationDetail, answers: AnswerCandidate[] = []): QueryClient {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: Infinity } } });
  qc.setQueryData(["forensics", "investigation", PROJECT_ID, INV_ID], investigation);
  qc.setQueryData(["forensics", "answers", PROJECT_ID], answers);
  return qc;
}

function DetailWrapper({ queryClient }: { queryClient: QueryClient }) {
  return (
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={[`/forensics/projects/${PROJECT_ID}/investigations/${INV_ID}`]}>
        <Routes>
          <Route
            path="/forensics/projects/:projectId/investigations/:investigationId"
            element={<InvestigationDetailPage />}
          />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>
  );
}

// ---------------------------------------------------------------------------
// Meta
// ---------------------------------------------------------------------------

const meta = {
  title: "Forensics/InvestigationDetail",
  component: InvestigationDetailPage,
  tags: ["autodocs"],
  parameters: { layout: "padded" },
} satisfies Meta<typeof InvestigationDetailPage>;

export default meta;
type Story = StoryObj<typeof meta>;

// ---------------------------------------------------------------------------
// Stories
// ---------------------------------------------------------------------------

export const ThreeStepRun: Story = {
  name: "3-Step Completed Run",
  render: () => (
    <DetailWrapper queryClient={makeQC(makeInvestigation([makeStep(1), makeStep(2), makeStep(3)]), ANSWERS)} />
  ),
};

export const TenStepRun: Story = {
  name: "10-Step Completed Run",
  render: () => (
    <DetailWrapper
      queryClient={makeQC(
        makeInvestigation(Array.from({ length: 10 }, (_, i) => makeStep(i + 1))),
        ANSWERS,
      )}
    />
  ),
};

export const FailedAtStep4: Story = {
  name: "Failed at Step 4",
  render: () => (
    <DetailWrapper
      queryClient={makeQC(
        makeInvestigation(
          [makeStep(1), makeStep(2), makeStep(3), makeFailedStep(4)],
          { status: "failed", final_answer: null, confidence: null, attempts_used: 4 } as Partial<InvestigationDetail>,
        ),
      )}
    />
  ),
};

export const StillRunning: Story = {
  name: "Still Running (3 steps so far)",
  render: () => (
    <DetailWrapper
      queryClient={makeQC(
        makeInvestigation(
          [makeStep(1), makeStep(2), makeStep(3)],
          { status: "running", final_answer: null, confidence: null, attempts_used: 3 } as Partial<InvestigationDetail>,
        ),
      )}
    />
  ),
};
