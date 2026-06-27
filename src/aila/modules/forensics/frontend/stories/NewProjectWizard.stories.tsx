import type { Meta, StoryObj } from "@storybook/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router";

import { MachineReadinessCheck } from "../components/MachineReadinessCheck";
import { NewProjectPage } from "../screens/NewProjectPage";
import type { MachineReadinessResult, RegisteredSystem } from "../types";

// ---------------------------------------------------------------------------
// Mock data
// ---------------------------------------------------------------------------

const SYSTEMS: RegisteredSystem[] = [
  { id: 1, name: "analyzer-01", host: "192.168.1.50", username: "analyst", port: 22 },
  { id: 2, name: "analyzer-02", host: "192.168.1.51", username: "analyst", port: 22 },
];

const READINESS_ALL_PASS: MachineReadinessResult = {
  ready: true,
  system_id: 1,
  system_name: "analyzer-01",
  analyzer_os: "linux",
  message: "All required tools are installed and ready.",
  tools: [
    { tool_name: "volatility3", required: true, status: "installed", version: "2.4.0", message: null },
    { tool_name: "zeek", required: true, status: "installed", version: "6.0.2", message: null },
    { tool_name: "ghidra", required: false, status: "installed", version: "11.0", message: null },
    { tool_name: "tshark", required: true, status: "installed", version: "4.0.8", message: null },
  ],
};

const READINESS_PARTIAL_FAIL: MachineReadinessResult = {
  ready: false,
  system_id: 1,
  system_name: "analyzer-01",
  analyzer_os: "linux",
  message: "Some required tools are missing.",
  tools: [
    { tool_name: "volatility3", required: true, status: "installed", version: "2.4.0", message: null },
    { tool_name: "zeek", required: true, status: "missing", version: null, message: "Not found in PATH. Install the Zeek package for your distro." },
    { tool_name: "tshark", required: true, status: "install_failed", version: null, message: "apt-get failed: permission denied" },
    { tool_name: "ghidra", required: false, status: "missing", version: null, message: null },
  ],
};

const READINESS_SSH_FAIL: MachineReadinessResult = {
  ready: false,
  system_id: 2,
  system_name: "analyzer-02",
  analyzer_os: "linux",
  message: "SSH connection to analyzer-02 failed: Connection refused",
  tools: [],
};

function makeQC(systems?: RegisteredSystem[]): QueryClient {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: Infinity } } });
  if (systems) qc.setQueryData(["platform", "systems"], systems);
  return qc;
}

// ---------------------------------------------------------------------------
// Meta -- wizard form screen
// ---------------------------------------------------------------------------

const meta = {
  title: "Forensics/NewProjectWizard",
  component: NewProjectPage,
  tags: ["autodocs"],
  parameters: { layout: "padded" },
  decorators: [
    (Story: React.ComponentType, ctx: { parameters: { queryClient?: QueryClient } }) => (
      <QueryClientProvider client={ctx.parameters.queryClient ?? makeQC()}>
        <MemoryRouter initialEntries={["/forensics/projects/new"]}>
          <div className="p-6 max-w-2xl">
            <Story />
          </div>
        </MemoryRouter>
      </QueryClientProvider>
    ),
  ],
} satisfies Meta<typeof NewProjectPage>;

export default meta;
type Story = StoryObj<typeof meta>;

export const BlankForm: Story = {
  name: "Blank Form -- systems loaded",
  parameters: { queryClient: makeQC(SYSTEMS) },
};

export const SystemsLoading: Story = {
  name: "Systems Loading",
  parameters: { queryClient: makeQC() },
};

// ---------------------------------------------------------------------------
// Readiness check states -- use MachineReadinessCheck directly
// ---------------------------------------------------------------------------

export const ReadinessChecking: Story = {
  name: "Readiness -- checking (loading)",
  render: () => (
    <MachineReadinessCheck
      readinessResult={null}
      isLoading={true}
      onRetry={() => {}}
      onContinue={() => {}}
    />
  ),
};

export const ReadinessAllPass: Story = {
  name: "Readiness -- all tools installed",
  render: () => (
    <MachineReadinessCheck
      readinessResult={READINESS_ALL_PASS}
      isLoading={false}
      onRetry={() => {}}
      onContinue={() => {}}
    />
  ),
};

export const ReadinessPartialFail: Story = {
  name: "Readiness -- some tools missing",
  render: () => (
    <MachineReadinessCheck
      readinessResult={READINESS_PARTIAL_FAIL}
      isLoading={false}
      onRetry={() => {}}
      onContinue={() => {}}
    />
  ),
};

export const ReadinessSSHUnreachable: Story = {
  name: "Readiness -- SSH unreachable",
  render: () => (
    <MachineReadinessCheck
      readinessResult={READINESS_SSH_FAIL}
      isLoading={false}
      onRetry={() => {}}
      onContinue={() => {}}
    />
  ),
};
