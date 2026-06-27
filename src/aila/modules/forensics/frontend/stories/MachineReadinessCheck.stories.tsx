import type { Meta, StoryObj } from "@storybook/react";

import { MachineReadinessCheck } from "../components/MachineReadinessCheck";
import type { MachineReadinessResult } from "../types";

// ---------------------------------------------------------------------------
// Mock data
// ---------------------------------------------------------------------------

const ALL_READY: MachineReadinessResult = {
  ready: true,
  system_id: 1,
  system_name: "analyzer-01",
  analyzer_os: "linux",
  message: "All required tools are installed and ready.",
  tools: [
    { tool_name: "volatility3", required: true, status: "installed", version: "2.4.0", message: null },
    { tool_name: "zeek", required: true, status: "installed", version: "6.0.2", message: null },
    { tool_name: "tshark", required: true, status: "installed", version: "4.0.8", message: null },
    { tool_name: "ghidra", required: false, status: "installed", version: "11.0", message: null },
    { tool_name: "capa", required: false, status: "installed", version: "7.0.1", message: null },
  ],
};

const PARTIAL_FAILURE: MachineReadinessResult = {
  ready: false,
  system_id: 1,
  system_name: "analyzer-01",
  analyzer_os: "linux",
  message: "Some required tools are missing or failed to install.",
  tools: [
    { tool_name: "volatility3", required: true, status: "installed", version: "2.4.0", message: null },
    { tool_name: "zeek", required: true, status: "missing", version: null, message: "Not found in PATH. Install the Zeek package for your distro." },
    { tool_name: "tshark", required: true, status: "install_failed", version: null, message: "apt-get install tshark failed: E: Unable to locate package" },
    { tool_name: "ghidra", required: false, status: "missing", version: null, message: null },
  ],
};

const SSH_UNREACHABLE: MachineReadinessResult = {
  ready: false,
  system_id: 2,
  system_name: "analyzer-02",
  analyzer_os: "linux",
  message: "SSH connection to analyzer-02 (192.168.1.51:22) failed: Connection refused",
  tools: [],
};

const WINDOWS_READY: MachineReadinessResult = {
  ready: true,
  system_id: 3,
  system_name: "win-analyzer-01",
  analyzer_os: "windows",
  message: "All required tools are installed and ready.",
  tools: [
    { tool_name: "volatility3", required: true, status: "installed", version: "2.4.0", message: null },
    { tool_name: "x64dbg", required: false, status: "installed", version: "2024-01-01", message: null },
    { tool_name: "regripper", required: true, status: "installed", version: "3.0", message: null },
  ],
};

// ---------------------------------------------------------------------------
// Meta
// ---------------------------------------------------------------------------

const meta = {
  title: "Forensics/MachineReadinessCheck",
  component: MachineReadinessCheck,
  tags: ["autodocs"],
  parameters: { layout: "padded" },
  decorators: [
    (Story: React.ComponentType) => (
      <div className="p-6 max-w-2xl">
        <Story />
      </div>
    ),
  ],
  argTypes: {
    onRetry: { action: "retry" },
    onContinue: { action: "continue" },
  },
} satisfies Meta<typeof MachineReadinessCheck>;

export default meta;
type Story = StoryObj<typeof meta>;

// ---------------------------------------------------------------------------
// Stories
// ---------------------------------------------------------------------------

export const Loading: Story = {
  name: "Loading -- checking readiness",
  args: {
    readinessResult: null,
    isLoading: true,
    onRetry: () => {},
    onContinue: () => {},
  },
};

export const AllReady: Story = {
  name: "All Tools Installed",
  args: {
    readinessResult: ALL_READY,
    isLoading: false,
    onRetry: () => {},
    onContinue: () => {},
  },
};

export const PartialFailure: Story = {
  name: "Partial Failure -- some tools missing",
  args: {
    readinessResult: PARTIAL_FAILURE,
    isLoading: false,
    onRetry: () => {},
    onContinue: () => {},
  },
};

export const SSHUnreachable: Story = {
  name: "SSH Unreachable",
  args: {
    readinessResult: SSH_UNREACHABLE,
    isLoading: false,
    onRetry: () => {},
    onContinue: () => {},
  },
};

export const WindowsAnalyzer: Story = {
  name: "Windows Analyzer -- all ready",
  args: {
    readinessResult: WINDOWS_READY,
    isLoading: false,
    onRetry: () => {},
    onContinue: () => {},
  },
};
