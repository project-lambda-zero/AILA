import type { Meta, StoryObj } from "@storybook/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

import { WriteUpViewer } from "../components/WriteUpViewer";
import type { WriteUpItem } from "../types";

// ---------------------------------------------------------------------------
// Mock data
// ---------------------------------------------------------------------------

const PROJECT_ID = "proj-001";

function makeWriteup(overrides: Partial<WriteUpItem> = {}): WriteUpItem {
  return {
    id: crypto.randomUUID(),
    project_id: PROJECT_ID,
    investigation_id: "inv-001",
    title: "Case 001 -- Logon Persistence Analysis",
    content_markdown: `## Executive Summary

Analysis of the Case 001 memory image revealed a **persistence mechanism** installed via the Windows registry.

## Findings

### Persistence via Run Key

A suspicious executable \`svchost32.exe\` was found in \`C:\\Users\\Public\\\` and registered under:

\`\`\`
HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater
\`\`\`

### Process Anomalies

The following parent-child relationship is anomalous:

- **winlogon.exe** (PID 492) → **cmd.exe** (PID 4892) → **svchost32.exe** (PID 5012)

### Network Activity

During the analysis window, outbound connections to \`185.220.101.42:443\` were observed, consistent with command-and-control beaconing.

## Recommendations

1. Quarantine the affected endpoint immediately
2. Remove the registry autorun entry
3. Investigate \`svchost32.exe\` for additional payloads
4. Block \`185.220.101.42\` at the perimeter firewall`,
    methodology: "Memory forensics via Volatility3, followed by registry analysis and network session correlation.",
    artifacts_referenced: ["art-pslist-001", "art-autoruns-002", "art-netscan-003"],
    created_at: "2026-04-10T10:30:00Z",
    ...overrides,
  };
}

function makeQC(writeups?: WriteUpItem[]): QueryClient {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: Infinity } } });
  if (writeups) qc.setQueryData(["forensics", "writeups", PROJECT_ID], writeups);
  return qc;
}

// ---------------------------------------------------------------------------
// Meta
// ---------------------------------------------------------------------------

const meta = {
  title: "Forensics/WriteupViewer",
  component: WriteUpViewer,
  tags: ["autodocs"],
  parameters: { layout: "padded" },
  decorators: [
    (Story: React.ComponentType, ctx: { parameters: { queryClient?: QueryClient } }) => (
      <QueryClientProvider client={ctx.parameters.queryClient ?? makeQC()}>
        <div className="p-6 max-w-3xl">
          <Story />
        </div>
      </QueryClientProvider>
    ),
  ],
  args: { projectId: PROJECT_ID },
} satisfies Meta<typeof WriteUpViewer>;

export default meta;
type Story = StoryObj<typeof meta>;

// ---------------------------------------------------------------------------
// Stories
// ---------------------------------------------------------------------------

export const NoWriteups: Story = {
  name: "No Writeups -- empty state",
  parameters: { queryClient: makeQC([]) },
};

export const OneWriteup: Story = {
  name: "One Writeup",
  parameters: { queryClient: makeQC([makeWriteup()]) },
};

export const LongWriteupWithSections: Story = {
  name: "Long Writeup with Sections",
  parameters: {
    queryClient: makeQC([
      makeWriteup({
        title: "Case 001 -- Comprehensive Incident Report",
        content_markdown: `# Case 001 Comprehensive Incident Report

## 1. Incident Overview

**Date of Analysis:** 2026-04-10
**Analyst:** AI Lab Assistant (AILA)
**Confidence:** High

This report documents the findings from forensic analysis of the Case 001 case involving a compromised Windows endpoint.

## 2. Timeline of Events

| Timestamp | Event |
|-----------|-------|
| 07:12:04 | Initial logon -- user john |
| 07:14:22 | cmd.exe spawned from winlogon.exe |
| 07:15:01 | svchost32.exe dropped to Public folder |
| 07:15:03 | Registry autorun key created |
| 07:16:44 | Outbound connection to 185.220.101.42:443 |

## 3. Persistence Mechanisms

### 3.1 Registry Autoruns

\`\`\`
HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run
  Updater = C:\\Users\\Public\\svchost32.exe
\`\`\`

### 3.2 Scheduled Tasks

No additional scheduled tasks were found.

## 4. Network Indicators

Observed C2 traffic:
- **185.220.101.42:443** -- TLS 1.3, SNI: update.microsoft-cdn.com (spoofed)
- **Total bytes sent:** 48.2 KB over 3 sessions

## 5. Recommendations

1. **Immediate:** Isolate endpoint from network
2. **Short-term:** Full reimaging of affected system
3. **Long-term:** Deploy endpoint detection and response (EDR) solution

## 6. Appendix -- Artifact IDs

- \`art-pslist-001\` -- Process list snapshot
- \`art-autoruns-002\` -- Registry autorun export
- \`art-netscan-003\` -- Network connection table`,
        methodology: "Full-disk and memory forensics. Volatility3 for memory analysis, RegRipper for registry, Wireshark/tshark for network.",
        artifacts_referenced: ["art-pslist-001", "art-autoruns-002", "art-netscan-003", "art-mft-004", "art-prefetch-005"],
      }),
    ]),
  },
};
