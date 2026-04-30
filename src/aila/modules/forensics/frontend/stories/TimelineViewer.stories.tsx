import type { Meta, StoryObj } from "@storybook/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

import { TimelineViewer } from "../components/TimelineViewer";
import type { TimelineEntry } from "../types";

// ---------------------------------------------------------------------------
// Mock data
// ---------------------------------------------------------------------------

const PROJECT_ID = "proj-001";

const SOURCES = ["evtx", "mft", "prefetch", "registry", "pcap", "lnk"];
const EVENT_TYPES = ["process_start", "file_write", "network_conn", "registry_write", "logon", "service_start"];
const DESCRIPTIONS = [
  "cmd.exe spawned from winlogon.exe (PID 4892)",
  "File written: C:\\Users\\Public\\svchost32.exe",
  "Network connection to 185.220.101.42:443",
  "Registry write: HKCU\\Run\\Updater",
  "Interactive logon for user DESKTOP-01\\john",
  "Service created: WindowsUpdaterHelper",
  "svchost32.exe executed from C:\\Users\\Public\\",
  "LSASS memory read by unknown process",
  "DNS query: suspicious-c2-domain.ru",
  "Scheduled task created: \\Microsoft\\Windows\\Updater",
];

function makeEntry(i: number, baseTime = new Date("2026-04-10T07:00:00Z")): TimelineEntry {
  const t = new Date(baseTime.getTime() + i * 37000); // ~37s apart
  return {
    timestamp: t.toISOString(),
    source: SOURCES[i % SOURCES.length],
    event_type: EVENT_TYPES[i % EVENT_TYPES.length],
    description: DESCRIPTIONS[i % DESCRIPTIONS.length],
    artifact_id: i % 3 === 0 ? `art-${i}` : null,
    data: { raw_value: `value_${i}` },
  };
}

function makeQC(entries?: TimelineEntry[]): QueryClient {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: Infinity } } });
  if (entries) qc.setQueryData(["forensics", "timeline", PROJECT_ID, 500], entries);
  return qc;
}

// ---------------------------------------------------------------------------
// Meta
// ---------------------------------------------------------------------------

const meta = {
  title: "Forensics/TimelineViewer",
  component: TimelineViewer,
  tags: ["autodocs"],
  parameters: { layout: "padded" },
  decorators: [
    (Story: React.ComponentType, ctx: { parameters: { queryClient?: QueryClient } }) => (
      <QueryClientProvider client={ctx.parameters.queryClient ?? makeQC()}>
        <div className="p-6">
          <Story />
        </div>
      </QueryClientProvider>
    ),
  ],
  args: { projectId: PROJECT_ID },
} satisfies Meta<typeof TimelineViewer>;

export default meta;
type Story = StoryObj<typeof meta>;

// ---------------------------------------------------------------------------
// Stories
// ---------------------------------------------------------------------------

export const EmptyTimeline: Story = {
  name: "Empty Timeline",
  parameters: { queryClient: makeQC([]) },
};

export const TwentyEvents: Story = {
  name: "20 Events",
  parameters: {
    queryClient: makeQC(Array.from({ length: 20 }, (_, i) => makeEntry(i))),
  },
};

export const FiveHundredEvents: Story = {
  name: "500-Event Performance Variant",
  parameters: {
    queryClient: makeQC(Array.from({ length: 500 }, (_, i) => makeEntry(i))),
  },
};
