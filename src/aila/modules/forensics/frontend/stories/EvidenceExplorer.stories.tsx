import type { Meta, StoryObj } from "@storybook/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

import { ArtifactExplorer } from "../components/ArtifactExplorer";
import { EvidenceTree } from "../components/EvidenceTree";
import type { EvidenceItem, NormalizedArtifact, PaginatedResponse } from "../types";

// ---------------------------------------------------------------------------
// Mock data
// ---------------------------------------------------------------------------

const PROJECT_ID = "proj-001";

function makeEvidence(overrides: Partial<EvidenceItem> = {}): EvidenceItem {
  return {
    id: crypto.randomUUID(),
    file_path: "/evidence/case-001/memory.raw",
    evidence_type: "memory_dump",
    file_hash_sha256: "a".repeat(64),
    size_bytes: 8589934592,
    ...overrides,
  };
}

function makeArtifact(family: string, type: string): NormalizedArtifact {
  return {
    id: crypto.randomUUID(),
    project_id: PROJECT_ID,
    artifact_family: family,
    artifact_type: type,
    source_tool: "volatility3",
    source_evidence_id: null,
    source_investigation_id: null,
    data: { name: "explorer.exe", pid: 1234 },
    lead_score: Math.random() > 0.7 ? Math.round(Math.random() * 100) : null,
  };
}

function makeArtifactPage(items: NormalizedArtifact[]): PaginatedResponse<NormalizedArtifact> {
  return { total: items.length, page: 1, page_size: 50, pages: 1, items };
}

function makeQC(evidence?: EvidenceItem[], artifacts?: PaginatedResponse<NormalizedArtifact>): QueryClient {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: Infinity } } });
  if (evidence) qc.setQueryData(["forensics", "evidence", PROJECT_ID], evidence);
  if (artifacts) {
    qc.setQueryData(["forensics", "artifacts", PROJECT_ID, {}], artifacts);
  }
  return qc;
}

// ---------------------------------------------------------------------------
// Meta — renders side by side
// ---------------------------------------------------------------------------

interface ExplorerArgs {
  queryClient: QueryClient;
}

function ExplorerLayout({ queryClient }: ExplorerArgs) {
  return (
    <QueryClientProvider client={queryClient}>
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 p-6">
        <EvidenceTree projectId={PROJECT_ID} />
        <ArtifactExplorer projectId={PROJECT_ID} />
      </div>
    </QueryClientProvider>
  );
}

const meta: Meta<ExplorerArgs> = {
  title: "Forensics/EvidenceExplorer",
  component: ExplorerLayout,
  tags: ["autodocs"],
  parameters: { layout: "fullscreen" },
};

export default meta;
type Story = StoryObj<ExplorerArgs>;

// ---------------------------------------------------------------------------
// Stories
// ---------------------------------------------------------------------------

export const EmptyState: Story = {
  name: "Empty — no evidence ingested",
  args: { queryClient: makeQC([], makeArtifactPage([])) },
};

export const LoadedMixedFamilies: Story = {
  name: "Loaded — mixed artifact families",
  args: {
    queryClient: makeQC(
      [
        makeEvidence({ evidence_type: "memory_dump", file_path: "/evidence/case-001/memory.raw" }),
        makeEvidence({ evidence_type: "disk_image", file_path: "/evidence/case-001/disk.E01", size_bytes: 107374182400 }),
        makeEvidence({ evidence_type: "pcap", file_path: "/evidence/case-001/capture.pcapng", size_bytes: 52428800 }),
        makeEvidence({ evidence_type: "log_file", file_path: "/evidence/case-001/evtx.zip", size_bytes: 1048576 }),
      ],
      makeArtifactPage([
        ...Array.from({ length: 8 }, () => makeArtifact("process", "pslist")),
        ...Array.from({ length: 5 }, () => makeArtifact("network", "netscan")),
        ...Array.from({ length: 3 }, () => makeArtifact("persistence", "autoruns")),
        ...Array.from({ length: 12 }, () => makeArtifact("filesystem", "mft_entry")),
      ]),
    ),
  },
};

export const FilteredView: Story = {
  name: "Filtered — persistence family only",
  args: {
    queryClient: (() => {
      const qc = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: Infinity } } });
      qc.setQueryData(["forensics", "evidence", PROJECT_ID], [
        makeEvidence({ evidence_type: "disk_image" }),
      ]);
      qc.setQueryData(
        ["forensics", "artifacts", PROJECT_ID, { family: "persistence", page: 1, pageSize: 50 }],
        makeArtifactPage([
          makeArtifact("persistence", "autoruns"),
          makeArtifact("persistence", "services"),
          makeArtifact("persistence", "scheduled_tasks"),
        ]),
      );
      return qc;
    })(),
  },
};
