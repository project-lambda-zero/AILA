import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { ProjectSummary } from "../../../../api/forensics";
import { FindingsTab } from "./findings";

function project(status: string, artifactCount: number): ProjectSummary {
  return {
    id: "p1",
    name: "case",
    description: "",
    system_id: 1,
    system_name: "lab-01",
    evidence_directory: "/evidence",
    analyzer_os: "linux",
    project_kind: "disk_evidence",
    status,
    failure_reason: null,
    evidence_count: 3,
    artifact_count: artifactCount,
    lead_count: 0,
    investigation_count: 0,
    created_at: null,
    updated_at: null,
  };
}

function renderFindings(p: ProjectSummary): void {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });

  render(
    <QueryClientProvider client={client}>
      <FindingsTab projectId="p1" project={p} onOpenInvestigation={() => {}} />
    </QueryClientProvider>,
  );
}

describe("FindingsTab empty state", () => {
  beforeEach(() => {
    // The findings route answers with no rows for every case below.
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response(JSON.stringify({ data: [] }), { status: 200, headers: { "content-type": "application/json" } })),
    );
  });

  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it("does not report a clean result for a project that was never analyzed", async () => {
    renderFindings(project("ready", 0));

    expect(await screen.findByText("not analyzed yet; run analysis to produce artifacts and findings.")).toBeTruthy();
    expect(screen.queryByText("no suspicious findings.")).toBeNull();
  });

  it("says analysis is running while no artifacts exist yet", async () => {
    renderFindings(project("analyzing", 0));

    expect(await screen.findByText("analysis running; no artifacts parsed yet.")).toBeTruthy();
    expect(screen.queryByText("no suspicious findings.")).toBeNull();
  });

  it("reports no suspicious findings once analysis produced artifacts", async () => {
    renderFindings(project("completed", 12));

    expect(await screen.findByText("no suspicious findings.")).toBeTruthy();
  });
});
