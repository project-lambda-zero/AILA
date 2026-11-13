import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { ProjectSummary } from "../../../../api/forensics";
import { OverviewTab } from "./overview";

const REACT_INTERNALS = ["$$typeof", "_owner", "_store"];

const PROJECT: ProjectSummary = {
  id: "p1",
  name: "wasm triage",
  description: "",
  system_id: 7,
  system_name: "lab-01",
  evidence_directory: "/evidence/p1",
  analyzer_os: "windows",
  project_kind: "dfir",
  status: "completed",
  evidence_count: 0,
  artifact_count: 0,
  lead_count: 0,
  investigation_count: 0,
  created_at: null,
  updated_at: null,
};

// Stands in for the backend at the network boundary: list endpoints return an
// empty envelope and the artifacts page returns an empty `{items, total}`.
function jsonResponse(data: unknown): Response {
  return new Response(JSON.stringify({ data }), {
    status: 200,
    headers: { "content-type": "application/json" },
  });
}

function renderOverview(project: ProjectSummary | null) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const { container } = render(
    <QueryClientProvider client={client}>
      <OverviewTab projectId="p1" project={project} onOpenInvestigation={() => {}} />
    </QueryClientProvider>,
  );
  return { container, client };
}

describe("OverviewTab", () => {
  beforeEach(() => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: string | URL) => {
        const url = String(input);
        return url.includes("/artifacts") ? jsonResponse({ items: [], total: 0 }) : jsonResponse([]);
      }),
    );
  });

  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it("shows the project status badge as text, not React internals", async () => {
    const { container, client } = renderOverview(PROJECT);

    expect(screen.getByText("completed")).toBeTruthy();
    expect(container.textContent).toContain("wasm triage");
    for (const marker of REACT_INTERNALS) {
      expect(container.textContent).not.toContain(marker);
    }

    await screen.findByText("no leads yet.");
    client.clear();
  });

  it("shows the recorded failure reason for a failed project", async () => {
    const reason = "intake failed: UpstreamError: analyzer ssh transport down";
    const { client } = renderOverview({ ...PROJECT, status: "failed", failure_reason: reason });

    expect(screen.getByText("failure reason")).toBeTruthy();
    expect(screen.getByText(reason)).toBeTruthy();
    await screen.findByText("no leads yet.");
    client.clear();
  });

  it("hides a stale failure reason once the project is not failed", async () => {
    const { client } = renderOverview({
      ...PROJECT,
      status: "completed",
      failure_reason: "intake failed: UpstreamError: old",
    });

    expect(screen.queryByText("intake failed: UpstreamError: old")).toBeNull();
    await screen.findByText("no leads yet.");
    client.clear();
  });

  it("reports empty sections once the queries settle", async () => {
    const { client } = renderOverview(PROJECT);

    expect(await screen.findByText("no leads yet.")).toBeTruthy();
    expect(await screen.findByText("no investigations yet.")).toBeTruthy();
    expect(await screen.findByText("no artifacts yet.")).toBeTruthy();
    client.clear();
  });
});
