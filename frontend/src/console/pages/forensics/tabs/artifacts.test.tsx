import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { aggregateCarvedFileTypes, parseArtifactPage } from "../../../../api/forensics";
import { ArtifactsTab } from "./artifacts";

interface CaptureSummary {
  evidence_path: string;
  rows: { mime_type: string; count: number }[];
  total_carved: number;
}

interface SummaryItem {
  id: string;
  project_id: string;
  artifact_family: string;
  artifact_type: string;
  source_tool: string;
  source_evidence_id: null;
  source_investigation_id: null;
  data: CaptureSummary & { unique_mimes: number };
  lead_score: null;
}

function summaryItem(id: string, summary: CaptureSummary): SummaryItem {
  return {
    id,
    project_id: "p1",
    artifact_family: "network",
    artifact_type: "carved_file_types",
    source_tool: "pcap",
    source_evidence_id: null,
    source_investigation_id: null,
    data: { ...summary, unique_mimes: summary.rows.length },
    lead_score: null,
  };
}

// The strip's summary query and the main artifacts list share one route; the
// summary is selected by its artifact_type in the request URL.
function artifactsResponse(url: string, summaries: SummaryItem[]): Response {
  const isSummary = new URL(url, "http://test.local").searchParams.get("artifact_type") === "carved_file_types";
  const body = isSummary ? { items: summaries, total: summaries.length } : { items: [], total: 0 };

  return new Response(JSON.stringify({ data: body }), {
    status: 200,
    headers: { "content-type": "application/json" },
  });
}

function renderTab(): QueryClient {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });

  render(
    <QueryClientProvider client={client}>
      <ArtifactsTab projectId="p1" onOpenInvestigation={() => {}} />
    </QueryClientProvider>,
  );

  return client;
}

function stubSummaries(summaries: SummaryItem[]): void {
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: string | URL) => artifactsResponse(String(input), summaries)),
  );
}

describe("ArtifactsTab carved file-type strip", () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it("sums MIME counts across captures and orders chips by count", async () => {
    stubSummaries([
      summaryItem("s1", {
        evidence_path: "a.pcap",
        rows: [
          { mime_type: "application/pdf", count: 3 },
          { mime_type: "text/html", count: 1 },
        ],
        total_carved: 4,
      }),
      summaryItem("s2", {
        evidence_path: "b.pcap",
        rows: [
          { mime_type: "text/html", count: 4 },
          { mime_type: "image/png", count: 1 },
        ],
        total_carved: 5,
      }),
    ]);
    const client = renderTab();

    const html = await screen.findByText("text/html 5");
    const pdf = screen.getByText("application/pdf 3");
    const png = screen.getByText("image/png 1");

    expect(screen.getByText("9 files \u00b7 2 captures")).toBeTruthy();
    expect(html.compareDocumentPosition(pdf) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    expect(pdf.compareDocumentPosition(png) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    client.clear();
  });

  it("says nothing was carved instead of listing chips when every capture carved zero files", async () => {
    stubSummaries([
      summaryItem("s1", { evidence_path: "a.pcap", rows: [], total_carved: 0 }),
      summaryItem("s2", { evidence_path: "b.pcap", rows: [], total_carved: 0 }),
    ]);
    const client = renderTab();

    expect(await screen.findByText("no files carved from 2 captures")).toBeTruthy();
    expect(screen.queryByText(/0 files/)).toBeNull();
    expect(screen.queryByText(/text\/html/)).toBeNull();
    client.clear();
  });

  it("renders no strip when the project has no capture summaries", async () => {
    stubSummaries([]);
    const client = renderTab();

    await screen.findByText("no artifacts match.");
    await waitFor(() => expect(client.getQueryState(["forensics", "p1", "artifacts", "carved_file_types"])?.status).toBe("success"));
    expect(screen.queryByText("carved file types")).toBeNull();
    client.clear();
  });
});

describe("aggregateCarvedFileTypes", () => {
  it("counts only capture summaries, skipping zero and unnamed MIME rows", () => {
    const { items } = parseArtifactPage({
      items: [
        summaryItem("s1", {
          evidence_path: "a.pcap",
          rows: [
            { mime_type: "text/html", count: 2 },
            { mime_type: "image/png", count: 0 },
            { mime_type: "", count: 7 },
          ],
          total_carved: 2,
        }),
        { ...summaryItem("x1", { evidence_path: "z.pcap", rows: [{ mime_type: "text/html", count: 100 }], total_carved: 100 }), artifact_type: "carved_file" },
        summaryItem("s2", {
          evidence_path: "b.pcap",
          rows: [
            { mime_type: "text/html", count: 1 },
            { mime_type: "image/png", count: 1 },
            { mime_type: "application/pdf", count: 1 },
          ],
          total_carved: 3,
        }),
      ],
    });

    expect(aggregateCarvedFileTypes(items)).toEqual({
      captures: 2,
      total_carved: 5,
      mimes: [
        { mime_type: "text/html", count: 3 },
        { mime_type: "application/pdf", count: 1 },
        { mime_type: "image/png", count: 1 },
      ],
    });
  });
});
