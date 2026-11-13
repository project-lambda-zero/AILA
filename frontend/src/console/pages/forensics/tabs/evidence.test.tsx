import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { EvidenceTab } from "./evidence";

const TOTAL = 150;

const filePath = (i: number): string => `/evidence/f${String(i).padStart(3, "0")}.raw`;

// Stands in for the paginated evidence route: slices a 150-row project by the
// request's page and page_size and reports the project total on every page.
function evidenceResponse(url: string): Response {
  const params = new URL(url, "http://test.local").searchParams;
  const page = Number(params.get("page") ?? "1");
  const pageSize = Number(params.get("page_size") ?? "100");
  const start = (page - 1) * pageSize;
  const items = [];

  for (let i = start; i < Math.min(start + pageSize, TOTAL); i += 1) {
    items.push({ id: `e${i}`, file_path: filePath(i), evidence_type: "disk_image", file_hash_sha256: null, size_bytes: 1024 });
  }

  return new Response(JSON.stringify({ data: { items, total: TOTAL, page, page_size: pageSize, pages: Math.ceil(TOTAL / pageSize) } }), {
    status: 200,
    headers: { "content-type": "application/json" },
  });
}

function renderEvidence() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });

  render(
    <QueryClientProvider client={client}>
      <EvidenceTab projectId="p1" onOpenInvestigation={() => {}} />
    </QueryClientProvider>,
  );

  return client;
}

describe("EvidenceTab", () => {
  const requested: string[] = [];

  beforeEach(() => {
    requested.length = 0;
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: string | URL) => {
        const url = String(input);
        requested.push(url);

        return evidenceResponse(url);
      }),
    );
  });

  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it("shows the project total and reaches the rows past the first page", async () => {
    const client = renderEvidence();

    expect(await screen.findByText("page 1 \u00b7 100 rows \u00b7 total 150")).toBeTruthy();
    expect(screen.getByText(filePath(0))).toBeTruthy();
    expect(screen.queryByText(filePath(120))).toBeNull();

    fireEvent.click(screen.getByTitle("next page"));

    expect(await screen.findByText(filePath(120))).toBeTruthy();
    expect(screen.getByText("page 2 \u00b7 50 rows \u00b7 total 150")).toBeTruthy();
    expect(screen.getByText(filePath(149))).toBeTruthy();
    expect(screen.queryByText(filePath(0))).toBeNull();
    expect(screen.getByTitle("next page").hasAttribute("disabled")).toBe(true);
    expect(requested.some((u) => u.includes("page=2&page_size=100"))).toBe(true);
    client.clear();
  });
});
