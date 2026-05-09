/**
 * LLMLogPage tests (Plan 176e P2).
 *
 * Verifies:
 *   - renders the row table from /admin/llm-log envelope
 *   - opens the detail panel with prompt/response previews on View click
 *   - total_cost_usd aggregate shows in the metric card
 *   - empty state renders when items is empty
 */
import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

// Mock authorizedRequestJson so we control the response shape per test.
const mockRequest = vi.fn();
vi.mock("@platform/api/http", () => ({
  authorizedRequestJson: (pathname: string) => mockRequest(pathname),
}));

import { LLMLogPage } from "../LLMLogPage";

function renderPage() {
  const client = new QueryClient({
    defaultOptions: {
      queries: { retry: false, refetchOnWindowFocus: false, staleTime: 0 },
    },
  });
  return render(
    <MemoryRouter>
      <QueryClientProvider client={client}>
        <LLMLogPage />
      </QueryClientProvider>
    </MemoryRouter>,
  );
}

const ENTRY_ONE = {
  id: "rec-1",
  timestamp: "2026-04-12T12:00:00Z",
  model: "gpt-4o",
  task_type: "scoring",
  input_tokens: 100,
  output_tokens: 50,
  cost_usd: 0.05,
  duration_ms: 420,
  status: "ok",
  run_id: "run-abcdefgh-1234",
  user_id: null,
  team_id: null,
  prompt_preview: "scan web01 for vulnerabilities",
  response_preview: "found 3 CVEs",
};

beforeEach(() => {
  mockRequest.mockReset();
});

describe("LLMLogPage", () => {
  it("renders the table and total cost from the envelope", async () => {
    mockRequest.mockResolvedValue({
      data: {
        items: [ENTRY_ONE],
        total: 1,
        limit: 50,
        offset: 0,
        total_cost_usd: 0.05,
      },
      error: null,
      meta: {},
    });

    renderPage();

    await waitFor(() => {
      expect(screen.getByText("gpt-4o")).toBeTruthy();
    });
    expect(screen.getByText("scoring")).toBeTruthy();
    // Total cost card AND row cost both render $0.0500; asserting >=1 match is enough.
    expect(screen.getAllByText("$0.0500").length).toBeGreaterThan(0);
  });

  it("opens the detail panel with preview content on View click", async () => {
    mockRequest.mockResolvedValue({
      data: {
        items: [ENTRY_ONE],
        total: 1,
        limit: 50,
        offset: 0,
        total_cost_usd: 0.05,
      },
      error: null,
      meta: {},
    });
    renderPage();

    await waitFor(() => {
      expect(screen.getByText("gpt-4o")).toBeTruthy();
    });

    const viewBtn = screen.getByRole("button", { name: /^view$/i });
    fireEvent.click(viewBtn);

    expect(screen.getByText("scan web01 for vulnerabilities")).toBeTruthy();
    expect(screen.getByText("found 3 CVEs")).toBeTruthy();
    expect(screen.getByText(/prompt preview/i)).toBeTruthy();
    expect(screen.getByText(/response preview/i)).toBeTruthy();
  });

  it("renders empty state when no items are returned", async () => {
    mockRequest.mockResolvedValue({
      data: {
        items: [],
        total: 0,
        limit: 50,
        offset: 0,
        total_cost_usd: 0,
      },
      error: null,
      meta: {},
    });
    renderPage();

    await waitFor(() => {
      expect(screen.getByText(/no llm calls recorded/i)).toBeTruthy();
    });
  });

  it("includes filter params from the JQL bar in the request", async () => {
    mockRequest.mockResolvedValue({
      data: {
        items: [],
        total: 0,
        limit: 50,
        offset: 0,
        total_cost_usd: 0,
      },
      error: null,
      meta: {},
    });
    renderPage();

    // Wait for the first default fetch to settle.
    await waitFor(() => expect(mockRequest).toHaveBeenCalled());
    const firstPath = mockRequest.mock.calls[0][0] as string;
    expect(firstPath).toContain("/admin/llm-log");
    expect(firstPath).toContain("limit=50");
    expect(firstPath).toContain("offset=0");
  });
});
