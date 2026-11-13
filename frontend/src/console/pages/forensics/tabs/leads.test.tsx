import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Mock } from "vitest";

import { LeadsTab } from "./leads";

const ROUTE_MAX_LIMIT = 100;

type FetchMock = Mock<(input: string | URL) => Promise<Response>>;

// Stands in for the leads route, which rejects a limit outside 1..100 with 422.
function leadsRoute(input: string | URL): Response {
  const url = new URL(String(input));
  const limit = Number(url.searchParams.get("limit"));
  if (!(limit >= 1 && limit <= ROUTE_MAX_LIMIT)) {
    return new Response(JSON.stringify({ detail: "limit out of range" }), {
      status: 422,
      headers: { "content-type": "application/json" },
    });
  }
  return new Response(JSON.stringify({ data: [] }), {
    status: 200,
    headers: { "content-type": "application/json" },
  });
}

function requestedLimits(fetchMock: FetchMock): number[] {
  return fetchMock.mock.calls.map(([input]) => Number(new URL(String(input)).searchParams.get("limit")));
}

describe("LeadsTab limit", () => {
  let fetchMock: FetchMock;

  beforeEach(() => {
    fetchMock = vi.fn(async (input: string | URL) => leadsRoute(input));
    vi.stubGlobal("fetch", fetchMock);
  });

  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it("loads with the default limit and every option without a validation error", async () => {
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    const { container } = render(
      <QueryClientProvider client={client}>
        <LeadsTab projectId="p1" onOpenInvestigation={() => {}} />
      </QueryClientProvider>,
    );

    expect(await screen.findByText("no leads yet.")).toBeTruthy();

    const select = container.querySelector("select");
    expect(select).not.toBeNull();
    const options = Array.from(select!.querySelectorAll("option")).map((o) => o.value);
    expect(options.length).toBeGreaterThan(0);
    for (const value of options) {
      fireEvent.change(select!, { target: { value } });
      await waitFor(() => expect(requestedLimits(fetchMock)).toContain(Number(value)));
      expect(await screen.findByText("no leads yet.")).toBeTruthy();
    }

    for (const limit of requestedLimits(fetchMock)) {
      expect(limit).toBeLessThanOrEqual(ROUTE_MAX_LIMIT);
    }
    client.clear();
  });
});
