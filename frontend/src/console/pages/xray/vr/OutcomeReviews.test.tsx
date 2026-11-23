import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { VrOutcome } from "../../../../api/types";
import { OutcomeReviews } from "./OutcomeReviews";

let rows: VrOutcome[] = [];

function outcome(id: string, payload: Record<string, unknown>): VrOutcome {
  return {
    id,
    investigation_id: "inv-1",
    branch_id: "branch-1",
    outcome_kind: "assessment_report",
    payload,
    confidence: "unknown",
    evidence_refs: [],
    accepted_by_operator: false,
    dispatch_status: "pending",
    dispatch_target: null,
    created_at: "2026-11-22T12:00:00Z",
    state: "draft",
    approve_count: 0,
    reject_count: 0,
    request_edit_count: 0,
    abstain_count: 0,
    quorum_k: 2,
  };
}

function json(data: unknown): Response {
  return new Response(JSON.stringify({ data }), {
    status: 200,
    headers: { "Content-Type": "application/json" },
  });
}

function renderOutcomes(): void {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(<QueryClientProvider client={client}><OutcomeReviews invId="inv-1" branches={[]} /></QueryClientProvider>);
}

beforeEach(() => {
  vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL) => {
    const raw = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
    const url = new URL(raw, "http://test");
    if (url.pathname.endsWith("/reviews")) return json([]);
    if (url.pathname === "/vr/investigations/inv-1/outcomes") return json(rows);
    return json([]);
  }));
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  rows = [];
});

describe("OutcomeReviews discovery identity", () => {
  it("shows distinct ledger vulnerability titles and their actual review state", async () => {
    rows = [
      outcome("ledger-1", { title: "SQL injection in login", ledger_discovery_id: 1, review_state: "unverified" }),
      outcome("ledger-2", { claim: "XSS in profile rendering", ledger_discovery_id: 2, review_state: "confirmed" }),
    ];
    renderOutcomes();

    const first = await screen.findByRole("button", { name: /SQL injection in login/ });
    expect(screen.getByRole("button", { name: /XSS in profile rendering/ })).toBeTruthy();
    expect(screen.getByText("unverified")).toBeTruthy();
    expect(screen.getByText("confirmed")).toBeTruthy();

    fireEvent.click(first);
    await waitFor(() => expect(first.getAttribute("aria-expanded")).toBe("true"));
  });

  it("uses the canonical answer as a fallback without inventing a ledger review state", async () => {
    rows = [outcome("canonical", { answer: "\n\nCanonical conclusion\nSupporting detail" })];
    renderOutcomes();

    expect(await screen.findByText("Canonical conclusion")).toBeTruthy();
    expect(screen.queryByText("unverified")).toBeNull();
    expect(screen.queryByText("confirmed")).toBeNull();
  });
});
