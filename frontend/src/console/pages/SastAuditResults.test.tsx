import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import SastAuditResults from "./SastAuditResults";

function json(data: unknown): Response {
  return new Response(JSON.stringify({ data, meta: {} }), { status: 200, headers: { "content-type": "application/json" } });
}

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe("SastAuditResults", () => {
  it("renders the staged prepared list and opens a skill investigation", async () => {
    const onOpen = vi.fn();
    vi.stubGlobal("fetch", vi.fn(async (input: string | URL) => {
      const path = new URL(String(input)).pathname;
      if (path === "/vr/investigations") return json([{ id: "sast-parent", kind: "sast_audit" }]);
      if (path.endsWith("/sast-audit-aggregate")) return json({
        parent_status: "running",
        status_counts: { running: 14, completed: 1, created: 1 },
        results: [
          { skill_id: "sast-analysis", title: "Codebase analysis", phase: "analysis", investigation_id: "analysis-1", status: "completed", outcome_kind: "assessment_report", confidence: "high", summary: "Architecture mapped" },
          { skill_id: "sast-sqli", title: "SQL injection", phase: "detection", investigation_id: "sqli-1", status: "running" },
          { skill_id: "sast-report", title: "Consolidated report", phase: "report", investigation_id: "report-1", status: "created" },
        ],
      });
      throw new Error(`Unexpected ${path}`);
    }));
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    render(<QueryClientProvider client={client}><SastAuditResults targetId="source-1" onOpenXray={onOpen} /></QueryClientProvider>);
    expect(await screen.findByText("Architecture mapped")).toBeTruthy();
    expect(screen.getByText("3 skills · 1 detectors")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "SQL injection" }));
    expect(onOpen).toHaveBeenCalledWith(expect.objectContaining({ id: "sqli-1", target_id: "source-1" }));
  });
});
