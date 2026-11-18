import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import ForensicsProjectPage from "./ForensicsProjectPage";

interface Call {
  method: string;
  path: string;
}

const READINESS = {
  ready: true,
  system_id: 7,
  system_name: "lab-01",
  analyzer_os: "linux",
  tools: [],
  message: "all required tools present",
  already_queued: false,
  existing_task_id: null,
};

function jsonResponse(body: unknown): Response {
  return new Response(JSON.stringify(body), { status: 200, headers: { "content-type": "application/json" } });
}

// Network boundary only: the readiness POST queues `task-1`, the task reports
// `status`, and a completed task's result is the readiness payload. Every other
// read gets an empty envelope so the tabs render without real data.
function backend(calls: Call[], task: { status: string; error: string | null }) {
  return vi.fn(async (input: string | URL, init?: RequestInit) => {
    const path = new URL(String(input), "http://test.local").pathname;
    const method = init?.method ?? "GET";
    calls.push({ method, path });

    if (method === "POST" && path.endsWith("/readiness-check")) return jsonResponse({ data: { task_id: "task-1", status: "queued" } });
    if (path === "/tasks/task-1/result") return jsonResponse({ data: READINESS });
    if (path === "/tasks/task-1") return jsonResponse({ task_id: "task-1", status: task.status, error: task.error });
    return jsonResponse({ data: [] });
  });
}

function renderPage(): void {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={client}>
      <ForensicsProjectPage
        windowId="w-project"
        title="project"
        onBack={() => {}}
        onMinimize={() => {}}
        section={null}
        onNavigate={() => {}}
        investigationId="project-1"
      />
    </QueryClientProvider>,
  );
}

describe("ForensicsProjectPage readiness check", () => {
  const calls: Call[] = [];

  beforeEach(() => {
    calls.length = 0;
  });

  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it("queues the check, waits for the worker, and reports completion", async () => {
    vi.stubGlobal("fetch", backend(calls, { status: "done", error: null }));
    renderPage();

    fireEvent.click(screen.getByText("readiness check"));

    expect(await screen.findByText("readiness check completed successfully.")).toBeTruthy();
    expect(calls.filter((c) => c.method === "POST").map((c) => c.path)).toEqual(["/forensics/projects/project-1/readiness-check"]);
    expect(calls.some((c) => c.path === "/tasks/task-1/result")).toBe(true);
  });

  it("reports the worker failure without fetching a result", async () => {
    vi.stubGlobal("fetch", backend(calls, { status: "failed", error: "worker crashed" }));
    renderPage();

    fireEvent.click(screen.getByText("readiness check"));

    expect(await screen.findByText(/readiness-check failed: worker task task-1 failed: worker crashed/)).toBeTruthy();
    expect(calls.some((c) => c.path.endsWith("/result"))).toBe(false);
  });
});
