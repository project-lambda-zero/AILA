import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { ForensicsWizard } from "./ForensicsWizard";

interface Call {
  method: string;
  path: string;
  body: string | null;
}

function jsonResponse(data: unknown): Response {
  return new Response(JSON.stringify({ data }), {
    status: 200,
    headers: { "content-type": "application/json" },
  });
}

// Stands in for the backend at the network boundary: one registered analyzer,
// a project create that hands out sequential ids, and a readiness check that
// queues a worker task. The task finishes at once with `task`'s status, and a
// completed task's result reports the analyzer not ready.
function backend(calls: Call[], task: { status: string; error: string | null } = { status: "done", error: null }) {
  let created = 0;
  let queued = 0;

  return vi.fn(async (input: string | URL, init?: RequestInit) => {
    const path = new URL(String(input), "http://test.local").pathname;
    const method = init?.method ?? "GET";
    calls.push({ method, path, body: init?.body == null ? null : String(init.body) });

    if (path.endsWith("/systems")) return jsonResponse({ items: [{ id: 7, name: "lab-01", host: "10.0.0.7", distro: "ubuntu" }] });

    if (method === "POST" && path.endsWith("/forensics/projects")) {
      created += 1;

      return jsonResponse({ id: `proj-${created}`, name: "case" });
    }

    if (method === "POST" && path.endsWith("/readiness-check")) {
      queued += 1;

      return jsonResponse({ task_id: `task-${queued}`, status: "queued" });
    }

    if (path.startsWith("/tasks/") && path.endsWith("/result")) {
      return jsonResponse({ ready: false, system_name: "lab-01", analyzer_os: "linux", tools: [], message: "volatility missing" });
    }

    if (path.startsWith("/tasks/")) {
      return new Response(JSON.stringify({ task_id: path.split("/")[2], status: task.status, error: task.error }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    }

    return new Response("unexpected request", { status: 500 });
  });
}

const creates = (calls: Call[]): Call[] => calls.filter((c) => c.method === "POST" && c.path.endsWith("/forensics/projects"));
const readinessPaths = (calls: Call[]): string[] => calls.flatMap((c) => (c.path.endsWith("/readiness-check") ? [c.path] : []));

async function fillAndCheck(evidenceDirectory: string): Promise<void> {
  fireEvent.change(screen.getByPlaceholderText("Absolute path on the analyzer"), { target: { value: evidenceDirectory } });
  fireEvent.click(screen.getByText("create & check \u25b8"));
}

describe("ForensicsWizard readiness retry", () => {
  const calls: Call[] = [];

  beforeEach(() => {
    calls.length = 0;
    vi.stubGlobal("fetch", backend(calls));
  });

  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it("re-checks the project it already created and creates a new one only when the inputs change", async () => {
    render(<ForensicsWizard onBind={() => {}} />);

    fireEvent.change(screen.getByPlaceholderText("Project name"), { target: { value: "case" } });
    await screen.findByText(/lab-01/);
    fireEvent.change(screen.getByRole("combobox"), { target: { value: "7" } });
    await fillAndCheck("/evidence/a");
    // The not-ready message lands in the error row, which carries the retry.
    fireEvent.click(await screen.findByText("retry"));
    await waitFor(() => expect(readinessPaths(calls)).toHaveLength(2));
    await screen.findByText("retry");

    expect(creates(calls)).toHaveLength(1);
    expect(readinessPaths(calls)).toEqual(["/forensics/projects/proj-1/readiness-check", "/forensics/projects/proj-1/readiness-check"]);

    fireEvent.click(screen.getByText("back"));
    await fillAndCheck("/evidence/b");
    await waitFor(() => expect(readinessPaths(calls)).toHaveLength(3));

    expect(creates(calls)).toHaveLength(2);
    expect(JSON.parse(creates(calls)[1]?.body ?? "{}")).toMatchObject({ evidence_directory: "/evidence/b", system_id: 7 });
    expect(readinessPaths(calls)[2]).toBe("/forensics/projects/proj-2/readiness-check");
  });
});

describe("ForensicsWizard readiness worker failure", () => {
  const calls: Call[] = [];

  beforeEach(() => {
    calls.length = 0;
    vi.stubGlobal("fetch", backend(calls, { status: "failed", error: "worker crashed" }));
  });

  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it("keeps the operator on readiness with the worker error and never reads a result", async () => {
    render(<ForensicsWizard onBind={() => {}} />);

    fireEvent.change(screen.getByPlaceholderText("Project name"), { target: { value: "case" } });
    await screen.findByText(/lab-01/);
    fireEvent.change(screen.getByRole("combobox"), { target: { value: "7" } });
    await fillAndCheck("/evidence/a");

    // The message renders in both the inline error row and the global alert.
    const messages = await screen.findAllByText(/worker task task-1 failed: worker crashed/);
    expect(messages.length).toBeGreaterThanOrEqual(2);
    expect(screen.getByText("retry")).toBeTruthy();
    expect(calls.some((c) => c.path.endsWith("/result"))).toBe(false);
    expect(readinessPaths(calls)).toEqual(["/forensics/projects/proj-1/readiness-check"]);
  });
});
