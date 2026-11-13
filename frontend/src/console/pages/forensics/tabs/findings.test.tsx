import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
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

function finding(overrides: Record<string, unknown>): Record<string, unknown> {
  return {
    fingerprint: "fp-1",
    artifact_type: "prefetch",
    artifact_family: "execution",
    source_tool: "disk",
    suspicious_reasons: ["unsigned"],
    executable: null,
    path: null,
    name: null,
    user: null,
    last_run: null,
    run_count: null,
    occurrences: 1,
    workflow_state: "new",
    raw_record: {},
    ...overrides,
  };
}

function diskImage(id: string, file: string) {
  return { id, file_path: file, evidence_type: "disk_image", file_hash_sha256: null, size_bytes: 1024 };
}

const json = (data: unknown, status = 200): Response =>
  new Response(JSON.stringify(data), { status, headers: { "content-type": "application/json" } });

interface Call {
  url: string;
  method: string;
  body: string | null;
}

describe("FindingsTab extraction", () => {
  const calls: Call[] = [];
  const downloads: string[] = [];
  const originalCreate = URL.createObjectURL;
  const originalRevoke = URL.revokeObjectURL;
  let rows: Record<string, unknown>[] = [];
  let images: unknown[] = [];

  beforeEach(() => {
    calls.length = 0;
    downloads.length = 0;
    rows = [];
    images = [];
    URL.createObjectURL = vi.fn(() => "blob:test");
    URL.revokeObjectURL = vi.fn();
    vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(function (this: HTMLAnchorElement) {
      downloads.push(this.download);
    });
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: string | URL, init?: RequestInit) => {
        const url = String(input);
        calls.push({ url, method: init?.method ?? "GET", body: typeof init?.body === "string" ? init.body : null });

        if (url.includes("/retrieve-file")) {
          return new Response(new Blob(["x"]), { status: 200, headers: { "content-disposition": 'attachment; filename="bad.exe"' } });
        }
        if (url.includes("evidence_type=disk_image")) return json({ data: { items: images, total: images.length, page: 1, page_size: 500, pages: 1 } });
        if (url.includes("/findings/workflow/states")) return json({ data: { states: ["new"], transitions: { new: [] } } });
        if (url.includes("/findings")) return json({ data: rows });
        return json({ data: [] });
      }),
    );
  });

  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
    URL.createObjectURL = originalCreate;
    URL.revokeObjectURL = originalRevoke;
  });

  it("extracts a finding path from the single disk image without naming an image", async () => {
    rows = [finding({ path: "C:\\Temp\\bad.exe" })];
    images = [diskImage("img-a", "/images/a.E01")];
    renderFindings(project("completed", 12));

    fireEvent.click(await screen.findByRole("button", { name: "extract" }));

    await waitFor(() => expect(downloads).toEqual(["bad.exe"]));
    const retrieve = calls.find((c) => c.url.includes("/retrieve-file"));
    expect(retrieve?.method).toBe("POST");
    expect(JSON.parse(retrieve?.body ?? "null")).toEqual({ virtual_path: "C:\\Temp\\bad.exe" });
  });

  it("offers no extract for a command line in the executable slot", async () => {
    rows = [finding({ raw_record: { command: "cmd.exe /c powershell -enc AAAA" } })];
    images = [diskImage("img-a", "/images/a.E01")];
    renderFindings(project("completed", 12));

    fireEvent.click(await screen.findByText("prefetch"));

    expect(await screen.findByText("fingerprint")).toBeTruthy();
    expect(screen.queryByRole("button", { name: "extract" })).toBeNull();
  });

  it("extracts the executable path shown in the detail", async () => {
    rows = [finding({ raw_record: { executable: "C:\\Temp\\bad.exe" } })];
    images = [diskImage("img-a", "/images/a.E01")];
    renderFindings(project("completed", 12));

    fireEvent.click(await screen.findByText("prefetch"));

    expect(await screen.findByText("fingerprint")).toBeTruthy();
    const buttons = screen.getAllByRole("button", { name: "extract" });
    expect(buttons.length).toBeGreaterThan(0);
    fireEvent.click(buttons[buttons.length - 1]);

    await waitFor(() => expect(downloads).toEqual(["bad.exe"]));
    const retrieve = calls.find((c) => c.url.includes("/retrieve-file"));
    expect(JSON.parse(retrieve?.body ?? "null")).toEqual({ virtual_path: "C:\\Temp\\bad.exe" });
  });

  it("offers no extract on a raw_directory project", async () => {
    rows = [finding({ path: "C:\\Temp\\bad.exe" })];
    images = [diskImage("img-a", "/images/a.E01")];
    renderFindings({ ...project("completed", 12), project_kind: "raw_directory" });

    expect(await screen.findByText("C:\\Temp\\bad.exe")).toBeTruthy();
    expect(screen.queryByRole("button", { name: "extract" })).toBeNull();
    expect(calls.some((c) => c.url.includes("evidence_type=disk_image"))).toBe(false);
  });
});
