import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { ProjectSummary } from "../../../../api/forensics";
import { ToastViewport } from "../../../toast";
import { EvidenceTab } from "./evidence";

const TOTAL = 150;

const filePath = (i: number): string => `/evidence/f${String(i).padStart(3, "0")}.raw`;

function jsonResponse(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), { status, headers: { "content-type": "application/json" } });
}

function pageEnvelope(items: unknown[], total: number, page: number, pageSize: number): Response {
  return jsonResponse({ data: { items, total, page, page_size: pageSize, pages: Math.ceil(total / pageSize) } });
}

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

  return pageEnvelope(items, TOTAL, page, pageSize);
}

function image(id: string, file: string) {
  return { id, file_path: file, evidence_type: "disk_image", file_hash_sha256: null, size_bytes: 1024 };
}

function project(kind: string): ProjectSummary {
  return {
    id: "p1",
    name: "case",
    description: "",
    system_id: 1,
    system_name: "lab-01",
    evidence_directory: "/evidence",
    analyzer_os: "linux",
    project_kind: kind,
    status: "completed",
    failure_reason: null,
    evidence_count: 3,
    artifact_count: 0,
    lead_count: 0,
    investigation_count: 0,
    created_at: null,
    updated_at: null,
  };
}

interface Call {
  url: string;
  method: string;
  body: string | null;
}

/** Disk images the disk-image picker query returns for the current test. */
let diskImages: unknown[] = [];
/** Response for the retrieve-file route; set per test. */
let retrieveResponse: () => Response = () => new Response(new Blob(["x"]), { status: 200 });

function route(url: string, init?: RequestInit): Response {
  if (url.includes("/retrieve-file")) return retrieveResponse();
  if (url.includes("/fetch-raw")) {
    return new Response(new Blob(["zip"]), {
      status: 200,
      headers: { "content-disposition": 'attachment; filename="case-42.zip"' },
    });
  }
  if (url.includes("evidence_type=disk_image")) return pageEnvelope(diskImages, diskImages.length, 1, 500);
  if (init?.method === "POST") return jsonResponse({ detail: "unexpected request" }, 500);
  return evidenceResponse(url);
}

function renderEvidence(p: ProjectSummary | null) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });

  render(
    <QueryClientProvider client={client}>
      <EvidenceTab projectId="p1" project={p} onOpenInvestigation={() => {}} />
      <ToastViewport />
    </QueryClientProvider>,
  );

  return client;
}

describe("EvidenceTab", () => {
  const calls: Call[] = [];
  const downloads: string[] = [];
  const originalCreate = URL.createObjectURL;
  const originalRevoke = URL.revokeObjectURL;

  beforeEach(() => {
    calls.length = 0;
    downloads.length = 0;
    diskImages = [];
    retrieveResponse = () => new Response(new Blob(["x"]), { status: 200 });
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

        return route(url, init);
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

  it("shows the project total and reaches the rows past the first page", async () => {
    const client = renderEvidence(null);

    expect(await screen.findByText("page 1 \u00b7 100 rows \u00b7 total 150")).toBeTruthy();
    expect(screen.getByText(filePath(0))).toBeTruthy();
    expect(screen.queryByText(filePath(120))).toBeNull();

    fireEvent.click(screen.getByTitle("next page"));

    expect(await screen.findByText(filePath(120))).toBeTruthy();
    expect(screen.getByText("page 2 \u00b7 50 rows \u00b7 total 150")).toBeTruthy();
    expect(screen.getByText(filePath(149))).toBeTruthy();
    expect(screen.queryByText(filePath(0))).toBeNull();
    expect(screen.getByTitle("next page").hasAttribute("disabled")).toBe(true);
    expect(calls.some((c) => c.url.includes("page=2&page_size=100"))).toBe(true);
    client.clear();
  });

  it("saves a raw_directory file under the name the analyzer returns", async () => {
    renderEvidence(project("raw_directory"));

    expect(await screen.findByText(filePath(0))).toBeTruthy();
    fireEvent.click(screen.getAllByRole("button", { name: "fetch" })[0]);

    await waitFor(() => expect(downloads).toEqual(["case-42.zip"]));
    const fetchCall = calls.find((c) => c.url.includes("/fetch-raw"));
    expect(fetchCall?.method).toBe("POST");
    expect(JSON.parse(fetchCall?.body ?? "null")).toEqual({ evidence_id: "e0" });
    expect(calls.some((c) => c.url.includes("evidence_type=disk_image"))).toBe(false);
  });

  it("sends the chosen disk image id with an in-image path", async () => {
    diskImages = [image("img-a", "/images/a.E01"), image("img-b", "/images/b.E01")];
    renderEvidence(project("disk_evidence"));

    const pathInput = await screen.findByPlaceholderText(/drivers/);
    const extract = screen.getByRole("button", { name: "extract" });
    expect(extract.hasAttribute("disabled")).toBe(true);

    fireEvent.change(pathInput, { target: { value: "C:\\Windows\\System32\\drivers\\etc\\hosts" } });
    expect(extract.hasAttribute("disabled")).toBe(false);

    fireEvent.change(screen.getByRole("combobox"), { target: { value: "img-b" } });
    fireEvent.click(extract);

    await waitFor(() => expect(calls.some((c) => c.url.includes("/retrieve-file"))).toBe(true));
    const retrieve = calls.find((c) => c.url.includes("/retrieve-file"));
    expect(retrieve?.method).toBe("POST");
    expect(JSON.parse(retrieve?.body ?? "null")).toEqual({
      virtual_path: "C:\\Windows\\System32\\drivers\\etc\\hosts",
      evidence_id: "img-b",
    });
    await waitFor(() => expect(downloads).toEqual(["hosts"]));
  });

  it("reports a path the image does not contain", async () => {
    diskImages = [image("img-a", "/images/a.E01")];
    retrieveResponse = () => jsonResponse({ detail: "file not found in image" }, 404);
    renderEvidence(project("disk_evidence"));

    fireEvent.change(await screen.findByPlaceholderText(/drivers/), { target: { value: "C:\\missing.bin" } });
    fireEvent.click(screen.getByRole("button", { name: "extract" }));

    expect(await screen.findByText("extract failed: file not found in image")).toBeTruthy();
    const retrieve = calls.find((c) => c.url.includes("/retrieve-file"));
    expect(JSON.parse(retrieve?.body ?? "null")).toEqual({ virtual_path: "C:\\missing.bin" });
    expect(downloads).toEqual([]);
  });
});
