import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { downloadWorkerArtifact, fetchWorkerResult } from "./workerJobs";

interface RecordedCall {
  method: string;
  path: string;
}

function jsonResponse(data: unknown, envelope = false): Response {
  return new Response(JSON.stringify(envelope ? { data } : data), {
    status: 200,
    headers: { "content-type": "application/json" },
  });
}

function taskStatus(status: string, error: string | null = null): Response {
  return jsonResponse({ task_id: "task-1", status, error });
}

function requestPath(input: string | URL | Request): string {
  return new URL(input instanceof Request ? input.url : String(input)).pathname;
}

const originalCreateObjectURL = Object.getOwnPropertyDescriptor(URL, "createObjectURL");
const originalRevokeObjectURL = Object.getOwnPropertyDescriptor(URL, "revokeObjectURL");

beforeEach(() => {
  Object.defineProperty(URL, "createObjectURL", { configurable: true, value: vi.fn(() => "blob:worker-artifact") });
  Object.defineProperty(URL, "revokeObjectURL", { configurable: true, value: vi.fn() });
});

afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  if (originalCreateObjectURL) Object.defineProperty(URL, "createObjectURL", originalCreateObjectURL);
  else Reflect.deleteProperty(URL, "createObjectURL");
  if (originalRevokeObjectURL) Object.defineProperty(URL, "revokeObjectURL", originalRevokeObjectURL);
  else Reflect.deleteProperty(URL, "revokeObjectURL");
});

describe("worker job API", () => {
  it("polls queued -> running -> done every two seconds, then fetches the result", async () => {
    vi.useFakeTimers();
    const calls: RecordedCall[] = [];
    const statuses = ["queued", "running", "done"];
    vi.stubGlobal("fetch", vi.fn(async (input: string | URL | Request, init?: RequestInit) => {
      const path = requestPath(input);
      calls.push({ method: init?.method ?? "GET", path });
      if (path === "/tasks/task%201") return taskStatus(statuses.shift() ?? "done");
      if (path === "/tasks/task%201/result") return jsonResponse({ ready: true, message: "checked" }, true);
      throw new Error(`unexpected path ${path}`);
    }));

    const resultPromise = fetchWorkerResult<{ ready: boolean; message: string }>("task 1");
    await vi.advanceTimersByTimeAsync(0);
    expect(calls).toEqual([{ method: "GET", path: "/tasks/task%201" }]);

    await vi.advanceTimersByTimeAsync(1999);
    expect(calls).toHaveLength(1);
    await vi.advanceTimersByTimeAsync(1);
    expect(calls).toHaveLength(2);

    await vi.advanceTimersByTimeAsync(2000);
    await expect(resultPromise).resolves.toEqual({ ready: true, message: "checked" });
    expect(calls).toEqual([
      { method: "GET", path: "/tasks/task%201" },
      { method: "GET", path: "/tasks/task%201" },
      { method: "GET", path: "/tasks/task%201" },
      { method: "GET", path: "/tasks/task%201/result" },
    ]);
  });

  it("waits for queued -> running -> done, then downloads a blob under a safe filename", async () => {
    vi.useFakeTimers();
    const calls: RecordedCall[] = [];
    const statuses = ["queued", "running", "done"];
    const downloads: string[] = [];
    vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(function (this: HTMLAnchorElement) {
      downloads.push(this.download);
    });
    vi.stubGlobal("fetch", vi.fn(async (input: string | URL | Request, init?: RequestInit) => {
      const path = requestPath(input);
      calls.push({ method: init?.method ?? "GET", path });
      if (path === "/tasks/task%2Fpdf") return taskStatus(statuses.shift() ?? "done");
      if (path === "/tasks/task%2Fpdf/artifact") {
        return new Response(new Uint8Array([37, 80, 68, 70]), {
          status: 200,
          headers: { "content-type": "application/pdf" },
        });
      }
      throw new Error(`unexpected path ${path}`);
    }));

    const downloadPromise = downloadWorkerArtifact("task/pdf", "../../report:final.pdf");
    await vi.advanceTimersByTimeAsync(0);
    await vi.advanceTimersByTimeAsync(2000);
    await vi.advanceTimersByTimeAsync(2000);
    await expect(downloadPromise).resolves.toBeUndefined();

    expect(calls.map((call) => call.path)).toEqual([
      "/tasks/task%2Fpdf",
      "/tasks/task%2Fpdf",
      "/tasks/task%2Fpdf",
      "/tasks/task%2Fpdf/artifact",
    ]);
    expect(downloads).toEqual(["report_final.pdf"]);
    expect(URL.createObjectURL).toHaveBeenCalledWith(expect.objectContaining({ size: 4, type: "application/pdf" }));
    expect(URL.revokeObjectURL).toHaveBeenCalledWith("blob:worker-artifact");
  });

  it.each([
    ["failed", "worker task task-1 failed: analyzer offline"],
    ["cancelled", "worker task task-1 cancelled"],
    ["dead_letter", "worker task task-1 dead_letter"],
  ])("rejects a %s task without fetching a result", async (status, message) => {
    const fetchMock = vi.fn(async () => taskStatus(status, status === "failed" ? "analyzer offline" : null));
    vi.stubGlobal("fetch", fetchMock);

    await expect(fetchWorkerResult("task-1")).rejects.toThrow(message);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("surfaces a result endpoint failure after the task completes", async () => {
    vi.stubGlobal("fetch", vi.fn(async (input: string | URL | Request) => {
      if (requestPath(input) === "/tasks/task-1") return taskStatus("done");
      return new Response("result unavailable", { status: 500 });
    }));

    await expect(fetchWorkerResult("task-1")).rejects.toMatchObject({ status: 500, message: "result unavailable" });
  });

  it("surfaces an artifact endpoint failure without creating a download", async () => {
    const click = vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => {});
    vi.stubGlobal("fetch", vi.fn(async (input: string | URL | Request) => {
      if (requestPath(input) === "/tasks/task-1") return taskStatus("done");
      return new Response("artifact unavailable", { status: 404 });
    }));

    await expect(downloadWorkerArtifact("task-1", "report.pdf")).rejects.toMatchObject({ status: 404, message: "artifact unavailable" });
    expect(click).not.toHaveBeenCalled();
    expect(URL.createObjectURL).not.toHaveBeenCalled();
  });
});
