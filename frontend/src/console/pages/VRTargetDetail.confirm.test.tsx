// @vitest-environment jsdom
/** Regression for issue #366: VR toolbar actions that retry, re-run, re-rank,
 * refresh, or audit analysis must ask for confirmation before any request is
 * sent.
 *
 * Only the HTTP transport and window.confirm are faked. The component and
 * query client run unmodified. Synthetic data only. */

import { act } from "react";
import { createRoot } from "react-dom/client";
import type { Root } from "react-dom/client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { MockInstance } from "vitest";

import VRTargetDetail from "./VRTargetDetail";

const TARGET = "/vr/targets/tgt-1";

const ROW = {
  id: "tgt-1",
  display_name: "sample.apk",
  kind: "android_apk",
  primary_language: "java",
  status: "active",
  analysis_state: "failed",
  tags: [],
  secondary_languages: [],
};

interface RecordedRequest {
  method: string;
  pathname: string;
  body: BodyInit | null;
}

let container: HTMLDivElement;
let root: Root;
let queryClient: QueryClient;
let requests: RecordedRequest[];
let confirmSpy: MockInstance<typeof window.confirm>;

function jsonResponse(body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { "Content-Type": "application/json" },
  });
}

/** Records every request. The live single-target read returns the row; every
 * other endpoint answers with a quiet payload. */
function fakeFetch(row: Record<string, unknown>): (input: string, init?: RequestInit) => Promise<Response> {
  return async (input: string, init?: RequestInit): Promise<Response> => {
    const url = new URL(input);
    const method = init?.method ?? "GET";
    requests.push({ method, pathname: url.pathname, body: init?.body ?? null });
    if (url.pathname === TARGET && method === "GET") return jsonResponse(row);
    if (method !== "GET") return jsonResponse({ data: { target_id: "tgt-1" } });
    return jsonResponse({ data: [], meta: { total: 0, offset: 0, limit: 50 } });
  };
}

async function flush(): Promise<void> {
  await act(async () => {
    await new Promise((resolve) => setTimeout(resolve, 0));
  });
}

async function renderDetail(row: Record<string, unknown> = ROW): Promise<void> {
  vi.stubGlobal("fetch", fakeFetch(row));
  await act(async () => {
    root.render(
      <QueryClientProvider client={queryClient}>
        <VRTargetDetail row={row} onOpenXray={() => undefined} />
      </QueryClientProvider>,
    );
  });
  await flush();
  requests = [];
}

function buttonNamed(label: string): HTMLButtonElement | undefined {
  return Array.from(container.querySelectorAll("button")).find(
    (b) => b.textContent === label,
  );
}

async function clickButton(label: string): Promise<void> {
  const button = buttonNamed(label);
  if (!button) throw new Error(`no toolbar button "${label}"`);
  await act(async () => {
    button.click();
  });
}

beforeEach(() => {
  Object.assign(globalThis, { IS_REACT_ACT_ENVIRONMENT: true });
  queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  container = document.createElement("div");
  document.body.append(container);
  root = createRoot(container);
  requests = [];
  confirmSpy = vi.spyOn(window, "confirm");
});

afterEach(async () => {
  await act(async () => {
    root.unmount();
  });
  queryClient.clear();
  container.remove();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

const GATED_ACTIONS = [
  {
    label: "retry analysis",
    path: `${TARGET}/resume-analysis`,
    message:
      "Retry analysis? This resets failed stages to pending and re-enqueues the pipeline; completed stages are kept.",
  },
  {
    label: "re-analyze",
    path: `${TARGET}/analyze`,
    message: "Re-analyze this target? This re-runs the backend ingestion pipeline.",
  },
  {
    label: "re-rank",
    path: `${TARGET}/rank`,
    message: "Re-rank this target? This enqueues a new function-ranking run.",
  },
  {
    label: "refresh source",
    path: `${TARGET}/refresh-source`,
    message:
      "Refresh the source? This re-runs ingestion for this target; for APK targets it resets the APK analysis stages to pending and rebuilds them.",
  },
  {
    label: "apk static audit",
    path: `${TARGET}/apk-static-audit`,
    message:
      "Run an APK static audit? This creates an audit investigation with one child investigation per static check and queues them for analysis.",
  },
  {
    label: "masvs audit",
    path: `${TARGET}/masvs-audit`,
    message:
      "Run a MASVS audit? This creates an audit investigation with one child investigation per MASVS control and queues them for analysis.",
  },
] as const;

describe("VRTargetDetail analysis actions confirm before requesting", () => {
  it.each(GATED_ACTIONS)("$label: cancel sends no request", async ({ label, message }) => {
    confirmSpy.mockReturnValue(false);
    await renderDetail();

    await clickButton(label);
    await flush();

    expect(confirmSpy).toHaveBeenCalledTimes(1);
    expect(confirmSpy).toHaveBeenCalledWith(message);
    expect(requests).toEqual([]);
  });

  it.each(GATED_ACTIONS)("$label: accept sends exactly one request to the same path", async ({ label, message, path }) => {
    confirmSpy.mockReturnValue(true);
    await renderDetail();

    await clickButton(label);
    await flush();

    expect(confirmSpy).toHaveBeenCalledTimes(1);
    expect(confirmSpy).toHaveBeenCalledWith(message);
    const mutations = requests.filter((r) => r.method !== "GET");
    expect(mutations).toEqual([{ method: "POST", pathname: path, body: null }]);
  });
});

describe("VRTargetDetail delete and availability are unchanged", () => {
  it("delete confirms once and cancel sends no request", async () => {
    confirmSpy.mockReturnValue(false);
    await renderDetail();

    await clickButton("delete");
    await flush();

    expect(confirmSpy).toHaveBeenCalledTimes(1);
    expect(confirmSpy).toHaveBeenCalledWith("Delete this target? This cannot be undone.");
    expect(requests).toEqual([]);
  });

  it("delete accept sends one DELETE to the target", async () => {
    confirmSpy.mockReturnValue(true);
    await renderDetail();

    await clickButton("delete");
    await flush();

    const mutations = requests.filter((r) => r.method !== "GET");
    expect(mutations).toEqual([{ method: "DELETE", pathname: TARGET, body: null }]);
  });

  it("APK audit buttons are absent for a non-APK target", async () => {
    await renderDetail({ ...ROW, kind: "source_repo" });

    expect(buttonNamed("apk static audit")).toBeUndefined();
    expect(buttonNamed("masvs audit")).toBeUndefined();
    expect(buttonNamed("re-rank")).toBeDefined();
  });
});
