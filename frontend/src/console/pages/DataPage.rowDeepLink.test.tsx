// @vitest-environment jsdom
/** Deep link into the malware targets window: a window opened with an entity id
 * (the global search hit path) selects that target in the detail panel, even
 * when it sits off the loaded list page.
 *
 * The window is rendered through PAGE_REGISTRY, so the production wiring runs
 * unmodified: `detailBody` -> MalwareTargetDetail and the window props spread
 * into DataPage. Only the HTTP transport is faked. Synthetic data only. */

import { act } from "react";
import { createRoot } from "react-dom/client";
import type { Root } from "react-dom/client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { PAGE_REGISTRY } from "./registry";

const TOTAL = 60;
/** Default page size of the malware targets list. Target 060 sits on page 2. */
const PAGE_SIZE = 50;
const DEEP_ID = "tgt-060";

function pad(n: number): string {
  return String(n).padStart(3, "0");
}

const TARGETS = Array.from({ length: TOTAL }, (_, i) => {
  const n = i + 1;
  return {
    id: `tgt-${pad(n)}`,
    display_name: `target-${pad(n)}`,
    kind: "elf",
    primary_language: "c",
    status: "active",
    analysis_state: "pending",
    uploaded_filename: `sample-${pad(n)}.bin`,
    sha256: `sha-${pad(n)}`,
    created_at: new Date(Date.UTC(2026, 0, 1, i)).toISOString(),
  };
});

let requested: URL[] = [];

function jsonResponse(body: unknown, status: number): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

/** HTTP transport double: the paged target list and the single-target GET. */
async function fakeFetch(input: string): Promise<Response> {
  const url = new URL(input);
  requested.push(url);
  if (url.pathname === "/malware/targets") {
    const offset = Number(url.searchParams.get("offset") ?? "0");
    const limit = Number(url.searchParams.get("limit") ?? String(PAGE_SIZE));
    return jsonResponse({ data: TARGETS.slice(offset, offset + limit), meta: { total: TOTAL, offset, limit } }, 200);
  }
  const single = TARGETS.find((t) => url.pathname === `/malware/targets/${t.id}`);
  if (single) return jsonResponse({ data: single }, 200);
  return jsonResponse({ detail: "not found" }, 404);
}

let container: HTMLDivElement;
let root: Root;
let queryClient: QueryClient;

beforeEach(() => {
  Object.assign(globalThis, { IS_REACT_ACT_ENVIRONMENT: true });
  requested = [];
  vi.stubGlobal("fetch", fakeFetch);
  queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  container = document.createElement("div");
  document.body.append(container);
  root = createRoot(container);
});

afterEach(async () => {
  await act(async () => {
    root.unmount();
  });
  queryClient.clear();
  container.remove();
  vi.unstubAllGlobals();
});

const noop = (): void => undefined;

/** Render the malware targets window exactly as the shell does for a page id. */
async function renderTargetsWindow(investigationId: string | null): Promise<void> {
  const entry = PAGE_REGISTRY["malware:targets"];
  if (!entry) throw new Error("malware:targets is not registered");
  await act(async () => {
    root.render(
      <QueryClientProvider client={queryClient}>
        {entry.render({
          windowId: "malware-targets",
          title: "malware \u00b7 targets",
          section: "targets",
          onNavigate: noop,
          onBack: noop,
          onMinimize: noop,
          investigationId,
        })}
      </QueryClientProvider>,
    );
  });
}

/** Retry until the rendered DOM satisfies `ready`; each attempt flushes React
 * work first so resolved queries reach the DOM. */
async function until(ready: () => boolean): Promise<void> {
  await vi.waitFor(
    async () => {
      await act(async () => undefined);
      if (!ready()) throw new Error("condition not yet met");
    },
    { timeout: 3000, interval: 10 },
  );
}

describe("malware targets window deep link", () => {
  it("opens the linked target's detail even when it is off the loaded list page", async () => {
    await renderTargetsWindow(DEEP_ID);
    await until(() => container.textContent?.includes("sha-060") ?? false);
    expect(container.textContent).toContain("sha-060");
    expect(requested.map((u) => u.pathname)).toContain(`/malware/targets/${DEEP_ID}`);
  });

  it("opens no detail when the window has no entity id", async () => {
    await renderTargetsWindow(null);
    await until(() => container.querySelectorAll("tbody tr").length > 0);
    expect(container.querySelectorAll("tbody tr").length).toBe(PAGE_SIZE);
    expect(container.textContent).not.toContain("sha-");
    expect(requested.some((u) => u.pathname.startsWith("/malware/targets/tgt-"))).toBe(false);
  });
});
