// @vitest-environment jsdom
/** DataPage live-data behaviour: rows stay on screen while the next page key
 * loads (placeholderData: keepPreviousData), and the primary row query keeps
 * its 15 s poll. Only the HTTP transport is faked; PAGE_CONFIGS, DataPage and
 * useDataRows run unmodified. Synthetic data only. */

import { act } from "react";
import { createRoot } from "react-dom/client";
import type { Root } from "react-dom/client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import DataPage from "./DataPage";
import { PAGE_CONFIGS } from "./configs";

const TOTAL = 250;
const PAGE_SIZE = 50;
const NEXT = "\u25b6";
const POLL_MS = 15000;

function pad(n: number): string {
  return String(n).padStart(3, "0");
}

function targetName(n: number): string {
  return `target-${pad(n)}`;
}

function expectedNames(first: number, last: number): string[] {
  return Array.from({ length: last - first + 1 }, (_, i) => targetName(first + i));
}

const TARGETS = Array.from({ length: TOTAL }, (_, i) => {
  const n = i + 1;
  return {
    id: `tgt-${pad(n)}`,
    display_name: targetName(n),
    kind: "elf",
    primary_language: "c",
    status: "active",
    analysis_state: "pending",
    uploaded_filename: `sample-${pad(n)}.bin`,
    created_at: new Date(Date.UTC(2026, 0, 1, i)).toISOString(),
  };
});

let requested: URL[] = [];
/** Resolves the held response for the second page (offset 50). */
let releaseSecondPage: () => void = () => undefined;
let secondPageGate: Promise<void> = Promise.resolve();

function jsonResponse(body: unknown, status: number): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

/** Serves GET /malware/targets. The offset-50 response is held until
 * `releaseSecondPage` runs, so the test can observe the in-flight page. */
async function fakeFetch(input: string): Promise<Response> {
  const url = new URL(input);
  requested.push(url);
  if (url.pathname !== "/malware/targets") return jsonResponse({ detail: "not found" }, 404);
  const offset = Number(url.searchParams.get("offset") ?? "0");
  const limit = Number(url.searchParams.get("limit") ?? "50");
  if (offset === PAGE_SIZE) await secondPageGate;
  return jsonResponse({ data: TARGETS.slice(offset, offset + limit), meta: { total: TOTAL, offset, limit } }, 200);
}

let container: HTMLDivElement;
let root: Root;
let queryClient: QueryClient;

beforeEach(() => {
  Object.assign(globalThis, { IS_REACT_ACT_ENVIRONMENT: true });
  requested = [];
  secondPageGate = new Promise<void>((resolve) => {
    releaseSecondPage = resolve;
  });
  vi.stubGlobal("fetch", fakeFetch);
  queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  container = document.createElement("div");
  document.body.append(container);
  root = createRoot(container);
});

afterEach(async () => {
  releaseSecondPage();
  await act(async () => {
    root.unmount();
  });
  queryClient.clear();
  container.remove();
  vi.unstubAllGlobals();
});

const noop = (): void => undefined;

async function renderTargets(): Promise<void> {
  await act(async () => {
    root.render(
      <QueryClientProvider client={queryClient}>
        <DataPage
          config={PAGE_CONFIGS["malware:targets"]}
          configKey="malware:targets"
          windowId="malware-targets"
          title="malware \u00b7 targets"
          onBack={noop}
          onMinimize={noop}
        />
      </QueryClientProvider>,
    );
  });
}

/** Name cell per body row, located by content (see DataPage.malwareTargets.test). */
function renderedNames(): string[] {
  return Array.from(container.querySelectorAll("tbody tr"), (tr) => {
    const cells = Array.from(tr.querySelectorAll("td"), (td) => td.textContent?.trim() ?? "");
    return cells.find((text) => text.startsWith("target-")) ?? "";
  });
}

function nextButton(): HTMLButtonElement {
  const found = Array.from(container.querySelectorAll("button")).find((b) => b.textContent === NEXT);
  if (!found) throw new Error(`pager button ${NEXT} is not rendered`);
  return found;
}

function lastRequest(): URL | undefined {
  return requested[requested.length - 1];
}

async function click(button: HTMLButtonElement): Promise<void> {
  await act(async () => {
    button.click();
  });
}

async function until(check: () => boolean, what: string): Promise<void> {
  for (let i = 0; i < 300; i += 1) {
    if (check()) return;
    await act(async () => {
      await new Promise((resolve) => setTimeout(resolve, 10));
    });
  }
  throw new Error(`timed out waiting for ${what}`);
}

describe("DataPage live retention (real PAGE_CONFIGS entry)", () => {
  it("keeps the previous page's rows on screen while the next page key loads", async () => {
    await renderTargets();
    await until(() => renderedNames().length === PAGE_SIZE && renderedNames()[0] === targetName(1), "page 1");

    await click(nextButton());
    await until(() => lastRequest()?.searchParams.get("offset") === String(PAGE_SIZE), "page 2 request");

    expect(renderedNames()).toEqual(expectedNames(1, PAGE_SIZE));

    releaseSecondPage();
    await until(() => renderedNames()[0] === targetName(PAGE_SIZE + 1), "page 2 rows");
    expect(renderedNames()).toEqual(expectedNames(PAGE_SIZE + 1, PAGE_SIZE * 2));
  });

  it("keeps the 15 second poll on the primary row query", async () => {
    await renderTargets();
    await until(() => renderedNames().length === PAGE_SIZE, "page 1");

    const rowQuery = queryClient
      .getQueryCache()
      .findAll({ queryKey: ["datapage"] })
      .find((q) => q.queryKey[1] === "/malware/targets");

    expect(rowQuery?.observers[0]?.options.refetchInterval).toBe(POLL_MS);
  });
});
