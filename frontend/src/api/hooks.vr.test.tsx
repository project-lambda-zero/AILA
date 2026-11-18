import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, renderHook, waitFor } from "@testing-library/react";
import type { ReactNode } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { useInvestigations, useMessages } from "./hooks";
import type { Investigation } from "./types";

type Row = { id: string };
type FetchInput = RequestInfo | URL;

const INVESTIGATION_ID = "synthetic-investigation";
const MESSAGES_PATH = `/vr/investigations/${INVESTIGATION_ID}/messages`;
const MESSAGES_KEY = ["vr", "messages", INVESTIGATION_ID];
const INVESTIGATION_KEY = ["vr", "investigation", INVESTIGATION_ID];
const INVESTIGATIONS_PATH = "/vr/investigations";
const LIVE_POLL_MS = 8000;

const clients: QueryClient[] = [];

function requestUrl(input: FetchInput): URL {
  if (typeof input === "string") return new URL(input);
  if (input instanceof URL) return input;
  return new URL(input.url);
}

function rowsNamed(count: number, prefix: string): Row[] {
  return Array.from({ length: count }, (_, i) => ({ id: `${prefix}${i}` }));
}

/** Offset/limit list route. Applies `defaultLimit` when the request omits `limit` and clamps to `maxLimit`. */
function stubListRoute(path: string, rows: () => Row[], defaultLimit: number, maxLimit: number) {
  const fetchMock = vi.fn(async (input: FetchInput) => {
    const url = requestUrl(input);
    if (url.pathname !== path) return new Response("{}", { status: 404 });
    const limit = Math.min(Number(url.searchParams.get("limit") ?? defaultLimit), maxLimit);
    const offset = Number(url.searchParams.get("offset") ?? 0);
    const all = rows();
    const body = { data: all.slice(offset, offset + limit), meta: { offset, limit, total: all.length } };
    return new Response(JSON.stringify(body), { status: 200, headers: { "Content-Type": "application/json" } });
  });
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}

interface FetchCalls {
  mock: { calls: [FetchInput, RequestInit?][] };
}

function offsetsFor(fetchMock: FetchCalls, path: string): number[] {
  return fetchMock.mock.calls
    .map(([input]) => requestUrl(input))
    .filter((url) => url.pathname === path)
    .map((url) => Number(url.searchParams.get("offset") ?? 0));
}

/** Renders a hook under a fresh QueryClient and returns that client for cache assertions. */
function renderWithClient<T>(hook: () => T) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  clients.push(client);
  function Wrapper({ children }: { children: ReactNode }) {
    return <QueryClientProvider client={client}>{children}</QueryClientProvider>;
  }
  const rendered = renderHook(hook, { wrapper: Wrapper });
  return { ...rendered, client };
}

/** Reads the refetch interval the query was registered with, as react-query evaluates it. */
function pollIntervalFor(client: QueryClient, queryKey: readonly unknown[]): number | false | undefined {
  const query = client.getQueryCache().find({ queryKey });
  if (!query) return undefined;
  const option = query.observers[0]?.options.refetchInterval;
  return typeof option === "function" ? option(query) : option;
}

afterEach(() => {
  cleanup();
  for (const client of clients.splice(0)) client.clear();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe("useMessages", () => {
  it("loads a 1500-message transcript across bounded pages in server order", async () => {
    const fetchMock = stubListRoute(MESSAGES_PATH, () => rowsNamed(1500, "m"), 10000, 10000);
    const { result } = renderWithClient(() => useMessages(INVESTIGATION_ID));

    await waitFor(() => expect(result.current.data?.length).toBe(1500));
    expect(offsetsFor(fetchMock, MESSAGES_PATH)).toEqual([0, 1000]);
    const limits = fetchMock.mock.calls
      .map(([input]) => requestUrl(input))
      .filter((url) => url.pathname === MESSAGES_PATH)
      .map((url) => url.searchParams.get("limit"));
    expect(limits).toEqual(["1000", "1000"]);
    expect(result.current.data?.[0]?.id).toBe("m0");
    expect(result.current.data?.[1499]?.id).toBe("m1499");
  });

  it("dedupes rows repeated across page boundaries by id", async () => {
    const rows = [...rowsNamed(1000, "m"), ...rowsNamed(500, "m")];
    stubListRoute(MESSAGES_PATH, () => rows, 10000, 10000);
    const { result } = renderWithClient(() => useMessages(INVESTIGATION_ID));

    await waitFor(() => expect(result.current.data?.length).toBe(1000));
    expect(new Set(result.current.data?.map((m) => m.id)).size).toBe(1000);
  });

  it("warns when the transcript exceeds the page ceiling", async () => {
    const all = rowsNamed(60_000, "m");
    stubListRoute(MESSAGES_PATH, () => all, 10000, 10000);
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    const { result } = renderWithClient(() => useMessages(INVESTIGATION_ID));

    await waitFor(() => expect(result.current.data?.length).toBe(50_000));
    expect(warn).toHaveBeenCalled();
  });

  it("stops polling once the cached investigation is terminal", async () => {
    stubListRoute(MESSAGES_PATH, () => rowsNamed(3, "m"), 1000, 1000);
    const { result, client } = renderWithClient(() => useMessages(INVESTIGATION_ID));
    await waitFor(() => expect(result.current.data?.length).toBe(3));

    for (const status of ["completed", "failed", "abandoned", "stalled"]) {
      client.setQueryData<Investigation>(INVESTIGATION_KEY, { status } as Investigation);
      expect(pollIntervalFor(client, MESSAGES_KEY)).toBe(false);
    }
  });

  it("keeps polling while the investigation is live or its status is unknown", async () => {
    stubListRoute(MESSAGES_PATH, () => rowsNamed(3, "m"), 1000, 1000);
    const { result, client } = renderWithClient(() => useMessages(INVESTIGATION_ID));
    await waitFor(() => expect(result.current.data?.length).toBe(3));

    expect(pollIntervalFor(client, MESSAGES_KEY)).toBe(LIVE_POLL_MS);
    for (const status of ["created", "running", "paused"]) {
      client.setQueryData<Investigation>(INVESTIGATION_KEY, { status } as Investigation);
      expect(pollIntervalFor(client, MESSAGES_KEY)).toBe(LIVE_POLL_MS);
    }
  });
});

describe("useInvestigations", () => {
  it("pages the rail beyond 100 investigations in server order", async () => {
    const fetchMock = stubListRoute(INVESTIGATIONS_PATH, () => rowsNamed(250, "inv"), 50, 500);
    const { result } = renderWithClient(() => useInvestigations());

    await waitFor(() => expect(result.current.data?.length).toBe(250));
    expect(offsetsFor(fetchMock, INVESTIGATIONS_PATH)).toEqual([0, 200]);
    expect(result.current.data?.[0]?.id).toBe("inv0");
    expect(result.current.data?.[249]?.id).toBe("inv249");
  });

  it("warns when the rail exceeds the page ceiling", async () => {
    const all = rowsNamed(60_000, "inv");
    stubListRoute(INVESTIGATIONS_PATH, () => all, 50, 500);
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    const { result } = renderWithClient(() => useInvestigations());

    await waitFor(() => expect(result.current.data?.length).toBe(10_000));
    expect(warn).toHaveBeenCalled();
  });
});
