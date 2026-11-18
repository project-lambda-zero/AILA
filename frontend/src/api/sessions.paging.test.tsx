import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, cleanup, renderHook, waitFor } from "@testing-library/react";
import type { ReactNode } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { useSessionMessages, type SessionMessagesResponse } from "./sessions";

type FetchInput = RequestInfo | URL;

const SESSION_ID = "synthetic-session";
const MESSAGES_PATH = `/sessions/${SESSION_ID}/messages`;
const MESSAGES_KEY = ["sessions", SESSION_ID, "messages"];

const clients: QueryClient[] = [];

function requestUrl(input: FetchInput): URL {
  if (typeof input === "string") return new URL(input, "http://localhost");
  if (input instanceof URL) return input;
  return new URL(input.url);
}

/** Session messages route mirroring the backend contract: 1-based page, page_size
 *  clamped by the caller, `pages` = ceil(total / page_size) or 0, ascending items.
 *  `count` is read per request so a test can grow or shrink the thread. */
function stubMessagesRoute(count: () => number, status = 200) {
  const fetchMock = vi.fn(async (input: FetchInput) => {
    const url = requestUrl(input);
    if (url.pathname !== MESSAGES_PATH) return new Response("{}", { status: 404 });
    if (status !== 200) return new Response("{}", { status });
    const total = count();
    const page = Number(url.searchParams.get("page") ?? 1);
    const pageSize = Number(url.searchParams.get("page_size") ?? 50);
    const start = (page - 1) * pageSize;
    const size = Math.max(0, Math.min(pageSize, total - start));
    const body: SessionMessagesResponse = {
      total,
      page,
      page_size: pageSize,
      pages: total > 0 ? Math.ceil(total / pageSize) : 0,
      items: Array.from({ length: size }, (_, i) => ({
        message_id: `m${start + i}`,
        role: "user" as const,
        content: `message-${start + i}`,
        actions: [],
      })),
    };
    return new Response(JSON.stringify(body), { status: 200, headers: { "Content-Type": "application/json" } });
  });
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}

function requestedPages(fetchMock: { mock: { calls: [FetchInput, RequestInit?][] } }): number[] {
  return fetchMock.mock.calls
    .filter(([input]) => requestUrl(input).pathname === MESSAGES_PATH)
    .map(([input]) => Number(requestUrl(input).searchParams.get("page") ?? 1));
}

function renderWithClient() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  clients.push(client);
  function Wrapper({ children }: { children: ReactNode }) {
    return <QueryClientProvider client={client}>{children}</QueryClientProvider>;
  }
  const rendered = renderHook(() => useSessionMessages(SESSION_ID), { wrapper: Wrapper });
  return { ...rendered, client };
}

afterEach(() => {
  cleanup();
  for (const client of clients.splice(0)) client.clear();
  vi.unstubAllGlobals();
});

describe("useSessionMessages latest-page delivery", () => {
  it.each([
    { count: 0, page: 1, items: 0 },
    { count: 1, page: 1, items: 1 },
    { count: 50, page: 1, items: 50 },
    { count: 51, page: 2, items: 1 },
    { count: 100, page: 2, items: 50 },
    { count: 101, page: 3, items: 1 },
  ])("delivers the latest page for $count messages", async ({ count, page, items }) => {
    stubMessagesRoute(() => count);
    const { result } = renderWithClient();

    await waitFor(() => expect(result.current.data).toBeDefined());
    expect(result.current.data?.total).toBe(count);
    expect(result.current.data?.page).toBe(page);
    expect(result.current.data?.items).toHaveLength(items);
    expect(result.current.data?.items.at(-1)?.content).toBe(
      count > 0 ? `message-${count - 1}` : undefined,
    );
  });

  it("issues exactly one request per steady-state refetch", async () => {
    const fetchMock = stubMessagesRoute(() => 101);
    const { result, client } = renderWithClient();
    await waitFor(() => expect(result.current.data?.page).toBe(3));
    expect(requestedPages(fetchMock)).toEqual([1, 3]);

    const before = requestedPages(fetchMock).length;
    await act(async () => {
      await client.refetchQueries({ queryKey: MESSAGES_KEY });
    });

    expect(requestedPages(fetchMock).slice(before)).toEqual([3]);
    expect(result.current.data?.page).toBe(3);
  });

  it("follows the thread onto a new page when messages cross a boundary", async () => {
    let total = 100;
    const fetchMock = stubMessagesRoute(() => total);
    const { result, client } = renderWithClient();
    await waitFor(() => expect(result.current.data?.page).toBe(2));

    total = 101;
    const before = requestedPages(fetchMock).length;
    await act(async () => {
      await client.refetchQueries({ queryKey: MESSAGES_KEY });
    });

    expect(requestedPages(fetchMock).slice(before)).toEqual([2, 3]);
    await waitFor(() => expect(result.current.data?.page).toBe(3));
    expect(result.current.data?.items.map((m) => m.content)).toEqual(["message-100"]);
  });

  it("falls back to the new last page when the thread shrinks", async () => {
    let total = 101;
    const fetchMock = stubMessagesRoute(() => total);
    const { result, client } = renderWithClient();
    await waitFor(() => expect(result.current.data?.page).toBe(3));

    total = 50;
    const before = requestedPages(fetchMock).length;
    await act(async () => {
      await client.refetchQueries({ queryKey: MESSAGES_KEY });
    });

    expect(requestedPages(fetchMock).slice(before)).toEqual([3, 1]);
    await waitFor(() => expect(result.current.data?.page).toBe(1));
    expect(result.current.data?.items).toHaveLength(50);
  });

  it("propagates a failed messages request as a query error", async () => {
    stubMessagesRoute(() => 0, 500);
    const { result } = renderWithClient();

    await waitFor(() => expect(result.current.isError).toBe(true));
    expect(result.current.data).toBeUndefined();
  });
});
