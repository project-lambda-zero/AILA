import { afterEach, describe, expect, it, vi } from "vitest";

import { fetchAllOffsetPages } from "./offsetPages";

type Row = { id: string };
type FetchInput = RequestInfo | URL;

function requestUrl(input: FetchInput): URL {
  if (typeof input === "string") return new URL(input);
  if (input instanceof URL) return input;
  return new URL(input.url);
}

function envelope(data: Row[], offset: number, limit: number, total: number): Response {
  return new Response(JSON.stringify({ data, meta: { offset, limit, total } }), {
    status: 200,
    headers: { "Content-Type": "application/json" },
  });
}

/** Offset/limit list route over a fixed row set, capped at `maxLimit` like the backend. */
function stubListRoute(path: string, rows: Row[], maxLimit: number) {
  const fetchMock = vi.fn(async (input: FetchInput) => {
    const url = requestUrl(input);
    const limit = Math.min(Number(url.searchParams.get("limit") ?? 50), maxLimit);
    const offset = Number(url.searchParams.get("offset") ?? 0);
    return envelope(rows.slice(offset, offset + limit), offset, limit, rows.length);
  });
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}

function rowsNamed(count: number, prefix = "r"): Row[] {
  return Array.from({ length: count }, (_, i) => ({ id: `${prefix}${i}` }));
}

interface FetchCalls {
  mock: { calls: [FetchInput, RequestInit?][] };
}

function offsetsRequested(fetchMock: FetchCalls): number[] {
  return fetchMock.mock.calls.map(([input]) => Number(requestUrl(input).searchParams.get("offset")));
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("fetchAllOffsetPages", () => {
  it("reads meta.total and requests the next page while rows remain", async () => {
    const fetchMock = stubListRoute("/x", rowsNamed(25), 1000);

    const result = await fetchAllOffsetPages<Row>("/x", {}, 10);

    expect(offsetsRequested(fetchMock)).toEqual([0, 10, 20]);
    expect(result.rows).toHaveLength(25);
    expect(result.total).toBe(25);
    expect(result.truncated).toBe(false);
  });

  it("stops on meta.total even when the last page is full", async () => {
    const fetchMock = stubListRoute("/x", rowsNamed(10), 1000);

    const result = await fetchAllOffsetPages<Row>("/x", {}, 10);

    expect(offsetsRequested(fetchMock)).toEqual([0]);
    expect(result.rows).toHaveLength(10);
  });

  it("de-duplicates rows by id, keeping the first appearance and server order", async () => {
    const pages: Row[][] = [
      [{ id: "a" }, { id: "b" }],
      [{ id: "b" }, { id: "c" }],
    ];
    const fetchMock = vi.fn(async (input: FetchInput) => {
      const offset = Number(requestUrl(input).searchParams.get("offset"));
      return envelope(pages[offset / 2] ?? [], offset, 2, 4);
    });
    vi.stubGlobal("fetch", fetchMock);

    const result = await fetchAllOffsetPages<Row>("/x", {}, 2);

    expect(result.rows.map((r) => r.id)).toEqual(["a", "b", "c"]);
  });

  it("stops at the page bound and reports truncation when the total is never reached", async () => {
    const fetchMock = vi.fn(async (input: FetchInput) => {
      const url = requestUrl(input);
      const offset = Number(url.searchParams.get("offset"));
      const limit = Number(url.searchParams.get("limit"));
      const page = Array.from({ length: limit }, (_, i) => ({ id: `e${offset + i}` }));
      return envelope(page, offset, limit, 1_000_000);
    });
    vi.stubGlobal("fetch", fetchMock);

    const result = await fetchAllOffsetPages<Row>("/x", {}, 10);

    expect(fetchMock).toHaveBeenCalledTimes(50);
    expect(result.rows).toHaveLength(500);
    expect(result.truncated).toBe(true);
    expect(result.total).toBe(1_000_000);
  });
});
