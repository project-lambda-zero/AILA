import { afterEach, describe, expect, it, vi } from "vitest";

import { ApiError, apiFetch } from "./client";

function stubFetch(response: Response) {
  const fetchMock = vi.fn(async () => response);
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}

describe("apiFetch response handling", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("resolves a 204 labelled application/json without parsing a body", async () => {
    stubFetch(new Response(null, { status: 204, headers: { "content-type": "application/json" } }));

    await expect(apiFetch("/api/forensics/directives/x", { method: "DELETE" })).resolves.toBeUndefined();
  });

  it("resolves an empty 200 JSON body without parsing", async () => {
    stubFetch(new Response("", { status: 200, headers: { "content-type": "application/json" } }));

    await expect(apiFetch("/api/x", { method: "DELETE" })).resolves.toBeUndefined();
  });

  it("unwraps the data envelope of a JSON 200", async () => {
    stubFetch(
      new Response(JSON.stringify({ data: { id: "a1" } }), {
        status: 200,
        headers: { "content-type": "application/json; charset=utf-8" },
      }),
    );

    await expect(apiFetch<{ id: string }>("/api/x")).resolves.toEqual({ id: "a1" });
  });

  it("returns text for a non-JSON 200", async () => {
    stubFetch(new Response("plain", { status: 200, headers: { "content-type": "text/plain" } }));

    await expect(apiFetch<string>("/api/x")).resolves.toBe("plain");
  });

  it("throws ApiError with the body detail on an error status", async () => {
    stubFetch(new Response('{"detail":"gone"}', { status: 404, headers: { "content-type": "application/json" } }));

    const err = await apiFetch("/api/x").catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ApiError);
    expect(err).toMatchObject({ status: 404, message: '{"detail":"gone"}' });
  });
});
