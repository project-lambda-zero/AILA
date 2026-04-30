/**
 * Unit tests for sseStreamPost (Phase 176c).
 *
 * Exercises the SSE parser against a hand-rolled ReadableStream so the tests
 * do not depend on a live backend. Covers:
 *   - token events dispatch onToken + onEvent
 *   - done event dispatches onDone and terminates the stream
 *   - non-2xx response surfaces onError with ApiHttpError
 *   - abort signal short-circuits gracefully (no onError)
 *   - trailing event without final blank line is still flushed
 */
import { afterEach, describe, expect, it, vi } from "vitest";

import { sseStreamPost, type SseEventPayload } from "@/lib/sseClient";
import { ApiHttpError } from "@platform/api/http";

function makeStream(chunks: string[]): ReadableStream<Uint8Array> {
  const encoder = new TextEncoder();
  let idx = 0;
  return new ReadableStream<Uint8Array>({
    pull(controller) {
      if (idx >= chunks.length) {
        controller.close();
        return;
      }
      controller.enqueue(encoder.encode(chunks[idx++]));
    },
  });
}

function mockFetchOnce(response: Response) {
  const spy = vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(response);
  return spy;
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe("sseStreamPost", () => {
  it("dispatches token events to onToken + onEvent and terminates on done", async () => {
    const body = makeStream([
      'data: {"type":"token","token":"Hello"}\n\n',
      'data: {"type":"token","token":" world"}\n\n',
      'data: {"type":"done","run_id":"run-42"}\n\n',
    ]);
    mockFetchOnce(
      new Response(body, { status: 200, headers: { "Content-Type": "text/event-stream" } }),
    );

    const tokens: string[] = [];
    const events: SseEventPayload[] = [];
    let doneRunId: string | null | undefined = undefined;

    await sseStreamPost("/sessions/s1/messages", {
      token: "t",
      body: { content: "hi" },
      onToken: (tok) => tokens.push(tok),
      onEvent: (ev) => events.push(ev),
      onDone: (p) => {
        doneRunId = p.run_id;
      },
    });

    expect(tokens).toEqual(["Hello", " world"]);
    expect(events).toHaveLength(3);
    expect(doneRunId).toBe("run-42");
  });

  it("invokes onError with ApiHttpError on non-2xx response", async () => {
    mockFetchOnce(
      new Response(
        JSON.stringify({
          code: "LLM_MISCONFIGURED",
          message: "LLM provider not configured",
          hint: "Set AILA_LLM_PROVIDER in the env",
          trace_id: null,
        }),
        { status: 503, headers: { "Content-Type": "application/json" } },
      ),
    );

    const onError = vi.fn();
    const onToken = vi.fn();
    await sseStreamPost("/sessions/s1/messages", {
      token: "t",
      body: { content: "hi" },
      onError,
      onToken,
    });

    expect(onToken).not.toHaveBeenCalled();
    expect(onError).toHaveBeenCalledTimes(1);
    const err = onError.mock.calls[0][0];
    expect(err).toBeInstanceOf(ApiHttpError);
    expect((err as ApiHttpError).status).toBe(503);
    expect((err as ApiHttpError).envelope?.hint).toBe(
      "Set AILA_LLM_PROVIDER in the env",
    );
  });

  it("returns silently when the signal is aborted before fetch resolves", async () => {
    const controller = new AbortController();
    controller.abort();
    // Fetch throws synchronously when signal already aborted -- mirror that.
    vi.spyOn(globalThis, "fetch").mockImplementationOnce(() => {
      return Promise.reject(new DOMException("aborted", "AbortError"));
    });

    const onError = vi.fn();
    await sseStreamPost("/sessions/s1/messages", {
      token: "t",
      body: {},
      signal: controller.signal,
      onError,
    });
    expect(onError).not.toHaveBeenCalled();
  });

  it("flushes a trailing event missing its terminating blank line", async () => {
    const body = makeStream([
      'data: {"type":"token","token":"last"}',
    ]);
    mockFetchOnce(
      new Response(body, { status: 200, headers: { "Content-Type": "text/event-stream" } }),
    );

    const tokens: string[] = [];
    await sseStreamPost("/sessions/s1/messages", {
      token: "t",
      body: {},
      onToken: (tok) => tokens.push(tok),
    });
    expect(tokens).toEqual(["last"]);
  });

  it("invokes onError when the body JSON is unparseable", async () => {
    const body = makeStream([
      "data: {not-valid-json\n\n",
    ]);
    mockFetchOnce(
      new Response(body, { status: 200, headers: { "Content-Type": "text/event-stream" } }),
    );

    const onError = vi.fn();
    const onToken = vi.fn();
    await sseStreamPost("/sessions/s1/messages", {
      token: "t",
      body: {},
      onError,
      onToken,
    });
    expect(onToken).not.toHaveBeenCalled();
    expect(onError).toHaveBeenCalledTimes(1);
    expect(onError.mock.calls[0][0]).toBeInstanceOf(SyntaxError);
  });
});
