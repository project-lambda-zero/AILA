/**
 * useSSEStream.test.ts -- unit tests for the generic SSE transport hook.
 *
 * useSSEStream opens a fetch + ReadableStream connection, splits the body
 * into ``data:`` lines, parses each through ``parseEvent``, and forwards
 * non-null results to ``onMessage``. These tests drive that path with a
 * mocked fetch whose body is a real ReadableStream, plus the
 * observable-state cases (no-connect, abort-on-unmount) in the D-08 style
 * used by useSSE.test.ts.
 */
import { act, renderHook } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

vi.mock("../auth/useAuthStore", () => ({
  getAuthTokenStandalone: async () => "mock-token",
}));

import { useSSEStream } from "./useSSEStream";

interface Msg {
  id: string;
  kind: string;
}

/** A Response test double whose body streams the given lines (one per
 *  ``\n``-terminated chunk) then closes. Only ``ok`` and ``body`` are
 *  read by the hook, so the rest of the Response surface is omitted. */
function streamResponse(lines: string[]): Response {
  const encoder = new TextEncoder();
  let i = 0;
  const body = new ReadableStream<Uint8Array>({
    pull(controller) {
      if (i < lines.length) {
        controller.enqueue(encoder.encode(`${lines[i]}\n`));
        i += 1;
      } else {
        controller.close();
      }
    },
  });
  // Test double: the hook only reads ok + body.
  const doubled = { ok: true, body } as unknown as Response;
  return doubled;
}

/** JSON-parse a data line into a Msg, or null when it lacks the id field
 *  (models a heartbeat / envelope-without-message). */
function parseMsg(raw: string): Msg | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return null;
  }
  if (parsed && typeof parsed === "object" && "id" in parsed && "kind" in parsed) {
    return parsed as Msg;
  }
  return null;
}

describe("useSSEStream", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    vi.clearAllTimers();
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  it("stays disconnected and never fetches when buildUrl returns null", () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    const { result } = renderHook(() =>
      useSSEStream<Msg>({
        buildUrl: () => null,
        parseEvent: parseMsg,
        onMessage: vi.fn(),
        reconnect: false,
        deps: [],
      }),
    );
    expect(result.current.status).toBe("disconnected");
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("streams a data line through parseEvent into onMessage", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        streamResponse(['data: {"id":"m1","kind":"text"}']),
      ),
    );
    const onMessage = vi.fn();
    const { result } = renderHook(() =>
      useSSEStream<Msg>({
        buildUrl: () => "http://localhost/stream",
        parseEvent: parseMsg,
        onMessage,
        reconnect: false,
        deps: [1],
      }),
    );

    await vi.waitFor(() => {
      expect(onMessage).toHaveBeenCalledWith({ id: "m1", kind: "text" });
    });
    // Stream ended -- a single-attempt (reconnect:false) stream settles
    // to disconnected once the body closes.
    await vi.waitFor(() => {
      expect(result.current.status).toBe("disconnected");
    });
  });

  it("drops events parseEvent rejects and ignores non-data lines", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        streamResponse([
          ":keepalive",
          "event: message.created",
          "data: {}",
          "data: heartbeat",
          'data: {"id":"m2","kind":"x"}',
        ]),
      ),
    );
    const onMessage = vi.fn();
    renderHook(() =>
      useSSEStream<Msg>({
        buildUrl: () => "http://localhost/stream",
        parseEvent: parseMsg,
        onMessage,
        reconnect: false,
        deps: [1],
      }),
    );

    await vi.waitFor(() => {
      expect(onMessage).toHaveBeenCalledTimes(1);
    });
    expect(onMessage).toHaveBeenCalledWith({ id: "m2", kind: "x" });
  });

  it("aborts the request on unmount", async () => {
    const abortSpy = vi.fn();
    class MockAbortController {
      abort = abortSpy;
      signal = { aborted: false } as unknown as AbortSignal;
    }
    vi.stubGlobal("AbortController", MockAbortController);
    vi.stubGlobal(
      "fetch",
      // Never resolves -- keeps the connection pending until unmount.
      vi.fn().mockImplementation(() => new Promise<Response>(() => {})),
    );

    const { unmount } = renderHook(() =>
      useSSEStream<Msg>({
        buildUrl: () => "http://localhost/stream",
        parseEvent: parseMsg,
        onMessage: vi.fn(),
        reconnect: false,
        deps: [1],
      }),
    );

    await act(async () => {
      await Promise.resolve();
    });

    unmount();
    expect(abortSpy).toHaveBeenCalled();
  });
});
