/**
 * POST-based SSE consumer (Phase 176c).
 *
 * Chat uses POST /sessions/{id}/messages with Accept: text/event-stream to
 * stream assistant tokens. The platform's existing @platform/api/sse helper
 * only supports GET (used for scan event feeds), so this module provides a
 * POST-capable stream reader built on the same fetch+ReadableStream pattern.
 *
 * Each SSE event line looks like:
 *   data: {"type":"token","token":"hello "}
 *   data: {"type":"done","run_id":"run_abc"}
 *
 * Callbacks:
 *   - onToken(token, raw)   called per `{type:"token", token:string}` event
 *   - onDone(raw)            called on `{type:"done"}` (optional)
 *   - onError(err)           called on non-2xx response or parse failure
 *   - signal                 AbortSignal for graceful cancellation
 *
 * Authentication reuses the same bearer-token pattern as authorizedRequestJson
 * so callers do not need to reimplement token fetch / 401 refresh.
 */
import { buildApiError, buildApiUrl } from "@platform/api/http";

export interface SseTokenPayload {
  type: "token";
  token: string;
}

export interface SseDonePayload {
  type: "done";
  run_id?: string | null;
}

export type SseEventPayload = SseTokenPayload | SseDonePayload | Record<string, unknown>;

export interface SseStreamOptions {
  /** Bearer token for the Authorization header. */
  token: string;
  /** JSON body POSTed to the SSE endpoint. */
  body: unknown;
  /** Optional abort signal; when aborted the reader stops and the fetch is cancelled. */
  signal?: AbortSignal;
  /** Called with the `token` field each time a `{type:"token"}` event arrives. */
  onToken?: (token: string, payload: SseTokenPayload) => void;
  /** Called once the server emits `{type:"done"}`. */
  onDone?: (payload: SseDonePayload) => void;
  /**
   * Called on network / parse / non-2xx errors. The returned promise from
   * sseStreamPost resolves normally after onError is invoked so callers get
   * a single code path for error handling.
   */
  onError?: (err: unknown) => void;
  /** Optional generic event hook -- invoked for every parsed event, regardless of type. */
  onEvent?: (payload: SseEventPayload) => void;
}

/**
 * POST to `pathname` with `Accept: text/event-stream`, parse each
 * `data: {...}\n\n` event, and dispatch to the provided callbacks.
 *
 * Resolves when the stream ends (or is aborted). Never rejects -- errors are
 * delivered through `onError` so the caller only needs one branch.
 */
export async function sseStreamPost(
  pathname: string,
  options: SseStreamOptions,
): Promise<void> {
  let response: Response;
  try {
    response = await fetch(buildApiUrl(pathname), {
      method: "POST",
      headers: {
        Accept: "text/event-stream",
        "Content-Type": "application/json",
        Authorization: `Bearer ${options.token}`,
      },
      body: JSON.stringify(options.body ?? {}),
      signal: options.signal,
    });
  } catch (networkErr) {
    if (options.signal?.aborted) {
      return;
    }
    options.onError?.(networkErr);
    return;
  }

  if (!response.ok) {
    try {
      options.onError?.(await buildApiError(response));
    } catch (buildErr) {
      options.onError?.(buildErr);
    }
    return;
  }

  if (!response.body) {
    options.onError?.(new Error("The server did not provide an event stream body."));
    return;
  }

  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  let dataLines: string[] = [];

  const flushEvent = () => {
    if (dataLines.length === 0) {
      return;
    }
    const payloadText = dataLines.join("\n");
    dataLines = [];
    let parsed: SseEventPayload;
    try {
      parsed = JSON.parse(payloadText) as SseEventPayload;
    } catch (parseErr) {
      options.onError?.(parseErr);
      return;
    }
    options.onEvent?.(parsed);
    const eventType = (parsed as { type?: unknown }).type;
    if (eventType === "token" && typeof (parsed as SseTokenPayload).token === "string") {
      options.onToken?.((parsed as SseTokenPayload).token, parsed as SseTokenPayload);
    } else if (eventType === "done") {
      options.onDone?.(parsed as SseDonePayload);
    }
  };

  try {
    // eslint-disable-next-line no-constant-condition
    while (true) {
      const { done, value } = await reader.read();
      if (done) {
        break;
      }
      buffer += decoder.decode(value, { stream: true });
      const lines = buffer.split(/\r?\n/);
      buffer = lines.pop() ?? "";
      for (const line of lines) {
        if (line === "") {
          flushEvent();
          continue;
        }
        if (line.startsWith(":")) {
          continue;
        }
        if (line.startsWith("data:")) {
          dataLines.push(line.slice(5).trimStart());
        }
        // event:/id: fields are ignored -- the chat protocol only uses data:.
      }
    }
    // Flush a trailing event with no terminating blank line (some servers).
    if (buffer.trim().startsWith("data:")) {
      dataLines.push(buffer.trim().slice(5).trimStart());
    }
    flushEvent();
  } catch (readErr) {
    if (options.signal?.aborted) {
      return;
    }
    options.onError?.(readErr);
  }
}
