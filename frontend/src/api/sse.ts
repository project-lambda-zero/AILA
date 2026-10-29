/**
 * Authenticated Server-Sent Events over fetch.
 *
 * Native EventSource cannot send an Authorization header, so streams are
 * opened with fetch() and parsed from the body's ReadableStream. The hook
 * reconnects with exponential backoff (1s doubling to a 30s cap). The backoff
 * resets only after a connection stayed healthy for 15s, which keeps a
 * flapping backend from burning the per-user rate limit on /events/stream
 * (10 connects per minute, 300s server-side lifetime). A 429/503 with
 * Retry-After waits at least that long. 401 signs the user out; 401, 403 and
 * 404 close the stream for good, as does the configured stop event.
 *
 * When `resumeParam` is set, the last received `id:` is sent back as that
 * query parameter on reconnect so the server resumes after it.
 */

import { useEffect, useRef, useState } from "react";

import { useAuth } from "./auth";
import { API_BASE } from "./client";

export type SseConnectionState = "connecting" | "open" | "reconnecting" | "closed";

export interface SseMessage {
  /** `event:` field, "message" when the frame has none. */
  event: string;
  /** `data:` lines joined with "\n". */
  data: string;
  /** Last event id seen on this stream at dispatch time ("" when none). */
  lastEventId: string;
}

export interface SseOpenInfo {
  /** True when this open follows an earlier successful open (events may have been missed). */
  reconnected: boolean;
}

export interface UseSseStreamOptions {
  /** API path (e.g. "/events/stream"); null disables the stream. */
  path: string | null;
  onMessage: (msg: SseMessage) => void;
  onOpen?: (info: SseOpenInfo) => void;
  /** Query parameter that carries the last event id on reconnect. */
  resumeParam?: string;
  /** Event name that ends the stream; it is delivered to onMessage first. */
  stopEvent?: string;
}

export interface SseStreamStatus {
  state: SseConnectionState;
  /** Set when the stream closed for good on an error (401/403/404). */
  error: string | null;
}

const BACKOFF_BASE_MS = 1_000;
const BACKOFF_CAP_MS = 30_000;
const HEALTHY_RESET_MS = 15_000;

/** Incremental parser for the text/event-stream format (WHATWG HTML 9.2.6). */
export class SseParser {
  private buffer = "";
  private eventType = "";
  private dataLines: string[] = [];
  lastEventId: string;

  constructor(lastEventId = "") {
    this.lastEventId = lastEventId;
  }

  /** Feed a decoded chunk; returns every message completed by it. */
  feed(chunk: string): SseMessage[] {
    this.buffer += chunk;
    const out: SseMessage[] = [];
    for (;;) {
      const match = /\r\n|\n|\r/.exec(this.buffer);
      if (!match) break;
      // A trailing lone "\r" may be the first half of "\r\n": wait for more input.
      if (match[0] === "\r" && match.index === this.buffer.length - 1) break;
      const line = this.buffer.slice(0, match.index);
      this.buffer = this.buffer.slice(match.index + match[0].length);
      const msg = this.processLine(line);
      if (msg) out.push(msg);
    }
    return out;
  }

  private processLine(line: string): SseMessage | null {
    if (line === "") {
      if (this.dataLines.length === 0) {
        this.eventType = "";
        return null;
      }
      const msg: SseMessage = {
        event: this.eventType || "message",
        data: this.dataLines.join("\n"),
        lastEventId: this.lastEventId,
      };
      this.eventType = "";
      this.dataLines = [];
      return msg;
    }
    if (line.startsWith(":")) return null; // comment / keepalive
    const colon = line.indexOf(":");
    const field = colon === -1 ? line : line.slice(0, colon);
    let value = colon === -1 ? "" : line.slice(colon + 1);
    if (value.startsWith(" ")) value = value.slice(1);
    if (field === "event") this.eventType = value;
    else if (field === "data") this.dataLines.push(value);
    else if (field === "id" && !value.includes("\0")) this.lastEventId = value;
    return null;
  }
}

/** Parse a Retry-After header (delta seconds or HTTP date) into milliseconds. */
function retryAfterMs(res: Response): number | null {
  const raw = res.headers.get("Retry-After");
  if (!raw) return null;
  const seconds = Number(raw);
  if (Number.isFinite(seconds)) return Math.max(0, seconds * 1000);
  const at = Date.parse(raw);
  return Number.isNaN(at) ? null : Math.max(0, at - Date.now());
}

function sleep(ms: number, signal: AbortSignal): Promise<void> {
  return new Promise((resolve) => {
    const timer = setTimeout(done, ms);
    function done() {
      clearTimeout(timer);
      signal.removeEventListener("abort", done);
      resolve();
    }
    signal.addEventListener("abort", done);
  });
}

type Outcome =
  | { kind: "stopped" }
  | { kind: "aborted" }
  | { kind: "fatal"; error: string }
  | { kind: "retry"; healthyMs: number; waitAtLeastMs: number };

export function useSseStream(opts: UseSseStreamOptions): SseStreamStatus {
  const { path, resumeParam, stopEvent } = opts;
  const [status, setStatus] = useState<SseStreamStatus>({
    state: path ? "connecting" : "closed",
    error: null,
  });
  const onMessageRef = useRef(opts.onMessage);
  const onOpenRef = useRef(opts.onOpen);
  useEffect(() => {
    onMessageRef.current = opts.onMessage;
    onOpenRef.current = opts.onOpen;
  });

  useEffect(() => {
    if (path === null) {
      setStatus({ state: "closed", error: null });
      return;
    }
    const controller = new AbortController();
    const signal = controller.signal;
    let lastEventId = "";
    let everOpened = false;

    async function connectOnce(): Promise<Outcome> {
      const url = new URL(API_BASE + path);
      if (resumeParam && lastEventId) url.searchParams.set(resumeParam, lastEventId);
      const token = useAuth.getState().token;
      const headers: Record<string, string> = { Accept: "text/event-stream" };
      if (token) headers.Authorization = `Bearer ${token}`;

      let res: Response;
      try {
        res = await fetch(url, { signal, headers, cache: "no-store" });
      } catch {
        return signal.aborted ? { kind: "aborted" } : { kind: "retry", healthyMs: 0, waitAtLeastMs: 0 };
      }
      if (res.status === 401) {
        useAuth.getState().logout();
        return { kind: "fatal", error: "401 session expired" };
      }
      if (res.status === 403 || res.status === 404) {
        return { kind: "fatal", error: `${res.status} ${res.statusText || "not available"}` };
      }
      if (!res.ok || !res.body) {
        return { kind: "retry", healthyMs: 0, waitAtLeastMs: retryAfterMs(res) ?? 0 };
      }

      const openedAt = Date.now();
      onOpenRef.current?.({ reconnected: everOpened });
      everOpened = true;
      setStatus({ state: "open", error: null });

      const reader = res.body.getReader();
      const decoder = new TextDecoder();
      const parser = new SseParser(lastEventId);
      try {
        for (;;) {
          const { value, done } = await reader.read();
          if (done) break;
          for (const msg of parser.feed(decoder.decode(value, { stream: true }))) {
            lastEventId = msg.lastEventId;
            onMessageRef.current(msg);
            if (stopEvent && msg.event === stopEvent) {
              await reader.cancel();
              return { kind: "stopped" };
            }
          }
          lastEventId = parser.lastEventId;
        }
      } catch {
        if (signal.aborted) return { kind: "aborted" };
      }
      return { kind: "retry", healthyMs: Date.now() - openedAt, waitAtLeastMs: 0 };
    }

    void (async () => {
      let delay = BACKOFF_BASE_MS;
      setStatus({ state: "connecting", error: null });
      for (;;) {
        const outcome = await connectOnce();
        if (outcome.kind === "aborted") return;
        if (outcome.kind === "stopped") {
          setStatus({ state: "closed", error: null });
          return;
        }
        if (outcome.kind === "fatal") {
          setStatus({ state: "closed", error: outcome.error });
          return;
        }
        if (outcome.healthyMs >= HEALTHY_RESET_MS) delay = BACKOFF_BASE_MS;
        setStatus({ state: "reconnecting", error: null });
        await sleep(Math.max(delay, outcome.waitAtLeastMs), signal);
        if (signal.aborted) return;
        delay = Math.min(delay * 2, BACKOFF_CAP_MS);
      }
    })();

    return () => controller.abort();
  }, [path, resumeParam, stopEvent]);

  return status;
}
