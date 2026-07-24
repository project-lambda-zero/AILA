import { useEffect, useRef, useState } from "react";

import { getAuthTokenStandalone } from "../auth/useAuthStore";

/** Live connection status for a Server-Sent Events stream.
 *
 *  Green = connected, amber = reconnecting, red = disconnected. Matches
 *  the module-level ``LiveStatus`` union (components/LiveDot) verbatim so
 *  a module hook can hand the return value straight to its LiveDot. */
export type SSEStreamStatus = "connected" | "reconnecting" | "disconnected";

/** Options for {@link useSSEStream}.
 *
 *  The generic parameter ``T`` is the parsed message type a consumer
 *  merges into its own query cache. The transport (auth, fetch, line
 *  splitting, reconnect/backoff, abort) is owned here; every
 *  module-specific concern is a callback so the same connection loop
 *  serves streams that differ in URL shape, event framing, and cache
 *  layout. */
export interface UseSSEStreamOpts<T> {
  /** Build the full stream URL at connect time. Return ``null`` to skip
   *  connecting (e.g. the investigation id is empty). Called once per
   *  connection attempt so time-sensitive query params -- a
   *  ``since_iso=now()`` cursor, say -- are computed fresh at connect
   *  rather than frozen at render. */
  buildUrl: () => string | null;
  /** Parse one raw SSE ``data:`` payload into a message, or ``null`` to
   *  drop it. Heartbeats, envelopes carrying no message, and malformed
   *  JSON all return ``null``. Any throw is treated as ``null``. */
  parseEvent: (raw: string) => T | null;
  /** Merge a parsed message into the consumer's cache. Closes over the
   *  query client and cache keys in the calling hook. */
  onMessage: (message: T) => void;
  /** When true, auto-reconnect on stream end / network error with
   *  exponential backoff (1s -> 2s -> 4s -> 8s -> 16s capped at 30s,
   *  reset to 1s on every successful connect). When false, a single
   *  attempt runs and the status settles to ``disconnected`` when the
   *  stream ends (the component remounts to reopen). */
  reconnect: boolean;
  /** Effect dependencies that trigger a reconnect when they change --
   *  the investigation id plus any filter or cursor params. The three
   *  callbacks above are read through refs and MUST NOT be listed here;
   *  keeping unstable inline closures out of the dep array is what
   *  prevents a reconnect on every render. */
  deps: readonly unknown[];
}

const MAX_BACKOFF_MS = 30_000;

/** Single-connection Server-Sent Events tail with optional reconnect.
 *
 *  Opens one ``text/event-stream`` request, splits the body into
 *  ``data:`` lines, parses each via {@link UseSSEStreamOpts.parseEvent},
 *  and forwards non-null results to {@link UseSSEStreamOpts.onMessage}.
 *  The connection closes on unmount via AbortController; when
 *  ``reconnect`` is set it re-opens on stream end / error with
 *  exponential backoff whose sleep is abort-aware (unmount teardown is
 *  immediate, never blocked on a pending 30s wait). */
export function useSSEStream<T>(
  opts: UseSSEStreamOpts<T>,
): { status: SSEStreamStatus } {
  const { reconnect, deps } = opts;
  const [status, setStatus] = useState<SSEStreamStatus>("reconnecting");

  // Callbacks via refs. They close over render-scope values (the query
  // client, ids, cursors) and are recreated each render; listing them
  // in the effect deps would tear down and reopen the stream on every
  // render. Refs keep the latest closure callable without driving a
  // reconnect.
  const buildUrlRef = useRef(opts.buildUrl);
  const parseEventRef = useRef(opts.parseEvent);
  const onMessageRef = useRef(opts.onMessage);
  buildUrlRef.current = opts.buildUrl;
  parseEventRef.current = opts.parseEvent;
  onMessageRef.current = opts.onMessage;

  useEffect(() => {
    if (buildUrlRef.current() === null) {
      setStatus("disconnected");
      return;
    }
    setStatus("reconnecting");
    const ac = new AbortController();
    let backoffMs = 1000;

    const connectOnce = async (): Promise<void> => {
      let token: string | null = null;
      try {
        token = await getAuthTokenStandalone();
      } catch {
        // Unauthenticated -- the backend refuses the request.
      }

      const url = buildUrlRef.current();
      if (url === null) return;

      let response: Response;
      try {
        response = await fetch(url, {
          headers: {
            Accept: "text/event-stream",
            ...(token ? { Authorization: `Bearer ${token}` } : {}),
          },
          signal: ac.signal,
        });
      } catch {
        return;
      }
      if (!response.ok || !response.body) return;
      setStatus("connected");
      // Successful connection -- reset backoff so the NEXT drop gets the
      // quick first-retry treatment instead of inheriting a stale 30s
      // wait from earlier failures.
      backoffMs = 1000;

      const reader = response.body.getReader();
      const decoder = new TextDecoder();
      let buf = "";

      const pushLine = (line: string) => {
        if (!line.startsWith("data:")) return;
        const raw = line.slice(5).trimStart();
        if (!raw) return;
        let parsed: T | null;
        try {
          parsed = parseEventRef.current(raw);
        } catch {
          // Malformed event -- skip.
          return;
        }
        if (parsed !== null && parsed !== undefined) {
          onMessageRef.current(parsed);
        }
      };

      try {
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          buf += decoder.decode(value, { stream: true });
          const lines = buf.split(/\r?\n/);
          buf = lines.pop() ?? "";
          for (const line of lines) pushLine(line);
        }
      } catch {
        // Aborted or network error -- the loop below decides on retry.
      }
    };

    if (reconnect) {
      // Reconnect loop -- runs until the effect cleans up. Each
      // iteration opens one stream, awaits its end, then waits
      // backoffMs before the next attempt.
      void (async () => {
        while (!ac.signal.aborted) {
          setStatus("reconnecting");
          await connectOnce();
          if (ac.signal.aborted) break;
          setStatus("disconnected");
          // Abort-aware sleep: resolve early on abort so unmount
          // teardown doesn't wait up to 30s for the backoff to expire.
          await new Promise<void>((resolve) => {
            const t = setTimeout(resolve, backoffMs);
            const onAbort = () => {
              clearTimeout(t);
              resolve();
            };
            ac.signal.addEventListener("abort", onAbort, { once: true });
          });
          backoffMs = Math.min(backoffMs * 2, MAX_BACKOFF_MS);
        }
      })();
    } else {
      // Single attempt -- settle to disconnected on end. The component
      // remounts (React strict-mode or navigation) to reopen.
      void (async () => {
        await connectOnce();
        if (!ac.signal.aborted) setStatus("disconnected");
      })();
    }

    return () => {
      ac.abort();
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [reconnect, ...deps]);

  return { status };
}
