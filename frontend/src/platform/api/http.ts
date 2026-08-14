import { appEnv } from "@platform/config/env";

import { isErrorEnvelope, type ErrorEnvelope as ApiErrorEnvelope } from "@/lib/errorEnvelope";

// ---------------------------------------------------------------------------
// #47 -- CSRF double-submit token.
//
// Every mutating request (POST/PUT/PATCH/DELETE) carries an `X-CSRF-Token`
// header derived from a random per-tab token. The same token is mirrored into
// a `SameSite=Strict` cookie so the backend can enforce the double-submit
// pattern (compare header to cookie, reject on mismatch) once the matching
// server-side check ships. Until then the header is a no-op the backend
// ignores; adding it eagerly is defense-in-depth and pre-positions the app
// for the eventual `HttpOnly` cookie migration described in useAuthStore.
//
// The final hardened state is HttpOnly + Secure + SameSite=Strict cookies
// issued by the backend on login, plus this same double-submit header sent on
// every mutation. That combination gives credentials that JS cannot exfiltrate
// while still protecting against cross-site request forgery through the
// standard double-submit pattern.
// ---------------------------------------------------------------------------

export const CSRF_HEADER_NAME = "X-CSRF-Token";
const CSRF_COOKIE_NAME = "aila_csrf";
const MUTATING_METHODS: Record<string, true> = {
  POST: true,
  PUT: true,
  PATCH: true,
  DELETE: true,
};

function readCookie(name: string): string | null {
  if (typeof document === "undefined") return null;
  const cookies = document.cookie ? document.cookie.split(";") : [];
  for (const entry of cookies) {
    const eq = entry.indexOf("=");
    if (eq < 0) continue;
    const key = entry.slice(0, eq).trim();
    if (key === name) {
      return decodeURIComponent(entry.slice(eq + 1).trim());
    }
  }
  return null;
}

function writeCsrfCookie(value: string): void {
  if (typeof document === "undefined") return;
  const secure = typeof location !== "undefined" && location.protocol === "https:" ? "; Secure" : "";
  // SameSite=Strict blocks the cookie from riding along on cross-site
  // navigations, which is the property that lets the backend treat the
  // cookie as a proof-of-first-party-origin on mutating requests.
  document.cookie = `${CSRF_COOKIE_NAME}=${encodeURIComponent(value)}; Path=/; SameSite=Strict${secure}`;
}

/** Return the current CSRF token, minting one if none exists yet.
 *
 * Exported so raw `fetch` call sites (multipart upload, POST-based SSE) can
 * attach the same header without going through {@link requestJson}. Prefer
 * routing through the wrappers here whenever possible; this getter exists
 * only for call sites that cannot use the JSON helpers. */
export function getCsrfToken(): string {
  const existing = readCookie(CSRF_COOKIE_NAME);
  if (existing) return existing;
  const fresh = mintCsrfToken();
  writeCsrfCookie(fresh);
  return fresh;
}

function mintCsrfToken(): string {
  const cryptoImpl = typeof globalThis !== "undefined" ? globalThis.crypto : undefined;
  if (cryptoImpl && typeof cryptoImpl.randomUUID === "function") {
    return cryptoImpl.randomUUID();
  }
  const bytes = new Uint8Array(16);
  if (cryptoImpl && typeof cryptoImpl.getRandomValues === "function") {
    cryptoImpl.getRandomValues(bytes);
  } else {
    // Environment without WebCrypto (very old browsers / broken jsdom):
    // fall back to Math.random. The double-submit guarantee degrades to
    // "any string agreed between cookie and header", which the backend
    // will still validate as equal.
    for (let i = 0; i < bytes.length; i += 1) {
      bytes[i] = Math.floor(Math.random() * 256);
    }
  }
  let hex = "";
  for (const byte of bytes) {
    hex += byte.toString(16).padStart(2, "0");
  }
  return hex;
}

function applyCsrfHeader(headers: Headers, method: string): void {
  if (!MUTATING_METHODS[method.toUpperCase()]) return;
  if (headers.has(CSRF_HEADER_NAME)) return;
  const token = getCsrfToken();
  if (token) {
    headers.set(CSRF_HEADER_NAME, token);
  }
}

interface LegacyErrorPayload {
  detail?: string;
  code?: string | null;
  errors?: unknown;
  // 176a-01 envelope shape co-resident on the same JSON body.
  message?: string;
  hint?: string | null;
  trace_id?: string | null;
}

export interface RequestJsonOptions extends Omit<RequestInit, "body"> {
  body?: BodyInit | object | null;
  token?: string;
  /**
   * #47 -- per-request wall-clock timeout in milliseconds.
   *
   * When `signal` is not provided, an `AbortSignal.timeout(timeoutMs)`
   * is attached so a request that never returns cannot pin a browser
   * connection slot indefinitely. When the caller passes their own
   * `signal` (e.g. a react-query cancellation controller), `timeoutMs`
   * is layered by combining both signals so cancellation still wins.
   * Explicit `0` disables the timeout (needed for SSE `requestJson`
   * consumers that live for the duration of the connection).
   *
   * Defaults to `DEFAULT_REQUEST_TIMEOUT_MS`.
   */
  timeoutMs?: number;
}

/** #47 -- default per-request timeout (30 seconds). Long enough for a
 * heavy scan submit; short enough that a stalled TLS handshake cannot
 * park a fetch forever. */
export const DEFAULT_REQUEST_TIMEOUT_MS = 30_000;

function resolveAbortSignal(
  callerSignal: AbortSignal | null | undefined,
  timeoutMs: number,
): AbortSignal | undefined {
  if (timeoutMs <= 0) return callerSignal ?? undefined;
  const timeoutSignal = AbortSignal.timeout(timeoutMs);
  if (!callerSignal) return timeoutSignal;
  // AbortSignal.any composes cancellation deterministically: the first
  // aborter wins with its own `reason`. Available on every browser
  // matching the React 19 support matrix.
  return AbortSignal.any([callerSignal, timeoutSignal]);
}

export interface BlobResponsePayload {
  blob: Blob;
  fileName: string | null;
  contentType: string | null;
}

export class ApiHttpError extends Error {
  readonly status: number;
  readonly detail: string;
  readonly code: string | null;
  readonly errors: unknown;
  /**
   * 176a-01 ErrorEnvelope payload when the backend response matches
   * `{code, message, hint, trace_id}`. Consumed by the shared
   * apiErrorHandler in `src/lib/apiErrorHandler.ts` so the toast can show
   * `message`, `hint`, and `trace_id` instead of the generic "An error
   * occurred." fallback (D-10c, last-mile fix from 176a-03 Task 1).
   */
  readonly envelope: ApiErrorEnvelope | null;

  constructor(
    status: number,
    detail: string,
    code: string | null,
    errors: unknown,
    envelope: ApiErrorEnvelope | null = null,
  ) {
    super(detail);
    this.name = "ApiHttpError";
    this.status = status;
    this.detail = detail;
    this.code = code;
    this.errors = errors;
    this.envelope = envelope;
  }
}

export function buildApiUrl(pathname: string): string {
  if (/^https?:\/\//.test(pathname)) {
    return pathname;
  }
  const normalizedPath = pathname.startsWith("/") ? pathname : `/${pathname}`;
  return `${appEnv.apiBaseUrl}${normalizedPath}`;
}

async function buildApiError(response: Response): Promise<ApiHttpError> {
  let payload: LegacyErrorPayload = {};
  try {
    payload = (await response.json()) as LegacyErrorPayload;
  } catch {
    payload = {};
  }

  // Prefer the 176a-01 envelope `message` over the legacy `detail`. Both
  // shapes can co-exist; the message is operator-facing and stable.
  const detail =
    typeof payload.message === "string"
      ? payload.message
      : typeof payload.detail === "string"
        ? payload.detail
        : `${response.status} ${response.statusText}`;

  // Surface the full ErrorEnvelope when present so the shared apiErrorHandler
  // can render hint + trace_id (D-10c, D-26).
  const envelope: ApiErrorEnvelope | null = isErrorEnvelope(payload)
    ? payload
    : null;

  return new ApiHttpError(
    response.status,
    detail,
    typeof payload.code === "string" ? payload.code : null,
    payload.errors ?? null,
    envelope,
  );
}

function normalizeRequestBody(
  body: BodyInit | object | null | undefined,
): BodyInit | null | undefined {
  if (body === undefined || body === null) {
    return body;
  }
  if (
    typeof body === "string" ||
    body instanceof FormData ||
    body instanceof URLSearchParams ||
    body instanceof Blob ||
    body instanceof ArrayBuffer
  ) {
    return body;
  }
  if (ArrayBuffer.isView(body)) {
    return body as unknown as BodyInit;
  }
  return JSON.stringify(body);
}

function extractFileName(response: Response): string | null {
  const disposition = response.headers.get("Content-Disposition");
  if (!disposition) {
    return null;
  }
  const utf8Match = disposition.match(/filename\*=UTF-8''([^;]+)/i);
  if (utf8Match?.[1]) {
    return decodeURIComponent(utf8Match[1]);
  }
  const quotedMatch = disposition.match(/filename="([^"]+)"/i);
  if (quotedMatch?.[1]) {
    return quotedMatch[1];
  }
  const simpleMatch = disposition.match(/filename=([^;]+)/i);
  return simpleMatch?.[1]?.trim() ?? null;
}

export async function requestJson<T>(
  pathname: string,
  options: RequestJsonOptions = {},
): Promise<T> {
  const headers = new Headers(options.headers);

  if (!headers.has("Accept")) {
    headers.set("Accept", "application/json");
  }

  if (options.body !== undefined && !(options.body instanceof FormData) && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }

  if (options.token) {
    headers.set("Authorization", `Bearer ${options.token}`);
  }

  applyCsrfHeader(headers, options.method ?? "GET");

  const signal = resolveAbortSignal(
    options.signal,
    options.timeoutMs ?? DEFAULT_REQUEST_TIMEOUT_MS,
  );

  const response = await fetch(buildApiUrl(pathname), {
    // #119: `credentials: "include"` by default so the HttpOnly refresh
    // + readable CSRF cookies flow on every same-origin and CORS call.
    // Callers may override by setting `credentials` in `options`.
    credentials: "include",
    ...options,
    body: normalizeRequestBody(options.body),
    headers,
    signal,
  });

  if (!response.ok) {
    throw await buildApiError(response);
  }

  if (response.status === 204) {
    return undefined as T;
  }

  return (await response.json()) as T;
}

export async function requestBlob(
  pathname: string,
  options: RequestJsonOptions = {},
): Promise<BlobResponsePayload> {
  const headers = new Headers(options.headers);

  if (!headers.has("Accept")) {
    headers.set("Accept", "*/*");
  }

  if (options.token) {
    headers.set("Authorization", `Bearer ${options.token}`);
  }

  applyCsrfHeader(headers, options.method ?? "GET");

  const signal = resolveAbortSignal(
    options.signal,
    options.timeoutMs ?? DEFAULT_REQUEST_TIMEOUT_MS,
  );

  const response = await fetch(buildApiUrl(pathname), {
    // #119: default to sending credentials -- see rationale in requestJson.
    credentials: "include",
    ...options,
    body: normalizeRequestBody(options.body),
    headers,
    signal,
  });

  if (!response.ok) {
    throw await buildApiError(response);
  }

  return {
    blob: await response.blob(),
    fileName: extractFileName(response),
    contentType: response.headers.get("Content-Type"),
  };
}

export { buildApiError };

/**
 * Makes an authenticated JSON request using the Zustand auth store token.
 * Catches 401 responses, refreshes the token once, and retries (D-13).
 * Uses dynamic import to avoid circular dependency:
 *   http.ts → (dynamic) → useAuthStore.ts → auth.ts → http.ts
 */
export async function authorizedRequestJson<T>(
  pathname: string,
  options: Omit<RequestJsonOptions, "token"> = {},
): Promise<T> {
  const { getAuthTokenStandalone } = await import("@platform/auth/useAuthStore");
  const token = await getAuthTokenStandalone();
  try {
    return await requestJson<T>(pathname, { ...options, token });
  } catch (error) {
    if (error instanceof ApiHttpError && error.status === 401) {
      // 401 interceptor fallback (D-13): refresh once and retry
      const { useAuthStore } = await import("@platform/auth/useAuthStore");
      await useAuthStore.getState().refreshTokens();
      const newToken = useAuthStore.getState().accessToken;
      if (newToken) {
        return await requestJson<T>(pathname, { ...options, token: newToken });
      }
    }
    throw error;
  }
}
