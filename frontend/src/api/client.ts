/**
 * Thin fetch wrapper for the AILA backend.
 *
 * The dev frontend (:3000) talks to the backend (:8000) cross-origin; there is
 * no vite proxy, and the backend enables CORS for the app origin. Auth is a
 * Bearer access token held in memory by the auth store; `configureApi` injects
 * the token getter and the session renewer without creating an import cycle
 * with the store. The refresh token lives in an HttpOnly cookie that only the
 * session calls (login, refresh, logout) send.
 */

export const API_BASE = `${window.location.protocol}//${window.location.hostname}:8000`;

/** Non-HttpOnly cookie the auth routes mint; mirrored into CSRF_HEADER on
 * cookie-authenticated calls (double-submit check in the API). */
const CSRF_COOKIE = "aila_csrf";
const CSRF_HEADER = "X-CSRF-Token";

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

let tokenGetter: () => string | null = () => null;
let sessionRenewer: () => Promise<string | null> = async () => null;
let renewal: Promise<string | null> | null = null;

export function configureApi(opts: {
  getToken: () => string | null;
  /** Exchange the refresh cookie for a new access token and store it; resolves
   * null (after signing out) when the session cannot be renewed. */
  renewSession: () => Promise<string | null>;
}): void {
  tokenGetter = opts.getToken;
  sessionRenewer = opts.renewSession;
}

/** Renew the access token through the refresh cookie. Concurrent callers share
 * one in-flight renewal, so a burst of 401s costs a single refresh call. */
export function renewAccessToken(): Promise<string | null> {
  if (renewal === null) {
    renewal = sessionRenewer().finally(() => {
      renewal = null;
    });
  }

  return renewal;
}

/** Fetch `path` (relative to API_BASE) with the Bearer token. A 401 renews the
 * token once and retries the request with it; when another request already
 * renewed the token, the retry uses that token without a second refresh. If
 * renewal fails the store has signed out and the 401 response is returned. */
export async function authorizedFetch(path: string, init: RequestInit = {}): Promise<Response> {
  const send = (token: string | null): Promise<Response> => {
    const headers = new Headers(init.headers);

    if (token) headers.set("Authorization", `Bearer ${token}`);

    return fetch(API_BASE + path, { ...init, headers });
  };
  const sent = tokenGetter();
  const res = await send(sent);

  if (res.status !== 401) return res;

  const current = tokenGetter();
  const token = current !== null && current !== sent ? current : await renewAccessToken();

  return token === null ? res : send(token);
}

function readCookie(name: string): string | null {
  for (const pair of document.cookie.split("; ")) {
    const eq = pair.indexOf("=");

    if (eq > 0 && pair.slice(0, eq) === name) return decodeURIComponent(pair.slice(eq + 1));
  }

  return null;
}

/** Parse a backend response: throws `ApiError` on non-2xx, returns undefined
 * for an empty body, the parsed JSON for a JSON body, and text otherwise. */
async function readBody(res: Response): Promise<unknown> {
  if (!res.ok) {
    const detail = await res.text().catch(() => "");
    throw new ApiError(res.status, detail || res.statusText);
  }

  // A 204 (or any empty success body) has nothing to parse; the backend
  // still labels some empty 204s as application/json.
  const body = await res.text();
  if (res.status === 204 || body === "") {
    return undefined;
  }
  const contentType = res.headers.get("content-type") ?? "";
  if (!contentType.includes("application/json")) {
    return body;
  }
  return JSON.parse(body);
}

function unwrap<T>(json: unknown): T {
  if (json && typeof json === "object" && "data" in json) {
    // SAFETY: T is the caller's declared response type; the payload is untrusted
    // JSON and callers narrow it at the boundary (api/parse.ts) before use.
    return json.data as T;
  }
  // SAFETY: same contract as the envelope branch above; T is the caller's declared type.
  return json as T;
}

/**
 * Fetch JSON from the backend through {@link authorizedFetch}. Throws
 * `ApiError` on non-2xx; a 401 that survives token renewal throws a
 * session-expired error.
 */
async function requestJson(path: string, opts: RequestInit): Promise<unknown> {
  const headers = new Headers(opts.headers);
  // Only stamp JSON on serialized bodies. A FormData body must keep the
  // browser-generated multipart boundary, so leave its Content-Type unset.
  if (opts.body && !(opts.body instanceof FormData) && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }

  const res = await authorizedFetch(path, { ...opts, headers });

  if (res.status === 401) {
    throw new ApiError(401, "Session expired -- sign in again.");
  }

  return readBody(res);
}

/** POST to an auth session route (login, refresh, logout). Sends the refresh
 * and CSRF cookies plus the CSRF header, never a Bearer token, and never
 * renews on 401: the caller owns the failure. Unwraps the data envelope. */
export async function sessionRequest<T>(path: string, body?: unknown): Promise<T> {
  const headers = new Headers();
  const csrf = readCookie(CSRF_COOKIE);

  if (csrf) headers.set(CSRF_HEADER, csrf);

  if (body !== undefined) headers.set("Content-Type", "application/json");

  const res = await fetch(API_BASE + path, {
    method: "POST",
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
    credentials: "include",
  });

  return unwrap<T>(await readBody(res));
}

export async function apiFetch<T>(path: string, opts: RequestInit = {}): Promise<T> {
  return unwrap<T>(await requestJson(path, opts));
}

/** Like {@link apiFetch} but returns the FULL response envelope without
 * unwrapping `.data`. Use when the caller needs sibling metadata that
 * apiFetch would drop -- e.g. a `PaginatedMeta` {total, offset, limit} that
 * lives next to `data`, not inside it (DataEnvelope[list] endpoints). */
export async function apiFetchEnvelope<T>(path: string, opts: RequestInit = {}): Promise<T> {
  // SAFETY: T is the caller's declared envelope type; callers narrow the untrusted payload at the boundary.
  return (await requestJson(path, opts)) as T;
}
