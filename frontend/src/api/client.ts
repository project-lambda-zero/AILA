/**
 * Thin fetch wrapper for the AILA backend.
 *
 * The dev frontend (:3000) talks to the backend (:8000) cross-origin; there is
 * no vite proxy, and the backend enables CORS for the app origin. Auth is a
 * Bearer access token held by the auth store; `configureApi` injects the
 * getter + a 401 handler without creating an import cycle with the store.
 */

export const API_BASE = `${window.location.protocol}//${window.location.hostname}:8000`;

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
let unauthorizedHandler: () => void = () => {};

export function configureApi(opts: {
  getToken: () => string | null;
  onUnauthorized: () => void;
}): void {
  tokenGetter = opts.getToken;
  unauthorizedHandler = opts.onUnauthorized;
}

/**
 * Fetch JSON from the backend. Unwraps the `{ data: ... }` envelope the API
 * returns for most routes. Throws `ApiError` on non-2xx; a 401 also triggers
 * the configured logout handler so the app falls back to the login screen.
 */
async function requestJson(path: string, opts: RequestInit): Promise<unknown> {
  const headers = new Headers(opts.headers);
  // Only stamp JSON on serialized bodies. A FormData body must keep the
  // browser-generated multipart boundary, so leave its Content-Type unset.
  if (opts.body && !(opts.body instanceof FormData) && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }
  const token = tokenGetter();
  if (token) {
    headers.set("Authorization", `Bearer ${token}`);
  }

  const res = await fetch(API_BASE + path, { ...opts, headers });

  if (res.status === 401) {
    unauthorizedHandler();
    throw new ApiError(401, "Session expired -- sign in again.");
  }
  if (!res.ok) {
    const detail = await res.text().catch(() => "");
    throw new ApiError(res.status, detail || res.statusText);
  }

  const contentType = res.headers.get("content-type") ?? "";
  if (!contentType.includes("application/json")) {
    return await res.text();
  }
  return await res.json();
}

export async function apiFetch<T>(path: string, opts: RequestInit = {}): Promise<T> {
  const json = await requestJson(path, opts);
  if (json && typeof json === "object" && "data" in json) {
    return json.data as T;
  }
  return json as T;
}

/** Like {@link apiFetch} but returns the FULL response envelope without
 * unwrapping `.data`. Use when the caller needs sibling metadata that
 * apiFetch would drop -- e.g. a `PaginatedMeta` {total, offset, limit} that
 * lives next to `data`, not inside it (DataEnvelope[list] endpoints). */
export async function apiFetchEnvelope<T>(path: string, opts: RequestInit = {}): Promise<T> {
  return (await requestJson(path, opts)) as T;
}
