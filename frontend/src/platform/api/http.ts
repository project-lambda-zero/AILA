import { appEnv } from "@platform/config/env";

import { isErrorEnvelope, type ErrorEnvelope as ApiErrorEnvelope } from "@/lib/errorEnvelope";

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

  const response = await fetch(buildApiUrl(pathname), {
    ...options,
    body: normalizeRequestBody(options.body),
    headers,
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

  const response = await fetch(buildApiUrl(pathname), {
    ...options,
    body: normalizeRequestBody(options.body),
    headers,
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
