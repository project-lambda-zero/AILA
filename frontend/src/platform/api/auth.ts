import { requestJson } from "@platform/api/http";
import type { AppRole } from "@platform/auth/roles";

export interface TokenResponse {
  access_token: string;
  /** #119: the refresh token now ships as an HttpOnly cookie
   * (`aila_refresh`) set by the backend on /auth/login,
   * /auth/refresh/user, and the OIDC callback. It is intentionally
   * unreachable from JS -- XSS cannot exfiltrate it. The field is
   * kept optional on the wire so non-browser API-key clients can still
   * receive a value; browser SPAs must ignore it. */
  refresh_token?: string | null;
  token_type: string;
  expires_in: number;
}

export interface UserTokenClaims {
  userId: string;
  role: AppRole;
  exp: number;
}

interface DataEnvelope<T> {
  data: T;
  meta?: unknown;
}

function decodeBase64Url(payload: string): string {
  const padded = payload.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(payload.length / 4) * 4, "=");
  const binary = atob(padded);
  const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0));
  return new TextDecoder().decode(bytes);
}

export function decodeUserTokenClaims(token: string): UserTokenClaims {
  const segments = token.split(".");
  if (segments.length < 2) {
    throw new Error("JWT access token is malformed.");
  }

  const payload = JSON.parse(decodeBase64Url(segments[1])) as Record<string, unknown>;
  if (
    typeof payload.user_id !== "string" ||
    typeof payload.role !== "string" ||
    typeof payload.exp !== "number"
  ) {
    throw new Error("JWT access token is missing required claims (user_id, role, exp).");
  }

  return {
    userId: payload.user_id,
    role: payload.role as AppRole,
    exp: payload.exp,
  };
}

export async function loginWithPassword(
  username: string,
  password: string,
): Promise<TokenResponse> {
  // #119: `credentials: 'include'` lets the browser accept the Set-Cookie
  // headers that carry the HttpOnly refresh + readable CSRF cookies.
  const envelope = await requestJson<DataEnvelope<TokenResponse>>("/auth/login", {
    method: "POST",
    body: { username, password },
    credentials: "include",
  });
  return envelope.data;
}

export async function refreshUserToken(): Promise<TokenResponse> {
  // #119: the refresh token lives in the `aila_refresh` HttpOnly cookie
  // the browser attaches automatically. `credentials: 'include'` is what
  // triggers that attachment on same-origin CORS calls, and it also
  // accepts the fresh cookies the backend sends back.
  const envelope = await requestJson<DataEnvelope<TokenResponse>>("/auth/refresh/user", {
    method: "POST",
    credentials: "include",
  });
  return envelope.data;
}

export async function logoutUser(): Promise<void> {
  // #119: revokes the DB row keyed off the cookie and clears both auth
  // cookies via Set-Cookie in the response.
  await requestJson<unknown>("/auth/logout", {
    method: "POST",
    credentials: "include",
  });
}

export async function fetchOidcAuthorizeUrl(redirectUri?: string): Promise<string> {
  const params = new URLSearchParams();
  if (redirectUri) {
    params.set("redirect_uri", redirectUri);
  }
  const search = params.toString();
  const path = search ? `/auth/oidc/authorize?${search}` : "/auth/oidc/authorize";
  const envelope = await requestJson<DataEnvelope<{ authorization_url: string }>>(path);
  return envelope.data.authorization_url;
}

export async function exchangeOidcCode(
  code: string,
  state: string,
  redirectUri?: string,
): Promise<TokenResponse> {
  const params = new URLSearchParams({ code, state });
  if (redirectUri) {
    params.set("redirect_uri", redirectUri);
  }
  // #119: the callback also issues the auth cookies -- credentials must
  // flow so the Set-Cookie headers are accepted by the browser.
  const envelope = await requestJson<DataEnvelope<TokenResponse>>(
    `/auth/oidc/callback?${params.toString()}`,
    { credentials: "include" },
  );
  return envelope.data;
}
