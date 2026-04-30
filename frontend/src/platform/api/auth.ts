import { requestJson } from "@platform/api/http";
import type { AppRole } from "@platform/auth/roles";

export interface TokenResponse {
  access_token: string;
  refresh_token: string;
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
  const envelope = await requestJson<DataEnvelope<TokenResponse>>("/auth/login", {
    method: "POST",
    body: { username, password },
  });
  return envelope.data;
}

export async function refreshUserToken(refreshToken: string): Promise<TokenResponse> {
  // CRITICAL: Query parameter, NOT request body (backend uses Query(...) not Pydantic body)
  const envelope = await requestJson<DataEnvelope<TokenResponse>>(
    `/auth/refresh/user?refresh_token=${encodeURIComponent(refreshToken)}`,
  );
  return envelope.data;
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
  const envelope = await requestJson<DataEnvelope<TokenResponse>>(
    `/auth/oidc/callback?${params.toString()}`,
  );
  return envelope.data;
}
