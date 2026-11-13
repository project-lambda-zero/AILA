import { create } from "zustand";

import { configureApi, renewAccessToken, sessionRequest } from "./client";
import { apiErrDetail } from "./parse";
import type { LoginResponse, User } from "./types";

/** Decode the JWT payload for profile fields. External input -> narrow, no casts. */
function decodeToken(token: string): User {
  const part = token.split(".")[1];
  if (!part) return {};
  let json: unknown;
  try {
    json = JSON.parse(atob(part.replace(/-/g, "+").replace(/_/g, "/")));
  } catch {
    return {};
  }
  if (!json || typeof json !== "object") return {};
  const out: User = {};
  if ("sub" in json && typeof json.sub === "string") out.id = json.sub;
  if ("user_id" in json && typeof json.user_id === "string") out.id = json.user_id;
  if ("username" in json && typeof json.username === "string") out.username = json.username;
  if ("role" in json && typeof json.role === "string") out.role = json.role;
  if ("team_id" in json && typeof json.team_id === "string") out.team_id = json.team_id;
  return out;
}

interface AuthState {
  /** Access token, in memory only; a reload restores it through the refresh cookie. */
  token: string | null;
  user: User | null;
  /** "restoring" until the startup refresh settles. */
  status: "restoring" | "anon" | "authed";
  error: string | null;
  busy: boolean;
  login: (username: string, password: string) => Promise<void>;
  logout: () => void;
}

const SIGNED_OUT: Pick<AuthState, "token" | "user" | "status" | "error"> = { token: null, user: null, status: "anon", error: null };

export const useAuth = create<AuthState>((set) => ({
  token: null,
  user: null,
  status: "restoring",
  error: null,
  busy: false,
  login: async (username, password) => {
    set({ busy: true, error: null });
    try {
      const res = await sessionRequest<LoginResponse>("/auth/login", { username, password });
      set({
        token: res.access_token,
        user: res.user ?? { username, ...decodeToken(res.access_token) },
        status: "authed",
        busy: false,
      });
    } catch (e) {
      set({ error: apiErrDetail(e) || "Sign-in failed.", busy: false });
    }
  },
  logout: () => {
    set(SIGNED_OUT);
    // Revoke the refresh token and clear its cookie server-side. The local
    // session is already gone, so a failed call changes nothing here.
    sessionRequest("/auth/logout").catch(() => {});
  },
}));

/** Exchange the refresh cookie for a new access token. Any failure signs the
 * user out locally and resolves null. */
async function renewSession(): Promise<string | null> {
  try {
    const res = await sessionRequest<LoginResponse>("/auth/refresh/user");
    // Token claims (id, role, team) come from the new token; the username the
    // login response supplied is kept, since the token does not carry it.
    const user: User = { ...useAuth.getState().user, ...decodeToken(res.access_token) };

    useAuth.setState({ token: res.access_token, user, status: "authed", error: null });

    return res.access_token;
  } catch {
    useAuth.setState(SIGNED_OUT);

    return null;
  }
}

configureApi({
  getToken: () => useAuth.getState().token,
  renewSession,
});

/** Restore the session after a page load from the refresh cookie. */
export function restoreSession(): Promise<string | null> {
  return renewAccessToken();
}
