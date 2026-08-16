import { create } from "zustand";

import { apiFetch, configureApi } from "./client";
import type { LoginResponse, User } from "./types";

const TOKEN_KEY = "aila.token";

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
  return out;
}

interface AuthState {
  token: string | null;
  user: User | null;
  status: "anon" | "authed";
  error: string | null;
  busy: boolean;
  login: (username: string, password: string) => Promise<void>;
  logout: () => void;
}

const initialToken = localStorage.getItem(TOKEN_KEY);

export const useAuth = create<AuthState>((set) => ({
  token: initialToken,
  user: initialToken ? decodeToken(initialToken) : null,
  status: initialToken ? "authed" : "anon",
  error: null,
  busy: false,
  login: async (username, password) => {
    set({ busy: true, error: null });
    try {
      const res = await apiFetch<LoginResponse>("/auth/login", {
        method: "POST",
        body: JSON.stringify({ username, password }),
      });
      localStorage.setItem(TOKEN_KEY, res.access_token);
      set({
        token: res.access_token,
        user: res.user ?? { username, ...decodeToken(res.access_token) },
        status: "authed",
        busy: false,
      });
    } catch (e) {
      set({ error: e instanceof Error ? e.message : "Sign-in failed.", busy: false });
    }
  },
  logout: () => {
    localStorage.removeItem(TOKEN_KEY);
    set({ token: null, user: null, status: "anon", error: null });
  },
}));

configureApi({
  getToken: () => useAuth.getState().token,
  onUnauthorized: () => useAuth.getState().logout(),
});
