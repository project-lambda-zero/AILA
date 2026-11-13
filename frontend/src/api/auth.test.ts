import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { restoreSession, useAuth } from "./auth";
import { ApiError, apiFetch } from "./client";

interface Sent {
  path: string;
  authorization: string | null;
  csrf: string | null;
  credentials: RequestCredentials | undefined;
}

const jwt = (claims: Record<string, string>): string => `h.${btoa(JSON.stringify(claims))}.s`;

const OLD = jwt({ user_id: "u1", role: "operator" });
const NEW = jwt({ user_id: "u1", role: "operator", n: "2" });

const json = (status: number, body: unknown): Response =>
  new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });

// The API at the network boundary: a protected route that accepts only the
// current access token, and the session routes keyed on the refresh cookie.
function api(opts: { refreshOk: boolean; refreshGate?: Promise<void> }) {
  const sent: Sent[] = [];
  const fetchMock = vi.fn(async (input: string | URL, init?: RequestInit) => {
    const headers = new Headers(init?.headers);
    const path = new URL(String(input)).pathname;

    sent.push({ path, authorization: headers.get("Authorization"), csrf: headers.get("X-CSRF-Token"), credentials: init?.credentials });

    if (path === "/auth/refresh/user") {
      await opts.refreshGate;

      return opts.refreshOk
        ? json(200, { data: { access_token: NEW, token_type: "bearer", expires_in: 3600 } })
        : json(401, { detail: "Invalid or expired refresh token" });
    }

    if (path === "/auth/login") return json(200, { data: { access_token: NEW, token_type: "bearer", expires_in: 3600 } });

    if (path === "/auth/logout") return json(200, { data: { revoked: true } });

    return headers.get("Authorization") === `Bearer ${NEW}` ? json(200, { data: { ok: true } }) : json(401, { detail: "expired" });
  });

  vi.stubGlobal("fetch", fetchMock);

  return { sent, refreshes: () => sent.filter((s) => s.path === "/auth/refresh/user") };
}

describe("access token renewal", () => {
  beforeEach(() => {
    document.cookie = "aila_csrf=csrf-1; path=/";
    localStorage.clear();
    useAuth.setState({ token: OLD, user: { id: "u1", username: "ana", role: "operator" }, status: "authed", error: null, busy: false });
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("renews once on 401 and retries the request with the new token", async () => {
    const { sent, refreshes } = api({ refreshOk: true });

    await expect(apiFetch<{ ok: boolean }>("/systems")).resolves.toEqual({ ok: true });

    expect(refreshes()).toHaveLength(1);
    expect(refreshes()[0]).toMatchObject({ credentials: "include", csrf: "csrf-1", authorization: null });
    expect(sent.filter((s) => s.path === "/systems").map((s) => s.authorization)).toEqual([`Bearer ${OLD}`, `Bearer ${NEW}`]);
    expect(useAuth.getState()).toMatchObject({ token: NEW, status: "authed", user: { username: "ana" } });
  });

  it("shares one refresh across concurrent 401s", async () => {
    let open = (): void => {};
    const refreshGate = new Promise<void>((resolve) => {
      open = resolve;
    });
    const { sent, refreshes } = api({ refreshOk: true, refreshGate });

    const calls = Promise.all([apiFetch("/a"), apiFetch("/b"), apiFetch("/c")]);

    await vi.waitFor(() => expect(sent.filter((s) => s.authorization === `Bearer ${OLD}`)).toHaveLength(3));
    open();
    await calls;

    expect(refreshes()).toHaveLength(1);
    expect(sent.filter((s) => s.authorization === `Bearer ${NEW}`).map((s) => s.path).sort()).toEqual(["/a", "/b", "/c"]);
  });

  it("signs the user out when the refresh fails", async () => {
    const { refreshes } = api({ refreshOk: false });

    const err = await apiFetch("/systems").catch((e: unknown) => e);

    expect(err).toBeInstanceOf(ApiError);
    expect(err).toMatchObject({ status: 401 });
    expect(refreshes()).toHaveLength(1);
    expect(useAuth.getState()).toMatchObject({ token: null, user: null, status: "anon" });
  });
});

describe("session persistence", () => {
  beforeEach(() => {
    document.cookie = "aila_csrf=csrf-2; path=/";
    localStorage.clear();
    useAuth.setState({ token: null, user: null, status: "anon", error: null, busy: false });
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("keeps the access token out of localStorage and sends the login with cookies", async () => {
    const { sent } = api({ refreshOk: true });

    await useAuth.getState().login("ana", "pw");

    expect(useAuth.getState()).toMatchObject({ token: NEW, status: "authed" });
    expect(sent.find((s) => s.path === "/auth/login")?.credentials).toBe("include");
    const stored = Array.from({ length: localStorage.length }, (_, i) => localStorage.getItem(localStorage.key(i) ?? "") ?? "");

    expect(stored).not.toContain(NEW);
  });

  it("restores the session on load through the refresh cookie", async () => {
    useAuth.setState({ status: "restoring" });
    const { refreshes } = api({ refreshOk: true });

    await restoreSession();

    expect(refreshes()).toHaveLength(1);
    expect(useAuth.getState()).toMatchObject({ token: NEW, status: "authed", user: { id: "u1", role: "operator" } });
  });
});
