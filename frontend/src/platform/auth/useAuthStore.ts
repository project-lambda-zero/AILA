import { create } from "zustand";
import { createJSONStorage, persist, type StateStorage } from "zustand/middleware";

import {
  decodeUserTokenClaims,
  loginWithPassword,
  refreshUserToken,
  type TokenResponse,
} from "@platform/api/auth";
import type { AppRole } from "@platform/auth/roles";

// ---------------------------------------------------------------------------
// #47 -- hardened auth storage.
//
// Prior versions persisted BOTH the access token and the refresh token to
// `localStorage`. That surface is readable by any script executing in the
// origin, so a single XSS foothold (or a rogue browser extension) exfiltrates
// long-lived credentials that outlive the tab. The rewrite splits the two
// tokens by lifetime and blast radius:
//
//   * Access token  -- kept in memory only. It never touches Web Storage, so
//                      a page reload always forces the refresh path below.
//                      The token dies with the JS heap; there is no on-disk
//                      copy for an attacker to lift after the fact.
//   * Refresh token -- persisted to `sessionStorage` with a short TTL so it
//                      dies when the browser tab closes and additionally
//                      self-expires after `REFRESH_TTL_MS`. `sessionStorage`
//                      is still same-origin readable, but its lifetime is
//                      bounded by the tab, which cuts the exposure window
//                      dramatically compared to `localStorage`.
//   * Lightweight UI hints (role/userId/username) travel with the refresh
//     token so the shell can render the correct chrome during the
//     bootstrapping refresh; they are not credentials by themselves.
//
// The end-state we would prefer is that neither token ever reaches JS: the
// backend would issue the refresh token as a `HttpOnly; Secure;
// SameSite=Strict` cookie scoped to `/auth/refresh/user`, and the access
// token would either follow the same pattern or be short-lived enough that
// in-memory storage suffices. That migration requires backend changes
// (`Set-Cookie` on the login/refresh endpoints, CSRF double-submit
// validation on every mutating route, CORS `credentials: "include"` on the
// fetch layer). Until that lands, sessionStorage plus TTL plus double-submit
// CSRF is the tightest posture the frontend can enforce unilaterally.
// ---------------------------------------------------------------------------

const AUTH_STORAGE_KEY = "aila-auth";

/** Hard ceiling on how long a refresh token may live in sessionStorage even
 * if the tab is left open. 12h matches the backend refresh-token lifetime
 * default; anything older is treated as expired and cleared eagerly. */
const REFRESH_TTL_MS = 12 * 60 * 60 * 1000;

// Purge tokens leaked to `localStorage` by prior releases so an upgrade
// closes the exposure immediately -- users do not need to log out first.
if (typeof window !== "undefined") {
  try {
    window.localStorage.removeItem(AUTH_STORAGE_KEY);
  } catch {
    // Storage disabled -- nothing to purge.
  }
}

/** sessionStorage adapter with a TTL envelope. Zustand's `createJSONStorage`
 * treats the returned object as a `Storage`, calling `getItem`/`setItem`
 * with raw string payloads. We wrap the payload in `{savedAt, payload}` so a
 * stale envelope is dropped on the next read. */
const ttlSessionStorage: StateStorage = {
  getItem: (name: string): string | null => {
    if (typeof sessionStorage === "undefined") return null;
    const raw = sessionStorage.getItem(name);
    if (!raw) return null;
    try {
      const parsed = JSON.parse(raw) as { savedAt?: number; payload?: string };
      const savedAt = typeof parsed.savedAt === "number" ? parsed.savedAt : 0;
      if (savedAt + REFRESH_TTL_MS < Date.now()) {
        sessionStorage.removeItem(name);
        return null;
      }
      return typeof parsed.payload === "string" ? parsed.payload : null;
    } catch {
      sessionStorage.removeItem(name);
      return null;
    }
  },
  setItem: (name: string, value: string): void => {
    if (typeof sessionStorage === "undefined") return;
    const envelope = JSON.stringify({ savedAt: Date.now(), payload: value });
    sessionStorage.setItem(name, envelope);
  },
  removeItem: (name: string): void => {
    if (typeof sessionStorage === "undefined") return;
    sessionStorage.removeItem(name);
  },
};

interface AuthState {
  accessToken: string | null;
  refreshToken: string | null;
  role: AppRole | null;
  userId: string | null;
  username: string | null;
  isAuthenticated: boolean;
  status: "bootstrapping" | "authenticated" | "unauthenticated";
  // Actions
  login: (username: string, password: string) => Promise<void>;
  loginWithTokens: (tokens: TokenResponse, usernameHint?: string) => void;
  logout: () => void;
  refreshTokens: () => Promise<void>;
  getAccessToken: () => Promise<string>;
}

// Module-level proactive refresh timer -- lives outside React lifecycle.
// `window.setTimeout` returns a plain `number` handle in every browser, which
// dodges the runtime-dependent `NodeJS.Timeout | number` typing seen with the
// bare global.
let refreshTimer: number | null = null;
// Mutex to prevent concurrent refresh calls (race between proactive timer + 401 interceptor)
let refreshInFlight: Promise<void> | null = null;

function scheduleProactiveRefresh(expiresIn: number): void {
  if (refreshTimer !== null) {
    window.clearTimeout(refreshTimer);
    refreshTimer = null;
  }
  // Fire 60 seconds before expiry, minimum 10s (avoid instant fire on short-lived tokens)
  const refreshIn = Math.max((expiresIn - 60) * 1000, 10_000);
  refreshTimer = window.setTimeout(() => {
    void useAuthStore.getState().refreshTokens();
  }, refreshIn);
}

function clearProactiveRefresh(): void {
  if (refreshTimer !== null) {
    window.clearTimeout(refreshTimer);
    refreshTimer = null;
  }
}

export const useAuthStore = create<AuthState>()(
  persist(
    (set, get) => ({
      accessToken: null,
      refreshToken: null,
      role: null,
      userId: null,
      username: null,
      isAuthenticated: false,
      status: "bootstrapping",

      login: async (username: string, password: string): Promise<void> => {
        const tokens = await loginWithPassword(username, password);
        const claims = decodeUserTokenClaims(tokens.access_token);
        set({
          accessToken: tokens.access_token,
          refreshToken: tokens.refresh_token,
          role: claims.role,
          userId: claims.userId,
          username,
          isAuthenticated: true,
          status: "authenticated",
        });
        scheduleProactiveRefresh(tokens.expires_in);
      },

      loginWithTokens: (tokens: TokenResponse, usernameHint?: string): void => {
        const claims = decodeUserTokenClaims(tokens.access_token);
        set({
          accessToken: tokens.access_token,
          refreshToken: tokens.refresh_token,
          role: claims.role,
          userId: claims.userId,
          username: usernameHint ?? null,
          isAuthenticated: true,
          status: "authenticated",
        });
        scheduleProactiveRefresh(tokens.expires_in);
      },

      logout: (): void => {
        clearProactiveRefresh();
        set({
          accessToken: null,
          refreshToken: null,
          role: null,
          userId: null,
          username: null,
          isAuthenticated: false,
          status: "unauthenticated",
        });
      },

      refreshTokens: async (): Promise<void> => {
        // Mutex: if a refresh is already in flight, wait for it instead of firing a second one.
        // This prevents the race where proactive timer + 401 interceptor both call refresh
        // simultaneously, the second uses an invalidated refresh token, and triggers logout.
        if (refreshInFlight) {
          await refreshInFlight;
          return;
        }

        const currentRefreshToken = get().refreshToken;
        if (!currentRefreshToken) {
          get().logout();
          return;
        }

        const doRefresh = async (): Promise<void> => {
          const tokens = await refreshUserToken(currentRefreshToken);
          const claims = decodeUserTokenClaims(tokens.access_token);
          set({
            accessToken: tokens.access_token,
            refreshToken: tokens.refresh_token,
            role: claims.role,
            userId: claims.userId,
            isAuthenticated: true,
            status: "authenticated",
          });
          scheduleProactiveRefresh(tokens.expires_in);
        };

        refreshInFlight = doRefresh()
          .catch(() => {
            // Never auto-logout mid-session. If the refresh endpoint fails
            // for any reason (expired, revoked, server restart, network
            // blip), keep the stored tokens and retry on the next cycle.
            // The user stays "authenticated" from the UI's perspective;
            // any protected request will surface a 401 which the HTTP
            // layer can handle on demand. Rehydrate-time failures are
            // handled separately in `onRehydrateStorage`.
            if (get().isAuthenticated) {
              scheduleProactiveRefresh(90);
            }
          })
          .finally(() => {
            refreshInFlight = null;
          });

        await refreshInFlight;
      },

      getAccessToken: async (): Promise<string> => {
        const { accessToken } = get();
        if (accessToken) {
          // Return directly when the in-memory access token still has more
          // than 60 seconds of life. Malformed tokens fall through to the
          // refresh path.
          try {
            const { exp } = decodeUserTokenClaims(accessToken);
            const nowSeconds = Math.floor(Date.now() / 1000);
            if (exp - nowSeconds > 60) {
              return accessToken;
            }
          } catch {
            // fall through to refresh
          }
        }
        // No in-memory token, near-expiry, or malformed -- refresh from the
        // sessionStorage refresh token. After a full page reload the
        // accessToken is null by design (memory only), so this is the
        // common path on the first authorized call after navigation.
        await get().refreshTokens();
        const newToken = get().accessToken;
        if (!newToken) {
          throw new Error("Session expired. Sign in again.");
        }
        return newToken;
      },
    }),
    {
      name: AUTH_STORAGE_KEY,
      storage: createJSONStorage(() => ttlSessionStorage),
      // Persist ONLY the refresh token and non-credential UI hints. The
      // access token is intentionally excluded -- it lives in memory only.
      partialize: (state) => ({
        refreshToken: state.refreshToken,
        role: state.role,
        userId: state.userId,
        username: state.username,
      }),
      version: 2,
      // Rehydrate: sessionStorage may have a valid refresh token but the
      // in-memory access token is always null after a reload. Kick off a
      // background refresh so protected routes can transition from
      // `bootstrapping` to `authenticated` without a manual login. On
      // refresh failure the session is cleared so the user lands on the
      // login screen instead of hanging in bootstrapping.
      onRehydrateStorage: () => (state) => {
        if (!state) {
          // No persisted state (fresh session, cleared storage, or TTL
          // expired). Transition out of `bootstrapping` so ProtectedRoute
          // redirects to /login instead of showing a spinner forever.
          useAuthStore.setState({ status: "unauthenticated" });
          return;
        }
        // The access token never persists; make the invariant explicit.
        state.accessToken = null;
        const { refreshToken } = state;
        if (!refreshToken) {
          state.status = "unauthenticated";
          state.isAuthenticated = false;
          return;
        }
        // Optimistically mark the caller as authenticated so the shell can
        // render the correct chrome (username, role-gated nav) while the
        // background refresh runs. If the refresh fails we hard-clear.
        state.status = "bootstrapping";
        state.isAuthenticated = true;
        void (async () => {
          try {
            await useAuthStore.getState().refreshTokens();
            const current = useAuthStore.getState();
            if (current.accessToken) {
              useAuthStore.setState({
                status: "authenticated",
                isAuthenticated: true,
              });
            } else {
              // Refresh swallowed the error; treat missing access token as
              // a hard failure at rehydrate time and clear the session.
              useAuthStore.getState().logout();
            }
          } catch {
            useAuthStore.getState().logout();
          }
        })();
      },
    },
  ),
);

// Standalone getter for use in http.ts interceptor (outside React components)
export const getAuthTokenStandalone = (): Promise<string> =>
  useAuthStore.getState().getAccessToken();
