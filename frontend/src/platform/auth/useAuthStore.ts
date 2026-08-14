import { create } from "zustand";
import { createJSONStorage, persist } from "zustand/middleware";

import {
  decodeUserTokenClaims,
  loginWithPassword,
  logoutUser,
  refreshUserToken,
  type TokenResponse,
} from "@platform/api/auth";
import type { AppRole } from "@platform/auth/roles";

// ---------------------------------------------------------------------------
// #119 -- HttpOnly cookie auth storage.
//
// Prior versions kept the refresh token in `sessionStorage` under a TTL
// envelope. That surface is readable by any script executing in the origin,
// so a single XSS foothold (or a rogue browser extension) exfiltrated a
// long-lived credential that outlived the tab. The backend now issues the
// refresh token as an `HttpOnly; Secure; SameSite=Lax` cookie
// (`aila_refresh`); JS cannot read it, and the browser attaches it
// automatically to `/auth/refresh/user` and `/auth/logout`.
//
// The client contract is therefore:
//
//   * Access token  -- kept in memory only. Never written to Web Storage.
//                      Dies with the JS heap; a page reload always goes
//                      through the refresh path below.
//   * Refresh token -- lives ONLY in the HttpOnly cookie. This store no
//                      longer touches it in any form. The reload-time
//                      refresh call succeeds when the cookie is still
//                      valid, and fails cleanly to the login screen when
//                      it is not.
//   * UI hints (role/userId/username) -- persisted so the shell can render
//                      chrome without waiting for the refresh to complete.
//                      Not credentials.
//   * CSRF token    -- lives in the readable `aila_csrf` cookie and is
//                      mirrored into the `X-CSRF-Token` header by
//                      `platform/api/http.ts` on every mutating request.
//                      The backend enforces the double-submit match; see
//                      `aila.api.middleware.csrf.CSRFMiddleware`.
//
// `sessionStorage` under the auth key is purged on load so an upgrade from
// the old shape drops the residual refresh token immediately.
// ---------------------------------------------------------------------------

const AUTH_STORAGE_KEY = "aila-auth";

// Purge any refresh token leaked to Web Storage by prior releases so the
// upgrade closes the exposure without waiting for a logout.
if (typeof window !== "undefined") {
  try {
    window.localStorage.removeItem(AUTH_STORAGE_KEY);
  } catch {
    // Storage disabled -- nothing to purge.
  }
  try {
    window.sessionStorage.removeItem(AUTH_STORAGE_KEY);
  } catch {
    // Storage disabled -- nothing to purge.
  }
}

interface AuthState {
  accessToken: string | null;
  role: AppRole | null;
  userId: string | null;
  username: string | null;
  isAuthenticated: boolean;
  status: "bootstrapping" | "authenticated" | "unauthenticated";
  // Actions
  login: (username: string, password: string) => Promise<void>;
  loginWithTokens: (tokens: TokenResponse, usernameHint?: string) => void;
  logout: () => Promise<void>;
  refreshTokens: () => Promise<void>;
  getAccessToken: () => Promise<string>;
  bootstrap: () => Promise<void>;
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
          role: claims.role,
          userId: claims.userId,
          username: usernameHint ?? null,
          isAuthenticated: true,
          status: "authenticated",
        });
        scheduleProactiveRefresh(tokens.expires_in);
      },

      logout: async (): Promise<void> => {
        clearProactiveRefresh();
        // Best-effort: revoke the DB row and clear the cookies server-side.
        // A failure here (e.g. network offline) still tears down the local
        // session -- the cookies will expire on their own.
        try {
          await logoutUser();
        } catch {
          // Swallow -- local teardown below is the important half.
        }
        set({
          accessToken: null,
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

        const doRefresh = async (): Promise<void> => {
          // #119: the refresh token comes from the HttpOnly cookie the
          // browser attaches automatically. No argument to pass.
          const tokens = await refreshUserToken();
          const claims = decodeUserTokenClaims(tokens.access_token);
          set({
            accessToken: tokens.access_token,
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
            // blip), keep the current in-memory access token and retry on
            // the next cycle. The user stays "authenticated" from the UI's
            // perspective; any protected request will surface a 401 which
            // the HTTP layer can handle on demand. Rehydrate-time failures
            // are handled separately in `onRehydrateStorage`.
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
        // No in-memory token, near-expiry, or malformed -- refresh via the
        // HttpOnly cookie. After a full page reload the accessToken is null
        // by design (memory only), so this is the common path on the first
        // authorized call after navigation.
        await get().refreshTokens();
        const newToken = get().accessToken;
        if (!newToken) {
          throw new Error("Session expired. Sign in again.");
        }
        return newToken;
      },

      bootstrap: async (): Promise<void> => {
        // Guarantee the console never wedges on the "Restoring session"
        // screen. `onRehydrateStorage` is the only other path out of the
        // initial `bootstrapping` status, and it does not reliably run its
        // refresh transition (sessionStorage is purged on load, and a
        // slow/unreachable backend can stall the cookie refresh). This
        // mount-time watchdog bounds the refresh and always resolves to a
        // terminal status, so the login screen is reachable even when the
        // refresh hangs. Idempotent: a no-op once a terminal status is set.
        if (get().status !== "bootstrapping") {
          return;
        }
        const watchdog = new Promise<void>((resolve) => {
          window.setTimeout(resolve, 6000);
        });
        try {
          await Promise.race([get().refreshTokens(), watchdog]);
        } catch {
          // refreshTokens swallows its own errors; ignore here too.
        }
        // A concurrent path (login, or the rehydrate refresh) may have
        // resolved the status already -- do not override it.
        if (get().status !== "bootstrapping") {
          return;
        }
        if (get().accessToken) {
          set({ status: "authenticated", isAuthenticated: true });
          return;
        }
        // No token within the bound: fall through to the login screen.
        // Clear locally WITHOUT a network logout (which could also hang).
        clearProactiveRefresh();
        set({
          accessToken: null,
          role: null,
          userId: null,
          username: null,
          isAuthenticated: false,
          status: "unauthenticated",
        });
      },
    }),
    {
      name: AUTH_STORAGE_KEY,
      // Persist UI hints in sessionStorage so tab close clears them.
      // No credentials of any kind are persisted -- the refresh token
      // lives only in the HttpOnly cookie.
      storage: createJSONStorage(() => sessionStorage),
      partialize: (state) => ({
        role: state.role,
        userId: state.userId,
        username: state.username,
      }),
      version: 3,
      // Rehydrate: sessionStorage carries only non-credential UI hints.
      // Kick off a background refresh so the shell can transition from
      // `bootstrapping` to `authenticated` when the cookie is still
      // valid, or fall back to `unauthenticated` when it is not.
      onRehydrateStorage: () => (state) => {
        if (!state) {
          useAuthStore.setState({ status: "unauthenticated" });
          return;
        }
        // The access token never persists; make the invariant explicit.
        state.accessToken = null;
        // Optimistically mark the caller as authenticated so the shell can
        // render the correct chrome (username, role-gated nav) while the
        // background refresh runs. If the refresh fails we hard-clear.
        state.status = "bootstrapping";
        state.isAuthenticated = Boolean(state.userId);
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
              await useAuthStore.getState().logout();
            }
          } catch {
            await useAuthStore.getState().logout();
          }
        })();
      },
    },
  ),
);

// Standalone getter for use in http.ts interceptor (outside React components)
export const getAuthTokenStandalone = (): Promise<string> =>
  useAuthStore.getState().getAccessToken();
