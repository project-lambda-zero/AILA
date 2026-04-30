import { create } from "zustand";
import { persist, createJSONStorage } from "zustand/middleware";

import {
  decodeUserTokenClaims,
  loginWithPassword,
  refreshUserToken,
  type TokenResponse,
} from "@platform/api/auth";
import type { AppRole } from "@platform/auth/roles";

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

// Module-level proactive refresh timer — lives outside React lifecycle
let refreshTimer: ReturnType<typeof setTimeout> | null = null;
// Mutex to prevent concurrent refresh calls (race between proactive timer + 401 interceptor)
let refreshInFlight: Promise<void> | null = null;

function scheduleProactiveRefresh(expiresIn: number): void {
  if (refreshTimer) {
    clearTimeout(refreshTimer);
    refreshTimer = null;
  }
  // Fire 60 seconds before expiry, minimum 10s (avoid instant fire on short-lived tokens)
  const refreshIn = Math.max((expiresIn - 60) * 1000, 10_000);
  refreshTimer = setTimeout(() => {
    void useAuthStore.getState().refreshTokens();
  }, refreshIn);
}

function clearProactiveRefresh(): void {
  if (refreshTimer) {
    clearTimeout(refreshTimer);
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
            // Never auto-logout. If the refresh endpoint fails for any
            // reason (expired, revoked, server restart, network blip),
            // keep the stored tokens and retry on the next cycle. The
            // user stays "authenticated" from the UI's perspective; any
            // protected request will surface a 401 which the HTTP layer
            // can handle on demand.
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
        if (!accessToken) {
          throw new Error("Not authenticated.");
        }
        // Check expiry: return directly if more than 60s remain
        try {
          const { exp } = decodeUserTokenClaims(accessToken);
          const nowSeconds = Math.floor(Date.now() / 1000);
          if (exp - nowSeconds > 60) {
            return accessToken;
          }
        } catch {
          // Malformed token — fall through to refresh
        }
        // Token near expiry or malformed — refresh first
        await get().refreshTokens();
        const newToken = get().accessToken;
        if (!newToken) {
          throw new Error("Session expired. Sign in again.");
        }
        return newToken;
      },
    }),
    {
      name: "aila-auth",
      storage: createJSONStorage(() => localStorage),
      // Only persist serializable token data — no function refs (D-12)
      partialize: (state) => ({
        accessToken: state.accessToken,
        refreshToken: state.refreshToken,
        role: state.role,
        userId: state.userId,
        username: state.username,
        isAuthenticated: state.isAuthenticated,
      }),
      version: 1,
      // After hydration: validate restored token, set correct status (Pitfall 3)
      onRehydrateStorage: () => (state) => {
        if (!state) {
          return;
        }
        const { accessToken, refreshToken } = state;
        if (!accessToken) {
          state.status = "unauthenticated";
          return;
        }
        try {
          const { exp } = decodeUserTokenClaims(accessToken);
          const nowSeconds = Math.floor(Date.now() / 1000);
          if (exp > nowSeconds) {
            // Valid token — mark authenticated and schedule proactive refresh
            state.status = "authenticated";
            const expiresIn = exp - nowSeconds;
            scheduleProactiveRefresh(expiresIn);
          } else if (refreshToken) {
            // Access token expired — keep the session and refresh in the
            // background. Do NOT clear tokens: the refresh token is long-
            // lived and refresh may succeed silently.
            state.status = "authenticated";
            state.isAuthenticated = true;
            void useAuthStore.getState().refreshTokens();
          } else {
            state.status = "unauthenticated";
          }
        } catch {
          // Malformed token — go to login, don't hang
          state.status = "unauthenticated";
        }
      },
    },
  ),
);

// Standalone getter for use in http.ts interceptor (outside React components)
export const getAuthTokenStandalone = (): Promise<string> =>
  useAuthStore.getState().getAccessToken();
