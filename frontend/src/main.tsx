import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

import App from "./App";
import { OIDC_CALLBACK_PATH, completeOidcSignIn, restoreSession } from "./api/auth";
import { loadTheme } from "./theme";
import "./styles/globals.css";

// Apply the persisted theme before first paint so the console loads styled.
loadTheme();

// The access token is held in memory only. The identity provider's return page
// completes OIDC sign-in; every other load restores the session from the refresh cookie.
if (window.location.pathname === OIDC_CALLBACK_PATH) {
  void completeOidcSignIn(window.location.search);
} else {
  void restoreSession();
}

const queryClient = new QueryClient({
  defaultOptions: {
    queries: { retry: 1, refetchOnWindowFocus: false, staleTime: 5000 },
  },
});

const root = document.getElementById("root");
if (root) {
  createRoot(root).render(
    <StrictMode>
      <QueryClientProvider client={queryClient}>
        <App />
      </QueryClientProvider>
    </StrictMode>,
  );
}
