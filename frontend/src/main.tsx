import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

import App from "./App";
import { restoreSession } from "./api/auth";
import { loadTheme } from "./theme";
import "./styles/globals.css";

// Apply the persisted theme before first paint so the console loads styled.
loadTheme();

// The access token is held in memory only; the refresh cookie restores it.
void restoreSession();

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
