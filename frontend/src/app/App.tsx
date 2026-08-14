import { useEffect } from "react";
import { RouterProvider } from "react-router";

import { AppProviders } from "@app/providers";
import { appRouter } from "@app/router";
import { useAuthStore } from "@platform/auth/useAuthStore";

export function App() {
  // Watchdog: guarantee the auth store leaves the initial `bootstrapping`
  // status so the console never hangs on the "Restoring session" screen
  // when there is no stored session or the refresh call stalls. Runs once
  // on mount; a no-op once a terminal status is reached.
  useEffect(() => {
    void useAuthStore.getState().bootstrap();
  }, []);

  return (
    <AppProviders>
      <RouterProvider router={appRouter} />
    </AppProviders>
  );
}
