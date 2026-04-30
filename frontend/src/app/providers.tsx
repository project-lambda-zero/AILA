import {
  MutationCache,
  QueryCache,
  QueryClient,
  QueryClientProvider,
} from "@tanstack/react-query";
import type { ReactNode } from "react";

import { ThemeProvider } from "@/providers/ThemeProvider";
import { SSEProvider } from "@/providers/SSEProvider";
import { Toaster } from "@/components/ui/sonner";
import { apiErrorHandler } from "@/lib/apiErrorHandler";

/**
 * QueryClient factory.
 *
 * TanStack Query v5 (preflight FE-A) removed `defaultOptions.queries.onError`
 * in favour of cache-level handlers passed at construction time. This is the
 * only supported way to wire a global onError in v5 — queryCache.config
 * is read-only post-construction.
 */
export function makeQueryClient(): QueryClient {
  return new QueryClient({
    queryCache: new QueryCache({ onError: apiErrorHandler }),
    mutationCache: new MutationCache({ onError: apiErrorHandler }),
    defaultOptions: {
      queries: {
        refetchOnWindowFocus: false,
        retry: 1,
      },
    },
  });
}

const queryClient = makeQueryClient();

interface AppProvidersProps {
  children: ReactNode;
}

export function AppProviders({ children }: AppProvidersProps) {
  return (
    <ThemeProvider>
      <QueryClientProvider client={queryClient}>
        <SSEProvider>
          {children}
        </SSEProvider>
        <Toaster />
      </QueryClientProvider>
    </ThemeProvider>
  );
}
