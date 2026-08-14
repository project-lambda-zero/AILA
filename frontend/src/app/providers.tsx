import {
  MutationCache,
  QueryCache,
  QueryClient,
  QueryClientProvider,
} from "@tanstack/react-query";
import type { ReactNode } from "react";

import { ThemeProvider } from "@/providers/ThemeProvider";
import { SSEProvider } from "@/providers/SSEProvider";
import { ActivityFeedProvider } from "@/providers/ActivityFeedProvider";
import { Toaster } from "@/components/ui/sonner";
import { apiErrorHandler } from "@/lib/apiErrorHandler";

/**
 * QueryClient factory.
 *
 * TanStack Query v5 (preflight FE-A) removed `defaultOptions.queries.onError`
 * in favour of cache-level handlers passed at construction time. This is the
 * only supported way to wire a global onError in v5 -- queryCache.config
 * is read-only post-construction.
 */
// #47: bound the react-query cache so sensitive data (findings, session
// info, scan results) does NOT sit in memory forever after the last
// component that read it unmounted. TanStack Query v5's default gcTime
// is 5 minutes but must be set explicitly here because a caller that
// overrides `defaultOptions.queries` (some module screens do) would
// otherwise fall back to `Infinity` on any option they leave unset.
// staleTime is set moderately so hooks that don't override it still
// re-fetch on remount instead of serving from a possibly-stale cache.
const DEFAULT_GC_TIME_MS = 5 * 60 * 1000;   // 5 minutes
const DEFAULT_STALE_TIME_MS = 30 * 1000;    // 30 seconds

export function makeQueryClient(): QueryClient {
  return new QueryClient({
    queryCache: new QueryCache({ onError: apiErrorHandler }),
    mutationCache: new MutationCache({ onError: apiErrorHandler }),
    defaultOptions: {
      queries: {
        refetchOnWindowFocus: false,
        retry: 1,
        gcTime: DEFAULT_GC_TIME_MS,
        staleTime: DEFAULT_STALE_TIME_MS,
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
          <ActivityFeedProvider>
            {children}
          </ActivityFeedProvider>
        </SSEProvider>
        <Toaster />
      </QueryClientProvider>
    </ThemeProvider>
  );
}
