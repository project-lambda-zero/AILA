import { useQueryClient } from "@tanstack/react-query";
import { type ReactNode } from "react";

import { AppErrorBoundary } from "@app/ErrorBoundary";
import { AilaCard } from "@/components/aila/AilaCard";

/**
 * PanelBoundary -- scoped error boundary for a single heavy async panel
 * inside a VR detail page.
 *
 * Design intent:
 * -- The router already wraps every VR route in AppErrorBoundary (D-23)
 *    via withFeatureBoundary. That boundary catches render errors so they
 *    don't unmount the shell, but it also blanks the whole page.
 * -- On a detail page we host multiple heavy panels (EvidenceGraph,
 *    ReactFlow branch tree, LiveRunPanel). A render error thrown inside
 *    ONE panel should not blank sibling panels. Wrapping each panel in
 *    its own AppErrorBoundary contains the blast radius to that panel.
 * -- The fallback renders a compact "Failed to load" surface with a
 *    Retry button. Retry does two things:
 *      1. Resets the boundary state so children re-mount cleanly.
 *      2. Optionally invalidates a query-key prefix so the panel's
 *         fetches re-run (this covers the common case where the render
 *         error was caused by a bad server response).
 *
 * Note on query-error propagation: TanStack Query returns errors via
 * `isError` on the hook by default -- they do NOT bubble to error
 * boundaries unless the query opts into `throwOnError: true`. This
 * component therefore catches:
 *   -- Synchronous render errors inside the panel subtree.
 *   -- Async errors that surface via Suspense or `throwOnError` queries.
 * `isError` handling remains local to each panel.
 */
export function PanelBoundary({
  label,
  invalidateKeyPrefix,
  children,
}: {
  /** Short human name for the panel, used in the fallback ("Evidence graph"). */
  label: string;
  /**
   * Optional TanStack Query key prefix to invalidate on Retry. Pass the
   * shared prefix (e.g. `["vr", "evidence-graph", investigationId]`) so
   * the panel refetches on retry.
   */
  invalidateKeyPrefix?: readonly unknown[];
  children: ReactNode;
}) {
  const queryClient = useQueryClient();
  return (
    <AppErrorBoundary
      fallback={({ error, traceId, timestamp, reset }) => (
        <AilaCard className="border-border-danger" techBorder glow>
          <div
            role="alert"
            aria-live="polite"
            className="space-y-2 p-1"
            data-testid={`vr-panel-boundary-${label.toLowerCase().replace(/\s+/g, "-")}`}
          >
            <p className="text-xs uppercase tracking-wide text-text-muted font-mono">
              {label} failed to render
            </p>
            <p className="text-sm text-text-danger break-words">
              {error.message || "Unexpected panel error."}
            </p>
            <p className="text-3xs text-text-muted font-mono">
              {traceId ? <>trace_id: <code>{traceId}</code></> : <>timestamp: <code>{timestamp}</code></>}
            </p>
            <div className="flex gap-2 pt-1">
              <button
                type="button"
                onClick={() => {
                  if (invalidateKeyPrefix) {
                    queryClient.invalidateQueries({ queryKey: invalidateKeyPrefix });
                  }
                  reset();
                }}
                className="rounded-[2px] border border-border bg-surface px-3 py-1 font-mono text-xs text-text hover:border-border-hover"
              >
                Retry
              </button>
            </div>
          </div>
        </AilaCard>
      )}
    >
      {children}
    </AppErrorBoundary>
  );
}
