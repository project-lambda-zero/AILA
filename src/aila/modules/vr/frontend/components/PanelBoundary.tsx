import { useQueryClient } from "@tanstack/react-query";
import { type ReactNode } from "react";

import { AppErrorBoundary } from "@app/ErrorBoundary";
import { WindowPanel } from "@/components/aila/WindowPanel";

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
 * -- The fallback renders a WindowPanel(title="error", tone="accent")
 *    with role=alert mono text (message, trace_id / timestamp) and a
 *    Retry action in the title bar. Retry does two things:
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
      fallback={({ error, traceId, timestamp, reset }) => {
        const testId = `vr-panel-boundary-${label.toLowerCase().replace(/\s+/g, "-")}`;
        const onRetry = () => {
          if (invalidateKeyPrefix) {
            queryClient.invalidateQueries({ queryKey: invalidateKeyPrefix });
          }
          reset();
        };
        return (
          <WindowPanel
            title="error"
            tone="accent"
            actions={
              <button
                type="button"
                onClick={onRetry}
                className="font-mono uppercase"
                style={{
                  height: 22,
                  padding: "0 10px",
                  fontSize: 9.5,
                  letterSpacing: "0.08em",
                  background: "var(--accent)",
                  border: "1px solid var(--accent)",
                  color: "var(--text-on-accent)",
                  borderRadius: 3,
                  cursor: "pointer",
                }}
              >
                retry
              </button>
            }
          >
            <div
              role="alert"
              aria-live="polite"
              data-testid={testId}
              className="font-mono flex flex-col"
              style={{ gap: 8, fontSize: 11, lineHeight: 1.5 }}
            >
              <div
                style={{
                  fontSize: 9.5,
                  letterSpacing: "0.08em",
                  color: "var(--text-muted)",
                  textTransform: "uppercase",
                }}
              >
                {label} failed to render
              </div>
              <div
                style={{
                  color: "var(--accent)",
                  fontSize: 12,
                  wordBreak: "break-word",
                }}
              >
                {error.message || "Unexpected panel error."}
              </div>
              <div
                style={{
                  fontSize: 9.5,
                  letterSpacing: "0.06em",
                  color: "var(--text-faint)",
                }}
              >
                {traceId ? (
                  <>
                    trace_id: <code>{traceId}</code>
                  </>
                ) : (
                  <>
                    timestamp: <code>{timestamp}</code>
                  </>
                )}
              </div>
            </div>
          </WindowPanel>
        );
      }}
    >
      {children}
    </AppErrorBoundary>
  );
}
