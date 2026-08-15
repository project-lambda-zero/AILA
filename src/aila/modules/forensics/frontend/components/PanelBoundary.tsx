import { AppErrorBoundary } from "@app/ErrorBoundary";
import { WindowPanel } from "@/components/aila/WindowPanel";
import { Button } from "@/components/ui/button";

interface PanelBoundaryProps {
  /** Short label used to describe the panel in the fallback message. */
  label: string;
  /** Optional refetch to run when the operator clicks Retry, invoked
   *  BEFORE the boundary resets so an incoming re-render sees the
   *  refreshed query state. */
  onRetry?: () => void;
  children: React.ReactNode;
}

/**
 * Panel-level error boundary for the forensics module.
 *
 * The shell already wraps every routed page in `AppErrorBoundary` (see
 * `frontend/src/app/router.tsx`); this helper reuses the same primitive
 * to isolate individual heavy async panels (reasoning-replay diff,
 * timeline viz, live-event stream) so a throw in one panel does NOT
 * unmount the surrounding investigation detail page.
 *
 * The fallback is compact (fits inside a card), shows the sanitized
 * error message, and offers a Retry action that first invokes the
 * caller-supplied refetch (if any) then resets the boundary. No stack
 * traces are ever surfaced (T-176a-02-01).
 */
export function PanelBoundary({ label, onRetry, children }: PanelBoundaryProps) {
  return (
    <AppErrorBoundary
      fallback={({ error, traceId, timestamp, reset }) => {
        const message =
          typeof error.message === "string" && error.message.length > 0
            ? error.message
            : "An unexpected error occurred.";
        return (
          <WindowPanel
            role="alert"
            aria-live="polite"
            tone="warn"
            title="render error"
            status="forensics ; panel failed to render"
            data-testid="forensics-panel-boundary-fallback"
          >
            <div className="space-y-2">
              <p className="text-sm font-semibold text-critical">
                {label} could not render.
              </p>
              <p className="text-xs text-text-muted break-words">{message}</p>
              <p className="text-3xs text-text-muted font-mono">
                {traceId ? <>trace_id: <code>{traceId}</code></> : <>ts: <code>{timestamp}</code></>}
              </p>
              <Button
                type="button"
                size="sm"
                variant="outline"
                onClick={() => {
                  if (onRetry) {
                    try {
                      onRetry();
                    } catch {
                      /* refetch failure resurfaces on next render */
                    }
                  }
                  reset();
                }}
              >
                Retry
              </Button>
            </div>
          </WindowPanel>
        );
      }}
    >
      {children}
    </AppErrorBoundary>
  );
}
