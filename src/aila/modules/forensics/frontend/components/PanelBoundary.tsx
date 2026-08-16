import { AppErrorBoundary } from "@app/ErrorBoundary";
import { WindowPanel } from "@/components/aila/WindowPanel";

interface PanelBoundaryProps {
  /** Short label used to describe the panel in the fallback message. */
  label: string;
  /** Optional refetch to run when the operator clicks Retry, invoked
   *  BEFORE the boundary resets so an incoming re-render sees the
   *  refreshed query state. */
  onRetry?: () => void;
  children: React.ReactNode;
}

const RETRY_BTN: React.CSSProperties = {
  height: 26,
  padding: "0 12px",
  fontSize: 9.5,
  letterSpacing: "0.08em",
  color: "var(--text-muted)",
  background: "transparent",
  border: "1px solid var(--border-soft)",
  borderRadius: 3,
  cursor: "pointer",
};

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
              <p
                className="font-mono"
                style={{ fontSize: 11, color: "var(--accent)" }}
              >
                {label} could not render.
              </p>
              <p
                className="font-mono break-words"
                style={{ fontSize: 10.5, color: "var(--text-muted)" }}
              >
                {message}
              </p>
              <p
                className="font-mono"
                style={{ fontSize: 9.5, color: "var(--text-faint)" }}
              >
                {traceId ? (
                  <>
                    trace_id: <code>{traceId}</code>
                  </>
                ) : (
                  <>
                    ts: <code>{timestamp}</code>
                  </>
                )}
              </p>
              <button
                type="button"
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
                className="font-mono uppercase"
                style={RETRY_BTN}
              >
                retry
              </button>
            </div>
          </WindowPanel>
        );
      }}
    >
      {children}
    </AppErrorBoundary>
  );
}
