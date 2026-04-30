import { Component, type ErrorInfo, type ReactNode } from "react";
import { Link } from "react-router-dom";

interface Props {
  children: ReactNode;
  /**
   * Optional override for the fallback UI rendered when an error is caught.
   * Receives the error (trace_id already sanitized to string) and a reset callback.
   */
  fallback?: (args: { error: Error; traceId: string | null; timestamp: string; reset: () => void }) => ReactNode;
}

interface State {
  error: Error | null;
  timestamp: string | null;
}

/**
 * Pull a trace_id field off an arbitrary error object, if present.
 *
 * Some errors (ApiHttpError / envelope-aware errors) annotate themselves with
 * a server-side correlation id. When absent we return null so the UI can fall
 * back to a current-timestamp display (D-26).
 */
function extractTraceId(error: unknown): string | null {
  if (!error || typeof error !== "object") return null;
  const candidate = (error as { trace_id?: unknown }).trace_id;
  return typeof candidate === "string" && candidate.length > 0 ? candidate : null;
}

/**
 * React error boundary that catches unhandled render errors and displays a
 * sanitized fallback UI with a "Reload" button (D-23).
 *
 * Security (T-176a-02-01): The rendered UI never exposes `error.stack`.
 * Only `error.message` (pre-sanitized) and trace_id / timestamp are shown.
 *
 * Placement: wrapped both at the shell root and per-feature route so that a
 * thrown render in a feature page does not unmount the shell.
 */
export class AppErrorBoundary extends Component<Props, State> {
  state: State = { error: null, timestamp: null };

  static getDerivedStateFromError(error: Error): State {
    // Capture timestamp at catch-time so it stays stable across re-renders
    // (C1). Computing it in render() produced a fresh ISO string on every
    // render, which visibly drifted in the UI and broke memoized fallbacks.
    return { error, timestamp: new Date().toISOString() };
  }

  componentDidCatch(error: Error, info: ErrorInfo): void {
    // T-140-09 / T-176a-02-01: log details to console only; never render stack to user.
    console.error("AppErrorBoundary caught:", error, info);
  }

  resetError = (): void => {
    this.setState({ error: null, timestamp: null });
  };

  render(): ReactNode {
    const { error, timestamp } = this.state;
    if (!error) return this.props.children;

    const traceId = extractTraceId(error);
    // timestamp is set by getDerivedStateFromError; the "" fallback guards
    // against the impossible race where render() fires with error but the
    // state-update has not yet flushed.
    const stableTimestamp = timestamp ?? "";

    if (this.props.fallback) {
      return this.props.fallback({ error, traceId, timestamp: stableTimestamp, reset: this.resetError });
    }

    // Default fallback: minimal, framework-neutral markup.
    const message = typeof error.message === "string" && error.message.length > 0
      ? error.message
      : "An unexpected error occurred.";

    return (
      <div
        role="alert"
        className="mx-auto max-w-xl p-6"
        data-testid="app-error-boundary-fallback"
      >
        <h2 className="font-mono text-lg font-semibold text-foreground">
          Something went wrong
        </h2>
        <p className="mt-2 font-mono text-sm text-text-muted break-words">
          {message}
        </p>
        <p className="mt-3 font-mono text-xs text-text-muted">
          {traceId ? (
            <>trace_id: <code>{traceId}</code></>
          ) : (
            <>Timestamp: <code>{stableTimestamp}</code></>
          )}
        </p>
        <div className="mt-4 flex gap-2">
          <button
            type="button"
            onClick={() => window.location.reload()}
            className="rounded-[2px] border border-border bg-surface px-3 py-1 font-mono text-xs text-text hover:border-border-hover"
          >
            Reload
          </button>
          <button
            type="button"
            onClick={this.resetError}
            className="rounded-[2px] border border-border bg-surface px-3 py-1 font-mono text-xs text-text hover:border-border-hover"
          >
            Try again
          </button>
          <Link
            to="/"
            className="rounded-[2px] border border-border bg-surface px-3 py-1 font-mono text-xs text-text hover:border-border-hover"
          >
            Home
          </Link>
        </div>
      </div>
    );
  }
}

