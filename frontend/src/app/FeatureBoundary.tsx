/**
 * FeatureBoundary -- feature-scoped error boundary with retry.
 *
 * Wraps `AppErrorBoundary` semantics with a compact WindowPanel fallback so a
 * single failed async widget renders a scoped retry surface instead of
 * blanking the entire page (V-24 resilience layer). Rebuilt to the mock kit:
 * the fallback is a warn-toned WindowPanel with a dense mono message body
 * and a raw mock retry button.
 *
 * Usage:
 *   <FeatureBoundary label="Cost trend" resetKeys={[historyMonths]}
 *                    onReset={() => void historyQuery.refetch()}>
 *     <CostTrendChart months={months} accent={accent} />
 *   </FeatureBoundary>
 *
 * Semantics:
 *   - `resetKeys` are shallow-compared; on any change the internal boundary
 *     is remounted (fresh state, children re-run), which mirrors
 *     react-error-boundary's `resetKeys` contract without a new dep.
 *   - `onReset` fires when the operator clicks Retry AND on `resetKeys`
 *     change. Typically wired to a TanStack Query `.refetch()`.
 *   - `label` is surfaced in the fallback heading and as an aria-label
 *     for the retry button so screen readers know which widget is
 *     recovering.
 *   - Reduced-motion safe: no animations, static markup.
 *
 * The router's root `withFeatureBoundary` (per-route AppErrorBoundary)
 * remains the outer safety net; this wrapper is intended to be dropped
 * around heavy async widgets INSIDE a page (charts, tables, side panels)
 * where blanking the entire route on one failed query is not acceptable.
 */
import { Component, type CSSProperties, type ErrorInfo, type ReactNode } from "react";
import { ArrowClockwise } from "@phosphor-icons/react/dist/csr/ArrowClockwise";
import { Warning } from "@phosphor-icons/react/dist/csr/Warning";

import { WindowPanel } from "@/components/aila/WindowPanel";

interface FeatureBoundaryProps {
  /** Rendered as the fallback heading and reused in the retry button's aria-label. */
  label?: string;
  /**
   * When any entry changes (shallow-compared), the internal boundary is
   * remounted so children re-run and query state is refreshed via `onReset`.
   */
  resetKeys?: readonly unknown[];
  /**
   * Fires on operator-driven retry AND on `resetKeys` change. Typically
   * wired to `query.refetch()`.
   */
  onReset?: () => void;
  children: ReactNode;
}

interface FeatureBoundaryState {
  error: Error | null;
}

/**
 * Shallow-compare two `resetKeys` arrays. Both null/undefined counts as
 * equal; length-mismatch or any element inequality counts as changed.
 */
function keysDiffer(
  prev: readonly unknown[] | undefined,
  next: readonly unknown[] | undefined,
): boolean {
  if (prev === next) return false;
  if (!prev || !next) return true;
  if (prev.length !== next.length) return true;
  for (let i = 0; i < prev.length; i++) {
    if (!Object.is(prev[i], next[i])) return true;
  }
  return false;
}

const RETRY_BUTTON_STYLE: CSSProperties = {
  height: 24,
  padding: "0 10px",
  fontSize: 9.5,
  letterSpacing: "0.1em",
  textTransform: "uppercase",
  fontFamily: "var(--font-mono)",
  color: "var(--status-warn)",
  background: "var(--surface-sunk)",
  border: "1px solid color-mix(in srgb, var(--status-warn) 45%, transparent)",
  borderRadius: 3,
  cursor: "pointer",
  display: "inline-flex",
  alignItems: "center",
  gap: 6,
};

/**
 * FeatureBoundary owns the class-component wiring directly (rather than
 * composing `AppErrorBoundary`) so we can honour `resetKeys` inside a
 * single lifecycle: `getDerivedStateFromProps` resets `error` when the
 * keys shift, without a remount that would nuke unrelated cache state
 * in child subtrees.
 */
export class FeatureBoundary extends Component<FeatureBoundaryProps, FeatureBoundaryState> {
  state: FeatureBoundaryState = { error: null };
  private lastKeys: readonly unknown[] | undefined;

  constructor(props: FeatureBoundaryProps) {
    super(props);
    this.lastKeys = props.resetKeys;
  }

  static getDerivedStateFromError(error: Error): FeatureBoundaryState {
    return { error };
  }

  componentDidCatch(error: Error, info: ErrorInfo): void {
    // Match AppErrorBoundary: log to console, never render stack to user.
    console.error(
      `FeatureBoundary caught${this.props.label ? ` (${this.props.label})` : ""}:`,
      error,
      info,
    );
  }

  componentDidUpdate(prevProps: FeatureBoundaryProps): void {
    if (keysDiffer(prevProps.resetKeys, this.props.resetKeys)) {
      this.lastKeys = this.props.resetKeys;
      if (this.state.error !== null) {
        // Clear caught error so children re-render with the new inputs.
        this.setState({ error: null });
      }
      // Fire onReset even when there was no error, so consumers that
      // key the boundary off a query hash still get a refetch on the
      // reset-key change. This mirrors react-error-boundary v4.
      this.props.onReset?.();
    }
  }

  private handleRetry = (): void => {
    // Clear the error first, then let the caller refetch. Order matters:
    // if refetch() throws synchronously (unlikely but possible for setup
    // paths) the boundary is already clean and can re-catch.
    this.setState({ error: null });
    this.props.onReset?.();
  };

  render(): ReactNode {
    const { error } = this.state;
    const { label, children } = this.props;

    if (!error) return children;

    const message =
      typeof error.message === "string" && error.message.length > 0
        ? error.message
        : "An unexpected error occurred while rendering this section.";
    const heading = label ? `${label} failed to load` : "Section failed to load";
    const retryAria = label ? `Retry loading ${label}` : "Retry loading section";
    const panelTitle = label ? `${label} error`.toLowerCase() : "section error";

    return (
      <WindowPanel
        title={panelTitle}
        tone="warn"
        status="ERROR"
        role="alert"
        aria-live="polite"
        data-testid="feature-boundary-fallback"
      >
        <div className="flex flex-col" style={{ gap: 12, padding: 4 }}>
          <div className="flex items-start" style={{ gap: 10 }}>
            <Warning
              aria-hidden="true"
              weight="fill"
              style={{ width: 16, height: 16, flex: "0 0 auto", color: "var(--status-warn)", marginTop: 2 }}
            />
            <div className="flex flex-col" style={{ minWidth: 0, flex: 1, gap: 4 }}>
              <div
                className="font-mono uppercase"
                style={{
                  fontSize: 11,
                  letterSpacing: "0.14em",
                  color: "var(--text-primary)",
                }}
              >
                {heading}
              </div>
              <div
                className="font-mono"
                style={{ fontSize: 10.5, color: "var(--text-muted)", wordBreak: "break-word" }}
              >
                {message}
              </div>
            </div>
          </div>
          <div>
            <button
              type="button"
              onClick={this.handleRetry}
              aria-label={retryAria}
              style={RETRY_BUTTON_STYLE}
            >
              <ArrowClockwise aria-hidden="true" style={{ width: 11, height: 11 }} />
              Retry
            </button>
          </div>
        </div>
      </WindowPanel>
    );
  }
}
