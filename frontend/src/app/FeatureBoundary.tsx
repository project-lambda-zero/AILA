/**
 * FeatureBoundary -- feature-scoped error boundary with retry.
 *
 * Wraps `AppErrorBoundary` with a compact, card-shaped fallback so a single
 * failed async widget renders a scoped retry surface instead of blanking
 * the entire page (V-24 resilience layer).
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
 *   - Fallback preserves the shell's design tokens (AilaCard + destructive
 *     border) so it reads as an in-place error card, not a full-page fatal.
 *
 * The router's root `withFeatureBoundary` (per-route AppErrorBoundary)
 * remains the outer safety net; this wrapper is intended to be dropped
 * around heavy async widgets INSIDE a page (charts, tables, side panels)
 * where blanking the entire route on one failed query is not acceptable.
 */
import { Component, type ErrorInfo, type ReactNode } from "react";
import { ArrowClockwise } from "@phosphor-icons/react/dist/csr/ArrowClockwise";
import { Warning } from "@phosphor-icons/react/dist/csr/Warning";

import { AilaCard } from "@/components/aila/AilaCard";
import { Button } from "@/components/ui/button";

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

    return (
      <AilaCard
        variant="default"
        padding="md"
        className="border-destructive/50 bg-destructive/5"
        role="alert"
        aria-live="polite"
        data-testid="feature-boundary-fallback"
      >
        <div className="flex flex-col gap-3">
          <div className="flex items-start gap-2">
            <Warning
              className="mt-0.5 h-4 w-4 shrink-0 text-destructive"
              aria-hidden="true"
              weight="fill"
            />
            <div className="min-w-0 flex-1">
              <p className="font-mono text-sm font-semibold text-text">
                {heading}
              </p>
              <p className="mt-1 font-mono text-xs text-text-muted break-words">
                {message}
              </p>
            </div>
          </div>
          <div>
            <Button
              type="button"
              size="xs"
              variant="outline"
              onClick={this.handleRetry}
              aria-label={retryAria}
              className="gap-1.5"
            >
              <ArrowClockwise className="h-3 w-3" aria-hidden="true" />
              Retry
            </Button>
          </div>
        </div>
      </AilaCard>
    );
  }
}
