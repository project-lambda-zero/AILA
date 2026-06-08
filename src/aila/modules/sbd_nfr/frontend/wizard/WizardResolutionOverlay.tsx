import { useEffect, useState } from "react";

import { useSessionEvents } from "./hooks/useSessionEvents";

// ──────────────────────────────────────────────────────────────────────────────
// Types
// ──────────────────────────────────────────────────────────────────────────────

export interface WizardResolutionOverlayProps {
  sessionId: string;
  onCompleted: () => void;
  onFailed: (error: string) => void;
}

// ──────────────────────────────────────────────────────────────────────────────
// WizardResolutionOverlay — full-viewport overlay with live SSE progress (D-11)
// Conditionally rendered by WizardPage when session transitions to "resolving".
// ──────────────────────────────────────────────────────────────────────────────

export function WizardResolutionOverlay({
  sessionId,
  onCompleted,
  onFailed,
}: WizardResolutionOverlayProps) {
  const { latestEvent, resolutionStatus } = useSessionEvents(sessionId, true);
  const [statusText, setStatusText] = useState("Preparing analysis...");

  // Derive status text from SSE events
  useEffect(() => {
    if (!latestEvent) return;

    const eventName = latestEvent.event;

    if (eventName === "resolution_started") {
      const count = latestEvent.answer_count ?? "?";
      setStatusText(`Processing ${count} answers...`);
    } else if (eventName === "resolution_completed") {
      const count = latestEvent.component_count ?? "?";
      setStatusText(`Analysis complete! ${count} components classified.`);
    } else if (eventName === "resolution_failed") {
      const errMsg = latestEvent.error ?? "Unknown error.";
      setStatusText(`Analysis failed: ${errMsg}`);
    } else if (latestEvent.message) {
      // Generic status message from stream
      setStatusText(latestEvent.message);
    }
  }, [latestEvent]);

  // Transition to results after resolution_completed
  useEffect(() => {
    if (resolutionStatus === "completed") {
      const timer = setTimeout(() => {
        onCompleted();
      }, 800);
      return () => clearTimeout(timer);
    }
    return undefined;
  }, [resolutionStatus, onCompleted]);

  // Notify parent on failure
  useEffect(() => {
    if (resolutionStatus === "failed") {
      const errMsg = latestEvent?.error ?? "Resolution failed.";
      onFailed(errMsg);
    }
    // Only trigger when resolutionStatus changes to "failed"
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [resolutionStatus]);

  const isFailed = resolutionStatus === "failed";
  const isCompleted = resolutionStatus === "completed";

  return (
    <div
      className="fixed inset-0 z-50 bg-black/70 flex items-center justify-center"
      role="dialog"
      aria-modal="true"
      aria-label="Analyzing assessment"
    >
      <div className="bg-elevated border border-border rounded-lg p-8 max-w-sm text-center flex flex-col items-center gap-4">
        <h2 className="font-display text-lg font-bold text-text">Analyzing your assessment...</h2>

        {!isFailed && !isCompleted && (
          <span
            className="w-5 h-5 rounded-full border-2 border-accent border-t-transparent animate-spin"
            aria-hidden="true"
          />
        )}

        {isCompleted && (
          <span
            className="text-2xl"
            style={{ color: "var(--color-accent)" }}
            aria-hidden="true"
          >
            &#10003;
          </span>
        )}

        <p className="text-sm text-text-muted" aria-live="polite">
          {statusText}
        </p>

        {isFailed && (
          <p className="text-sm text-critical">
            The analysis could not complete. Please close and try again.
          </p>
        )}
      </div>
    </div>
  );
}
