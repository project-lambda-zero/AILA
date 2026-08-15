/**
 * WorkflowActions -- operator transition controls for a single finding.
 *
 * Renders one button per legal next state (driven by the server-side state
 * machine returned by useWorkflowStates), opens a confirmation dialog with an
 * optional comment field, and invalidates the relevant queries on success
 * via useTransitionFinding so the table badge, kanban column, and detail
 * panel all refresh.
 *
 * Backed by:
 *   GET  /findings/workflow/states
 *   GET  /findings/{finding_id}/workflow
 *   POST /findings/{finding_id}/transition
 */
import { useState } from "react";

import { MonoBadge } from "@/components/aila/mock";
import { WindowPanel } from "@/components/aila/WindowPanel";
import { cn } from "@/lib/utils";

import {
  useFindingWorkflow,
  useTransitionFinding,
  useWorkflowStates,
  type TransitionFindingRequest,
} from "./workflowApi";

// ---------------------------------------------------------------------------
// State presentation -- known canonical states get a label + tone.
// Unknown states (e.g. module-contributed) fall back to muted + Title Case.
// ---------------------------------------------------------------------------

type Tone = "critical" | "high" | "medium" | "low" | "info" | "muted";

const STATE_LABELS: Record<string, string> = {
  new: "New",
  investigating: "Investigating",
  mitigated: "Mitigated",
  verified: "Verified",
  closed: "Closed",
};

const STATE_TONE: Record<string, Tone> = {
  new: "info",
  investigating: "medium",
  mitigated: "high",
  verified: "low",
  closed: "muted",
};

function stateLabel(state: string): string {
  return STATE_LABELS[state] ?? state.charAt(0).toUpperCase() + state.slice(1);
}

function stateTone(state: string): Tone {
  return STATE_TONE[state] ?? "muted";
}

// ---------------------------------------------------------------------------
// Mono button used for state transitions.
// ---------------------------------------------------------------------------

const MONO_BTN: React.CSSProperties = {
  height: 26,
  fontSize: 9.5,
  padding: "0 11px",
  borderRadius: 3,
  border: "1px solid var(--border-soft)",
  background: "var(--surface-sunk)",
  color: "var(--text-primary)",
  fontFamily: "var(--font-mono)",
  textTransform: "uppercase",
  letterSpacing: "0.08em",
  cursor: "pointer",
  display: "inline-flex",
  alignItems: "center",
  gap: 6,
  whiteSpace: "nowrap",
};

const MONO_BTN_ACCENT: React.CSSProperties = {
  ...MONO_BTN,
  background: "color-mix(in srgb, var(--accent) 20%, transparent)",
  borderColor: "color-mix(in srgb, var(--accent) 45%, transparent)",
  color: "var(--accent)",
};

// ---------------------------------------------------------------------------
// State badge -- exported so other surfaces (table column, list rows) can
// render the same chip without re-importing severity-mapping logic.
// Backed by MonoBadge -- keeps the same {state, size?, className?} API.
// ---------------------------------------------------------------------------

export interface WorkflowStateBadgeProps {
  state: string | null | undefined;
  size?: "sm" | "md";
  className?: string;
}

export function WorkflowStateBadge({
  state,
  className,
}: WorkflowStateBadgeProps) {
  const value = state ?? "new";
  return (
    <span
      className={className}
      data-testid="workflow-state-badge"
    >
      <MonoBadge tone={stateTone(value)}>{stateLabel(value).toUpperCase()}</MonoBadge>
    </span>
  );
}

// ---------------------------------------------------------------------------
// Confirmation dialog -- shown when an operator clicks a transition button.
// Captures an optional comment and POSTs to /findings/{id}/transition.
// ---------------------------------------------------------------------------

interface TransitionDialogProps {
  findingId: number | string;
  fromState: string;
  toState: string;
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onSuccess?: () => void;
}

function TransitionDialog({
  findingId,
  fromState,
  toState,
  open,
  onOpenChange,
  onSuccess,
}: TransitionDialogProps) {
  const [notes, setNotes] = useState("");
  const [error, setError] = useState<string | null>(null);
  const transition = useTransitionFinding();

  function close() {
    onOpenChange(false);
    setTimeout(() => {
      setNotes("");
      setError(null);
    }, 200);
  }

  async function handleConfirm(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    try {
      const req: TransitionFindingRequest = {
        findingId,
        target_state: toState,
        notes: notes.trim() ? notes.trim() : undefined,
      };
      await transition.mutateAsync(req);
      onSuccess?.();
      close();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Transition failed");
    }
  }

  if (!open) return null;

  return (
    <div
      className="fixed inset-0 flex items-center justify-center"
      style={{ zIndex: 80, background: "color-mix(in srgb, black 55%, transparent)" }}
      role="dialog"
      aria-modal="true"
    >
      <div
        role="button"
        tabIndex={-1}
        aria-label="Close transition dialog"
        onClick={close}
        onKeyDown={(e) => { if (e.key === "Escape") close(); }}
        style={{ position: "absolute", inset: 0 }}
      />
      <div style={{ position: "relative", width: "min(460px, 94vw)", zIndex: 1 }}>
        <WindowPanel
          title={`confirm transition -> ${stateLabel(toState).toLowerCase()}`}
          tone="accent"
          actions={
            <button
              type="button"
              onClick={close}
              aria-label="Close"
              style={{
                ...MONO_BTN,
                height: 20,
                fontSize: 9,
                padding: "0 8px",
              }}
            >
              {"\u2715"} CLOSE
            </button>
          }
        >
          <form className="flex flex-col" style={{ gap: 12 }} onSubmit={handleConfirm}>
            <div
              className="flex items-center"
              style={{ gap: 8, fontFamily: "var(--font-mono)", fontSize: 10 }}
            >
              <WorkflowStateBadge state={fromState} />
              <span style={{ color: "var(--text-muted)" }}>{"\u2192"}</span>
              <WorkflowStateBadge state={toState} />
            </div>

            <div className="flex flex-col" style={{ gap: 4 }}>
              <label
                htmlFor="wf-notes"
                className="font-mono uppercase"
                style={{ fontSize: 9, letterSpacing: "0.12em", color: "var(--text-muted)" }}
              >
                Comment (optional)
              </label>
              <textarea
                id="wf-notes"
                value={notes}
                onChange={(e) => setNotes(e.target.value)}
                maxLength={2048}
                rows={3}
                placeholder="Why is this finding moving to this state?"
                className="font-mono"
                style={{
                  width: "100%",
                  fontSize: 11,
                  padding: "8px 10px",
                  background: "var(--surface-sunk)",
                  border: "1px solid var(--border-soft)",
                  borderRadius: 3,
                  color: "var(--text-primary)",
                  resize: "none",
                  outline: "none",
                }}
              />
              <p
                className="font-mono"
                style={{ fontSize: 9, color: "var(--text-faint)", textAlign: "right" }}
              >
                {notes.length}/2048
              </p>
            </div>

            {error && (
              <div
                role="alert"
                aria-live="assertive"
                className="font-mono"
                style={{
                  border: "1px solid color-mix(in srgb, var(--status-warn) 40%, transparent)",
                  background: "color-mix(in srgb, var(--status-warn) 10%, transparent)",
                  color: "var(--status-warn)",
                  padding: "8px 12px",
                  fontSize: 11,
                  borderRadius: 3,
                }}
              >
                {error}
              </div>
            )}

            <div className="flex justify-end" style={{ gap: 8 }}>
              <button
                type="button"
                onClick={close}
                disabled={transition.isPending}
                style={{ ...MONO_BTN, opacity: transition.isPending ? 0.5 : 1 }}
              >
                CANCEL
              </button>
              <button
                type="submit"
                disabled={transition.isPending}
                style={{ ...MONO_BTN_ACCENT, opacity: transition.isPending ? 0.5 : 1 }}
              >
                {transition.isPending
                  ? "TRANSITIONING\u2026"
                  : `MOVE TO ${stateLabel(toState).toUpperCase()}`}
              </button>
            </div>
          </form>
        </WindowPanel>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Main component
// ---------------------------------------------------------------------------

export interface WorkflowActionsProps {
  findingId: number | string;
  /**
   * State to display before the workflow query resolves. Once the GET returns
   * the canonical state, that value takes over. This avoids a "Loading…"
   * flicker on detail panels that already know the workflow_state from the
   * findings list response.
   */
  fallbackState?: string | null;
  /**
   * Optional callback fired after a successful transition. The query cache
   * is already invalidated by useTransitionFinding; this is for callers that
   * need to perform additional UI work (close a panel, focus an element, …).
   */
  onTransitioned?: () => void;
  className?: string;
}

export function WorkflowActions({
  findingId,
  fallbackState,
  onTransitioned,
  className,
}: WorkflowActionsProps) {
  const statesQuery = useWorkflowStates();
  const workflowQuery = useFindingWorkflow(findingId);
  const [pending, setPending] = useState<string | null>(null);

  const currentState =
    workflowQuery.data?.current_state ?? fallbackState ?? "new";

  const allowed = statesQuery.data?.transitions[currentState] ?? [];

  const wrapperClass = cn("flex flex-col", className);
  const wrapperStyle: React.CSSProperties = { gap: 8 };

  const label = (
    <span
      className="font-mono uppercase"
      style={{ fontSize: 9, letterSpacing: "0.14em", color: "var(--text-muted)" }}
    >
      Triage
    </span>
  );

  if (statesQuery.isLoading || workflowQuery.isLoading) {
    return (
      <div className={wrapperClass} style={wrapperStyle} data-testid="workflow-actions">
        {label}
        <span
          className="font-mono"
          style={{ fontSize: 10, color: "var(--text-muted)" }}
        >
          Loading actions{"\u2026"}
        </span>
      </div>
    );
  }

  if (statesQuery.isError) {
    return (
      <div
        className={wrapperClass}
        style={wrapperStyle}
        data-testid="workflow-actions"
        role="alert"
        aria-live="assertive"
      >
        {label}
        <span
          className="font-mono"
          style={{ fontSize: 10, color: "var(--status-warn)" }}
        >
          Could not load workflow states.
        </span>
      </div>
    );
  }

  return (
    <div className={wrapperClass} style={wrapperStyle} data-testid="workflow-actions">
      {label}
      <div className="flex flex-wrap items-center" style={{ gap: 8 }}>
        <WorkflowStateBadge state={currentState} />
        {allowed.length === 0 ? (
          <span
            className="font-mono"
            style={{ fontSize: 10, color: "var(--text-muted)" }}
          >
            Terminal state -- no transitions available.
          </span>
        ) : (
          <>
            <span
              className="font-mono"
              style={{ fontSize: 11, color: "var(--text-faint)" }}
            >
              {"\u2192"}
            </span>
            {allowed.map((next) => (
              <button
                key={next}
                type="button"
                onClick={() => setPending(next)}
                data-testid={`workflow-action-${next}`}
                style={MONO_BTN}
              >
                {stateLabel(next).toUpperCase()}
              </button>
            ))}
          </>
        )}
      </div>

      {pending !== null && (
        <TransitionDialog
          findingId={findingId}
          fromState={currentState}
          toState={pending}
          open={pending !== null}
          onOpenChange={(v) => {
            if (!v) setPending(null);
          }}
          onSuccess={() => {
            setPending(null);
            onTransitioned?.();
          }}
        />
      )}
    </div>
  );
}
