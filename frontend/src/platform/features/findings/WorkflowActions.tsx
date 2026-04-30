/**
 * WorkflowActions — operator transition controls for a single finding.
 *
 * Renders one button per legal next state (driven by the server-side state
 * machine returned by useWorkflowStates), opens a confirmation dialog with an
 * optional comment field, and invalidates the relevant queries on success
 * via useTransitionFinding so the table badge, kanban column, and detail
 * panel all refresh.
 *
 * Backed by:
 *   GET  /findings/workflow/states
 *   GET  /findings/{id}/workflow
 *   POST /findings/{id}/transition
 */
import { useState } from "react";
import { ArrowRight } from "@phosphor-icons/react";

import { AilaBadge } from "@/components/aila/AilaBadge";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { cn } from "@/lib/utils";

import {
  useFindingWorkflow,
  useTransitionFinding,
  useWorkflowStates,
  type TransitionFindingRequest,
} from "./workflowApi";

// ---------------------------------------------------------------------------
// State presentation — known canonical states get a label + severity colour.
// Unknown states (e.g. module-contributed) fall back to neutral + Title Case.
// ---------------------------------------------------------------------------

type BadgeSeverity = "critical" | "high" | "medium" | "low" | "info" | "neutral";

const STATE_LABELS: Record<string, string> = {
  new: "New",
  investigating: "Investigating",
  mitigated: "Mitigated",
  verified: "Verified",
  closed: "Closed",
};

const STATE_SEVERITY: Record<string, BadgeSeverity> = {
  new: "info",
  investigating: "medium",
  mitigated: "high",
  verified: "low",
  closed: "neutral",
};

function stateLabel(state: string): string {
  return STATE_LABELS[state] ?? state.charAt(0).toUpperCase() + state.slice(1);
}

function stateSeverity(state: string): BadgeSeverity {
  return STATE_SEVERITY[state] ?? "neutral";
}

// ---------------------------------------------------------------------------
// State badge — exported so other surfaces (table column, list rows) can
// render the same chip without re-importing severity-mapping logic.
// ---------------------------------------------------------------------------

export interface WorkflowStateBadgeProps {
  state: string | null | undefined;
  size?: "sm" | "md";
  className?: string;
}

export function WorkflowStateBadge({
  state,
  size = "sm",
  className,
}: WorkflowStateBadgeProps) {
  const value = state ?? "new";
  return (
    <AilaBadge
      severity={stateSeverity(value)}
      size={size}
      className={className}
      data-testid="workflow-state-badge"
    >
      {stateLabel(value)}
    </AilaBadge>
  );
}

// ---------------------------------------------------------------------------
// Confirmation dialog — shown when an operator clicks a transition button.
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
    // Reset after the close animation so the previous content does not flash.
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

  return (
    <Dialog
      open={open}
      onOpenChange={(v) => {
        if (!v) close();
      }}
    >
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle className="font-mono text-text">
            Confirm transition
          </DialogTitle>
          <DialogDescription className="font-mono text-xs text-text-muted">
            Move this finding from {stateLabel(fromState).toLowerCase()} to{" "}
            {stateLabel(toState).toLowerCase()}.
          </DialogDescription>
        </DialogHeader>

        <div className="flex items-center gap-2">
          <WorkflowStateBadge state={fromState} />
          <ArrowRight size={12} className="text-text-muted" />
          <WorkflowStateBadge state={toState} />
        </div>

        <form className="flex flex-col gap-3" onSubmit={handleConfirm}>
          <div className="flex flex-col gap-1">
            <label
              className="font-mono text-xs text-text-muted"
              htmlFor="wf-notes"
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
              className="w-full text-xs bg-surface border border-border rounded-[2px] px-2 py-1.5 text-text placeholder:text-text-muted focus:outline-none focus:border-accent resize-none font-mono"
            />
            <p className="font-mono text-[10px] text-text-muted text-right">
              {notes.length}/2048
            </p>
          </div>

          {error && (
            <div
              role="alert"
              className="rounded-[4px] border border-destructive bg-destructive/10 px-3 py-2 font-mono text-xs text-destructive"
            >
              {error}
            </div>
          )}

          <div className="flex gap-2 justify-end">
            <Button
              type="button"
              size="sm"
              variant="outline"
              onClick={close}
              disabled={transition.isPending}
            >
              Cancel
            </Button>
            <Button type="submit" size="sm" disabled={transition.isPending}>
              {transition.isPending
                ? "Transitioning…"
                : `Move to ${stateLabel(toState)}`}
            </Button>
          </div>
        </form>
      </DialogContent>
    </Dialog>
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

  const wrapperClass = cn("flex flex-col gap-2", className);

  if (statesQuery.isLoading || workflowQuery.isLoading) {
    return (
      <div className={wrapperClass} data-testid="workflow-actions">
        <span className="font-mono text-[10px] uppercase tracking-widest text-text-muted">
          Triage
        </span>
        <span className="font-mono text-xs text-text-muted">
          Loading actions…
        </span>
      </div>
    );
  }

  if (statesQuery.isError) {
    return (
      <div
        className={wrapperClass}
        data-testid="workflow-actions"
        role="alert"
      >
        <span className="font-mono text-xs text-destructive">
          Could not load workflow states.
        </span>
      </div>
    );
  }

  return (
    <div className={wrapperClass} data-testid="workflow-actions">
      <span className="font-mono text-[10px] uppercase tracking-widest text-text-muted">
        Triage
      </span>
      <div className="flex flex-wrap items-center gap-2">
        <WorkflowStateBadge state={currentState} />
        {allowed.length === 0 ? (
          <span className="font-mono text-xs text-text-muted">
            Terminal state — no transitions available.
          </span>
        ) : (
          <>
            <span className="font-mono text-text-muted text-xs">→</span>
            {allowed.map((next) => (
              <Button
                key={next}
                type="button"
                size="xs"
                variant="outline"
                onClick={() => setPending(next)}
                data-testid={`workflow-action-${next}`}
              >
                {stateLabel(next)}
              </Button>
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
