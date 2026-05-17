/** Horizontal stepper for VR workflow states.
 *
 *  Renders the 5 states from VR_NDAY_V1 (or 3 from VR_INVESTIGATE_V1) as
 *  numbered steps with active highlight + completed checkmarks. The
 *  current state is outlined; completed states get a green check;
 *  pending states stay muted. This is the "live progress" widget from
 *  08_FRONTEND_UX.md §Topic 6 / VR_FRONTEND_UX_DISCUSSION.md.
 *
 *  Use:
 *    <WorkflowStepper
 *      flow="nday"
 *      currentState="research"
 *      failedAt={null}
 *    />
 */
export type WorkflowFlow = "nday" | "investigate";

const FLOWS: Record<WorkflowFlow, ReadonlyArray<{ id: string; label: string }>> = {
  nday: [
    { id: "setup",           label: "Setup" },
    { id: "research",        label: "Research" },
    { id: "poc_development", label: "PoC" },
    { id: "advisory",        label: "Advisory" },
    { id: "response_emit",   label: "Emit" },
  ],
  investigate: [
    { id: "investigation_setup", label: "Setup" },
    { id: "investigation_loop",  label: "Investigate" },
    { id: "investigation_emit",  label: "Emit" },
  ],
};

export function WorkflowStepper({
  flow,
  currentState,
  failedAt,
}: {
  flow: WorkflowFlow;
  currentState: string | null | undefined;
  failedAt?: string | null;
}) {
  const steps = FLOWS[flow];
  const currentIdx = currentState
    ? steps.findIndex((s) => s.id === currentState)
    : -1;
  const failedIdx = failedAt
    ? steps.findIndex((s) => s.id === failedAt)
    : -1;
  const isDone = currentState === "succeeded" || currentState === "done";

  return (
    <ol className="flex items-center gap-0 w-full font-mono text-xs select-none">
      {steps.map((step, i) => {
        const isCurrent = i === currentIdx && !isDone;
        const isFailed = i === failedIdx;
        const isComplete = isDone || (currentIdx >= 0 && i < currentIdx);
        const isPending = !isComplete && !isCurrent && !isFailed;

        let circleClasses = "w-6 h-6 rounded-full flex items-center justify-center text-[10px] font-bold border ";
        let labelClasses = "text-xs ";
        let connectorClasses = "h-px flex-1 ";

        if (isFailed) {
          circleClasses += "bg-surface border-border-danger text-text-danger";
          labelClasses += "text-text-danger font-semibold";
        } else if (isCurrent) {
          circleClasses += "bg-accent border-accent text-white ring-2 ring-accent/30";
          labelClasses += "text-foreground font-semibold";
        } else if (isComplete) {
          circleClasses += "bg-surface border-border-default text-text-muted";
          labelClasses += "text-text-muted";
        } else {
          circleClasses += "bg-surface border-border-default text-text-muted opacity-60";
          labelClasses += "text-text-muted opacity-60";
        }

        connectorClasses += isComplete ? "bg-accent/40" : "bg-border-default";

        return (
          <li key={step.id} className="flex items-center flex-1 last:flex-initial gap-2">
            <div className="flex items-center gap-2">
              <span className={circleClasses}>
                {isComplete ? "✓" : isFailed ? "!" : i + 1}
              </span>
              <span className={labelClasses}>{step.label}</span>
            </div>
            {i < steps.length - 1 && <div className={connectorClasses} />}
          </li>
        );
      })}
    </ol>
  );
}
