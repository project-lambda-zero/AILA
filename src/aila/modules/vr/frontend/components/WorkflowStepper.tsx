/** Horizontal stepper for VR workflow states.
 *
 *  Renders the 5 states from VR_NDAY_V1 (or 3 from VR_INVESTIGATE_V1) as
 *  reasoning-state markers with active highlight + completed checkmarks.
 *  The current state is outlined in accent and carries its phase glyph
 *  (spawn / cycle / merge / emit); completed states get a mint check;
 *  pending states stay muted with their ordinal. This is the "live
 *  progress" widget from 08_FRONTEND_UX.md §Topic 6.
 *
 *  Use:
 *    <WorkflowStepper
 *      flow="nday"
 *      currentState="research"
 *      failedAt={null}
 *    />
 */
import type { CSSProperties } from "react";

import { PixelIcon, type PixelIconName } from "@/components/aila/PixelIcon";

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

/** Map a workflow phase id to the reasoning-state pixel glyph that best
 *  describes it -- spawn (setup), cycle (research / loop), merge
 *  (advisory), emit (response). Falls back to the neutral status square. */
function phaseGlyph(id: string): PixelIconName {
  if (id.includes("emit")) return "emit";
  if (id.includes("loop") || id.includes("research")) return "cycle";
  if (id.includes("setup")) return "spawn";
  if (id.includes("advisory") || id.includes("merge")) return "merge";
  return "status";
}

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

        let circleClasses =
          "w-6 h-6 rounded-[2px] flex items-center justify-center text-3xs font-bold border ";
        let labelClasses = "text-2xs uppercase tracking-cyber-sm ";
        const connectorClasses =
          "h-px flex-1 " + (isComplete ? "bg-mint/40" : "bg-border");

        let circleStyle: CSSProperties = {};
        let marker: React.ReactNode;

        if (isFailed) {
          circleClasses += "bg-surface";
          circleStyle = { borderColor: "var(--color-critical)", color: "var(--color-critical)" };
          labelClasses += "text-critical font-semibold";
          marker = <PixelIcon name="close" size={12} />;
        } else if (isCurrent) {
          circleClasses += "bg-surface ring-2 ring-accent/30";
          circleStyle = { borderColor: "var(--color-accent)", color: "var(--color-accent)" };
          labelClasses += "text-foreground font-semibold";
          marker = <PixelIcon name={phaseGlyph(step.id)} size={12} />;
        } else if (isComplete) {
          circleClasses += "bg-surface";
          circleStyle = { borderColor: "var(--color-mint)", color: "var(--color-mint)" };
          labelClasses += "text-text-muted";
          marker = <PixelIcon name="ok" size={12} />;
        } else {
          circleClasses += "bg-surface opacity-60";
          circleStyle = { borderColor: "var(--color-border-bright)", color: "var(--color-text-faint)" };
          labelClasses += "text-text-muted opacity-60";
          marker = <span>{i + 1}</span>;
        }

        void isPending;

        return (
          <li key={step.id} className="flex items-center flex-1 last:flex-initial gap-2">
            <div className="flex items-center gap-2">
              <span className={circleClasses} style={circleStyle}>
                {marker}
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
