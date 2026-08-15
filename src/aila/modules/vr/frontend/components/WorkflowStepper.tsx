/** Horizontal stepper for VR workflow states.
 *
 *  Renders the 5 states from VR_NDAY_V1 (or 3 from VR_INVESTIGATE_V1) as
 *  inline bordered mono step boxes. Each box carries a MonoBadge whose
 *  tone reflects its state (pending -> muted, current -> accent, done ->
 *  ok, failed -> accent), a phase pixel-glyph, and the phase label.
 *  This is the "live progress" widget from 08_FRONTEND_UX.md §Topic 6.
 *
 *  Use:
 *    <WorkflowStepper
 *      flow="nday"
 *      currentState="research"
 *      failedAt={null}
 *    />
 */
import type { CSSProperties } from "react";

import { MonoBadge } from "@/components/aila/mock";
import { PixelIcon, type PixelIconName } from "@/components/aila/PixelIcon";

export type WorkflowFlow = "nday" | "investigate";

interface StepDef {
  id: string;
  label: string;
}

const FLOWS: Record<WorkflowFlow, ReadonlyArray<StepDef>> = {
  nday: [
    { id: "setup",           label: "setup" },
    { id: "research",        label: "research" },
    { id: "poc_development", label: "poc" },
    { id: "advisory",        label: "advisory" },
    { id: "response_emit",   label: "emit" },
  ],
  investigate: [
    { id: "investigation_setup", label: "setup" },
    { id: "investigation_loop",  label: "investigate" },
    { id: "investigation_emit",  label: "emit" },
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

type StepState = "pending" | "current" | "done" | "failed";
type BadgeTone = "muted" | "accent" | "ok";

interface StateStyle {
  badgeTone: BadgeTone;
  badgeText: string;
  borderColor: string;
  labelColor: string;
  glyphColor: string;
  opacity: number;
}

function styleFor(state: StepState, ordinal: number): StateStyle {
  switch (state) {
    case "current":
      return {
        badgeTone: "accent",
        badgeText: "current",
        borderColor: "var(--accent)",
        labelColor: "var(--text-primary)",
        glyphColor: "var(--accent)",
        opacity: 1,
      };
    case "done":
      return {
        badgeTone: "ok",
        badgeText: "done",
        borderColor: "var(--status-ok)",
        labelColor: "var(--text-muted)",
        glyphColor: "var(--status-ok)",
        opacity: 1,
      };
    case "failed":
      // Failed states re-use the accent tone (critical). MonoBadge does
      // not accept a "failed" tone key -- accent is the mock language's
      // critical/error signal.
      return {
        badgeTone: "accent",
        badgeText: "failed",
        borderColor: "var(--accent)",
        labelColor: "var(--accent)",
        glyphColor: "var(--accent)",
        opacity: 1,
      };
    case "pending":
    default:
      return {
        badgeTone: "muted",
        badgeText: String(ordinal).padStart(2, "0"),
        borderColor: "var(--border-soft)",
        labelColor: "var(--text-faint)",
        glyphColor: "var(--text-faint)",
        opacity: 0.7,
      };
  }
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
    <ol
      className="flex items-stretch w-full select-none font-mono"
      style={{ gap: 6, flexWrap: "wrap" }}
    >
      {steps.map((step, i) => {
        let state: StepState;
        if (i === failedIdx) state = "failed";
        else if (isDone) state = "done";
        else if (currentIdx >= 0 && i < currentIdx) state = "done";
        else if (i === currentIdx) state = "current";
        else state = "pending";

        const s = styleFor(state, i + 1);
        const boxStyle: CSSProperties = {
          border: `1px solid ${s.borderColor}`,
          background: "var(--surface-sunk)",
          padding: "6px 10px",
          borderRadius: 3,
          minWidth: 0,
          flex: "1 1 140px",
          display: "flex",
          alignItems: "center",
          gap: 8,
          opacity: s.opacity,
        };

        return (
          <li key={step.id} style={boxStyle}>
            <MonoBadge tone={s.badgeTone}>{s.badgeText}</MonoBadge>
            <span
              style={{
                display: "inline-flex",
                alignItems: "center",
                color: s.glyphColor,
              }}
            >
              <PixelIcon
                name={state === "failed" ? "close" : phaseGlyph(step.id)}
                size={12}
              />
            </span>
            <span
              className="uppercase truncate"
              style={{
                fontSize: 10,
                letterSpacing: "0.08em",
                color: s.labelColor,
                minWidth: 0,
                fontWeight: state === "current" || state === "failed" ? 600 : 500,
              }}
            >
              {step.label}
            </span>
          </li>
        );
      })}
    </ol>
  );
}
