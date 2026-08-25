/** Shared wizard-system types.
 *
 * `WizardShell` (WizardShell.tsx) is the one guided-flow chrome every
 * chat-reachable wizard renders inside -- IntakeWizard, ScanWizard, SystemForm,
 * UploadForm, and any wizard a sibling spec adds. It owns the `step N of M`
 * strip, the invalid-field summary that blocks Next, the Back / Next / Finish
 * controls, the progress segments, and the inline backend-error + Retry row.
 * Consumers own the per-step body, declare the step list, and compute the
 * current step's field issues.
 *
 * The catalog (`WizardDef`, registry.ts) is the single source both the chat
 * `+ open wizard` picker and dante's `open_wizard` action resolve through, so
 * the chat can never offer a wizard that has no working implementation. */

import type { ReactNode } from "react";

/** One named step. `title` is a short verb phrase; `purpose` is a one-sentence
 * description rendered beneath the step strip. */
export interface WizardStepDef {
  id: string;
  title: string;
  purpose: string;
}

/** One invalid field on the current step. Both fields render in the disabled-
 * Next summary so the operator sees exactly what blocks advancing. */
export interface WizardFieldIssue {
  /** Human-readable field label, e.g. "analyzer machine". */
  label: string;
  /** Why it is invalid, e.g. "required" / "must be a positive number". */
  reason: string;
}

export interface WizardShellProps {
  /** Optional flow name rendered above the step strip. */
  heading?: string;
  /** The ordered step list; drives the `step N of M` strip + progress. */
  steps: WizardStepDef[];
  /** 0-based index of the active step. */
  current: number;
  /** Issues on the CURRENT step. Empty => primary control enabled; non-empty
   * => primary disabled AND the inline summary lists each issue by label +
   * reason (no silent disables). */
  issues: WizardFieldIssue[];
  /** Back handler; the control is disabled on the first step. */
  onBack: () => void;
  /** Advance to the next step (every step but the last). */
  onNext: () => void;
  /** Primary action on the last step. */
  onFinish: () => void;
  /** Override the primary / back control labels. */
  nextLabel?: string;
  finishLabel?: string;
  backLabel?: string;
  /** In-flight backend/mutation work: disables the primary control and shows a
   * pending label. */
  busy?: boolean;
  /** Inline backend-error message for the current step; rendered above the
   * footer with a Retry control when `onRetry` is supplied. The wizard stays
   * on the current step -- it never throws the operator back to step one. */
  error?: string | null;
  onRetry?: () => void;
  /** Hide the primary (Next/Finish) control; used by terminal progress steps
   * that own no advance. Back still renders when applicable. Default true. */
  showPrimary?: boolean;
  /** The current step body. */
  children: ReactNode;
}

/** How the host opens a wizard. `intake` routes through App's IntakeWizard
 * window host (module-aware); `page` opens a registered page window via
 * openNamedPage. Both mount inside <ConsoleWindow>. */
export type WizardOpen =
  | { kind: "intake" }
  | { kind: "page"; moduleKey: string; section: string };

/** A wizard the chat picker + dante can open. `module` scopes the picker;
 * `id` is the stable handle dante references. Every def MUST resolve to a
 * surface that exists end-to-end. */
export interface WizardDef {
  id: string;
  module: string;
  label: string;
  purpose: string;
  open: WizardOpen;
}
