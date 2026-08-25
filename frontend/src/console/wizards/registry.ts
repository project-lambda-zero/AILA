/** The one wizard catalog.
 *
 * The chat `+ open wizard` picker and dante's `open_wizard` action both
 * resolve through this list, so the chat can never offer a wizard that has no
 * working implementation. Every entry maps to a surface that exists today:
 *   - `intake` -> the IntakeWizard window host (module-aware: vr / malware /
 *     forensics),
 *   - `page`   -> a registered page window opened via openNamedPage
 *     (register-system form, launch-scan, upload-target, new-automation).
 *
 * Not listed: a standalone tag-vocabulary wizard. That surface is a modal
 * inside SystemsPanel (no registered page), so offering it here would violate
 * the structural-honesty rule; it stays deferred to the tag-vocabulary spec. */

import type { WizardDef } from "./types";

export const WIZARDS: readonly WizardDef[] = [
  {
    id: "vr-intake",
    module: "vr",
    label: "new investigation",
    purpose: "open a VR investigation against a target.",
    open: { kind: "intake" },
  },
  {
    id: "vr-upload",
    module: "vr",
    label: "upload target",
    purpose: "register a new source or binary target to investigate.",
    open: { kind: "page", moduleKey: "vr", section: "new-target" },
  },
  {
    id: "malware-intake",
    module: "malware",
    label: "new investigation",
    purpose: "open a malware investigation against a sample.",
    open: { kind: "intake" },
  },
  {
    id: "malware-upload",
    module: "malware",
    label: "upload sample",
    purpose: "register a new sample target to analyze.",
    open: { kind: "page", moduleKey: "malware", section: "new-target" },
  },
  {
    id: "forensics-intake",
    module: "forensics",
    label: "new case",
    purpose: "configure an evidence project and check analyzer readiness.",
    open: { kind: "intake" },
  },
  {
    id: "vuln-scan",
    module: "vulnerability",
    label: "launch scan",
    purpose: "run a vulnerability scan across selected systems.",
    open: { kind: "page", moduleKey: "vulnerability", section: "scan" },
  },
  {
    id: "vuln-system",
    module: "vulnerability",
    label: "register system",
    purpose: "add an SSH-reachable system to the platform registry.",
    // The SSH host registry is platform-owned (system-registry-platform.md
    // req 11): this wizard raises the admin systems page, and the
    // operator hits "+ register system" inside for the create form.
    open: { kind: "page", moduleKey: "admin", section: "systems" },
  },
  {
    id: "admin-automation",
    module: "admin",
    label: "new automation",
    purpose: "schedule a recurring platform automation.",
    open: { kind: "page", moduleKey: "admin", section: "new-automation" },
  },
];

/** Wizards offered by the picker for a given console module. */
export function wizardsForModule(moduleId: string): WizardDef[] {
  return WIZARDS.filter((w) => w.module === moduleId);
}

export function resolveWizard(id: string): WizardDef | null {
  return WIZARDS.find((w) => w.id === id) ?? null;
}

/** The wizard a bare `+ new investigation` or a dante `open_wizard` action
 * opens for a module. vr / malware / forensics resolve to their intake flow;
 * vulnerability has no intake flow from chat, so it maps to the register-
 * system form -- matching the host's existing requestIntake behavior. Returns
 * null for an unknown module. */
export function primaryWizardIdForModule(moduleId: string): string | null {
  if (moduleId === "vr" || moduleId === "malware") return `${moduleId}-intake`;
  if (moduleId === "forensics") return "forensics-intake";
  if (moduleId === "vulnerability") return "vuln-system";
  return null;
}
