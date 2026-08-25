/** Wizard system barrel. Consumers import the guided-flow shell + the catalog
 * from here so the internal file layout stays private. */

export { WizardShell, FieldHelp } from "./WizardShell";
export { WIZARDS, wizardsForModule, resolveWizard, primaryWizardIdForModule } from "./registry";
export type { WizardShellProps, WizardStepDef, WizardFieldIssue, WizardDef, WizardOpen } from "./types";
