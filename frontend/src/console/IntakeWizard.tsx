/**
 * IntakeWizard -- fullscreen overlay ported from the AILA Console mock
 * (docs/design sys/AILA Console.dc.html). One overlay handles three modules
 * with two distinct flows, dispatched by the module's configured flow:
 *
 *  - vr / malware -> generic 3-step intake (./intake/TargetWizard): kind
 *    grid, pick a registered target, review (initial question +
 *    investigation kind + auto-pilot + budget), then a staged animation that
 *    runs alongside the real POST /{module}/investigations mutation and binds
 *    on success.
 *  - forensics -> a configure -> readiness -> confirm wizard
 *    (./intake/ForensicsWizard) with its own project-kind and analyzer-OS
 *    cards and a real backend readiness check before the confirm summary.
 *
 * Styling copies the mock's inline style strings 1:1 through css(). No
 * completion is fabricated: every flow drives a real backend call and binds
 * the created row through onBind.
 */

import type { JSX } from "react";

import type { IntakeWizardProps } from "./contract";
import { ForensicsWizard } from "./intake/ForensicsWizard";
import { TargetWizard } from "./intake/TargetWizard";

function IntakeWizard({ moduleId, onBind, onRequestUpload, prefill }: IntakeWizardProps): JSX.Element {
  if (moduleId === "forensics") {
    return <ForensicsWizard onBind={onBind} />;
  }
  return (
    <TargetWizard
      moduleId={moduleId === "malware" ? "malware" : "vr"}
      onBind={onBind}
      onRequestUpload={onRequestUpload}
      prefill={prefill}
    />
  );
}

export default IntakeWizard;
