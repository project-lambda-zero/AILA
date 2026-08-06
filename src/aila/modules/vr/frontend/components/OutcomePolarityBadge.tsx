/**
 * OutcomePolarityBadge -- renders an outcome's polarity (finding /
 * no_finding / inconclusive) as a clearly-colored pill.
 *
 * Distinct from OutcomeKindBadge, which answers "what KIND of outcome
 * is this" (Assessment Report vs Audit Memo vs ...). Polarity answers
 * "did we land on a vulnerability, refute one, or neither?" so an
 * operator scanning the investigations list can tell a real finding
 * from an audit-clean no_finding without opening the row.
 *
 * The derivation contract is FIXED and MUST stay bit-identical to the
 * backend `_derive_outcome_polarity(outcome_kind, payload)` in
 * `aila/modules/vr/api_router.py`. Detail page re-derives client-side
 * from the full outcome payload; list page reads
 * `primary_outcome_polarity` off the summary.
 */

import type { ComponentType } from "react";
import type { IconProps } from "@phosphor-icons/react/lib";
import { CheckCircle } from "@phosphor-icons/react/dist/csr/CheckCircle";
import { Warning } from "@phosphor-icons/react/dist/csr/Warning";
import { WarningCircle } from "@phosphor-icons/react/dist/csr/WarningCircle";

import { AilaBadge } from "@/components/aila/AilaBadge";

export type OutcomePolarity = "finding" | "no_finding" | "inconclusive";

/**
 * FIXED derivation contract (mirror of the backend
 * `_derive_outcome_polarity`). Precedence:
 *   1. `payload.verifier_report.verdict === "confirmed"` -> `finding`
 *      `payload.verifier_report.verdict === "refuted"`   -> `no_finding`
 *   2. `outcome_kind === "direct_finding"`                -> `finding`
 *   3. `outcome_kind === "audit_memo"` and
 *      `payload.verdict === "no_finding"`                 -> `no_finding`
 *   4. otherwise                                          -> `inconclusive`
 *
 * `payload` is defensively coerced -- a missing / non-object payload
 * degrades to `inconclusive` rather than throwing.
 */
export function outcomePolarity(
  outcomeKind: string,
  payload: Record<string, unknown> | null | undefined,
): OutcomePolarity {
  const p: Record<string, unknown> =
    payload && typeof payload === "object" ? payload : {};

  const vr = p["verifier_report"];
  if (vr && typeof vr === "object") {
    const verdict = (vr as Record<string, unknown>)["verdict"];
    if (verdict === "confirmed") return "finding";
    if (verdict === "refuted") return "no_finding";
  }

  if (outcomeKind === "direct_finding") return "finding";
  if (outcomeKind === "audit_memo" && p["verdict"] === "no_finding") {
    return "no_finding";
  }
  return "inconclusive";
}

interface PolarityMeta {
  icon: ComponentType<IconProps>;
  label: string;
}

const POLARITY_META: Record<OutcomePolarity, PolarityMeta> = {
  finding: { icon: Warning, label: "Finding" },
  no_finding: { icon: CheckCircle, label: "No Finding" },
  inconclusive: { icon: WarningCircle, label: "Inconclusive" },
};

interface OutcomePolarityBadgeProps {
  polarity: OutcomePolarity;
  /** Show the label text next to the icon. Default true. */
  showLabel?: boolean;
  /** AilaBadge size passthrough. Default `sm` matches the surrounding pills. */
  size?: "sm" | "md" | "lg";
  className?: string;
  title?: string;
}

/**
 * Colored polarity pill built on top of AilaBadge. Reuses the existing
 * AilaBadge vocabulary so the pill lands on WCAG-tuned theme tokens:
 *
 *   - `finding`      -> severity `critical` (red, matches MASVS finding)
 *   - `no_finding`   -> status   `completed` (bright green, "audited clean")
 *   - `inconclusive` -> severity `medium`   (amber, "insufficient info")
 *
 * `no_finding` intentionally rides the status-* token namespace instead
 * of severity `low` (which the shared severity ramp maps to muted gray)
 * so the "audited clean" signal actually reads as success at a glance.
 */
export function OutcomePolarityBadge({
  polarity,
  showLabel = true,
  size = "sm",
  className = "",
  title,
}: OutcomePolarityBadgeProps) {
  const meta = POLARITY_META[polarity];
  const Icon = meta.icon;

  const badgeProps =
    polarity === "no_finding"
      ? ({ status: "completed" } as const)
      : polarity === "finding"
        ? ({ severity: "critical" } as const)
        : ({ severity: "medium" } as const);

  return (
    <AilaBadge
      {...badgeProps}
      size={size}
      className={`gap-1 ${className}`.trim()}
      title={title ?? meta.label}
    >
      <Icon size={11} weight="fill" aria-hidden />
      {showLabel && <span>{meta.label}</span>}
    </AilaBadge>
  );
}

