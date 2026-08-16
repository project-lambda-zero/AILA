import type { ComponentType } from "react";
import type { IconProps } from "@phosphor-icons/react/lib";
import { Crosshair } from "@phosphor-icons/react/dist/csr/Crosshair";
import { FileText } from "@phosphor-icons/react/dist/csr/FileText";
import { GitBranch } from "@phosphor-icons/react/dist/csr/GitBranch";
import { Bug } from "@phosphor-icons/react/dist/csr/Bug";
import { Gear } from "@phosphor-icons/react/dist/csr/Gear";
import { TreeStructure } from "@phosphor-icons/react/dist/csr/TreeStructure";
import { Notepad } from "@phosphor-icons/react/dist/csr/Notepad";
import { Rocket } from "@phosphor-icons/react/dist/csr/Rocket";
import { MagnifyingGlass } from "@phosphor-icons/react/dist/csr/MagnifyingGlass";

import { MonoBadge } from "@/components/aila/mock";

import type { OutcomeKind } from "../types";

type OutcomeSeverity = "info" | "low" | "medium" | "high" | "critical";

interface OutcomeKindMeta {
  icon: ComponentType<IconProps>;
  label: string;
  severity: OutcomeSeverity;
}

const OUTCOME_KIND_MAP: Record<OutcomeKind, OutcomeKindMeta> = {
  direct_finding: {
    icon: Crosshair,
    label: "Finding",
    severity: "high",
  },
  assessment_report: {
    icon: FileText,
    label: "Assessment",
    severity: "info",
  },
  patch_assessment_report: {
    icon: FileText,
    label: "Patch Assessment",
    severity: "info",
  },
  variant_hunt_order: {
    icon: GitBranch,
    label: "Variant Hunt",
    severity: "medium",
  },
  crash_triage_report: {
    icon: Bug,
    label: "Crash Triage",
    severity: "critical",
  },
  audit_memo: {
    icon: Notepad,
    label: "Audit Memo",
    severity: "low",
  },
  strategy_descriptor: {
    icon: TreeStructure,
    label: "Strategy",
    severity: "low",
  },
  profile_spec_draft: {
    icon: Gear,
    label: "Profile Spec",
    severity: "low",
  },
  config_delta: {
    icon: Gear,
    label: "Config Delta",
    severity: "low",
  },
  campaign_launch: {
    icon: Rocket,
    label: "Fuzz Campaign",
    severity: "medium",
  },
  sub_investigation: {
    icon: MagnifyingGlass,
    label: "Sub-Investigation",
    severity: "medium",
  },
};

const FALLBACK: OutcomeKindMeta = {
  icon: FileText,
  label: "Unknown",
  severity: "info",
};

// Severity -> MonoBadge tone mapping (see wave-2 brief).
const SEVERITY_TONE: Record<OutcomeSeverity, string> = {
  info: "info",
  low: "ok",
  medium: "medium",
  high: "high",
  critical: "critical",
};

interface OutcomeKindBadgeProps {
  kind: OutcomeKind | string;
  /** Show the label text next to the icon. Default true. */
  showLabel?: boolean;
  className?: string;
}

/**
 * Renders an outcome_kind as an icon + human-readable label
 * inside a MonoBadge chip.
 */
export function OutcomeKindBadge({
  kind,
  showLabel = true,
  className: _className = "",
}: OutcomeKindBadgeProps) {
  const meta = OUTCOME_KIND_MAP[kind as OutcomeKind] ?? FALLBACK;
  const Icon = meta.icon;
  return (
    <MonoBadge tone={SEVERITY_TONE[meta.severity]} title={kind}>
      <span className="inline-flex items-center" style={{ gap: 4 }}>
        <Icon size={11} weight="bold" aria-hidden />
        {showLabel ? <span>{meta.label}</span> : null}
      </span>
    </MonoBadge>
  );
}

/** Expose severity mapping for callers (accepted values map cleanly to
 *  MonoBadge tone keys via the wave-2 severity->tone table). */
export function outcomeKindSeverity(
  kind: OutcomeKind | string,
): OutcomeSeverity {
  return (OUTCOME_KIND_MAP[kind as OutcomeKind] ?? FALLBACK).severity;
}

/** Expose label mapping for callers that need just the text. */
export function outcomeKindLabel(kind: OutcomeKind | string): string {
  return (OUTCOME_KIND_MAP[kind as OutcomeKind] ?? FALLBACK).label;
}
