import { useState } from "react";

import type { useReenqueueInvestigation, InvestigationKindOverride } from "../mutations";

/** Re-enqueue picker — kind dropdown + submit button as one unit.
 *
 *  When the operator leaves the dropdown at "keep current", the
 *  request goes out with no kind override (preserves inv.kind). When
 *  they pick a different kind, the backend updates inv.kind +
 *  strategy_family before submitting the task — turning a finished
 *  discovery into a variant_hunt (or vice versa) in one click.
 *
 *  Kind affects the system prompt (variant_hunt mandates emitting
 *  variant_hunt_orders) + the default strategy_family + which child
 *  spawning rules the dispatcher applies. Picking the wrong kind
 *  means the agent runs with the wrong instruction set, so the
 *  selector is deliberately visible (not buried in a modal).
 */
const KIND_OPTIONS: { value: InvestigationKindOverride; label: string }[] = [
  { value: "discovery",    label: "Discovery — find one bug" },
  { value: "variant_hunt", label: "Variant hunt — spawn child investigations" },
  { value: "triage",       label: "Triage — classify a reported issue" },
  { value: "n_day",        label: "N-day — assess a known patch" },
  { value: "audit",        label: "Audit — broad source review" },
];

export function ReenqueuePicker({
  currentKind,
  mutation,
}: {
  currentKind: string;
  mutation: ReturnType<typeof useReenqueueInvestigation>;
}) {
  const [picked, setPicked] = useState<InvestigationKindOverride | "">("");

  const willConvert = picked !== "" && picked !== currentKind;
  const label = mutation.isPending
    ? "Re-enqueueing…"
    : willConvert
      ? `Re-enqueue as ${picked} ↻`
      : "Re-enqueue ↻";
  const tooltip = willConvert
    ? `Update inv.kind from "${currentKind}" to "${picked}" + strategy_family, then submit a fresh run_vr_investigate task. Case state (hypotheses, observables) is preserved.`
    : `Reset to created + submit a fresh run_vr_investigate task. Case state (hypotheses, observables) is preserved — the agent resumes from where it left off, not from turn 1.`;

  return (
    <div className="flex items-center gap-1 flex-wrap min-w-0 max-w-full">
      <select
        value={picked}
        onChange={(e) => setPicked(e.target.value as InvestigationKindOverride | "")}
        disabled={mutation.isPending}
        className="text-xs px-2 py-1.5 rounded-md bg-surface border border-border-default text-foreground disabled:opacity-50 truncate"
        style={{ maxWidth: "10rem" }}
        title="Optionally convert to a different kind before re-enqueueing"
      >
        <option value="">keep: {currentKind}</option>
        {KIND_OPTIONS.filter((k) => k.value !== currentKind).map((k) => (
          <option key={k.value} value={k.value}>
            {k.label}
          </option>
        ))}
      </select>
      <button
        type="button"
        onClick={() => mutation.mutate(picked ? { kind: picked } : undefined)}
        disabled={mutation.isPending}
        className="px-3 py-1.5 text-xs font-medium rounded-md bg-surface border border-border-default hover:bg-surface-hover disabled:opacity-50 whitespace-nowrap"
        title={tooltip}
      >
        {label}
      </button>
    </div>
  );
}
