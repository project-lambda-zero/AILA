import { useState, type CSSProperties } from "react";

import type { useReenqueueInvestigation, InvestigationKindOverride } from "../mutations";

/** Re-enqueue picker -- kind dropdown + submit button as one unit.
 *
 *  When the operator leaves the dropdown at "keep current", the
 *  request goes out with no kind override (preserves inv.kind). When
 *  they pick a different kind, the backend updates inv.kind +
 *  strategy_family before submitting the task -- turning a finished
 *  discovery into a variant_hunt (or vice versa) in one click.
 *
 *  Kind affects the system prompt (variant_hunt mandates emitting
 *  variant_hunt_orders) + the default strategy_family + which child
 *  spawning rules the dispatcher applies. Picking the wrong kind
 *  means the agent runs with the wrong instruction set, so the
 *  selector is deliberately visible (not buried in a modal).
 */
const KIND_OPTIONS: { value: InvestigationKindOverride; label: string }[] = [
  { value: "discovery",    label: "discovery -- find one bug" },
  { value: "variant_hunt", label: "variant hunt -- spawn child investigations" },
  { value: "triage",       label: "triage -- classify a reported issue" },
  { value: "n_day",        label: "n-day -- assess a known patch" },
  { value: "audit",        label: "audit -- broad source review" },
];

const CTRL: CSSProperties = {
  height: 28,
  padding: "0 8px",
  fontSize: 10,
  letterSpacing: "0.06em",
  background: "var(--surface-sunk)",
  color: "var(--text-primary)",
  border: "1px solid var(--border-soft)",
  borderRadius: 3,
  fontFamily: "var(--font-mono)",
  textTransform: "uppercase",
  maxWidth: "12rem",
  minWidth: 0,
};

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
    ? "re-enqueueing\u2026"
    : willConvert
      ? `re-enqueue as ${picked} \u21bb`
      : "re-enqueue \u21bb";
  const tooltip = willConvert
    ? `Update inv.kind from "${currentKind}" to "${picked}" + strategy_family, then submit a fresh run_vr_investigate task. Case state (hypotheses, observables) is preserved.`
    : `Reset to created + submit a fresh run_vr_investigate task. Case state (hypotheses, observables) is preserved -- the agent resumes from where it left off, not from turn 1.`;

  return (
    <div className="flex items-center flex-wrap min-w-0 max-w-full" style={{ gap: 6 }}>
      <select
        value={picked}
        onChange={(e) => setPicked(e.target.value as InvestigationKindOverride | "")}
        disabled={mutation.isPending}
        className="truncate"
        style={{ ...CTRL, opacity: mutation.isPending ? 0.5 : 1 }}
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
        className="font-mono uppercase whitespace-nowrap"
        style={{
          height: 28,
          padding: "0 12px",
          fontSize: 10,
          letterSpacing: "0.08em",
          background: "var(--surface-sunk)",
          border: "1px solid var(--border-soft)",
          color: "var(--text-primary)",
          borderRadius: 3,
          cursor: mutation.isPending ? "not-allowed" : "pointer",
          opacity: mutation.isPending ? 0.5 : 1,
        }}
        title={tooltip}
      >
        {label}
      </button>
    </div>
  );
}
