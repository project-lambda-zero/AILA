import { AilaBadge } from "@/components/aila/AilaBadge";

/** Obligation checklist (08_FRONTEND_UX.md §Topic 8).
 *
 *  Three states: met / unmet / waived. Each row is `severity` +
 *  `label` + `state` + optional `evidence_ref` (a clickable turn jump)
 *  + optional `tooltip` describing what would satisfy the obligation.
 *
 *  Backend wiring is pending — no obligation API endpoint exists yet.
 *  This component is built so it's drop-in once that endpoint ships;
 *  for now callers should render an empty list with a "no obligations
 *  tracked yet" placeholder.
 *
 *  Color-blind safe: we render icons (✓ / ✗ / —) alongside colour so
 *  red-green distinction never carries semantic weight alone. */

export type ObligationSeverity = "critical" | "required" | "recommended";
export type ObligationState = "met" | "unmet" | "waived";

export interface Obligation {
  id: string;
  label: string;
  severity: ObligationSeverity;
  state: ObligationState;
  evidence_ref?: string | null;  // anchor in agent timeline (e.g. "#turn-12")
  waive_reason?: string | null;
  description?: string | null;
}

const SEVERITY_TONE: Record<
  ObligationSeverity,
  "info" | "low" | "medium" | "high" | "critical"
> = {
  critical: "critical",
  required: "high",
  recommended: "info",
};

const STATE_ICON: Record<ObligationState, string> = {
  met: "✓",
  unmet: "✗",
  waived: "—",
};

const STATE_TEXT_CLASS: Record<ObligationState, string> = {
  met: "text-green-500",
  unmet: "text-red-500",
  waived: "text-text-muted italic",
};

export function ObligationChecklist({
  obligations,
  emptyHint,
}: {
  obligations: ReadonlyArray<Obligation>;
  emptyHint?: string;
}) {
  if (obligations.length === 0) {
    return (
      <p className="text-xs text-text-muted text-center py-4">
        {emptyHint ?? "No obligations tracked yet."}
      </p>
    );
  }

  // Group by severity, criticals first.
  const order: Record<ObligationSeverity, number> = {
    critical: 0,
    required: 1,
    recommended: 2,
  };
  const sorted = [...obligations].sort(
    (a, b) => order[a.severity] - order[b.severity],
  );

  const total = obligations.length;
  const met = obligations.filter((o) => o.state === "met").length;
  const waived = obligations.filter((o) => o.state === "waived").length;
  const unmet = obligations.filter((o) => o.state === "unmet").length;

  return (
    <div className="space-y-2">
      <div className="flex items-center gap-2 flex-wrap text-xs text-text-muted">
        <AilaBadge severity="low" size="sm">
          met {met}/{total}
        </AilaBadge>
        {waived > 0 && (
          <AilaBadge severity="info" size="sm">
            waived {waived}
          </AilaBadge>
        )}
        {unmet > 0 && (
          <AilaBadge severity="critical" size="sm">
            unmet {unmet}
          </AilaBadge>
        )}
      </div>
      <ul className="space-y-1">
        {sorted.map((o) => (
          <li
            key={o.id}
            className="flex items-start gap-2 border border-border-default rounded px-2 py-1.5"
            title={o.description ?? undefined}
          >
            <span
              className={`text-base leading-none w-4 ${STATE_TEXT_CLASS[o.state]}`}
              aria-label={`state: ${o.state}`}
            >
              {STATE_ICON[o.state]}
            </span>
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2 flex-wrap">
                <span className="text-xs font-mono text-foreground truncate">
                  {o.label}
                </span>
                <AilaBadge severity={SEVERITY_TONE[o.severity]} size="sm">
                  {o.severity}
                </AilaBadge>
                {o.state === "waived" && o.waive_reason && (
                  <span className="text-3xs text-text-muted italic">
                    waived: {o.waive_reason}
                  </span>
                )}
              </div>
              {o.evidence_ref && (
                <a
                  href={o.evidence_ref}
                  className="text-3xs font-mono text-text-muted hover:text-foreground hover:underline"
                >
                  ↪ evidence
                </a>
              )}
            </div>
          </li>
        ))}
      </ul>
    </div>
  );
}
