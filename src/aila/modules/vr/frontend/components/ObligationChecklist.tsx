import { MonoBadge, toneColor } from "@/components/aila/mock";
import { PixelIcon, type PixelIconName } from "@/components/aila/PixelIcon";

/** Obligation checklist (08_FRONTEND_UX.md §Topic 8).
 *
 *  Three states: met / unmet / waived. Each row is `severity` +
 *  state icon + `label` + optional `evidence_ref` (a clickable turn jump)
 *  + optional `tooltip` describing what would satisfy the obligation.
 *
 *  Backend wiring is pending -- no obligation API endpoint exists yet.
 *  This component is built so it's drop-in once that endpoint ships;
 *  for now callers should render an empty list with a "no obligations
 *  tracked yet" placeholder.
 *
 *  Color-blind safe: we render pixel icons alongside colour so
 *  red-green distinction never carries semantic weight alone. */

export type ObligationSeverity = "critical" | "required" | "recommended";
export type ObligationState = "met" | "unmet" | "waived";

export interface Obligation {
  id: string;
  label: string;
  severity: ObligationSeverity;
  state: ObligationState;
  evidence_ref?: string | null; // anchor in agent timeline (e.g. "#turn-12")
  waive_reason?: string | null;
  description?: string | null;
}

const SEVERITY_TONE: Record<ObligationSeverity, "critical" | "high" | "info"> = {
  critical: "critical",
  required: "high",
  recommended: "info",
};

const STATE_ICON: Record<ObligationState, PixelIconName | null> = {
  met: "ok",
  unmet: "close",
  waived: null,
};

const STATE_COLOR: Record<ObligationState, string> = {
  met: toneColor("ok"),
  unmet: toneColor("accent"),
  waived: "var(--text-faint)",
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
      <div
        className="font-mono"
        style={{
          textAlign: "center",
          padding: "18px 0",
          fontSize: 10.5,
          color: "var(--text-faint)",
          letterSpacing: "0.06em",
        }}
      >
        {emptyHint ?? "no obligations tracked yet"}
      </div>
    );
  }

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
    <div>
      <div
        className="flex items-center flex-wrap font-mono"
        style={{ gap: 6, marginBottom: 8 }}
      >
        <MonoBadge tone="ok">
          met {met}/{total}
        </MonoBadge>
        {waived > 0 && <MonoBadge tone="info">waived {waived}</MonoBadge>}
        {unmet > 0 && <MonoBadge tone="critical">unmet {unmet}</MonoBadge>}
      </div>
      <ul style={{ display: "flex", flexDirection: "column", gap: 3 }}>
        {sorted.map((o) => {
          const stateColor = STATE_COLOR[o.state];
          const icon = STATE_ICON[o.state];
          return (
            <li
              key={o.id}
              title={o.description ?? undefined}
              style={{
                display: "grid",
                gridTemplateColumns: "48px 60px 1fr 80px",
                alignItems: "center",
                gap: 8,
                border: "1px solid var(--border-soft)",
                background: "var(--surface-sunk)",
                padding: "6px 8px",
                borderRadius: 2,
                minHeight: 30,
              }}
            >
              <MonoBadge tone={SEVERITY_TONE[o.severity]}>{o.severity}</MonoBadge>
              <span
                aria-label={`state: ${o.state}`}
                className="inline-flex items-center justify-center"
                style={{ color: stateColor, width: 22, height: 22 }}
              >
                {icon ? (
                  <PixelIcon name={icon} size={12} />
                ) : (
                  <span
                    className="font-mono"
                    style={{ fontSize: 11, letterSpacing: 0 }}
                  >
                    --
                  </span>
                )}
              </span>
              <div style={{ minWidth: 0 }}>
                <div
                  style={{
                    fontFamily: "var(--font-sans)",
                    fontSize: 11.5,
                    color: "var(--text-primary)",
                    overflow: "hidden",
                    textOverflow: "ellipsis",
                    whiteSpace: "nowrap",
                  }}
                >
                  {o.label}
                </div>
                {o.state === "waived" && o.waive_reason && (
                  <div
                    className="font-mono"
                    style={{
                      fontSize: 9.5,
                      color: "var(--text-faint)",
                      fontStyle: "italic",
                      marginTop: 2,
                      letterSpacing: "0.04em",
                    }}
                  >
                    waived: {o.waive_reason}
                  </div>
                )}
              </div>
              {o.evidence_ref ? (
                <a
                  href={o.evidence_ref}
                  className="font-mono"
                  style={{
                    fontSize: 10,
                    color: "var(--text-muted)",
                    letterSpacing: "0.05em",
                    textAlign: "right",
                    textDecoration: "none",
                  }}
                  onMouseOver={(e) =>
                    (e.currentTarget.style.color = "var(--accent)")
                  }
                  onMouseOut={(e) =>
                    (e.currentTarget.style.color = "var(--text-muted)")
                  }
                >
                  {o.evidence_ref.startsWith("#") ? o.evidence_ref : `#${o.evidence_ref}`}
                </a>
              ) : (
                <span />
              )}
            </li>
          );
        })}
      </ul>
    </div>
  );
}
