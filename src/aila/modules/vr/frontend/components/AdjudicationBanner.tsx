import { MonoBadge, toneColor } from "@/components/aila/mock";

/** Adjudication banner Topic 8.
 *
 *  Three verdicts:
 *    accepted   → mint accent block with check
 *    downgraded → amber accent block with reason
 *    blocked    → hot-pink accent block with unmet-obligations list
 *
 *  Render at the top of finding-detail / outcome surfaces. */
export type AdjudicationVerdict = "accepted" | "downgraded" | "blocked";

export interface AdjudicationResult {
  verdict: AdjudicationVerdict;
  reason?: string;
  unmet_obligations?: string[];
  hedge_phrases?: string[];
  met_critical?: number;
  total_critical?: number;
  budget_used_pct?: number;
}

const TONE: Record<
  AdjudicationVerdict,
  { hue: string; badge: "ok" | "warn" | "critical" }
> = {
  accepted: { hue: toneColor("ok"), badge: "ok" },
  downgraded: { hue: toneColor("warn"), badge: "warn" },
  blocked: { hue: toneColor("accent"), badge: "critical" },
};

export function AdjudicationBanner({ result }: { result: AdjudicationResult }) {
  const tone = TONE[result.verdict];
  return (
    <div
      className="font-mono"
      style={{
        border: "1px solid var(--border-soft)",
        borderLeft: `3px solid ${tone.hue}`,
        background: `color-mix(in srgb, ${tone.hue} 8%, transparent)`,
        padding: "8px 10px",
      }}
    >
      <div className="flex items-center flex-wrap" style={{ gap: 8 }}>
        <span
          aria-hidden
          style={{
            width: 12,
            height: 12,
            flex: "0 0 auto",
            background: tone.hue,
            boxShadow: `0 0 5px ${tone.hue}`,
          }}
        />
        <MonoBadge tone={tone.badge}>{result.verdict}</MonoBadge>
        {result.total_critical != null && (
          <span
            className="font-mono"
            style={{ fontSize: 10, color: "var(--text-muted)", letterSpacing: "0.06em" }}
          >
            {result.met_critical ?? 0}/{result.total_critical} critical met
          </span>
        )}
        {result.budget_used_pct != null && (
          <span
            className="font-mono"
            style={{ fontSize: 10, color: "var(--text-muted)", letterSpacing: "0.06em" }}
          >
            · budget {Math.round(result.budget_used_pct)}%
          </span>
        )}
      </div>
      {result.reason && (
        <p
          style={{
            marginTop: 6,
            fontFamily: "var(--font-sans)",
            fontSize: 11.5,
            lineHeight: 1.45,
            color: "var(--text-primary)",
          }}
        >
          {result.reason}
        </p>
      )}
      {result.hedge_phrases && result.hedge_phrases.length > 0 && (
        <div
          className="font-mono"
          style={{
            marginTop: 6,
            display: "flex",
            flexWrap: "wrap",
            gap: 6,
            alignItems: "center",
            fontSize: 10,
            color: "var(--text-muted)",
            letterSpacing: "0.05em",
          }}
        >
          <span>hedge:</span>
          {result.hedge_phrases.map((p) => (
            <code
              key={p}
              style={{
                fontFamily: "var(--font-mono)",
                fontSize: 10,
                padding: "1px 5px",
                border: "1px solid color-mix(in srgb, var(--status-warn) 32%, transparent)",
                background: "color-mix(in srgb, var(--status-warn) 10%, transparent)",
                color: "var(--status-warn)",
                borderRadius: 2,
              }}
            >
              {p}
            </code>
          ))}
        </div>
      )}
      {result.unmet_obligations && result.unmet_obligations.length > 0 && (
        <ul
          className="font-mono"
          style={{
            marginTop: 6,
            marginLeft: 14,
            fontSize: 10.5,
            color: "var(--text-muted)",
            listStyle: "disc",
            lineHeight: 1.55,
          }}
        >
          {result.unmet_obligations.map((o) => (
            <li key={o}>{o}</li>
          ))}
        </ul>
      )}
    </div>
  );
}
