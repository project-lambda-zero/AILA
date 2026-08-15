import { AilaBadge } from "@/components/aila/AilaBadge";

/** Adjudication banner Topic 8.
 *
 *  Three verdicts:
 *    accepted   → green banner with check
 *    downgraded → amber banner with reason
 *    blocked    → red banner with unmet-obligations list
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
  { hue: string; badge: "low" | "medium" | "critical"; icon: string }
> = {
  accepted: {
    hue: "var(--color-mint)",
    badge: "low",
    icon: "✓",
  },
  downgraded: {
    hue: "var(--color-amber)",
    badge: "medium",
    icon: "△",
  },
  blocked: {
    hue: "var(--color-critical)",
    badge: "critical",
    icon: "✗",
  },
};

export function AdjudicationBanner({ result }: { result: AdjudicationResult }) {
  const tone = TONE[result.verdict];
  return (
    <div
      className="border-l-4 rounded px-3 py-2"
      style={{
        borderColor: tone.hue,
        background: `color-mix(in srgb, ${tone.hue} 10%, transparent)`,
      }}
    >
      <div className="flex items-center gap-2 flex-wrap">
        <span className="text-lg leading-none" aria-hidden>
          {tone.icon}
        </span>
        <AilaBadge severity={tone.badge} size="sm">
          {result.verdict}
        </AilaBadge>
        {result.total_critical != null && (
          <span className="text-xs text-text-muted">
            {result.met_critical ?? 0}/{result.total_critical} critical
            obligations met
          </span>
        )}
        {result.budget_used_pct != null && (
          <span className="text-xs text-text-muted">
            · budget {Math.round(result.budget_used_pct)}%
          </span>
        )}
      </div>
      {result.reason && (
        <p className="text-xs text-foreground mt-1">{result.reason}</p>
      )}
      {result.hedge_phrases && result.hedge_phrases.length > 0 && (
        <p className="text-3xs text-text-muted mt-1">
          Hedge phrases:{" "}
          <code style={{ color: "var(--color-amber)" }}>
            {result.hedge_phrases.join(", ")}
          </code>
        </p>
      )}
      {result.unmet_obligations && result.unmet_obligations.length > 0 && (
        <ul className="text-3xs text-text-muted mt-1 list-disc ml-4">
          {result.unmet_obligations.map((o) => (
            <li key={o}>{o}</li>
          ))}
        </ul>
      )}
    </div>
  );
}
