import { AilaBadge } from "@/components/aila/AilaBadge";

/** CVSS v3.1 severity badge + breakdown table.
 *
 *  Colour scheme follows NVD (08_FRONTEND_UX.md §Topic 7 Lena's quote).
 *  Critical=dark red, High=red, Medium=orange, Low=yellow, None=gray. */

export type CVSSSeverity =
  | "critical"
  | "high"
  | "medium"
  | "low"
  | "none";

export function severityFromScore(score: number | null | undefined): CVSSSeverity {
  if (score == null || score <= 0) return "none";
  if (score >= 9.0) return "critical";
  if (score >= 7.0) return "high";
  if (score >= 4.0) return "medium";
  return "low";
}

const SEVERITY_TONE: Record<
  CVSSSeverity,
  "info" | "low" | "medium" | "high" | "critical"
> = {
  critical: "critical",
  high: "critical",
  medium: "high",
  low: "medium",
  none: "info",
};

export function CVSSBadge({
  score,
  vector,
  source,
  className = "",
}: {
  score: number | null | undefined;
  vector?: string | null;
  source?: string | null;
  className?: string;
}) {
  const sev = severityFromScore(score);
  const tip = [
    vector ? `Vector: ${vector}` : null,
    source ? `Source: ${source}` : null,
  ]
    .filter(Boolean)
    .join("\n");
  return (
    <AilaBadge severity={SEVERITY_TONE[sev]} size="sm" title={tip || undefined}>
      <span className={className}>
        {score != null ? score.toFixed(1) : "—"}{" "}
        <span className="opacity-80">{sev.toUpperCase()}</span>
      </span>
    </AilaBadge>
  );
}

// ─── CVSS v3.1 metric definitions ──────────────────────────────────────

interface MetricSpec {
  id: string;
  label: string;
  values: ReadonlyArray<{ id: string; label: string; description: string }>;
}

const ATTACK_VECTOR: MetricSpec = {
  id: "AV",
  label: "Attack Vector",
  values: [
    { id: "N", label: "Network", description: "Remote — across the network." },
    { id: "A", label: "Adjacent", description: "Adjacent network (same broadcast/collision domain)." },
    { id: "L", label: "Local", description: "Local logon required." },
    { id: "P", label: "Physical", description: "Physical access required." },
  ],
};
const ATTACK_COMPLEXITY: MetricSpec = {
  id: "AC",
  label: "Attack Complexity",
  values: [
    { id: "L", label: "Low", description: "No special conditions required." },
    { id: "H", label: "High", description: "Specialised configuration / race window required." },
  ],
};
const PRIVS_REQUIRED: MetricSpec = {
  id: "PR",
  label: "Privileges Required",
  values: [
    { id: "N", label: "None", description: "Unauthenticated attacker." },
    { id: "L", label: "Low", description: "User-level privileges." },
    { id: "H", label: "High", description: "Admin-level privileges." },
  ],
};
const USER_INTERACTION: MetricSpec = {
  id: "UI",
  label: "User Interaction",
  values: [
    { id: "N", label: "None", description: "No user action required." },
    { id: "R", label: "Required", description: "Victim must interact (e.g. open file)." },
  ],
};
const SCOPE: MetricSpec = {
  id: "S",
  label: "Scope",
  values: [
    { id: "U", label: "Unchanged", description: "Impact contained in vulnerable component." },
    { id: "C", label: "Changed", description: "Impact extends to other components." },
  ],
};
const CIA: MetricSpec = {
  id: "C",
  label: "Confidentiality Impact",
  values: [
    { id: "N", label: "None", description: "No impact." },
    { id: "L", label: "Low", description: "Limited disclosure." },
    { id: "H", label: "High", description: "Total disclosure." },
  ],
};
const INTEGRITY: MetricSpec = {
  ...CIA,
  id: "I",
  label: "Integrity Impact",
};
const AVAILABILITY: MetricSpec = {
  ...CIA,
  id: "A",
  label: "Availability Impact",
};

export const CVSS_METRICS: ReadonlyArray<MetricSpec> = [
  ATTACK_VECTOR,
  ATTACK_COMPLEXITY,
  PRIVS_REQUIRED,
  USER_INTERACTION,
  SCOPE,
  CIA,
  INTEGRITY,
  AVAILABILITY,
];

/** Parse a CVSS:3.1 vector string into a metric-id → value-id map. */
export function parseVector(vector: string | null | undefined): Record<string, string> {
  const out: Record<string, string> = {};
  if (!vector) return out;
  for (const part of vector.replace(/^CVSS:3\.[01]\//, "").split("/")) {
    const [k, v] = part.split(":");
    if (k && v) out[k] = v;
  }
  return out;
}

/** Render a CVSS vector as an 8-metric table — read-only display. */
export function CVSSBreakdown({
  vector,
  score,
  source,
}: {
  vector: string | null | undefined;
  score: number | null | undefined;
  source?: string | null;
}) {
  const parsed = parseVector(vector);
  const sev = severityFromScore(score);
  return (
    <div className="space-y-2">
      <div className="flex items-center gap-2 flex-wrap">
        <CVSSBadge score={score} vector={vector} source={source} />
        {vector && (
          <code className="text-3xs font-mono text-text-muted break-all">
            {vector}
          </code>
        )}
        {source && (
          <AilaBadge severity="info" size="sm">
            source: {source}
          </AilaBadge>
        )}
      </div>
      <table className="w-full text-xs font-mono">
        <tbody>
          {CVSS_METRICS.map((m) => {
            const selected = parsed[m.id];
            const valueSpec = m.values.find((v) => v.id === selected);
            return (
              <tr key={m.id} className="border-b border-border-default last:border-b-0">
                <td className="px-2 py-1 text-text-muted whitespace-nowrap w-32">
                  {m.label} ({m.id})
                </td>
                <td className="px-2 py-1 text-foreground">
                  {valueSpec ? (
                    <span>
                      <strong>{valueSpec.label}</strong>
                      <span className="text-text-muted ml-2 font-sans text-3xs">
                        {valueSpec.description}
                      </span>
                    </span>
                  ) : (
                    <span className="text-text-muted">—</span>
                  )}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
      <p className="text-3xs text-text-muted">
        Severity: <span className="uppercase font-semibold">{sev}</span>
        {score != null && ` · Score: ${score.toFixed(1)}`}
      </p>
    </div>
  );
}

// ─── CWE Badge ─────────────────────────────────────────────────────────

export function CWEBadge({
  cweId,
  name,
}: {
  cweId: string | null | undefined;
  name?: string | null;
}) {
  if (!cweId) return null;
  const href = `https://cwe.mitre.org/data/definitions/${cweId.replace(/^CWE-/, "")}.html`;
  return (
    <a
      href={href}
      target="_blank"
      rel="noopener noreferrer"
      title={name ?? `Open ${cweId} on cwe.mitre.org`}
      className="inline-flex items-center gap-1 text-3xs font-mono px-1.5 py-0.5 rounded bg-surface border border-border-default text-foreground hover:bg-surface-hover"
    >
      {cweId}
      {name && <span className="text-text-muted truncate" style={{ maxWidth: "18ch" }}>— {name}</span>}
    </a>
  );
}
