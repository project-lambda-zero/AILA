import { MonoBadge } from "@/components/aila/mock";

/** CVSS v3.1 severity badge + breakdown table.
 *
 *  Colour scheme follows NVD (08_FRONTEND_UX.md §Topic 7 Lena's quote).
 *  Critical=accent, High=warn, Medium=info, Low=ok, None=muted. */

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

const SEVERITY_TONE: Record<CVSSSeverity, string> = {
  critical: "critical",
  high: "high",
  medium: "medium",
  low: "ok",
  none: "muted",
};

export function CVSSBadge({
  score,
  vector,
  source,
  className: _className = "",
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
    <MonoBadge tone={SEVERITY_TONE[sev]} title={tip || undefined}>
      {score != null ? score.toFixed(1) : "--"}
      <span style={{ marginLeft: 4, opacity: 0.8 }}>{sev.toUpperCase()}</span>
    </MonoBadge>
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
    { id: "N", label: "Network", description: "Remote -- across the network." },
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

/** Render a CVSS vector as an 8-metric table -- read-only display.
 *
 *  Callers place this INSIDE a WindowPanel body, so no outer chrome.
 */
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
    <div className="flex flex-col" style={{ gap: 10 }}>
      <div className="flex items-center flex-wrap" style={{ gap: 8 }}>
        <CVSSBadge score={score} vector={vector} source={source} />
        {vector ? (
          <code
            className="font-mono"
            style={{
              fontSize: 10,
              color: "var(--text-muted)",
              wordBreak: "break-all",
            }}
          >
            {vector}
          </code>
        ) : null}
        {source ? (
          <MonoBadge tone="info">source: {source}</MonoBadge>
        ) : null}
      </div>
      <table
        className="font-mono"
        style={{
          width: "100%",
          fontSize: 11,
          borderCollapse: "collapse",
          border: "1px solid var(--border-soft)",
        }}
      >
        <caption className="sr-only">CVSS metric breakdown</caption>
        <tbody>
          {CVSS_METRICS.map((m, idx) => {
            const selected = parsed[m.id];
            const valueSpec = m.values.find((v) => v.id === selected);
            const isLast = idx === CVSS_METRICS.length - 1;
            return (
              <tr key={m.id}>
                <th
                  scope="row"
                  style={{
                    padding: "6px 10px",
                    textAlign: "left",
                    fontWeight: 400,
                    letterSpacing: "0.04em",
                    color: "var(--text-muted)",
                    background: "var(--surface-sunk)",
                    borderBottom: isLast
                      ? "none"
                      : "1px solid var(--border-soft)",
                    whiteSpace: "nowrap",
                    width: 160,
                  }}
                >
                  {m.label} ({m.id})
                </th>
                <td
                  style={{
                    padding: "6px 10px",
                    color: "var(--text-primary)",
                    borderBottom: isLast
                      ? "none"
                      : "1px solid var(--border-soft)",
                    borderLeft: "1px solid var(--border-soft)",
                  }}
                >
                  {valueSpec ? (
                    <span>
                      <strong style={{ fontWeight: 600 }}>{valueSpec.label}</strong>
                      <span
                        style={{
                          marginLeft: 8,
                          color: "var(--text-faint)",
                          fontFamily: "var(--font-display)",
                          fontSize: 10,
                        }}
                      >
                        {valueSpec.description}
                      </span>
                    </span>
                  ) : (
                    <span style={{ color: "var(--text-faint)" }}>--</span>
                  )}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
      <p
        className="font-mono uppercase"
        style={{
          fontSize: 10,
          letterSpacing: "0.06em",
          color: "var(--text-muted)",
        }}
      >
        Severity:{" "}
        <span style={{ fontWeight: 600, color: "var(--text-primary)" }}>
          {sev}
        </span>
        {score != null ? ` · Score: ${score.toFixed(1)}` : null}
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
  const label = name ? `${cweId} -- ${name}` : `Open ${cweId} on cwe.mitre.org`;
  return (
    <a
      href={href}
      target="_blank"
      rel="noopener noreferrer"
      title={label}
      className="inline-flex items-center"
      style={{ gap: 6, textDecoration: "none" }}
    >
      <MonoBadge tone="info">
        {cweId}
        {name ? (
          <span
            style={{
              marginLeft: 6,
              color: "var(--text-muted)",
              maxWidth: "18ch",
              overflow: "hidden",
              textOverflow: "ellipsis",
              whiteSpace: "nowrap",
              display: "inline-block",
              verticalAlign: "bottom",
            }}
          >
            {name}
          </span>
        ) : null}
      </MonoBadge>
    </a>
  );
}
