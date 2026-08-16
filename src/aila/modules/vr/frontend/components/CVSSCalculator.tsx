import { useEffect, useMemo, useState } from "react";

import { MonoBadge } from "@/components/aila/mock";

import {
  CVSS_METRICS,
  CVSSBadge,
  parseVector,
  severityFromScore,
} from "./CVSSBadge";

/** Interactive CVSS v3.1 calculator (08_FRONTEND_UX.md §1.8.2).
 *
 *  Operator clicks one button per metric. Vector string + base score
 *  recompute live. The base-score formula matches the FIRST CVSS v3.1
 *  spec (https://www.first.org/cvss/v3.1/specification-document §7.1).
 *  Read-only score; the operator's job is to set metrics, not adjust
 *  the number. */
export function CVSSCalculator({
  initialVector,
  onChange,
}: {
  initialVector?: string | null;
  onChange?: (vector: string, score: number) => void;
}) {
  const initial = parseVector(initialVector);
  const [values, setValues] = useState<Record<string, string>>(initial);
  const [version, setVersion] = useState<"v3.1" | "v4.0">("v3.1");

  const { vector, score } = useMemo(() => computeCVSS(values), [values]);

  useEffect(() => {
    if (onChange) onChange(vector, score);
  }, [vector, score, onChange]);

  function pick(metricId: string, valueId: string) {
    setValues((prev) => ({ ...prev, [metricId]: valueId }));
  }

  if (version === "v4.0") {
    return (
      <div className="flex flex-col" style={{ gap: 12 }}>
        <VersionTabs version={version} setVersion={setVersion} />
        <div
          style={{
            padding: 12,
            border: "1px dashed var(--border-soft)",
            borderRadius: 3,
            background: "var(--surface-sunk)",
          }}
        >
          <p
            className="font-mono uppercase"
            style={{
              fontSize: 10,
              letterSpacing: "0.06em",
              color: "var(--text-primary)",
            }}
          >
            <strong>CVSS v4.0 calculator -- backend pending.</strong>
          </p>
          <p
            style={{
              marginTop: 8,
              fontFamily: "var(--font-display)",
              fontSize: 11,
              color: "var(--text-muted)",
              lineHeight: 1.5,
            }}
          >
            v4.0 introduces 11 base metrics + threat + environmental +
            supplemental groups + a fundamentally different score
            formula. The spec calls for both v3.1 + v4.0 because some
            consumers (vendor PSIRTs) still demand the older vector
            string. Wiring v4 requires shipping the FIRST v4.0
            specification-document §7 computation; tracked as a
            v0.6 follow-up.
          </p>
          <p
            className="font-mono"
            style={{
              marginTop: 8,
              fontSize: 10,
              color: "var(--text-faint)",
              letterSpacing: "0.04em",
            }}
          >
            Use v3.1 above to produce a vector now.
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="flex flex-col" style={{ gap: 12 }}>
      <VersionTabs version={version} setVersion={setVersion} />
      {CVSS_METRICS.map((m) => (
        <div key={m.id}>
          <div
            className="font-mono uppercase"
            style={{
              marginBottom: 4,
              fontSize: 10,
              letterSpacing: "0.08em",
              color: "var(--text-muted)",
            }}
          >
            {m.label}{" "}
            <span style={{ opacity: 0.7 }}>({m.id})</span>
          </div>
          <div className="flex flex-wrap" style={{ gap: 4 }}>
            {m.values.map((v) => {
              const active = values[m.id] === v.id;
              return (
                <button
                  key={v.id}
                  type="button"
                  onClick={() => pick(m.id, v.id)}
                  title={v.description}
                  className="font-mono uppercase"
                  style={{
                    height: 26,
                    padding: "0 10px",
                    fontSize: 10,
                    letterSpacing: "0.06em",
                    borderRadius: 3,
                    cursor: "pointer",
                    color: active
                      ? "var(--text-on-accent)"
                      : "var(--text-primary)",
                    border: `1px solid ${active ? "var(--accent)" : "var(--border-soft)"}`,
                    background: active
                      ? "var(--accent)"
                      : "var(--surface-sunk)",
                  }}
                >
                  {v.label} ({v.id})
                </button>
              );
            })}
          </div>
        </div>
      ))}

      <div
        className="flex items-center flex-wrap"
        style={{
          gap: 8,
          paddingTop: 10,
          borderTop: "1px solid var(--border-soft)",
        }}
      >
        <CVSSBadge score={score} vector={vector} />
        <code
          className="font-mono"
          style={{
            fontSize: 10,
            color: "var(--text-muted)",
            wordBreak: "break-all",
          }}
        >
          {vector || "fill all 8 metrics \u2192"}
        </code>
        <MonoBadge tone="info">
          {severityFromScore(score).toUpperCase()}
        </MonoBadge>
      </div>
    </div>
  );
}

// ─── CVSS v3.1 base-score computation ──────────────────────────────────
// Reference: https://www.first.org/cvss/v3.1/specification-document §7.1

const WEIGHTS = {
  AV: { N: 0.85, A: 0.62, L: 0.55, P: 0.2 },
  AC: { L: 0.77, H: 0.44 },
  PR_U: { N: 0.85, L: 0.62, H: 0.27 }, // scope unchanged
  PR_C: { N: 0.85, L: 0.68, H: 0.5 },  // scope changed
  UI: { N: 0.85, R: 0.62 },
  C:  { N: 0, L: 0.22, H: 0.56 },
  I:  { N: 0, L: 0.22, H: 0.56 },
  A:  { N: 0, L: 0.22, H: 0.56 },
} as const;

function computeCVSS(values: Record<string, string>): {
  vector: string;
  score: number;
} {
  const required = ["AV", "AC", "PR", "UI", "S", "C", "I", "A"];
  if (!required.every((k) => values[k])) {
    return { vector: "", score: 0 };
  }

  const av = (WEIGHTS.AV as Record<string, number>)[values.AV];
  const ac = (WEIGHTS.AC as Record<string, number>)[values.AC];
  const scope = values.S; // U or C
  const pr =
    scope === "C"
      ? (WEIGHTS.PR_C as Record<string, number>)[values.PR]
      : (WEIGHTS.PR_U as Record<string, number>)[values.PR];
  const ui = (WEIGHTS.UI as Record<string, number>)[values.UI];
  const c = (WEIGHTS.C as Record<string, number>)[values.C];
  const i = (WEIGHTS.I as Record<string, number>)[values.I];
  const a = (WEIGHTS.A as Record<string, number>)[values.A];

  if ([av, ac, pr, ui, c, i, a].some((x) => x == null)) {
    return { vector: "", score: 0 };
  }

  const iss = 1 - (1 - c) * (1 - i) * (1 - a);
  const impact =
    scope === "U" ? 6.42 * iss : 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15);
  const exploitability = 8.22 * av * ac * pr * ui;

  let base: number;
  if (impact <= 0) {
    base = 0;
  } else if (scope === "U") {
    base = roundUp(Math.min(impact + exploitability, 10));
  } else {
    base = roundUp(Math.min(1.08 * (impact + exploitability), 10));
  }

  const vector =
    "CVSS:3.1/" +
    required.map((k) => `${k}:${values[k]}`).join("/");
  return { vector, score: base };
}

function roundUp(n: number): number {
  // CVSS rounds up to one decimal place
  return Math.ceil(n * 10) / 10;
}

function VersionTabs({
  version,
  setVersion,
}: {
  version: "v3.1" | "v4.0";
  setVersion: (v: "v3.1" | "v4.0") => void;
}) {
  return (
    <div
      className="flex"
      style={{
        gap: 4,
        paddingBottom: 4,
        borderBottom: "1px solid var(--border-soft)",
      }}
    >
      {(["v3.1", "v4.0"] as const).map((v) => {
        const active = version === v;
        return (
          <button
            key={v}
            type="button"
            onClick={() => setVersion(v)}
            className="font-mono uppercase"
            style={{
              height: 26,
              padding: "0 10px",
              fontSize: 10,
              letterSpacing: "0.08em",
              borderRadius: 3,
              cursor: "pointer",
              color: active
                ? "var(--text-on-accent)"
                : "var(--text-muted)",
              border: `1px solid ${active ? "var(--accent)" : "transparent"}`,
              background: active ? "var(--accent)" : "transparent",
            }}
          >
            CVSS {v}
          </button>
        );
      })}
    </div>
  );
}
