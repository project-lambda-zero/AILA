import { useEffect, useMemo, useState } from "react";

import { AilaBadge } from "@/components/aila/AilaBadge";

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

  const { vector, score } = useMemo(() => computeCVSS(values), [values]);

  useEffect(() => {
    if (onChange) onChange(vector, score);
  }, [vector, score, onChange]);

  function pick(metricId: string, valueId: string) {
    setValues((prev) => ({ ...prev, [metricId]: valueId }));
  }

  return (
    <div className="space-y-3">
      {CVSS_METRICS.map((m) => (
        <div key={m.id}>
          <div className="text-xs font-mono text-text-muted mb-1">
            {m.label}{" "}
            <span className="opacity-70">({m.id})</span>
          </div>
          <div className="flex flex-wrap gap-1">
            {m.values.map((v) => {
              const active = values[m.id] === v.id;
              return (
                <button
                  key={v.id}
                  type="button"
                  onClick={() => pick(m.id, v.id)}
                  title={v.description}
                  className={
                    "px-2 py-1 text-xs font-mono rounded border transition-colors " +
                    (active
                      ? "bg-accent text-white border-accent"
                      : "bg-surface text-foreground border-border-default hover:bg-surface-hover")
                  }
                >
                  {v.label} ({v.id})
                </button>
              );
            })}
          </div>
        </div>
      ))}

      <div className="pt-3 border-t border-border-default flex items-center gap-2 flex-wrap">
        <CVSSBadge score={score} vector={vector} />
        <code className="text-[10px] font-mono text-text-muted break-all">
          {vector || "fill all 8 metrics →"}
        </code>
        <AilaBadge severity="info" size="sm">
          {severityFromScore(score).toUpperCase()}
        </AilaBadge>
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
