/** BudgetWidget -- this month's LLM spend vs configured monthly cap.
 *
 * Spend: latest matching entry in `useCostHistory(3).months` (year_month
 * matching the current YYYY-MM, else the most recent entry).
 * Cap: `useCostConfig()` row whose key starts with `llm_monthly_budget_usd_`;
 * `effective_value` parsed as float. Multiple such rows are summed (each
 * represents a per-model budget line; the operator-visible aggregate is the
 * sum). No daily figure exists; the label states "this month" explicitly. */

import type { JSX } from "react";

import { useCostConfig, useCostHistory } from "../../api/cost";
import { css } from "../css";
import type { WidgetProps } from "./types";

const ROOT = css(
  "flex:1;min-height:0;display:flex;flex-direction:column;overflow:hidden;" +
  "padding:10px 12px;background:var(--surface-card);" +
  "font-family:var(--font-mono);color:var(--text-primary);gap:8px;",
);

const LABEL = css(
  "font-size:9px;letter-spacing:0.12em;text-transform:uppercase;" +
  "color:var(--text-faint);",
);

const MUTED = css("font-size:10px;color:var(--text-muted);");

function fmtUsd(v: number): string {
  return `$${v.toFixed(2)}`;
}

function currentYearMonth(now: Date): string {
  const y = now.getUTCFullYear();
  const m = String(now.getUTCMonth() + 1).padStart(2, "0");
  return `${y}-${m}`;
}

export default function BudgetWidget(_props: WidgetProps): JSX.Element {
  const history = useCostHistory(3);
  const config = useCostConfig();

  if (history.isLoading || config.isLoading) {
    return (
      <div style={ROOT}>
        <div style={LABEL}>this month spend</div>
        <div style={MUTED}>loading...</div>
      </div>
    );
  }
  if (history.isError) {
    return (
      <div style={ROOT}>
        <div style={LABEL}>this month spend</div>
        <div style={{ ...MUTED, color: "var(--status-warn)" }}>failed to load cost history</div>
      </div>
    );
  }

  const months = history.data?.months ?? [];
  const ym = currentYearMonth(new Date());
  const current = months.find((row) => row.year_month === ym)
    ?? [...months].sort((a, b) => (a.year_month < b.year_month ? 1 : -1))[0]
    ?? null;
  const spend = current ? current.total_cost_usd : 0;

  const rows = config.data ?? [];
  const capRows = rows.filter((row) => row.key.startsWith("llm_monthly_budget_usd_"));
  let cap = 0;
  let capValid = false;
  for (const row of capRows) {
    const v = parseFloat(row.effective_value);
    if (Number.isFinite(v)) {
      cap += v;
      capValid = true;
    }
  }

  const over = capValid && spend > cap;
  const spendColor = capValid
    ? (over ? "var(--status-warn)" : "var(--status-ok)")
    : "var(--text-primary)";
  const ratio = capValid && cap > 0 ? Math.min(1, spend / cap) : 0;
  const barFill = over ? "var(--status-warn)" : "var(--accent)";

  return (
    <div style={ROOT}>
      <div style={LABEL}>this month spend</div>
      <div style={{ display: "flex", alignItems: "baseline", gap: 6, fontVariantNumeric: "tabular-nums" }}>
        <span style={{ fontSize: 18, color: spendColor }}>{fmtUsd(spend)}</span>
        {capValid ? (
          <span style={{ fontSize: 11, color: "var(--text-muted)" }}>{` / ${fmtUsd(cap)}`}</span>
        ) : (
          <span style={{ ...MUTED, marginLeft: 4 }}>no cap set</span>
        )}
      </div>
      {capValid ? (
        <div
          style={{
            height: 3,
            background: "var(--border-faint)",
            borderRadius: 1,
            overflow: "hidden",
          }}
        >
          <div
            style={{
              width: `${(ratio * 100).toFixed(1)}%`,
              height: "100%",
              background: barFill,
            }}
          />
        </div>
      ) : null}
      {current ? (
        <div style={MUTED}>{current.year_month}</div>
      ) : (
        <div style={MUTED}>no spend recorded</div>
      )}
    </div>
  );
}
