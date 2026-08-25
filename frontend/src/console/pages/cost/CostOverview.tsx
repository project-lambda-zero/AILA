/**
 * `admin:cost` overview segment (req 47): spend-over-time chart, ROI trio,
 * three clickable breakdown widgets (model, task_type, module). Drill-in
 * clicks lift a `Dim` up to the page shell so the detail segment can pick
 * it up. Window-derived aggregates label their coverage honestly since
 * /cost/history has no task_type dimension and the llm-log fetch is capped
 * at 200 rows.
 */
import { useMemo, useState } from "react";
import type { CSSProperties, JSX } from "react";

import {
  BreakdownBars,
  SpendChart,
  StatCard,
  apiErrMessage,
  btnGhost,
  chipFaint,
  emptyNote,
  fmtInt,
  fmtPct,
  fmtUsd,
  moduleOf,
  monthShort,
  pad,
  panelBox,
  panelTitle,
  dot,
  scroll,
  segButton,
  stack,
} from "./kit";
import type { BreakdownItem, CostOverviewProps, Dim } from "./kit";
import { useCostHistory, useCostRoi, useLlmLog } from "../../../api/cost";

const WINDOWS: readonly number[] = [3, 6, 12, 24];

const headerRow: CSSProperties = {
  display: "flex",
  alignItems: "center",
  justifyContent: "space-between",
  gap: 12,
  flexWrap: "wrap",
};
const segStrip: CSSProperties = { display: "flex", gap: 6, alignItems: "center" };
const dimChipRow: CSSProperties = { display: "flex", gap: 8, alignItems: "center" };
const roiRow: CSSProperties = { display: "flex", gap: 12, flexWrap: "wrap" };
const gridRow: CSSProperties = { display: "flex", gap: 12, flexWrap: "wrap" };
const gridCell: CSSProperties = { flex: "1 1 260px", minWidth: 240, display: "flex" };
const noteLine: CSSProperties = {
  fontFamily: "var(--font-mono)",
  fontSize: 9.5,
  color: "var(--text-faint)",
  letterSpacing: "0.03em",
  padding: "6px 14px 10px",
};

export default function CostOverview(props: CostOverviewProps): JSX.Element {
  const [months, setMonths] = useState<number>(6);

  const since = useMemo(() => {
    const d = new Date();
    d.setUTCDate(1);
    d.setUTCMonth(d.getUTCMonth() - (months - 1));
    return d.toISOString().slice(0, 10);
  }, [months]);

  const hist = useCostHistory(months);
  const roi = useCostRoi(months);
  const win = useLlmLog({ limit: 200, timestamp_since: `${since}T00:00:00` });

  const dim = props.dim;

  const modelItems = useMemo<BreakdownItem[]>(() => {
    const acc: Record<string, { value: number; count: number }> = {};
    for (const m of hist.data?.months ?? []) {
      for (const mm of m.models) {
        const cur = acc[mm.model_id] ?? { value: 0, count: 0 };
        cur.value += mm.cost_usd;
        cur.count += mm.call_count;
        acc[mm.model_id] = cur;
      }
    }
    const out: BreakdownItem[] = Object.entries(acc).map(([k, v]) => ({
      key: k,
      label: k,
      value: v.value,
      count: v.count,
    }));
    out.sort((a, b) => b.value - a.value);
    return out.slice(0, 10);
  }, [hist.data]);

  const taskRows = win.data?.items ?? [];

  const taskItems = useMemo<BreakdownItem[]>(() => {
    const acc: Record<string, { value: number; count: number }> = {};
    for (const r of taskRows) {
      const cur = acc[r.task_type] ?? { value: 0, count: 0 };
      cur.value += r.cost_usd;
      cur.count += 1;
      acc[r.task_type] = cur;
    }
    const out: BreakdownItem[] = Object.entries(acc).map(([k, v]) => ({
      key: k,
      label: k,
      value: v.value,
      count: v.count,
    }));
    out.sort((a, b) => b.value - a.value);
    return out.slice(0, 10);
  }, [taskRows]);

  const moduleMap = useMemo<Record<string, string[]>>(() => {
    const byMod: Record<string, Record<string, true>> = {};
    for (const r of taskRows) {
      const mod = moduleOf(r.task_type);
      if (!byMod[mod]) byMod[mod] = {};
      byMod[mod][r.task_type] = true;
    }
    const out: Record<string, string[]> = {};
    for (const [k, s] of Object.entries(byMod)) out[k] = Object.keys(s).sort();
    return out;
  }, [taskRows]);

  const moduleItems = useMemo<BreakdownItem[]>(() => {
    const acc: Record<string, { value: number; count: number }> = {};
    for (const r of taskRows) {
      const mod = moduleOf(r.task_type);
      const cur = acc[mod] ?? { value: 0, count: 0 };
      cur.value += r.cost_usd;
      cur.count += 1;
      acc[mod] = cur;
    }
    const out: BreakdownItem[] = Object.entries(acc).map(([k, v]) => ({
      key: k,
      label: k,
      value: v.value,
      count: v.count,
    }));
    out.sort((a, b) => b.value - a.value);
    return out.slice(0, 10);
  }, [taskRows]);

  const points = useMemo<{ label: string; value: number }[]>(() => {
    const histMonths = hist.data?.months ?? [];
    if (!dim) {
      return histMonths.map((m) => ({ label: monthShort(m.year_month), value: m.total_cost_usd }));
    }
    if (dim.kind === "model") {
      return histMonths.map((m) => ({
        label: monthShort(m.year_month),
        value: m.models.find((x) => x.model_id === dim.value)?.cost_usd ?? 0,
      }));
    }
    const wanted = new Set(dim.taskTypes);
    return histMonths.map((m) => {
      let v = 0;
      for (const r of taskRows) {
        if (r.timestamp.slice(0, 7) === m.year_month && wanted.has(r.task_type)) {
          v += r.cost_usd;
        }
      }
      return { label: monthShort(m.year_month), value: v };
    });
  }, [dim, hist.data, taskRows]);

  const chartSourceNote =
    dim && (dim.kind === "task_type" || dim.kind === "module")
      ? "series bucketed from recent-window activity (200-row cap); /cost/history has no task_type dimension"
      : "from /cost/history";

  return (
    <div style={{ ...stack, ...scroll, ...pad }}>
      <div style={headerRow}>
        <div style={segStrip}>
          {WINDOWS.map((w) => (
            <button
              key={w}
              type="button"
              style={segButton(w === months)}
              onClick={() => setMonths(w)}
            >
              {w}m
            </button>
          ))}
        </div>
        {dim ? (
          <div style={dimChipRow}>
            <span style={chipFaint}>
              filtered: {dim.kind} = {dim.value}
            </span>
            <button type="button" style={btnGhost} onClick={() => props.onDim(null)}>
              clear
            </button>
          </div>
        ) : null}
      </div>

      <div style={panelBox}>
        <div style={panelTitle}>
          <span style={dot} />
          <span>spend over time ({months}m)</span>
        </div>
        {hist.isLoading ? (
          <div style={emptyNote}>loading cost history…</div>
        ) : hist.isError ? (
          <div style={emptyNote}>{apiErrMessage(hist.error)}</div>
        ) : (
          <>
            <div style={{ padding: "12px 14px 4px" }}>
              <SpendChart points={points} />
            </div>
            <div style={noteLine}>{chartSourceNote}</div>
          </>
        )}
      </div>

      <div style={panelBox}>
        <div style={panelTitle}>
          <span style={dot} />
          <span>roi ({months}m)</span>
        </div>
        {roi.isLoading ? (
          <div style={emptyNote}>loading roi…</div>
        ) : roi.isError ? (
          <div style={emptyNote}>{apiErrMessage(roi.error)}</div>
        ) : roi.data ? (
          <div style={{ ...roiRow, padding: "12px 14px" }}>
            <StatCard label="llm cost" value={fmtUsd(roi.data.llm_cost_usd)} tone="accent" />
            <StatCard
              label="human-equiv cost"
              value={fmtUsd(roi.data.human_equivalent_cost_usd)}
              sub={`${fmtInt(roi.data.run_count)} runs`}
            />
            <StatCard
              label="roi"
              value={fmtPct(roi.data.roi_percentage)}
              tone={roi.data.roi_percentage >= 0 ? "ok" : "warn"}
              sub={`${roi.data.human_equivalent_hours.toFixed(1)}h human-equivalent`}
            />
          </div>
        ) : (
          <div style={emptyNote}>no roi data</div>
        )}
      </div>

      <div style={gridRow}>
        <div style={gridCell}>
          <BreakdownBars
            title="by model"
            items={modelItems}
            activeKey={dim?.kind === "model" ? dim.value : null}
            onPick={(k) => props.onDim({ kind: "model", value: k, taskTypes: [] })}
            empty={hist.isLoading ? "loading…" : hist.isError ? apiErrMessage(hist.error) : "no model activity"}
            foot="from /cost/history"
          />
        </div>
        <div style={gridCell}>
          <BreakdownBars
            title="by task type"
            items={taskItems}
            activeKey={dim?.kind === "task_type" ? dim.value : null}
            onPick={(k) => props.onDim({ kind: "task_type", value: k, taskTypes: [k] })}
            empty={win.isLoading ? "loading…" : win.isError ? apiErrMessage(win.error) : "no recent calls"}
            foot={`top ${taskItems.length} of ${win.data?.total ?? 0} recent calls (200-row window)`}
          />
        </div>
        <div style={gridCell}>
          <BreakdownBars
            title="by module"
            items={moduleItems}
            activeKey={dim?.kind === "module" ? dim.value : null}
            onPick={(k) =>
              props.onDim({
                kind: "module",
                value: k,
                taskTypes: moduleMap[k] ?? [],
              } satisfies Dim)
            }
            empty={win.isLoading ? "loading…" : win.isError ? apiErrMessage(win.error) : "no recent calls"}
            foot={`grouped by task_type prefix; top ${moduleItems.length} of ${win.data?.total ?? 0} recent calls (200-row window)`}
          />
        </div>
      </div>
    </div>
  );
}
