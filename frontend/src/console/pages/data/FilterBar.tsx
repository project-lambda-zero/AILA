/** The DataPage filter/toolbar bar: one control per configured filter
 * (text/select/multi-select/segmented/date-range/numeric-range), the bespoke
 * toolbar slot, page-level action buttons, and the pagination chrome. */

import type { ChangeEvent, JSX, ReactNode } from "react";

import { css } from "../../css";
import type { FilterOptions } from "./useDataRows";
import { asList, asRange, asScalar } from "./rows";
import { actionBtn, FILTER_CTL } from "./styles";
import type { FilterValue, PageAction, PageFilter } from "./types";

export interface FilterBarProps {
  filters: PageFilter[];
  filterVals: Record<string, FilterValue>;
  setFilter: (name: string, value: string) => void;
  toggleFilter: (name: string, value: string) => void;
  setRangeFilter: (name: string, key: "lo" | "hi", value: string) => void;
  optionsFor: (f: PageFilter) => FilterOptions;
  toolbarExtra?: ReactNode;
  pageActions: PageAction[];
  onPageAction: (a: PageAction) => void;
  actionPending: boolean;
  pagination: boolean;
  page: number;
  pageCount: number;
  total: number;
  setPage: (n: number) => void;
}

export function FilterBar(props: FilterBarProps): JSX.Element {
  const {
    filters, filterVals, setFilter, toggleFilter, setRangeFilter, optionsFor,
    toolbarExtra, pageActions, onPageAction, actionPending,
    pagination, page, pageCount, total, setPage,
  } = props;

  const renderFilter = (f: PageFilter): JSX.Element => {
    if (f.type === "date-range" || f.type === "numeric-range") {
      const r = asRange(filterVals[f.name]);
      const inputType = f.type === "date-range" ? "date" : "number";
      return (
        <span key={f.name} style={css("display:inline-flex;align-items:center;gap:4px;")}>
          <input
            type={inputType}
            aria-label={`${f.label} from`}
            value={r.lo}
            onChange={(e: ChangeEvent<HTMLInputElement>) => setRangeFilter(f.name, "lo", e.target.value)}
            style={css(FILTER_CTL + "max-width:130px;")}
          />
          <span style={css("color:var(--text-faint);font-size:11px;")}>{"\u2013"}</span>
          <input
            type={inputType}
            aria-label={`${f.label} to`}
            value={r.hi}
            onChange={(e: ChangeEvent<HTMLInputElement>) => setRangeFilter(f.name, "hi", e.target.value)}
            style={css(FILTER_CTL + "max-width:130px;")}
          />
        </span>
      );
    }
    if (f.type === "segmented") {
      const { options } = optionsFor(f);
      const cur = asScalar(filterVals[f.name]);
      return (
        <span key={f.name} role="group" aria-label={f.label} style={css("display:inline-flex;border:1px solid var(--border-soft);border-radius:2px;overflow:hidden;")}>
          {options.map((o) => {
            const on = cur === o.value;
            return (
              <button
                key={o.value}
                type="button"
                aria-pressed={on}
                onClick={() => setFilter(f.name, on ? "" : o.value)}
                style={css(`min-height:28px;padding:3px 9px;border:0;border-right:1px solid var(--border-soft);background:${on ? "var(--accent)" : "transparent"};color:${on ? "var(--surface-sunk)" : "var(--text-muted)"};font-family:var(--font-mono);font-size:11px;letter-spacing:0.04em;text-transform:none;cursor:pointer;`)}
              >
                {o.label}
              </button>
            );
          })}
        </span>
      );
    }
    if (f.type === "multi-select") {
      const { options, loading } = optionsFor(f);
      const sel = asList(filterVals[f.name]);
      return (
        <span key={f.name} role="group" aria-label={f.label} style={css("display:inline-flex;align-items:center;gap:4px;flex-wrap:wrap;")}>
          <span style={css("font-size:11px;color:var(--text-faint);letter-spacing:0.04em;")}>{f.label}</span>
          {loading ? <span style={css("font-size:11px;color:var(--text-faint);")}>loading{"\u2026"}</span> : null}
          {options.map((o) => {
            const on = sel.includes(o.value);
            return (
              <button
                key={o.value}
                type="button"
                aria-pressed={on}
                onClick={() => toggleFilter(f.name, o.value)}
                style={css(`min-height:28px;padding:2px 7px;border:1px solid ${on ? "var(--accent)" : "var(--border-soft)"};border-radius:2px;background:${on ? "color-mix(in srgb,var(--accent) 18%,transparent)" : "var(--surface-sunk)"};color:${on ? "var(--accent)" : "var(--text-muted)"};font-family:var(--font-mono);font-size:11px;letter-spacing:0.03em;text-transform:none;cursor:pointer;`)}
              >
                {o.label}
              </button>
            );
          })}
        </span>
      );
    }
    if (f.type === "select") {
      const { options, loading } = optionsFor(f);
      return (
        <select
          key={f.name}
          aria-label={f.label}
          value={asScalar(filterVals[f.name])}
          onChange={(e: ChangeEvent<HTMLSelectElement>) => setFilter(f.name, e.target.value)}
          style={css(FILTER_CTL + "max-width:180px;cursor:pointer;")}
        >
          <option value="">{loading ? "loading\u2026" : f.label}</option>
          {options.map((o) => (
            <option key={o.value} value={o.value}>
              {o.label}
            </option>
          ))}
        </select>
      );
    }
    return (
      <input
        key={f.name}
        type="text"
        aria-label={f.label}
        value={asScalar(filterVals[f.name])}
        onChange={(e: ChangeEvent<HTMLInputElement>) => setFilter(f.name, e.target.value)}
        placeholder={f.label}
        style={css(FILTER_CTL + "max-width:160px;")}
      />
    );
  };

  return (
    <div style={css("display:flex;align-items:center;gap:8px;padding:6px 12px;border-bottom:1px solid var(--border-soft);flex-wrap:wrap;")}>
      {filters.length > 0 ? (
        <span style={css("font-size:11px;letter-spacing:0.08em;text-transform:uppercase;color:var(--text-faint);")}>filter</span>
      ) : null}
      {filters.map(renderFilter)}
      <span style={css("flex:1;")} />
      {toolbarExtra}
      {pageActions.map((a) => (
        <button
          key={a.label}
          type="button"
          onClick={() => onPageAction(a)}
          disabled={actionPending}
          style={actionBtn(a, "4px 10px")}
        >
          {a.label}
        </button>
      ))}
      {pagination ? (
        <span style={css("display:inline-flex;align-items:center;gap:6px;")}>
          <button type="button" onClick={() => setPage(Math.max(1, page - 1))} disabled={page <= 1} style={css("border:0;background:transparent;color:var(--text-muted);cursor:pointer;min-height:28px;display:inline-flex;align-items:center;font-size:11px;")}>
            {"\u25c0"}
          </button>
          <span style={css("font-size:11px;color:var(--text-faint);text-transform:none;letter-spacing:0.03em;")}>
            page {page} / {pageCount} {"\u00b7"} {total} total
          </span>
          <button type="button" onClick={() => setPage(page + 1)} disabled={page >= pageCount} style={css("border:0;background:transparent;color:var(--text-muted);cursor:pointer;min-height:28px;display:inline-flex;align-items:center;font-size:11px;")}>
            {"\u25b6"}
          </button>
        </span>
      ) : null}
    </div>
  );
}
