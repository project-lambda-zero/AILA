/** Step editors for the scheduled-report wizard: the live report-kind
 * catalog, the typed options form (a kind's declared config_schema), and the
 * raw key/value fallback editor. */

import type { ChangeEvent, JSX, ReactNode } from "react";

import type { ScheduledReportKind, ScheduledReportKindOption } from "../../../api/scheduledReports";
import { css } from "../../css";
import { fieldCol, helpText, inputStyle, labelStyle, selectStyle } from "../../wizards";

/** Seed one option's initial value from its declared default. A boolean
 * defaults to false, a select with no default to its first option, and a
 * string (or a select with no options) to "". */
export function optionInitialValue(opt: ScheduledReportKindOption): string | boolean {
  if (opt.type === "boolean") return opt.default === true;
  if (opt.type === "select" && Array.isArray(opt.options) && opt.options.length > 0) {
    return typeof opt.default === "string" ? opt.default : opt.options[0];
  }
  return typeof opt.default === "string" ? opt.default : "";
}

export function KindCatalog({
  kinds,
  loading,
  error,
  selectedType,
  onPick,
}: {
  kinds: ScheduledReportKind[];
  loading: boolean;
  error: string | null;
  selectedType: string;
  onPick: (reportType: string) => void;
}): JSX.Element {
  if (loading) {
    return <span style={css("font-size:11px;color:var(--text-faint);")}>{"loading report kinds\u2026"}</span>;
  }
  if (error) {
    return <span style={css("font-size:11px;color:var(--status-warn);")}>{error}</span>;
  }
  return (
    <div style={css("display:flex;flex-direction:column;gap:16px;")}>
      <p style={helpText}>
        {
          "a report kind is a server-side generator the scheduler can run on a cron. the catalog below reflects the live registry; pick one and configure its options on the next step."
        }
      </p>
      <div style={css("display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:8px;")}>
        {kinds.map((k) => {
          const active = k.report_type === selectedType;
          const border = active ? "var(--accent)" : "var(--border-soft)";
          const bg = active
            ? "color-mix(in srgb,var(--accent) 10%,transparent)"
            : "var(--surface-sunk)";
          return (
            <button
              key={k.report_type}
              type="button"
              onClick={() => onPick(k.report_type)}
              style={css(
                `text-align:left;padding:10px 12px;border:1px solid ${border};background:${bg};border-radius:3px;cursor:pointer;display:flex;flex-direction:column;gap:6px;font-family:var(--font-mono);`,
              )}
            >
              <span style={css("font-size:11.5px;color:var(--text-primary);letter-spacing:0.04em;")}>
                {k.name}
              </span>
              <span style={css("font-size:11px;color:var(--text-faint);letter-spacing:0.06em;")}>
                {k.report_type}
              </span>
              <span style={css("font-size:11px;color:var(--text-muted);letter-spacing:0.02em;line-height:1.45;")}>
                {k.description}
              </span>
            </button>
          );
        })}
      </div>
    </div>
  );
}

export function TypedOptionsForm({
  schema,
  values,
  onChange,
}: {
  schema: ScheduledReportKindOption[];
  values: Record<string, string | boolean>;
  onChange: (key: string, value: string | boolean) => void;
}): JSX.Element {
  return (
    <div style={css("display:flex;flex-direction:column;gap:10px;")}>
      <p style={helpText}>
        {"configure the kind's options; required fields are marked. values are sent verbatim in the report's config_json."}
      </p>
      {schema.map((opt) => {
        const cur = values[opt.key];
        const labelSuffix = opt.required ? " (required)" : "";
        let control: ReactNode;
        if (opt.type === "boolean") {
          control = (
            <label style={css("display:flex;align-items:center;gap:7px;font-size:11px;color:var(--text-muted);cursor:pointer;")}>
              <input
                type="checkbox"
                checked={cur === true}
                onChange={(e: ChangeEvent<HTMLInputElement>): void => onChange(opt.key, e.target.checked)}
              />
              {"enabled"}
            </label>
          );
        } else if (opt.type === "select" && Array.isArray(opt.options) && opt.options.length > 0) {
          control = (
            <select
              value={typeof cur === "string" ? cur : ""}
              onChange={(e: ChangeEvent<HTMLSelectElement>): void => onChange(opt.key, e.target.value)}
              style={selectStyle}
            >
              {opt.options.map((v) => (
                <option key={v} value={v}>
                  {v}
                </option>
              ))}
            </select>
          );
        } else {
          control = (
            <input
              type="text"
              value={typeof cur === "string" ? cur : ""}
              onChange={(e: ChangeEvent<HTMLInputElement>): void => onChange(opt.key, e.target.value)}
              style={inputStyle}
            />
          );
        }
        return (
          <label key={opt.key} style={fieldCol}>
            <span style={labelStyle}>{`${opt.label}${labelSuffix}`}</span>
            {control}
          </label>
        );
      })}
    </div>
  );
}

export interface KVRow {
  key: string;
  value: string;
}

export function KeyvalEditor({
  rows,
  onChange,
}: {
  rows: KVRow[];
  onChange: (rows: KVRow[]) => void;
}): JSX.Element {
  return (
    <div style={css("display:flex;flex-direction:column;gap:10px;")}>
      <p style={helpText}>
        {"this kind does not declare typed options. any keys/values entered below are passed verbatim in the report's config_json."}
      </p>
      <div style={css("display:flex;flex-direction:column;gap:6px;")}>
        {rows.map((row, i) => (
          <div key={i} style={css("display:grid;grid-template-columns:1fr 1fr auto;gap:6px;")}>
            <input
              placeholder="key"
              value={row.key}
              onChange={(e: ChangeEvent<HTMLInputElement>): void => {
                const next = rows.slice();
                next[i] = { ...next[i], key: e.target.value };
                onChange(next);
              }}
              style={inputStyle}
            />
            <input
              placeholder="value"
              value={row.value}
              onChange={(e: ChangeEvent<HTMLInputElement>): void => {
                const next = rows.slice();
                next[i] = { ...next[i], value: e.target.value };
                onChange(next);
              }}
              style={inputStyle}
            />
            <button
              type="button"
              onClick={(): void => onChange(rows.filter((_, j) => j !== i))}
              style={css(
                "padding:0 10px;border:1px solid var(--border-soft);background:transparent;color:var(--text-muted);font-family:var(--font-mono);font-size:11px;letter-spacing:0.06em;text-transform:uppercase;cursor:pointer;min-height:28px;display:inline-flex;align-items:center;border-radius:2px;",
              )}
            >
              remove
            </button>
          </div>
        ))}
      </div>
      <button
        type="button"
        onClick={(): void => onChange([...rows, { key: "", value: "" }])}
        style={css(
          "align-self:flex-start;padding:4px 10px;border:1px solid var(--accent);background:transparent;color:var(--accent);font-family:var(--font-mono);font-size:11px;letter-spacing:0.08em;text-transform:uppercase;cursor:pointer;border-radius:2px;",
        )}
      >
        {"+ add pair"}
      </button>
    </div>
  );
}

/** Collapse key/value rows into an object, dropping rows with empty keys. */
export function kvObjectFromRows(rows: KVRow[]): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const row of rows) {
    const key = row.key.trim();
    if (key === "") continue;
    out[key] = row.value;
  }
  return out;
}
