/** Step editors for the automation wizard: the param_schema parser (a
 * JSON-Schema-ish subset), the typed arguments form, and the key/value
 * fallback editor. */

import type { ChangeEvent, JSX, ReactNode } from "react";

import { css } from "../../css";
import { fieldCol, helpText, inputStyle, labelStyle, selectStyle } from "../../wizards";

/** Minimal shape we read from `param_schema.properties[name]`. Anything the
 * server does not send is treated as absent (the wizard is forward-compatible
 * with the JSON-Schema-ish extensions the registry might add later). */
export interface ParamPropSchema {
  type?: string;
  description?: string;
  enum?: unknown[];
  default?: unknown;
}

export interface ParsedParamSchema {
  props: Array<[string, ParamPropSchema]>;
  required: string[];
}

export function parseParamSchema(raw: Record<string, unknown> | null | undefined): ParsedParamSchema | null {
  if (!raw || typeof raw !== "object") return null;
  const propsRaw = raw["properties"];
  if (!propsRaw || typeof propsRaw !== "object") return null;
  const entries = Object.entries(propsRaw as Record<string, unknown>).filter(
    (e): e is [string, ParamPropSchema] => e[1] != null && typeof e[1] === "object",
  );
  if (entries.length === 0) return null;
  const required = Array.isArray(raw["required"])
    ? (raw["required"] as unknown[]).filter((x): x is string => typeof x === "string")
    : [];
  return { props: entries, required };
}

export function TypedArgsForm({
  schema,
  values,
  onChange,
}: {
  schema: ParsedParamSchema;
  values: Record<string, unknown>;
  onChange: (name: string, value: unknown) => void;
}): JSX.Element {
  return (
    <div style={css("display:flex;flex-direction:column;gap:10px;")}>
      <p style={helpText}>
        {"this action declares a typed argument set. required fields are marked; every value is sent verbatim to the runner."}
      </p>
      {schema.props.map(([name, spec]) => {
        const isRequired = schema.required.includes(name);
        const cur = values[name];
        const displayed = cur === undefined ? spec.default : cur;
        const labelSuffix = isRequired ? " (required)" : "";
        const desc = spec.description ?? "";
        const enumOpts = Array.isArray(spec.enum) ? spec.enum.map(String) : null;
        let control: ReactNode;
        if (enumOpts) {
          control = (
            <select
              value={displayed === undefined || displayed === null ? "" : String(displayed)}
              onChange={(e: ChangeEvent<HTMLSelectElement>): void => onChange(name, e.target.value)}
              style={selectStyle}
            >
              <option value="">{"\u2014 select \u2014"}</option>
              {enumOpts.map((v) => (
                <option key={v} value={v}>
                  {v}
                </option>
              ))}
            </select>
          );
        } else if (spec.type === "boolean") {
          control = (
            <label style={css("display:flex;align-items:center;gap:7px;font-size:11px;color:var(--text-muted);cursor:pointer;")}>
              <input
                type="checkbox"
                checked={Boolean(displayed)}
                onChange={(e: ChangeEvent<HTMLInputElement>): void => onChange(name, e.target.checked)}
              />
              {"enabled"}
            </label>
          );
        } else if (spec.type === "integer" || spec.type === "number") {
          control = (
            <input
              type="number"
              step={spec.type === "integer" ? 1 : "any"}
              value={displayed === undefined || displayed === null ? "" : String(displayed)}
              onChange={(e: ChangeEvent<HTMLInputElement>): void => {
                const raw = e.target.value;
                if (raw === "") {
                  onChange(name, undefined);
                  return;
                }
                const n = spec.type === "integer" ? parseInt(raw, 10) : Number(raw);
                onChange(name, Number.isFinite(n) ? n : raw);
              }}
              style={inputStyle}
            />
          );
        } else {
          control = (
            <input
              type="text"
              value={displayed === undefined || displayed === null ? "" : String(displayed)}
              onChange={(e: ChangeEvent<HTMLInputElement>): void => onChange(name, e.target.value)}
              style={inputStyle}
            />
          );
        }
        return (
          <label key={name} style={fieldCol}>
            <span style={labelStyle}>{`${name}${labelSuffix}`}</span>
            {control}
            {desc ? <span style={helpText}>{desc}</span> : null}
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
        {"this action does not declare typed arguments. any keys/values entered below are passed verbatim to the action at run time."}
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

export function kvRowsToKwargs(rows: KVRow[]): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const row of rows) {
    const key = row.key.trim();
    if (key === "") continue;
    out[key] = row.value;
  }
  return out;
}
