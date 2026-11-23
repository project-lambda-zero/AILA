import type { JSX } from "react";

import { asRecord } from "../api/parse";
import { css } from "./css";

const listCss = css("display:grid;grid-template-columns:minmax(110px,max-content) minmax(0,1fr);gap:5px 12px;margin:0;font-size:11px;line-height:1.45;");
const keyCss = css("color:var(--text-muted);overflow-wrap:anywhere;");
const valueCss = css("margin:0;min-width:0;color:var(--text-primary);overflow-wrap:anywhere;");
const nestedCss = css("padding-left:8px;border-left:1px solid var(--border-soft);");
const textCss = css("white-space:pre-wrap;");
const tableCss = css("width:100%;border-collapse:collapse;font-size:11px;line-height:1.35;");
const headerCellCss = css("padding:6px 8px;text-align:left;color:var(--text-muted);font-weight:600;border-bottom:1px solid var(--border);white-space:nowrap;background:var(--surface-chrome);");
const cellCss = css("padding:6px 8px;vertical-align:top;color:var(--text-primary);border-bottom:1px solid var(--border-soft);overflow-wrap:anywhere;");
const tableWrapCss = css("max-width:100%;overflow:auto;border:1px solid var(--border-soft);border-radius:2px;");

const MAX_DEPTH = 8;
const MAX_ITEMS = 50;
const MAX_FIELDS = 100;
const MAX_TABLE_COLUMNS = 12;

function fieldLabel(key: string): string {
  return key.replaceAll("_", " ");
}

function Scalar({ value }: { value: unknown }): JSX.Element {
  if (value === null || value === undefined || value === "") return <span style={keyCss}>—</span>;
  if (typeof value === "boolean") return <span>{value ? "Yes" : "No"}</span>;
  if (typeof value === "string" || typeof value === "number" || typeof value === "bigint") {
    return <span style={textCss}>{String(value)}</span>;
  }
  return <span>{String(value)}</span>;
}

export function structuredSummary(value: unknown): string {
  const record = asRecord(value);
  if (record) {
    for (const key of ["title", "name", "summary", "message", "kind", "action"]) {
      const candidate = record[key];
      if (typeof candidate === "string" && candidate.trim()) return candidate;
    }
    return `${Object.keys(record).length} fields`;
  }
  if (Array.isArray(value)) return `${value.length} items`;
  return typeof value === "string" ? value : String(value ?? "None");
}

export function StructuredData({ value, label = "Structured data", depth = 0 }: {
  value: unknown;
  label?: string;
  depth?: number;
}): JSX.Element {
  const record = asRecord(value);
  if (!record && !Array.isArray(value)) return <Scalar value={value} />;
  if (depth >= MAX_DEPTH) return <span style={keyCss}>—</span>;

  if (Array.isArray(value)) {
    if (value.length === 0) return <span style={keyCss}>—</span>;
    const rows = value.slice(0, MAX_ITEMS);
    const records = rows.map(asRecord);
    if (records.every((item) => item !== null)) {
      const columns = [...new Set(records.flatMap((item) => Object.keys(item ?? {})))].slice(0, MAX_TABLE_COLUMNS);
      return (
        <div style={tableWrapCss}>
          <table aria-label={label} style={tableCss}>
            {value.length > MAX_ITEMS ? <caption style={{ ...headerCellCss, captionSide: "bottom", textAlign: "left" }}>{MAX_ITEMS} / {value.length}</caption> : null}
            <thead><tr>{columns.map((key) => <th key={key} scope="col" style={headerCellCss}>{fieldLabel(key)}</th>)}</tr></thead>
            <tbody>
              {records.map((item, index) => <tr key={index}>
                {columns.map((key) => <td key={key} style={cellCss}><StructuredData value={item?.[key]} label={`${label} ${fieldLabel(key)}`} depth={depth + 1} /></td>)}
              </tr>)}
            </tbody>
          </table>
        </div>
      );
    }
    return (
      <ol aria-label={label} style={css("display:flex;flex-direction:column;gap:6px;margin:0;padding-left:20px;")}>
        {rows.map((item, index) => (
          <li key={index}><StructuredData value={item} label={`${label} item ${index + 1}`} depth={depth + 1} /></li>
        ))}
        {value.length > MAX_ITEMS ? <li style={keyCss}>{value.length - MAX_ITEMS} more</li> : null}
      </ol>
    );
  }

  const allEntries = Object.entries(record ?? {});
  const entries = allEntries.slice(0, MAX_FIELDS);
  if (entries.length === 0) return <span style={keyCss}>—</span>;
  return (
    <dl aria-label={label} style={listCss}>
      {entries.map(([key, item]) => {
        const nested = asRecord(item) !== null || Array.isArray(item);
        return (
          <div key={key} style={{ display: "contents" }}>
            <dt style={keyCss}>{fieldLabel(key)}</dt>
            <dd style={{ ...valueCss, ...(nested ? nestedCss : {}) }}>
              <StructuredData value={item} label={`${label} ${fieldLabel(key)}`} depth={depth + 1} />
            </dd>
          </div>
        );
      })}
      {allEntries.length > MAX_FIELDS ? <div style={{ display: "contents" }}><dt style={keyCss}>…</dt><dd style={valueCss}>{allEntries.length - MAX_FIELDS} more</dd></div> : null}
    </dl>
  );
}
