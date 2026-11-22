import type { JSX } from "react";

import { asRecord } from "../api/parse";
import { css } from "./css";

const listCss = css("display:grid;grid-template-columns:minmax(110px,max-content) minmax(0,1fr);gap:5px 12px;margin:0;font-size:11px;line-height:1.45;");
const keyCss = css("color:var(--text-muted);overflow-wrap:anywhere;");
const valueCss = css("margin:0;min-width:0;color:var(--text-primary);overflow-wrap:anywhere;");
const nestedCss = css("padding-left:8px;border-left:1px solid var(--border-soft);");
const textCss = css("white-space:pre-wrap;");

function fieldLabel(key: string): string {
  return key.replaceAll("_", " ");
}

function Scalar({ value }: { value: unknown }): JSX.Element {
  if (value === null || value === undefined || value === "") return <span style={keyCss}>None</span>;
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
  if (depth >= 8) return <span style={keyCss}>Maximum nesting reached</span>;

  if (Array.isArray(value)) {
    if (value.length === 0) return <span style={keyCss}>None</span>;
    return (
      <ol aria-label={label} style={css("display:flex;flex-direction:column;gap:6px;margin:0;padding-left:20px;")}>
        {value.map((item, index) => (
          <li key={index}>
            <StructuredData value={item} label={`${label} item ${index + 1}`} depth={depth + 1} />
          </li>
        ))}
      </ol>
    );
  }

  const entries = Object.entries(record ?? {});
  if (entries.length === 0) return <span style={keyCss}>None</span>;
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
    </dl>
  );
}
