/**
 * StructuredValue -- recursive typed renderer for JSON-ish values.
 * Any detail panel that used to `JSON.stringify(value, null, 2)` into a
 * blob should render `<StructuredValue value={v} />` instead. It never
 * emits a raw JSON dump: primitives render as text (bool as yes/no chip),
 * arrays of primitives as chip rows, arrays of objects as compact tables,
 * objects as key/value grids that nest with a subtle left border. Extreme
 * depth (>4) falls back to a collapsed monospace block so the layout
 * never explodes on runaway payloads.
 *
 * Style tokens mirror DataPage's detail grid (var(--text-faint) labels,
 * var(--text-primary) values, var(--surface-sunk)/var(--border-soft) for
 * nested blocks) so it drops into existing panels without theme drift.
 */
import type { JSX } from "react";

import { css } from "../css";

const MAX_DEPTH = 4;
const MAX_TABLE_COLUMNS = 8;
const MAX_TABLE_ROWS = 40;
const CODE_LOOK_MAX = 4000;

const emDash = css("color:var(--text-faint);");
const monoBlock = css(
  "margin:0;padding:6px 8px;border:1px solid var(--border-soft);border-radius:2px;background:var(--surface-sunk);font-family:var(--font-mono);font-size:10px;line-height:1.4;color:var(--text-primary);white-space:pre-wrap;word-break:break-word;max-height:320px;overflow:auto;",
);
const chip = css(
  "display:inline-block;padding:1px 6px;border:1px solid var(--border-soft);border-radius:2px;font-size:9.5px;line-height:1.5;color:var(--text-primary);background:var(--surface-sunk);word-break:break-word;",
);
const chipRow = css("display:inline-flex;flex-wrap:wrap;gap:4px;max-width:100%;");
const boolYes = css(
  "display:inline-block;padding:0 6px;border:1px solid var(--status-ok);border-radius:2px;font-size:9.5px;line-height:1.5;letter-spacing:0.08em;text-transform:uppercase;color:var(--status-ok);background:transparent;",
);
const boolNo = css(
  "display:inline-block;padding:0 6px;border:1px solid var(--border-soft);border-radius:2px;font-size:9.5px;line-height:1.5;letter-spacing:0.08em;text-transform:uppercase;color:var(--text-faint);background:transparent;",
);
const numberStyle = css("color:var(--text-primary);font-variant-numeric:tabular-nums;");
const kvGrid = css(
  "display:grid;grid-template-columns:minmax(120px,150px) 1fr;gap:4px 10px;font-size:10.5px;align-content:start;min-width:0;",
);
const nestedBlock = css(
  "padding:6px 8px;border-left:1px solid var(--border-soft);background:color-mix(in srgb,var(--surface-sunk) 60%,transparent);border-radius:0 2px 2px 0;min-width:0;",
);
const kvLabel = css("color:var(--text-faint);letter-spacing:0.04em;word-break:break-word;");
const kvVal = css("color:var(--text-primary);word-break:break-word;min-width:0;");
const tableWrap = css(
  "border:1px solid var(--border-soft);border-radius:2px;background:var(--surface-sunk);overflow:auto;max-width:100%;",
);
const tableEl = css("width:100%;border-collapse:collapse;font-size:10px;");
const thStyle = css(
  "text-align:left;padding:4px 7px;background:var(--surface-chrome);border-bottom:1px solid var(--border-soft);font-size:8px;letter-spacing:0.1em;text-transform:uppercase;color:var(--text-faint);white-space:nowrap;",
);
const tdStyle = css(
  "padding:4px 7px;border-bottom:1px solid var(--border-faint);color:var(--text-primary);vertical-align:top;max-width:280px;word-break:break-word;",
);
const captionStyle = css(
  "padding:3px 7px;font-size:8.5px;letter-spacing:0.08em;text-transform:uppercase;color:var(--text-faint);background:var(--surface-chrome);border-top:1px solid var(--border-faint);",
);

// Union of keys across the first N object rows, capped so a heterogeneous
// list doesn't produce a 40-column table. Records ordering by first
// appearance so the leftmost columns are the most common leading fields.
function unionKeys(rows: Record<string, unknown>[]): string[] {
  const seen: Record<string, true> = {};
  const order: string[] = [];
  for (const r of rows.slice(0, MAX_TABLE_ROWS)) {
    for (const k of Object.keys(r)) {
      if (seen[k]) continue;
      seen[k] = true;
      order.push(k);
      if (order.length >= MAX_TABLE_COLUMNS) return order;
    }
  }
  return order;
}

export function StructuredValue({
  value,
  depth = 0,
}: {
  value: unknown;
  depth?: number;
}): JSX.Element {
  if (value === null || value === undefined || value === "") {
    return <span style={emDash}>{"\u2014"}</span>;
  }

  if (typeof value === "boolean") {
    return <span style={value ? boolYes : boolNo}>{value ? "yes" : "no"}</span>;
  }

  if (typeof value === "number") {
    return <span style={numberStyle}>{Number.isFinite(value) ? String(value) : "\u2014"}</span>;
  }

  if (typeof value === "string") {
    // Multiline, JSON-ish, or very long strings get a scrollable mono block;
    // everything else stays inline. Pure prose and ISO-8601 dates render as-is.
    const head = value.trimStart();
    const looksLikeCode =
      value.length > CODE_LOOK_MAX ||
      value.indexOf("\n") !== -1 ||
      head.startsWith("{") ||
      head.startsWith("[");
    if (looksLikeCode) return <pre style={monoBlock}>{value}</pre>;
    return <span>{value}</span>;
  }

  if (depth >= MAX_DEPTH) {
    // Depth cap: fall back to a scrollable pretty-print so a runaway payload
    // can never blow up the layout. Cycles are rare in JSON-shaped values;
    // if `JSON.stringify` throws, `String()` is honest fallback.
    let text: string;
    try {
      text = JSON.stringify(value, null, 2);
    } catch {
      text = String(value);
    }
    return <pre style={monoBlock}>{text}</pre>;
  }

  if (Array.isArray(value)) {
    if (value.length === 0) return <span style={emDash}>{"\u2014"}</span>;
    const allPrim = value.every((x) => x === null || typeof x !== "object");
    if (allPrim) {
      return (
        <span style={chipRow}>
          {value.map((x, i) => (
            <span key={i} style={chip}>
              {x === null || x === undefined || x === "" ? "\u2014" : String(x)}
            </span>
          ))}
        </span>
      );
    }
    const rows: Record<string, unknown>[] = [];
    let nonObject = 0;
    for (const x of value) {
      if (typeof x === "object" && x !== null && !Array.isArray(x)) {
        rows.push(x as Record<string, unknown>);
      } else {
        nonObject += 1;
      }
    }
    if (rows.length === 0) {
      // Mixed array with no object rows and no all-primitive path taken:
      // stringify each item into a chip. Not a rendered "raw JSON blob" --
      // just a per-item label since a compact table has no columns to project.
      return (
        <span style={chipRow}>
          {value.map((x, i) => {
            let label: string;
            try {
              label = JSON.stringify(x);
            } catch {
              label = String(x);
            }
            return <span key={i} style={chip}>{label}</span>;
          })}
        </span>
      );
    }
    const cols = unionKeys(rows);
    const shown = rows.slice(0, MAX_TABLE_ROWS);
    return (
      <div style={tableWrap}>
        <table style={tableEl}>
          <thead>
            <tr>
              {cols.map((c) => (
                <th key={c} style={thStyle}>{c}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {shown.map((row, i) => (
              <tr key={i}>
                {cols.map((c) => (
                  <td key={c} style={tdStyle}>
                    <StructuredValue value={row[c]} depth={depth + 1} />
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
        <div style={captionStyle}>
          {rows.length} row{rows.length === 1 ? "" : "s"}
          {rows.length > shown.length ? ` \u00b7 showing ${shown.length}` : ""}
          {nonObject > 0 ? ` \u00b7 ${nonObject} non-object item(s) hidden` : ""}
        </div>
      </div>
    );
  }

  // Plain object: recurse into a key/value grid. Nested levels get a subtle
  // left-border block so hierarchy is visible without heavy chrome.
  const entries = Object.entries(value as Record<string, unknown>);
  if (entries.length === 0) return <span style={emDash}>{"\u2014"}</span>;
  const inner = (
    <div style={kvGrid}>
      {entries.map(([k, v]) => (
        <span key={k} style={{ display: "contents" }}>
          <span style={kvLabel}>{k}</span>
          <span style={kvVal}>
            <StructuredValue value={v} depth={depth + 1} />
          </span>
        </span>
      ))}
    </div>
  );
  if (depth === 0) return inner;
  return <div style={nestedBlock}>{inner}</div>;
}

export default StructuredValue;
