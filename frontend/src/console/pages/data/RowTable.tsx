/** The DataPage row table: header row, bulk-selection column, semantic cell
 * rendering, status rail, and optional groupBy sectioning. */

import type { CSSProperties, JSX } from "react";

import { css } from "../../css";
import { semanticCell, statusRailColor } from "../badges";
import { cellText, groupRows } from "./rows";
import type { DataRow, PageColumn } from "./types";

export interface RowTableProps {
  rows: DataRow[];
  columns: PageColumn[];
  numericFields: Set<string>;
  idField: string;
  sel: DataRow | null;
  setSel: (row: DataRow | null) => void;
  selected: Set<string>;
  toggleRow: (row: DataRow) => void;
  toggleAll: () => void;
  bulkEnabled: boolean;
  groupBy?: string;
  onRowActivate?: (row: DataRow) => void;
}

export function RowTable(props: RowTableProps): JSX.Element {
  const { rows, columns, numericFields, idField, sel, setSel, selected, toggleRow, toggleAll, bulkEnabled, groupBy, onRowActivate } = props;
  const headerCell = (numeric: boolean): CSSProperties =>
    css(
      `position:sticky;top:0;text-align:${numeric ? "right" : "left"};padding:8px 12px;background:var(--surface-chrome);border-bottom:1px solid color-mix(in srgb,var(--accent) 32%,var(--border));font-family:var(--font-mono);font-size:11px;font-weight:500;letter-spacing:0.14em;text-transform:uppercase;color:var(--text-muted);white-space:nowrap;z-index:1;`,
    );

  const renderRow = (row: DataRow, i: number): JSX.Element => {
    const key = cellText(row[idField]) + i;
    const active = sel === row;
    // Status-toned left ribbon: a continuous vertical rail the eye follows
    // down the table, encoding each row's state at the left edge. Rendered as
    // an inset box-shadow (no layout shift) so hover/active are free to use a
    // background tint. Active wins the ribbon in accent so the selected row
    // still reads.
    const rail = active ? "var(--accent)" : statusRailColor(row["status"]) ?? "transparent";
    return (
      <tr
        key={key}
        onClick={(e) => {
          // SAFETY: the click target is a DOM element inside the row's own tree.
          const target = e.target as HTMLElement;
          if (target.tagName === "INPUT") return; // checkbox click handled by its own onChange
          if (onRowActivate) onRowActivate(row);
          else setSel(sel === row ? null : row);
        }}
        style={css(
          `cursor:pointer;border-bottom:1px solid var(--border-faint);box-shadow:inset 3px 0 0 ${rail};${active ? "background:color-mix(in srgb,var(--accent) 16%,transparent);" : ""}`,
        )}
      >
        {bulkEnabled ? (
          <td style={css("padding:6px 8px;width:28px;")}>
            <input
              type="checkbox"
              checked={selected.has(String(row[idField] ?? ""))}
              onChange={() => toggleRow(row)}
              onClick={(e) => e.stopPropagation()}
            />
          </td>
        ) : null}
        {columns.map((c, ci) => {
          const isNum = numericFields.has(c.field);
          const isTitle = ci === 0 && !c.kind;
          // Title column anchors the row (bright, semibold); numeric columns
          // get mono tabular figures; everything else recedes to muted so the
          // eye lands on the anchor and the status color, not a wall of even
          // text.
          const emphasis = isTitle
            ? "color:var(--text-primary);font-weight:600;"
            : isNum
              ? "color:var(--text-muted);font-family:var(--font-mono);font-variant-numeric:tabular-nums;"
              : "color:var(--text-muted);";
          return (
            <td
              key={c.field}
              style={css(
                `padding:7px 12px;max-width:${isTitle ? 460 : 320}px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;text-align:${isNum ? "right" : "left"};${emphasis}`,
              )}
            >
              {c.render ? c.render(row[c.field], row) : c.kind ? semanticCell(c.kind, row[c.field]) : cellText(row[c.field])}
            </td>
          );
        })}
      </tr>
    );
  };

  // groupBy: partition the visible rows into sections keyed by row[groupBy].
  // The row key index runs across all groups (rows are siblings in one tbody).
  const groupField = groupBy;
  let idx = 0;
  const body = !groupField
    ? rows.map(renderRow)
    : groupRows(rows, groupField).map(([gk, bucket]) => {
        const colSpan = columns.length + (bulkEnabled ? 1 : 0);
        const section = (
          <tr key={`__group_${gk}`} style={css("background:var(--surface-chrome);")}>
            <td
              colSpan={colSpan}
              style={css("padding:6px 12px;border-bottom:1px solid var(--border);font-family:var(--font-mono);font-size:11px;letter-spacing:0.14em;text-transform:uppercase;color:var(--text-muted);")}
            >
              {gk || "\u2014"}
            </td>
          </tr>
        );
        const out: JSX.Element[] = [section];
        for (const row of bucket) {
          out.push(renderRow(row, idx));
          idx += 1;
        }
        return out;
      });

  return (
    <table className="dp-table" style={css("width:100%;border-collapse:collapse;font-size:11px;")}>
      <thead>
        <tr>
          {bulkEnabled ? (
            <th
              style={css("position:sticky;top:0;z-index:1;background:var(--surface-sunk);padding:6px 8px;text-align:left;font-size:11px;letter-spacing:0.1em;text-transform:uppercase;color:var(--text-faint);font-weight:400;width:28px;")}
            >
              <input
                type="checkbox"
                checked={rows.length > 0 && rows.every((r) => selected.has(String(r[idField] ?? "")))}
                onChange={toggleAll}
                title="select all rows on this page"
              />
            </th>
          ) : null}
          {columns.map((c) => (
            <th key={c.field} style={headerCell(numericFields.has(c.field))}>
              {c.label}
            </th>
          ))}
        </tr>
      </thead>
      <tbody>{body}</tbody>
    </table>
  );
}
