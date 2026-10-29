/** Shared chrome for the admin console pages: the window frame, a titled
 * section card, a key/value grid, query-state lines, and a compact table. */
import type { JSX, ReactNode } from "react";

import { apiErrDetail } from "../../../api/parse";
import type { ModulePageProps } from "../../contract";
import { css } from "../../css";
import { ConsoleWindow } from "../../window";
import { fieldStyle, formLabel } from "../xray/actions";

export const MONO = "font-family:var(--font-mono);";
export const FAINT = "color:var(--text-faint);";

export function AdminWindow({ page, children }: { page: ModulePageProps; children: ReactNode }): JSX.Element {
  return (
    <ConsoleWindow
      id={page.windowId}
      kind="page"
      title={page.title}
      isFocused={page.isFocused ?? true}
      onFocus={page.onFocus}
      onClose={page.onBack}
      onMinimize={page.onMinimize}
      isFullscreen={page.isFullscreen}
      onToggleFullscreen={page.onToggleFullscreen}
    >
      <div style={css("position:absolute;inset:0;overflow:auto;padding:16px 18px;display:flex;flex-direction:column;gap:14px;font-size:12px;")}>
        {children}
      </div>
    </ConsoleWindow>
  );
}

export function Section({ title, aside, children }: { title: string; aside?: ReactNode; children: ReactNode }): JSX.Element {
  return (
    <section style={css("border:1px solid var(--border);background:var(--surface-card);border-radius:4px;box-shadow:var(--bevel-raised);padding:12px 14px;display:flex;flex-direction:column;gap:10px;min-width:0;")}>
      <header style={css("display:flex;align-items:center;gap:9px;")}>
        <span style={css("width:8px;height:8px;background:var(--accent);flex:0 0 auto;")} />
        <span style={css(MONO + "font-size:11px;letter-spacing:0.14em;text-transform:uppercase;color:var(--text-primary);")}>{title}</span>
        <span style={css("flex:1;")} />
        {aside}
      </header>
      {children}
    </section>
  );
}

/** Loading / error / empty line for a query; renders nothing once data is ready. */
export function QueryState({ loading, error, empty, emptyText }: { loading: boolean; error: unknown; empty: boolean; emptyText: string }): JSX.Element | null {
  if (loading) return <div style={css(FAINT + MONO + "font-size:11px;")}>loading{"…"}</div>;
  if (error) return <div style={css("color:var(--status-warn);font-size:11px;" + MONO)}>{apiErrDetail(error)}</div>;
  if (empty) return <div style={css(FAINT + "font-size:11px;font-style:italic;")}>{emptyText}</div>;
  return null;
}

export function KvGrid({ rows }: { rows: readonly (readonly [label: string, value: ReactNode])[] }): JSX.Element {
  return (
    <div style={css("display:grid;grid-template-columns:150px 1fr;gap:5px 12px;font-size:11.5px;align-items:baseline;")}>
      {rows.map(([label, value]) => (
        <div key={label} style={css("display:contents;")}>
          <span style={css(FAINT)}>{label}</span>
          <span style={css("color:var(--text-primary);word-break:break-word;" + MONO)}>{value}</span>
        </div>
      ))}
    </div>
  );
}

export interface Column<T> {
  label: string;
  cell: (row: T) => ReactNode;
}

export function Table<T>({ rows, columns, rowKey, onRowClick, selectedKey }: {
  rows: readonly T[];
  columns: readonly Column<T>[];
  rowKey: (row: T) => string;
  onRowClick?: (row: T) => void;
  selectedKey?: string | null;
}): JSX.Element {
  return (
    <div style={css("overflow:auto;border:1px solid var(--border-soft);border-radius:2px;")}>
      <table style={css("width:100%;border-collapse:collapse;font-size:11px;" + MONO)}>
        <thead>
          <tr>
            {columns.map((c) => (
              <th key={c.label} style={css("text-align:left;padding:6px 8px;font-weight:400;letter-spacing:0.08em;text-transform:uppercase;background:var(--surface-sunk);border-bottom:1px solid var(--border-soft);white-space:nowrap;" + FAINT)}>
                {c.label}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((r) => {
            const k = rowKey(r);
            const selected = selectedKey === k;
            return (
              <tr
                key={k}
                onClick={onRowClick ? () => onRowClick(r) : undefined}
                style={css(
                  `border-bottom:1px solid var(--border-soft);${onRowClick ? "cursor:pointer;" : ""}${selected ? "background:color-mix(in srgb,var(--accent) 10%,transparent);" : ""}`,
                )}
              >
                {columns.map((c) => (
                  <td key={c.label} style={css("padding:6px 8px;color:var(--text-primary);vertical-align:top;word-break:break-word;")}>
                    {c.cell(r)}
                  </td>
                ))}
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

/** Labelled form control: caption above the field. */
export function Field({ label, children }: { label: string; children: ReactNode }): JSX.Element {
  return (
    <label style={css("display:flex;flex-direction:column;gap:3px;min-width:0;")}>
      <span style={formLabel}>{label}</span>
      {children}
    </label>
  );
}

/** Submit button for the lookup forms; 28px tall to match the action row. */
export function SubmitButton({ label, disabled, pending = false }: { label: string; disabled: boolean; pending?: boolean }): JSX.Element {
  return (
    <button
      type="submit"
      disabled={disabled || pending}
      style={{ ...fieldStyle, cursor: disabled || pending ? "default" : "pointer", color: "var(--accent)", opacity: disabled || pending ? 0.45 : 1 }}
    >
      {pending ? `${label}…` : label}
    </button>
  );
}

export function fmtTime(iso: string | null): string {
  if (!iso) return "—";
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleString();
}
