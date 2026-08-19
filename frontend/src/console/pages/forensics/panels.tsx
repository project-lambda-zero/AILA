/**
 * Shared primitives for the forensics project-detail UI: WindowPanel chrome
 * (mirrors XRayPage's Panel), the generic Table + KV + DictPanel renderers,
 * status/verdict badges, action buttons, and typed inline form controls.
 *
 * Every dict-valued field surfaces through DictPanel (recursive expandable
 * key/value); NEVER as a raw JSON blob. Every numeric/enum/text/checkbox
 * form control lives here so the tab modules can compose forms without any
 * ad-hoc styling.
 */
import type {
  ChangeEvent,
  CSSProperties,
  JSX,
  KeyboardEvent,
  ReactNode,
} from "react";
import { useMemo, useState } from "react";

import { css } from "../../css";
import StructuredValue from "../StructuredValue";

/* --- palette + shared style tokens (mirrors XRayPage.tsx) --------------- */
export const H = {
  acc: "#ff5f87",
  mint: "#97dbbe",
  amber: "#ffb85f",
  lav: "#af87d7",
  sig: "#f0a8c7",
  cream: "#ffd7af",
  warn: "#ffb85f",
  danger: "#ff5f5f",
} as const;

export const panelBoxRaw =
  ";min-height:0;display:flex;flex-direction:column;border:1px solid var(--border);border-radius:var(--radius-md,3px);background:color-mix(in srgb,var(--surface-card) 84%,transparent);overflow:hidden;box-shadow:var(--bevel-raised,inset 1px 1px 0 rgba(255,255,255,0.03));";

export const panelHatch =
  "height:2px;background-image:repeating-linear-gradient(135deg,var(--border) 0 1px,transparent 1px 3px);";

export const panelTitleStyle = css(
  "flex:0 0 auto;display:flex;align-items:center;gap:10px;height:var(--panel-title-h,28px);padding:0 12px;background:var(--surface-chrome);border-bottom:1px solid var(--border);font-family:var(--font-mono);font-size:11px;text-transform:uppercase;letter-spacing:0.14em;color:var(--text-muted);",
);

export const dotStyle = css(
  "width:8px;height:8px;border-radius:1px;background:var(--accent);box-shadow:0 0 6px var(--accent);flex:0 0 auto;",
);

export const emptyNote = css(
  "flex:1;display:flex;align-items:center;justify-content:center;padding:20px;font-family:var(--font-mono);font-size:11px;color:var(--text-faint);letter-spacing:0.04em;text-align:center;",
);

export const inlineNote = css(
  "padding:16px 20px;font-family:var(--font-mono);font-size:11px;color:var(--text-faint);letter-spacing:0.04em;text-align:center;",
);

/* --- WindowPanel primitive --------------------------------------------- */

export function Panel({
  title,
  tag,
  right,
  children,
  style,
  focused,
}: {
  title: string;
  tag?: string;
  right?: ReactNode;
  children: ReactNode;
  style?: CSSProperties;
  focused?: boolean;
}): JSX.Element {
  return (
    <section
      style={{
        ...css(
          "position:relative;" + panelBoxRaw + (focused ? "outline:1px solid color-mix(in srgb,var(--accent) 45%,transparent);outline-offset:-1px;" : ""),
        ),
        ...style,
      }}
    >
      <header style={panelTitleStyle}>
        <span style={dotStyle} />
        <span style={css("color:var(--text-primary);")}>{title}</span>
        {tag ? (
          <span style={css("font-size:9.5px;color:var(--text-faint);letter-spacing:0.08em;")}>{tag}</span>
        ) : null}
        <span style={css("flex:1;")} />
        {right}
      </header>
      <div style={css(panelHatch)} />
      <div style={css("flex:1;min-height:0;overflow:auto;")}>{children}</div>
    </section>
  );
}

/* --- button primitives ------------------------------------------------- */

export function CtlBtn({
  label,
  title,
  onClick,
  tone,
  disabled,
}: {
  label: string;
  title?: string;
  onClick: () => void;
  tone?: "accent" | "danger" | "warn" | "muted";
  disabled?: boolean;
}): JSX.Element {
  const c =
    tone === "danger"
      ? H.danger
      : tone === "warn"
      ? H.warn
      : tone === "accent"
      ? "var(--accent)"
      : "var(--text-muted)";
  return (
    <button
      type="button"
      title={title}
      disabled={disabled}
      onClick={disabled ? undefined : onClick}
      style={css(
        `flex:0 0 auto;font-family:var(--font-mono);font-size:10px;letter-spacing:0.08em;text-transform:uppercase;padding:4px 10px;height:26px;border:1px solid ${c}66;border-radius:2px;background:transparent;color:${c};cursor:${disabled ? "default" : "pointer"};${disabled ? "opacity:0.4;" : ""}`,
      )}
    >
      {label}
    </button>
  );
}

/** Small square icon-button for footer/window controls (matches DataPage). */
export function IconBtn({ label, title, onClick }: { label: string; title: string; onClick: () => void }): JSX.Element {
  return (
    <button
      type="button"
      title={title}
      onClick={onClick}
      style={css(
        "width:30px;flex:0 0 auto;display:flex;align-items:center;justify-content:center;border:0;border-left:1px solid var(--border-soft);background:transparent;color:var(--text-muted);cursor:pointer;font-family:inherit;font-size:12px;",
      )}
    >
      {label}
    </button>
  );
}

/* --- badges ------------------------------------------------------------ */

const STATUS_TONE: Record<string, string> = {
  created: "var(--text-muted)",
  ready: H.mint,
  analyzing: H.amber,
  completed: H.mint,
  failed: H.danger,
  cancelled: H.warn,
  pending: "var(--text-muted)",
  running: H.amber,
  exhausted: H.warn,
  paused: H.warn,
};

export function StatusBadge({ value }: { value: string | null | undefined }): JSX.Element {
  const v = (value ?? "").toLowerCase();
  const tone = STATUS_TONE[v] ?? "var(--text-faint)";
  return (
    <span
      style={css(
        `display:inline-flex;align-items:center;gap:6px;padding:2px 8px;border:1px solid ${tone}66;border-radius:2px;font-family:var(--font-mono);font-size:10px;letter-spacing:0.08em;text-transform:uppercase;color:${tone};background:color-mix(in srgb,${tone} 8%,transparent);`,
      )}
    >
      <span style={css(`width:6px;height:6px;border-radius:50%;background:${tone};`)} />
      {value ?? "\u2014"}
    </span>
  );
}

export function VerdictBadge({ verdict }: { verdict: string | null | undefined }): JSX.Element {
  const v = (verdict ?? "").toLowerCase();
  const tone = v === "true" ? H.mint : v === "false" ? H.danger : "var(--text-faint)";
  return (
    <span
      style={css(
        `display:inline-flex;align-items:center;padding:2px 8px;border:1px solid ${tone}66;border-radius:2px;font-family:var(--font-mono);font-size:10px;letter-spacing:0.08em;text-transform:uppercase;color:${tone};background:color-mix(in srgb,${tone} 8%,transparent);`,
      )}
    >
      {verdict ?? "\u2014"}
    </span>
  );
}

/* --- KV + Dict renderers ---------------------------------------------- */

export const kvStyle = css(
  "padding:11px 13px;display:grid;grid-template-columns:150px 1fr;gap:6px 12px;font-size:11px;align-content:start;",
);
export const kLabel = css(
  "color:var(--text-faint);letter-spacing:0.06em;word-break:break-word;",
);
export const kVal = css(
  "color:var(--text-primary);word-break:break-word;white-space:pre-wrap;",
);

/** Compact one-row KV strip. Values may be strings, numbers, booleans, or
 *  arrays/objects; complex values render through the shared
 *  <StructuredValue> renderer -- never a raw JSON blob. */
export function KV({ entries }: { entries: [string, unknown][] }): JSX.Element {
  return (
    <div style={kvStyle}>
      {entries.map(([k, v]) => (
        <span key={k} style={{ display: "contents" }}>
          <span style={kLabel}>{k}</span>
          <span style={kVal}>
            {renderValue(v)}
          </span>
        </span>
      ))}
    </div>
  );
}

/** Recursively render a value: primitives as inline text, everything
 *  structural (arrays, objects) via the shared <StructuredValue>. NEVER
 *  emits a raw JSON textarea. */
export function renderValue(v: unknown): ReactNode {
  if (v === null || v === undefined || v === "") return <span style={css("color:var(--text-faint);")}>{"\u2014"}</span>;
  if (typeof v === "boolean") return v ? "true" : "false";
  if (typeof v === "number") return String(v);
  if (typeof v === "string") return v;
  return <StructuredValue value={v} />;
}

/** A tucked-in table when a value is a list of objects (Network/Registry). */
export function SubTable({ rows }: { rows: unknown[] }): JSX.Element {
  const first = rows.find((r): r is Record<string, unknown> => r !== null && typeof r === "object");
  const cols = useMemo<string[]>(() => {
    if (!first) return [];
    const keys = new Set<string>();
    for (const r of rows.slice(0, 40)) {
      if (r && typeof r === "object") for (const k of Object.keys(r as Record<string, unknown>)) keys.add(k);
    }
    return Array.from(keys).slice(0, 8);
  }, [first, rows]);
  if (!first) return <span style={css("color:var(--text-faint);")}>{"\u2014"}</span>;
  return (
    <div style={css("overflow:auto;border:1px solid var(--border-soft);border-radius:2px;background:var(--surface-sunk);")}>
      <table style={css("width:100%;border-collapse:collapse;font-size:10px;")}>
        <thead>
          <tr>
            {cols.map((c) => (
              <th
                key={c}
                style={css(
                  "text-align:left;padding:5px 8px;background:var(--surface-chrome);border-bottom:1px solid var(--border-soft);font-size:8px;letter-spacing:0.1em;text-transform:uppercase;color:var(--text-faint);white-space:nowrap;",
                )}
              >
                {c}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.slice(0, 250).map((r, i) => {
            const row = (r && typeof r === "object" ? (r as Record<string, unknown>) : { value: r });
            return (
              <tr key={i} style={css("border-bottom:1px solid var(--border-faint);")}>
                {cols.map((c) => {
                  const cell = row[c];
                  const complex = cell !== null && typeof cell === "object";
                  return (
                    <td
                      key={c}
                      style={css(
                        complex
                          ? "padding:4px 8px;color:var(--text-primary);max-width:280px;vertical-align:top;word-break:break-word;"
                          : "padding:4px 8px;color:var(--text-primary);max-width:280px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;",
                      )}
                    >
                      {complex ? <StructuredValue value={cell} /> : primText(cell)}
                    </td>
                  );
                })}
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

function primText(v: unknown): string {
  if (v === null || v === undefined) return "\u2014";
  if (Array.isArray(v)) return v.length === 0 ? "\u2014" : `[${v.length}]`;
  if (typeof v === "object") {
    // Compact inline summary for narrow table cells; the detail view
    // renders the actual shape through <StructuredValue>. Never a raw
    // JSON blob dumped into an ellipsized cell.
    const n = Object.keys(v as Record<string, unknown>).length;
    return n === 0 ? "\u2014" : `{${n} field${n === 1 ? "" : "s"}}`;
  }
  return String(v);
}

/** Expandable key/value panel for dict-valued fields. Collapsed shows
 *  only the top-level keys; expanded recurses. NEVER renders raw JSON. */
export function DictPanel({ data, initialOpen }: { data: Record<string, unknown>; initialOpen?: boolean }): JSX.Element {
  const [open, setOpen] = useState<boolean>(initialOpen ?? false);
  const keys = Object.keys(data);
  if (keys.length === 0) return <span style={css("color:var(--text-faint);")}>{"{}"}</span>;
  return (
    <div style={css("border:1px solid var(--border-soft);border-radius:2px;background:var(--surface-sunk);")}>
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        style={css(
          `width:100%;text-align:left;display:flex;align-items:center;gap:8px;padding:5px 8px;background:var(--surface-chrome);border:0;border-bottom:${open ? "1px solid var(--border-soft)" : "0"};font-family:var(--font-mono);font-size:9px;letter-spacing:0.08em;text-transform:uppercase;color:var(--text-muted);cursor:pointer;`,
        )}
      >
        <span>{open ? "\u25be" : "\u25b8"}</span>
        <span>
          {keys.length} key{keys.length === 1 ? "" : "s"}
        </span>
        <span style={css("color:var(--text-faint);text-transform:none;letter-spacing:0.04em;")}>
          {keys.slice(0, 5).join(", ")}{keys.length > 5 ? "\u2026" : ""}
        </span>
      </button>
      {open ? (
        <div style={css("padding:7px 10px;display:grid;grid-template-columns:150px 1fr;gap:5px 10px;font-size:10.5px;")}>
          {keys.map((k) => (
            <span key={k} style={{ display: "contents" }}>
              <span style={kLabel}>{k}</span>
              <span style={kVal}>{renderValue(data[k])}</span>
            </span>
          ))}
        </div>
      ) : null}
    </div>
  );
}

/* --- Table primitive --------------------------------------------------- */

export interface TableColumn<R> {
  field: string;
  label: string;
  width?: number;
  render?: (row: R) => ReactNode;
}

export function DataTable<R extends Record<string, unknown>>({
  rows,
  columns,
  onSelect,
  selected,
  rowActions,
  idOf,
  empty,
}: {
  rows: R[];
  columns: TableColumn<R>[];
  onSelect?: (row: R) => void;
  selected?: R | null;
  rowActions?: (row: R) => ReactNode;
  idOf?: (row: R) => string;
  empty?: string;
}): JSX.Element {
  if (rows.length === 0) return <div style={emptyNote}>{empty ?? "no records."}</div>;
  return (
    <div style={css("overflow:auto;")}>
      <table style={css("width:100%;border-collapse:collapse;font-size:11px;")}>
        <thead>
          <tr>
            {columns.map((c) => (
              <th
                key={c.field}
                style={css(
                  `position:sticky;top:0;text-align:left;padding:7px 10px;background:var(--surface-chrome);border-bottom:1px solid var(--border);font-size:8.5px;letter-spacing:0.1em;text-transform:uppercase;color:var(--text-faint);white-space:nowrap;z-index:1;${c.width ? `width:${c.width}px;` : ""}`,
                )}
              >
                {c.label}
              </th>
            ))}
            {rowActions ? (
              <th
                style={css(
                  "position:sticky;top:0;text-align:right;padding:7px 10px;background:var(--surface-chrome);border-bottom:1px solid var(--border);font-size:8.5px;letter-spacing:0.1em;text-transform:uppercase;color:var(--text-faint);white-space:nowrap;z-index:1;",
                )}
              >
                actions
              </th>
            ) : null}
          </tr>
        </thead>
        <tbody>
          {rows.map((row, i) => {
            const key = (idOf ? idOf(row) : String(row.id ?? i)) + i;
            const active = selected === row;
            return (
              <tr
                key={key}
                onClick={onSelect ? () => onSelect(row) : undefined}
                style={css(
                  `${onSelect ? "cursor:pointer;" : ""}border-bottom:1px solid var(--border-faint);${active ? "background:color-mix(in srgb,var(--accent) 12%,transparent);" : ""}`,
                )}
              >
                {columns.map((c) => (
                  <td
                    key={c.field}
                    style={css(
                      "padding:6px 10px;color:var(--text-primary);max-width:340px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;",
                    )}
                  >
                    {c.render ? c.render(row) : primText(row[c.field])}
                  </td>
                ))}
                {rowActions ? (
                  <td
                    onClick={(e) => e.stopPropagation()}
                    style={css("padding:4px 10px;text-align:right;white-space:nowrap;")}
                  >
                    {rowActions(row)}
                  </td>
                ) : null}
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

/* --- typed form primitives -------------------------------------------- */

const inputBase =
  "width:100%;box-sizing:border-box;background:var(--surface-sunk);border:1px solid var(--border-soft);border-radius:2px;padding:6px 8px;font-family:var(--font-mono);font-size:11px;color:var(--text-primary);";

export function Field({ label, hint, children }: { label: string; hint?: string; children: ReactNode }): JSX.Element {
  return (
    <label style={css("display:flex;flex-direction:column;gap:4px;font-family:var(--font-mono);")}>
      <span style={css("font-size:9px;letter-spacing:0.12em;text-transform:uppercase;color:var(--text-muted);")}>
        {label}
      </span>
      {children}
      {hint ? (
        <span style={css("font-size:9px;color:var(--text-faint);letter-spacing:0.03em;")}>{hint}</span>
      ) : null}
    </label>
  );
}

export function TextInput({
  value,
  onChange,
  placeholder,
  onEnter,
}: {
  value: string;
  onChange: (v: string) => void;
  placeholder?: string;
  onEnter?: () => void;
}): JSX.Element {
  return (
    <input
      type="text"
      value={value}
      placeholder={placeholder}
      onChange={(e: ChangeEvent<HTMLInputElement>) => onChange(e.target.value)}
      onKeyDown={
        onEnter
          ? (e: KeyboardEvent<HTMLInputElement>) => {
              if (e.key === "Enter") {
                e.preventDefault();
                onEnter();
              }
            }
          : undefined
      }
      style={css(inputBase)}
    />
  );
}

export function NumberInput({
  value,
  onChange,
  min,
  max,
}: {
  value: number;
  onChange: (v: number) => void;
  min?: number;
  max?: number;
}): JSX.Element {
  return (
    <input
      type="number"
      value={value}
      min={min}
      max={max}
      onChange={(e: ChangeEvent<HTMLInputElement>) => {
        const n = Number(e.target.value);
        if (Number.isFinite(n)) onChange(n);
      }}
      style={css(inputBase)}
    />
  );
}

export function TextArea({
  value,
  onChange,
  rows,
  placeholder,
}: {
  value: string;
  onChange: (v: string) => void;
  rows?: number;
  placeholder?: string;
}): JSX.Element {
  return (
    <textarea
      value={value}
      rows={rows ?? 4}
      placeholder={placeholder}
      onChange={(e: ChangeEvent<HTMLTextAreaElement>) => onChange(e.target.value)}
      style={css(inputBase + "resize:vertical;font-family:var(--font-mono);line-height:1.5;")}
    />
  );
}

export function Select<T extends string>({
  value,
  onChange,
  options,
}: {
  value: T | "";
  onChange: (v: T | "") => void;
  options: { value: T | ""; label: string }[];
}): JSX.Element {
  return (
    <select
      value={value}
      onChange={(e: ChangeEvent<HTMLSelectElement>) => onChange(e.target.value as T | "")}
      style={css(inputBase + "cursor:pointer;")}
    >
      {options.map((o) => (
        <option key={String(o.value)} value={o.value}>
          {o.label}
        </option>
      ))}
    </select>
  );
}

export function Checkbox({
  checked,
  onChange,
  label,
}: {
  checked: boolean;
  onChange: (v: boolean) => void;
  label: string;
}): JSX.Element {
  return (
    <label
      style={css(
        "display:inline-flex;align-items:center;gap:8px;font-family:var(--font-mono);font-size:10.5px;color:var(--text-primary);cursor:pointer;",
      )}
    >
      <input type="checkbox" checked={checked} onChange={(e) => onChange(e.target.checked)} />
      {label}
    </label>
  );
}

/** Space-separated chip input. Backspace on empty removes the last chip. */
export function ChipInput({
  values,
  onChange,
  placeholder,
}: {
  values: string[];
  onChange: (v: string[]) => void;
  placeholder?: string;
}): JSX.Element {
  const [text, setText] = useState("");
  const commit = (raw: string): void => {
    const t = raw.trim();
    if (!t) return;
    if (values.includes(t)) return;
    onChange([...values, t]);
    setText("");
  };
  return (
    <div
      style={css(
        inputBase + "display:flex;flex-wrap:wrap;gap:5px;padding:5px 6px;min-height:32px;align-items:center;",
      )}
    >
      {values.map((v, i) => (
        <span
          key={v + i}
          style={css(
            "display:inline-flex;align-items:center;gap:5px;padding:1px 7px;border:1px solid var(--border-soft);border-radius:2px;font-size:9.5px;color:var(--text-primary);background:var(--surface-chrome);",
          )}
        >
          {v}
          <button
            type="button"
            onClick={() => onChange(values.filter((_, j) => j !== i))}
            style={css("background:transparent;border:0;color:var(--text-faint);cursor:pointer;font-size:11px;line-height:1;")}
          >
            {"\u2715"}
          </button>
        </span>
      ))}
      <input
        type="text"
        value={text}
        placeholder={placeholder}
        onChange={(e: ChangeEvent<HTMLInputElement>) => setText(e.target.value)}
        onKeyDown={(e: KeyboardEvent<HTMLInputElement>) => {
          if (e.key === "Enter" || e.key === ",") {
            e.preventDefault();
            commit(text);
          } else if (e.key === "Backspace" && text === "" && values.length) {
            onChange(values.slice(0, -1));
          }
        }}
        style={css(
          "flex:1;min-width:60px;border:0;background:transparent;color:var(--text-primary);font-family:var(--font-mono);font-size:11px;outline:none;",
        )}
      />
    </div>
  );
}

/** Radio group across an enum. */
export function Radio<T extends string>({
  value,
  onChange,
  options,
}: {
  value: T;
  onChange: (v: T) => void;
  options: { value: T; label: string }[];
}): JSX.Element {
  return (
    <div style={css("display:flex;gap:14px;font-family:var(--font-mono);font-size:11px;color:var(--text-primary);")}>
      {options.map((o) => (
        <label key={o.value} style={css("display:inline-flex;align-items:center;gap:6px;cursor:pointer;")}>
          <input type="radio" checked={value === o.value} onChange={() => onChange(o.value)} />
          {o.label}
        </label>
      ))}
    </div>
  );
}

export function FormBox({
  title,
  onCancel,
  onSubmit,
  submitLabel,
  submitting,
  error,
  children,
}: {
  title: string;
  onCancel: () => void;
  onSubmit: () => void;
  submitLabel: string;
  submitting?: boolean;
  error?: string | null;
  children: ReactNode;
}): JSX.Element {
  return (
    <div
      style={css(
        "position:absolute;inset:0;background:color-mix(in srgb,var(--surface-page) 78%,transparent);display:flex;align-items:center;justify-content:center;z-index:10;padding:32px;",
      )}
    >
      <div
        style={css(
          "width:min(540px,100%);max-height:100%;overflow:auto;border:1px solid var(--border);border-radius:var(--radius-md,3px);background:var(--surface-card);box-shadow:0 12px 36px rgba(0,0,0,0.55);display:flex;flex-direction:column;",
        )}
      >
        <div
          style={css(
            "display:flex;align-items:center;gap:10px;padding:9px 13px;background:var(--surface-chrome);border-bottom:1px solid var(--border);font-family:var(--font-mono);font-size:10px;letter-spacing:0.14em;text-transform:uppercase;color:var(--text-primary);",
          )}
        >
          <span style={dotStyle} />
          <span>{title}</span>
          <span style={css("flex:1;")} />
          <button
            type="button"
            onClick={onCancel}
            style={css("background:transparent;border:0;color:var(--text-faint);cursor:pointer;font-size:14px;")}
          >
            {"\u2715"}
          </button>
        </div>
        <div style={css("padding:16px 18px;display:flex;flex-direction:column;gap:14px;")}>{children}</div>
        {error ? (
          <div
            style={css(
              `margin:0 18px 10px;padding:8px 10px;border:1px solid ${H.danger}66;border-radius:2px;background:${H.danger}11;color:${H.danger};font-family:var(--font-mono);font-size:10.5px;`,
            )}
          >
            {error}
          </div>
        ) : null}
        <div
          style={css(
            "display:flex;justify-content:flex-end;gap:8px;padding:12px 18px;border-top:1px solid var(--border);background:var(--surface-chrome);",
          )}
        >
          <CtlBtn label="cancel" tone="muted" onClick={onCancel} />
          <CtlBtn label={submitting ? "submitting\u2026" : submitLabel} tone="accent" onClick={onSubmit} disabled={submitting} />
        </div>
      </div>
    </div>
  );
}
