/**
 * Typed inline form controls for the forensics project window: labelled
 * field wrapper, text/number/textarea inputs, select, checkbox, chip list,
 * radio group, and the modal FormBox with submit/cancel. Every numeric,
 * enum, text, and checkbox control lives here so forms compose without
 * ad-hoc styling.
 */
import type { ChangeEvent, JSX, KeyboardEvent, ReactNode } from "react";
import { useState } from "react";

import { css } from "../../css";
import { CtlBtn, H, dotStyle } from "./panels";

/* --- typed form primitives -------------------------------------------- */

const inputBase =
  "width:100%;box-sizing:border-box;background:var(--surface-sunk);border:1px solid var(--border-soft);border-radius:2px;padding:6px 8px;font-family:var(--font-mono);font-size:11px;color:var(--text-primary);";

export function Field({ label, hint, children }: { label: string; hint?: string; children: ReactNode }): JSX.Element {
  return (
    <label style={css("display:flex;flex-direction:column;gap:4px;font-family:var(--font-mono);")}>
      <span style={css("font-size:11px;letter-spacing:0.12em;text-transform:uppercase;color:var(--text-muted);")}>
        {label}
      </span>
      {children}
      {hint ? (
        <span style={css("font-size:11px;color:var(--text-faint);letter-spacing:0.03em;")}>{hint}</span>
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
        "display:inline-flex;align-items:center;gap:8px;font-family:var(--font-mono);font-size:11px;color:var(--text-primary);cursor:pointer;",
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
            "display:inline-flex;align-items:center;gap:5px;padding:1px 7px;border:1px solid var(--border-soft);border-radius:2px;font-size:11px;color:var(--text-primary);background:var(--surface-chrome);",
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
            "display:flex;align-items:center;gap:10px;padding:9px 13px;background:var(--surface-chrome);border-bottom:1px solid var(--border);font-family:var(--font-mono);font-size:11px;letter-spacing:0.14em;text-transform:uppercase;color:var(--text-primary);",
          )}
        >
          <span style={dotStyle} />
          <span>{title}</span>
          <span style={css("flex:1;")} />
          <button
            type="button"
            onClick={onCancel}
            style={css("background:transparent;border:0;color:var(--text-faint);cursor:pointer;min-height:28px;display:inline-flex;align-items:center;font-size:14px;")}
          >
            {"\u2715"}
          </button>
        </div>
        <div style={css("padding:16px 18px;display:flex;flex-direction:column;gap:14px;")}>{children}</div>
        {error ? (
          <div
            style={css(
              `margin:0 18px 10px;padding:8px 10px;border:1px solid ${H.danger}66;border-radius:2px;background:${H.danger}11;color:${H.danger};font-family:var(--font-mono);font-size:11px;`,
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
