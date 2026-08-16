/**
 * Generic typed create/edit form driven by a per-resource FormSpec.
 *
 * Renders labeled inputs for each field, tracks which fields the operator
 * touched (so PATCH omits untouched keys), serializes only the specced fields
 * into the payload (Pydantic Create/Patch models use `extra="forbid"`, so
 * even one stray key returns 400), and posts via useResourceMutation. On
 * success it invalidates the parent DataPage's query and calls `onDone`.
 *
 * NO raw-JSON textareas. Every field is a typed widget:
 *   text / textarea / password / number / checkbox / select / tags / keyval
 *   json-array-tags / json-object-keyval / steps (playbook step sub-form)
 */
import { useMemo, useState } from "react";
import type { ChangeEvent, JSX, KeyboardEvent } from "react";
import type { QueryKey } from "@tanstack/react-query";

import { ApiError } from "../../api/client";
import { useFieldOptions, useResourceMutation } from "../../api/mutations";
import { asRecord, readNum, readStr } from "../../api/parse";
import { css } from "../css";

export type FieldType =
  | "text"
  | "textarea"
  | "password"
  | "number"
  | "checkbox"
  | "select"
  | "tags"
  | "keyval"
  | "json-array-tags"
  | "json-object-keyval"
  | "steps";

export interface FieldSpec {
  name: string;
  label: string;
  type: FieldType;
  required?: boolean;
  /** Static enum options for `select`. */
  options?: { value: string; label: string }[];
  /** GET a list endpoint and use each row for select options. */
  optionsFrom?: string;
  /** Override the row field used as the option value (defaults to id-like). */
  optionsValueField?: string;
  /** Override the row field used as the option label (defaults to name-like). */
  optionsLabelField?: string;
  placeholder?: string;
  help?: string;
  /** Number bounds. */
  min?: number;
  max?: number;
  step?: number;
}

export interface FormSpec {
  /** Modal header. */
  title: string;
  /** Endpoint template; `{id}` is substituted from initial[idField] on PATCH. */
  endpoint: string;
  method: "POST" | "PATCH" | "PUT";
  fields: FieldSpec[];
  /** react-query key to invalidate on success (DataPage overrides this). */
  invalidateKey?: QueryKey;
  /** Row field used to substitute {id} in `endpoint`. Defaults to `id`. */
  idField?: string;
}

interface FieldFormProps {
  spec: FormSpec;
  /** Existing row for edit mode. Populates the form and enables PATCH-diff behavior. */
  initial?: Record<string, unknown> | null;
  onDone?: () => void;
  onCancel?: () => void;
  /** Overrides spec.invalidateKey when DataPage supplies its resolved query key. */
  invalidateKey?: QueryKey;
}

interface PlaybookStep {
  sequence: number;
  tool: string;
  args: Record<string, string>;
  expects: Record<string, string>;
  on_failure: string;
}

type FieldValue =
  | string
  | number
  | boolean
  | string[]
  | Record<string, string>
  | PlaybookStep[]
  | null
  | undefined;

// ---------- helpers ---------------------------------------------------------

/** Convert a stored raw value (from `initial`) into the widget's working form. */
function toWidgetValue(field: FieldSpec, raw: unknown): FieldValue {
  switch (field.type) {
    case "text":
    case "textarea":
    case "password":
    case "select":
      if (raw === null || raw === undefined) return "";
      return String(raw);
    case "number":
      if (raw === null || raw === undefined || raw === "") return "";
      return typeof raw === "number" ? raw : String(raw);
    case "checkbox":
      return Boolean(raw);
    case "tags":
      if (Array.isArray(raw)) return raw.map((v) => String(v));
      return [];
    case "keyval": {
      const rec = asRecord(raw);
      if (!rec) return {};
      const out: Record<string, string> = {};
      for (const [k, v] of Object.entries(rec)) {
        out[k] = typeof v === "string" ? v : JSON.stringify(v);
      }
      return out;
    }
    case "json-array-tags": {
      if (typeof raw === "string" && raw.length) {
        try {
          const parsed: unknown = JSON.parse(raw);
          if (Array.isArray(parsed)) return parsed.map((v) => String(v));
        } catch {
          /* fall through */
        }
      }
      if (Array.isArray(raw)) return raw.map((v) => String(v));
      return [];
    }
    case "json-object-keyval": {
      if (typeof raw === "string" && raw.length) {
        try {
          const rec = asRecord(JSON.parse(raw));
          if (rec) {
            const out: Record<string, string> = {};
            for (const [k, v] of Object.entries(rec)) {
              out[k] = typeof v === "string" ? v : JSON.stringify(v);
            }
            return out;
          }
        } catch {
          /* fall through */
        }
      }
      return {};
    }
    case "steps": {
      if (!Array.isArray(raw)) return [];
      return raw.map((s, i) => {
        const row = asRecord(s) ?? {};
        const args: Record<string, string> = {};
        const argsRec = asRecord(row["args"]);
        if (argsRec) {
          for (const [k, v] of Object.entries(argsRec)) {
            args[k] = typeof v === "string" ? v : JSON.stringify(v);
          }
        }
        const expects: Record<string, string> = {};
        const expectsRec = asRecord(row["expects"]);
        if (expectsRec) {
          for (const [k, v] of Object.entries(expectsRec)) {
            expects[k] = typeof v === "string" ? v : JSON.stringify(v);
          }
        }
        return {
          sequence: readNum(row, "sequence") ?? i,
          tool: readStr(row, "tool") ?? "",
          args,
          expects,
          on_failure: readStr(row, "on_failure") ?? "continue",
        };
      });
    }
    default:
      return null;
  }
}

/** Turn a widget value into what we send to the server, or null when the
 * value is empty and the field is not required (so `extra=forbid` + server
 * defaults hold). */
function serializeField(field: FieldSpec, value: FieldValue): unknown {
  switch (field.type) {
    case "text":
    case "textarea":
    case "password": {
      const s = typeof value === "string" ? value : "";
      if (!s.length) return field.required ? "" : undefined;
      return s;
    }
    case "select": {
      const s = typeof value === "string" ? value : "";
      if (!s.length) return field.required ? "" : undefined;
      return s;
    }
    case "number": {
      if (value === "" || value === null || value === undefined) return undefined;
      const n = typeof value === "number" ? value : Number(value);
      if (Number.isNaN(n)) return undefined;
      return n;
    }
    case "checkbox":
      return Boolean(value);
    case "tags": {
      const arr = Array.isArray(value) ? value : [];
      if (!arr.length && !field.required) return undefined;
      return arr;
    }
    case "keyval": {
      const obj = (asRecord(value) ?? {}) as Record<string, string>;
      const trimmed: Record<string, unknown> = {};
      for (const [k, v] of Object.entries(obj)) {
        if (k.length === 0) continue;
        // Try to coerce JSON literal / number / bool so payloads stay typed.
        trimmed[k] = coerceScalar(v);
      }
      if (Object.keys(trimmed).length === 0 && !field.required) return undefined;
      return trimmed;
    }
    case "json-array-tags": {
      const arr = Array.isArray(value) ? value : [];
      if (!arr.length && !field.required) return undefined;
      return JSON.stringify(arr);
    }
    case "json-object-keyval": {
      const obj = (asRecord(value) ?? {}) as Record<string, string>;
      const trimmed: Record<string, unknown> = {};
      for (const [k, v] of Object.entries(obj)) {
        if (k.length === 0) continue;
        trimmed[k] = coerceScalar(v);
      }
      if (Object.keys(trimmed).length === 0 && !field.required) return undefined;
      return JSON.stringify(trimmed);
    }
    case "steps": {
      const list = Array.isArray(value) ? (value as PlaybookStep[]) : [];
      if (!list.length) return field.required ? [] : undefined;
      return list.map((s, idx) => {
        const args: Record<string, unknown> = {};
        for (const [k, v] of Object.entries(s.args ?? {})) {
          if (k.length === 0) continue;
          args[k] = coerceScalar(v);
        }
        const expects: Record<string, unknown> = {};
        for (const [k, v] of Object.entries(s.expects ?? {})) {
          if (k.length === 0) continue;
          expects[k] = coerceScalar(v);
        }
        return {
          sequence: typeof s.sequence === "number" ? s.sequence : idx,
          tool: s.tool,
          args,
          expects,
          on_failure: s.on_failure || "continue",
        };
      });
    }
    default:
      return undefined;
  }
}

/** Best-effort typed coercion for keyval / step-args entries. `"true"` ->
 * boolean, `"42"` -> number, otherwise the original string. Anything that
 * looks like a JSON object/array is parsed. */
function coerceScalar(v: string): unknown {
  if (v === "") return "";
  if (v === "true") return true;
  if (v === "false") return false;
  if (v === "null") return null;
  const trimmed = v.trim();
  if (/^-?\d+$/.test(trimmed)) return Number.parseInt(trimmed, 10);
  if (/^-?\d+\.\d+$/.test(trimmed)) return Number.parseFloat(trimmed);
  if ((trimmed.startsWith("{") && trimmed.endsWith("}")) || (trimmed.startsWith("[") && trimmed.endsWith("]"))) {
    try {
      return JSON.parse(trimmed);
    } catch {
      /* fall through */
    }
  }
  return v;
}

// ---------- styling ---------------------------------------------------------

const label = css(
  "display:flex;flex-direction:column;gap:4px;font-family:var(--font-mono);font-size:10px;letter-spacing:0.06em;text-transform:uppercase;color:var(--text-muted);",
);
const help = css(
  "font-family:var(--font-mono);font-size:9.5px;color:var(--text-faint);letter-spacing:0.02em;text-transform:none;",
);
const inputStyle = css(
  "background:var(--surface-sunk);border:1px solid var(--border);border-radius:2px;color:var(--text-primary);font-family:var(--font-mono);font-size:11px;padding:6px 8px;letter-spacing:0.02em;text-transform:none;outline:none;",
);
const textareaStyle = css(
  "background:var(--surface-sunk);border:1px solid var(--border);border-radius:2px;color:var(--text-primary);font-family:var(--font-mono);font-size:11px;padding:7px 8px;letter-spacing:0.02em;text-transform:none;outline:none;min-height:72px;resize:vertical;",
);
const chipRow = css("display:flex;flex-wrap:wrap;gap:4px;align-items:center;padding:5px;background:var(--surface-sunk);border:1px solid var(--border);border-radius:2px;");
const chip = css(
  "display:inline-flex;align-items:center;gap:4px;padding:2px 6px;border:1px solid var(--border-soft);border-radius:2px;background:color-mix(in srgb,var(--accent) 12%,transparent);color:var(--text-primary);font-family:var(--font-mono);font-size:10px;letter-spacing:0.02em;text-transform:none;",
);
const chipInput = css(
  "flex:1;min-width:80px;background:transparent;border:0;color:var(--text-primary);font-family:var(--font-mono);font-size:11px;outline:none;padding:2px 4px;text-transform:none;letter-spacing:0.02em;",
);
const kvRow = css("display:grid;grid-template-columns:1fr 1fr auto;gap:6px;");
const kvBox = css("display:flex;flex-direction:column;gap:6px;padding:6px;background:color-mix(in srgb,var(--surface-sunk) 50%,transparent);border:1px solid var(--border-soft);border-radius:2px;");
const rowBtn = css(
  "padding:2px 8px;border:1px solid var(--border-soft);background:transparent;color:var(--text-muted);font-family:var(--font-mono);font-size:9.5px;letter-spacing:0.06em;text-transform:uppercase;cursor:pointer;border-radius:2px;",
);
const stepCard = css("display:flex;flex-direction:column;gap:8px;padding:9px;background:var(--surface-sunk);border:1px solid var(--border);border-radius:2px;");
const primaryBtn = css(
  "padding:6px 14px;border:1px solid var(--accent);background:var(--accent);color:var(--text-on-accent);font-family:var(--font-mono);font-size:10px;letter-spacing:0.1em;text-transform:uppercase;cursor:pointer;border-radius:2px;",
);
const ghostBtn = css(
  "padding:6px 14px;border:1px solid var(--border);background:transparent;color:var(--text-muted);font-family:var(--font-mono);font-size:10px;letter-spacing:0.1em;text-transform:uppercase;cursor:pointer;border-radius:2px;",
);
const errBox = css(
  "border:1px solid #ffb85f;border-radius:2px;padding:8px 10px;background:color-mix(in srgb,#ffb85f 12%,transparent);color:#ffb85f;font-family:var(--font-mono);font-size:10.5px;letter-spacing:0.02em;text-transform:none;white-space:pre-wrap;",
);

// ---------- widgets ---------------------------------------------------------

/** Chip / tag input. Empty string, Enter, comma, or blur commits the chip. */
function TagInput({
  value,
  onChange,
  placeholder,
}: {
  value: string[];
  onChange: (next: string[]) => void;
  placeholder?: string;
}): JSX.Element {
  const [draft, setDraft] = useState("");
  const commit = () => {
    const t = draft.trim();
    if (!t) return;
    onChange([...value, t]);
    setDraft("");
  };
  const onKey = (e: KeyboardEvent<HTMLInputElement>) => {
    if (e.key === "Enter" || e.key === "," || e.key === "Tab") {
      if (draft.trim()) {
        e.preventDefault();
        commit();
      }
    } else if (e.key === "Backspace" && !draft && value.length) {
      onChange(value.slice(0, -1));
    }
  };
  return (
    <div style={chipRow}>
      {value.map((v, i) => (
        <span key={v + i} style={chip}>
          <span>{v}</span>
          <button
            type="button"
            onClick={() => onChange(value.filter((_, j) => j !== i))}
            style={css("background:transparent;border:0;color:var(--text-muted);cursor:pointer;padding:0;font-size:11px;line-height:1;")}
            aria-label={`remove ${v}`}
          >
            {"\u2715"}
          </button>
        </span>
      ))}
      <input
        style={chipInput}
        value={draft}
        onChange={(e) => setDraft(e.target.value)}
        onKeyDown={onKey}
        onBlur={commit}
        placeholder={placeholder ?? "add\u2026"}
      />
    </div>
  );
}

function KeyValRows({
  value,
  onChange,
}: {
  value: Record<string, string>;
  onChange: (next: Record<string, string>) => void;
}): JSX.Element {
  const rows = Object.entries(value);
  const setRow = (idx: number, key: string, val: string) => {
    const next: Record<string, string> = {};
    rows.forEach(([k, v], i) => {
      if (i === idx) {
        if (key.length > 0) next[key] = val;
      } else {
        next[k] = v;
      }
    });
    onChange(next);
  };
  const remove = (idx: number) => {
    const next: Record<string, string> = {};
    rows.forEach(([k, v], i) => {
      if (i !== idx) next[k] = v;
    });
    onChange(next);
  };
  const add = () => {
    // Reserve a fresh key slot -- the operator types over the empty key.
    let base = "key";
    let n = 1;
    while (base in value) {
      n += 1;
      base = `key${n}`;
    }
    onChange({ ...value, [base]: "" });
  };
  return (
    <div style={kvBox}>
      {rows.length === 0 ? (
        <div style={css("font-family:var(--font-mono);font-size:9.5px;color:var(--text-faint);text-transform:none;letter-spacing:0.02em;padding:2px;")}>
          no entries
        </div>
      ) : null}
      {rows.map(([k, v], i) => (
        <div key={i} style={kvRow}>
          <input
            style={inputStyle}
            value={k}
            placeholder="key"
            onChange={(e) => setRow(i, e.target.value, v)}
          />
          <input
            style={inputStyle}
            value={v}
            placeholder="value"
            onChange={(e) => setRow(i, k, e.target.value)}
          />
          <button type="button" style={rowBtn} onClick={() => remove(i)}>remove</button>
        </div>
      ))}
      <button type="button" style={rowBtn} onClick={add}>+ entry</button>
    </div>
  );
}

function StepsEditor({
  value,
  onChange,
}: {
  value: PlaybookStep[];
  onChange: (next: PlaybookStep[]) => void;
}): JSX.Element {
  const setStep = (idx: number, patch: Partial<PlaybookStep>) => {
    onChange(value.map((s, i) => (i === idx ? { ...s, ...patch } : s)));
  };
  const remove = (idx: number) => {
    onChange(value.filter((_, i) => i !== idx).map((s, i) => ({ ...s, sequence: i })));
  };
  const add = () => {
    onChange([
      ...value,
      { sequence: value.length, tool: "", args: {}, expects: {}, on_failure: "continue" },
    ]);
  };
  return (
    <div style={css("display:flex;flex-direction:column;gap:9px;")}>
      {value.length === 0 ? (
        <div style={css("font-family:var(--font-mono);font-size:9.5px;color:var(--text-faint);text-transform:none;letter-spacing:0.02em;padding:2px;")}>
          no steps yet -- add at least one.
        </div>
      ) : null}
      {value.map((step, i) => (
        <div key={i} style={stepCard}>
          <div style={css("display:flex;align-items:center;gap:8px;font-family:var(--font-mono);font-size:9.5px;text-transform:uppercase;letter-spacing:0.1em;color:var(--text-muted);")}>
            <span>step {i + 1}</span>
            <span style={css("flex:1;")} />
            <button type="button" style={rowBtn} onClick={() => remove(i)}>remove step</button>
          </div>
          <label style={label}>
            <span>tool</span>
            <input
              style={inputStyle}
              value={step.tool}
              placeholder="ida_headless.capa_scan"
              onChange={(e) => setStep(i, { tool: e.target.value })}
            />
          </label>
          <label style={label}>
            <span>args</span>
            <KeyValRows value={step.args} onChange={(next) => setStep(i, { args: next })} />
          </label>
          <label style={label}>
            <span>expects (optional)</span>
            <KeyValRows value={step.expects} onChange={(next) => setStep(i, { expects: next })} />
          </label>
          <label style={label}>
            <span>on failure</span>
            <select
              style={inputStyle}
              value={step.on_failure}
              onChange={(e) => setStep(i, { on_failure: e.target.value })}
            >
              <option value="continue">continue</option>
              <option value="abort">abort</option>
            </select>
          </label>
        </div>
      ))}
      <button type="button" style={rowBtn} onClick={add}>+ step</button>
    </div>
  );
}

function SelectField({
  field,
  value,
  onChange,
}: {
  field: FieldSpec;
  value: string;
  onChange: (v: string) => void;
}): JSX.Element {
  const opts = useFieldOptions({
    endpoint: field.optionsFrom,
    valueField: field.optionsValueField,
    labelField: field.optionsLabelField,
  });
  const combined: { value: string; label: string }[] = [];
  if (field.options) combined.push(...field.options);
  if (opts.data) combined.push(...opts.data);
  const loading = Boolean(field.optionsFrom) && opts.isLoading;
  return (
    <select
      style={inputStyle}
      value={value}
      onChange={(e: ChangeEvent<HTMLSelectElement>) => onChange(e.target.value)}
      disabled={loading}
    >
      <option value="">{loading ? "loading\u2026" : field.required ? "select\u2026" : "(none)"}</option>
      {combined.map((o) => (
        <option key={o.value} value={o.value}>{o.label}</option>
      ))}
    </select>
  );
}

// ---------- component -------------------------------------------------------

export default function FieldForm({
  spec,
  initial,
  onDone,
  onCancel,
  invalidateKey,
}: FieldFormProps): JSX.Element {
  const editMode = spec.method === "PATCH" || spec.method === "PUT";
  // Seed working state from initial. For POST, initial is null and every
  // field starts empty.
  const [state, setState] = useState<Record<string, FieldValue>>(() => {
    const out: Record<string, FieldValue> = {};
    for (const f of spec.fields) {
      out[f.name] = toWidgetValue(f, initial ? initial[f.name] : undefined);
    }
    return out;
  });
  // Track which fields the operator changed so PATCH sends only those.
  const [touched, setTouched] = useState<Set<string>>(new Set());
  // Client-side gap message (required field empty). Separate from mutation
  // error so it survives a mutation.reset() and is cleared on the next submit.
  const [localError, setLocalError] = useState<string | null>(null);

  const idField = spec.idField ?? "id";
  const endpoint = useMemo(() => {
    // Substitute {id} from initial[idField], plus any other {name} placeholder
    // from initial[name] directly (used e.g. by /config/{namespace}/{key}).
    return spec.endpoint.replace(/{([a-zA-Z0-9_]+)}/g, (_m, name: string): string => {
      const source = name === "id" ? initial?.[idField] : initial?.[name];
      return encodeURIComponent(source === undefined || source === null ? "" : String(source));
    });
  }, [spec.endpoint, initial, idField]);

  const mutation = useResourceMutation({
    endpoint,
    method: spec.method,
    invalidateKey: invalidateKey ?? spec.invalidateKey,
  });

  const setField = (name: string, value: FieldValue) => {
    setState((cur) => ({ ...cur, [name]: value }));
    setTouched((cur) => {
      if (cur.has(name)) return cur;
      const next = new Set(cur);
      next.add(name);
      return next;
    });
  };

  const validate = (): string | null => {
    for (const f of spec.fields) {
      if (!f.required) continue;
      const v = state[f.name];
      if (
        v === undefined ||
        v === null ||
        v === "" ||
        (Array.isArray(v) && v.length === 0) ||
        (f.type === "steps" && Array.isArray(v) && v.length === 0)
      ) {
        return `${f.label} is required.`;
      }
    }
    return null;
  };

  const submit = () => {
    const err = validate();
    if (err) {
      // Surface the client-side gap without hitting the server.
      mutation.reset();
      setLocalError(err);
      return;
    }
    setLocalError(null);
    const payload: Record<string, unknown> = {};
    for (const f of spec.fields) {
      // In PATCH mode, skip fields the operator didn't touch so we don't
      // wipe server-side values with defaults.
      if (editMode && !touched.has(f.name)) continue;
      const serialized = serializeField(f, state[f.name]);
      if (serialized === undefined) continue;
      payload[f.name] = serialized;
    }
    mutation.mutate(payload, {
      onSuccess: () => onDone?.(),
    });
  };

  const errMessage = localError ?? (mutation.error
    ? mutation.error instanceof ApiError
      ? `${mutation.error.status}: ${mutation.error.message}`
      : mutation.error.message
    : null);

  return (
    <form
      onSubmit={(e) => {
        e.preventDefault();
        submit();
      }}
      style={css("display:flex;flex-direction:column;min-height:0;max-height:100%;background:var(--surface-card);border:1px solid var(--border);border-radius:var(--radius-md,3px);box-shadow:0 8px 30px rgba(0,0,0,0.35);")}
    >
      <header style={css("flex:0 0 auto;display:flex;align-items:center;gap:10px;padding:11px 14px;background:var(--surface-chrome);border-bottom:1px solid var(--border);font-family:var(--font-mono);font-size:10.5px;letter-spacing:0.14em;text-transform:uppercase;color:var(--text-primary);")}>
        <span style={css("width:8px;height:8px;border-radius:1px;background:var(--accent);box-shadow:0 0 6px var(--accent);")} />
        <span>{spec.title}</span>
        <span style={css("flex:1;")} />
        <button
          type="button"
          onClick={onCancel}
          style={css("background:transparent;border:0;color:var(--text-faint);cursor:pointer;font-size:14px;line-height:1;")}
          aria-label="close"
        >
          {"\u2715"}
        </button>
      </header>
      <div style={css("flex:1;min-height:0;overflow:auto;padding:16px 18px;display:flex;flex-direction:column;gap:14px;")}>
        {spec.fields.map((f) => {
          const v = state[f.name];
          const key = f.name;
          switch (f.type) {
            case "text":
            case "password":
              return (
                <label key={key} style={label}>
                  <span>{f.label}{f.required ? " *" : ""}</span>
                  <input
                    type={f.type === "password" ? "password" : "text"}
                    style={inputStyle}
                    value={typeof v === "string" ? v : ""}
                    placeholder={f.placeholder}
                    onChange={(e) => setField(key, e.target.value)}
                  />
                  {f.help ? <span style={help}>{f.help}</span> : null}
                </label>
              );
            case "textarea":
              return (
                <label key={key} style={label}>
                  <span>{f.label}{f.required ? " *" : ""}</span>
                  <textarea
                    style={textareaStyle}
                    value={typeof v === "string" ? v : ""}
                    placeholder={f.placeholder}
                    onChange={(e) => setField(key, e.target.value)}
                  />
                  {f.help ? <span style={help}>{f.help}</span> : null}
                </label>
              );
            case "number":
              return (
                <label key={key} style={label}>
                  <span>{f.label}{f.required ? " *" : ""}</span>
                  <input
                    type="number"
                    style={inputStyle}
                    value={v === undefined || v === null ? "" : String(v)}
                    placeholder={f.placeholder}
                    min={f.min}
                    max={f.max}
                    step={f.step ?? 1}
                    onChange={(e) => setField(key, e.target.value === "" ? "" : Number(e.target.value))}
                  />
                  {f.help ? <span style={help}>{f.help}</span> : null}
                </label>
              );
            case "checkbox":
              return (
                <label key={key} style={css("display:flex;align-items:center;gap:8px;font-family:var(--font-mono);font-size:11px;color:var(--text-primary);letter-spacing:0.02em;text-transform:none;")}>
                  <input
                    type="checkbox"
                    checked={Boolean(v)}
                    onChange={(e) => setField(key, e.target.checked)}
                  />
                  <span>{f.label}</span>
                  {f.help ? <span style={help}>{f.help}</span> : null}
                </label>
              );
            case "select":
              return (
                <label key={key} style={label}>
                  <span>{f.label}{f.required ? " *" : ""}</span>
                  <SelectField
                    field={f}
                    value={typeof v === "string" ? v : ""}
                    onChange={(val) => setField(key, val)}
                  />
                  {f.help ? <span style={help}>{f.help}</span> : null}
                </label>
              );
            case "tags":
            case "json-array-tags":
              return (
                <label key={key} style={label}>
                  <span>{f.label}{f.required ? " *" : ""}</span>
                  <TagInput
                    value={Array.isArray(v) ? (v as string[]) : []}
                    onChange={(next) => setField(key, next)}
                    placeholder={f.placeholder}
                  />
                  {f.help ? <span style={help}>{f.help}</span> : null}
                </label>
              );
            case "keyval":
            case "json-object-keyval":
              return (
                <label key={key} style={label}>
                  <span>{f.label}{f.required ? " *" : ""}</span>
                  <KeyValRows
                    value={(asRecord(v) ?? {}) as Record<string, string>}
                    onChange={(next) => setField(key, next)}
                  />
                  {f.help ? <span style={help}>{f.help}</span> : null}
                </label>
              );
            case "steps":
              return (
                <label key={key} style={label}>
                  <span>{f.label}{f.required ? " *" : ""}</span>
                  <StepsEditor
                    value={Array.isArray(v) ? (v as PlaybookStep[]) : []}
                    onChange={(next) => setField(key, next)}
                  />
                  {f.help ? <span style={help}>{f.help}</span> : null}
                </label>
              );
            default:
              return null;
          }
        })}
        {errMessage ? <div style={errBox}>{errMessage}</div> : null}
      </div>
      <footer style={css("flex:0 0 auto;display:flex;align-items:center;gap:8px;padding:11px 14px;background:var(--surface-chrome);border-top:1px solid var(--border);")}>
        <span style={css("flex:1;")} />
        <button type="button" style={ghostBtn} onClick={onCancel} disabled={mutation.isPending}>
          cancel
        </button>
        <button type="submit" style={primaryBtn} disabled={mutation.isPending}>
          {mutation.isPending ? "submitting\u2026" : editMode ? "save" : "create"}
        </button>
      </footer>
    </form>
  );
}
