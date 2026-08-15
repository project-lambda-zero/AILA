/**
 * SchemaField -- recursive JSON Schema -> form field renderer.
 *
 * Rebuilt to the AILA mock language: raw `<input> / <select> / <textarea> /
 * <button>` toggles styled inline with the mock tokens, no shadcn primitives.
 * Handles: string, integer, number, boolean, object, array. Preserves the
 * schema-driven props API (name/type/value/onChange/label/description/required).
 */
import { useState, type CSSProperties } from "react";

import type { JSONSchema } from "./tools-types";

// ---------------------------------------------------------------------------
// Shared mock-styled input primitives
// ---------------------------------------------------------------------------

const INPUT_STYLE: CSSProperties = {
  height: 28,
  padding: "0 10px",
  fontSize: 11,
  color: "var(--text-primary)",
  background: "var(--surface-sunk)",
  border: "1px solid var(--border-soft)",
  borderRadius: 3,
  outline: "none",
};

const TEXTAREA_STYLE: CSSProperties = {
  minHeight: 96,
  padding: "8px 10px",
  fontSize: 11,
  lineHeight: 1.5,
  color: "var(--text-primary)",
  background: "var(--surface-sunk)",
  border: "1px solid var(--border-soft)",
  borderRadius: 3,
  outline: "none",
  resize: "vertical",
};

function FieldLabel({
  htmlFor,
  name,
  required,
  description,
  type,
}: {
  htmlFor?: string;
  name: string;
  required: boolean;
  description?: string;
  type?: string;
}) {
  return (
    <label
      htmlFor={htmlFor}
      className="font-mono flex items-baseline flex-wrap"
      style={{
        gap: 6,
        fontSize: 10,
        letterSpacing: "0.1em",
        color: "var(--text-muted)",
      }}
    >
      <span style={{ color: "var(--text-primary)", textTransform: "uppercase" }}>
        {name}
      </span>
      {required && (
        <span aria-hidden="true" style={{ color: "var(--accent)" }}>
          *
        </span>
      )}
      {type && (
        <span
          className="uppercase"
          style={{
            fontSize: 8.5,
            letterSpacing: "0.14em",
            color: "var(--text-faint)",
          }}
        >
          ({type})
        </span>
      )}
      {description && (
        <span
          style={{
            color: "var(--text-faint)",
            fontSize: 10,
            letterSpacing: "0.02em",
            textTransform: "none",
          }}
        >
          {description}
        </span>
      )}
    </label>
  );
}

// ---------------------------------------------------------------------------
// Sub-component: JSON textarea for object/array types (isolated useState)
// ---------------------------------------------------------------------------

interface JsonTextareaFieldProps {
  name: string;
  schema: JSONSchema;
  required: boolean;
  value: unknown;
  onChange: (name: string, value: unknown) => void;
}

function JsonTextareaField({
  name,
  schema,
  required,
  value,
  onChange,
}: JsonTextareaFieldProps) {
  const defaultValue = schema.type === "array" ? [] : {};
  const [text, setText] = useState<string>(
    JSON.stringify(value ?? defaultValue, null, 2),
  );
  const [parseError, setParseError] = useState<string | null>(null);

  function handleTextChange(raw: string): void {
    setText(raw);
    try {
      onChange(name, JSON.parse(raw));
      setParseError(null);
    } catch (err) {
      setParseError(err instanceof SyntaxError ? err.message : "Invalid JSON");
    }
  }

  const fieldId = `schema-field-${name}`;

  return (
    <div className="flex flex-col" style={{ gap: 5 }}>
      <FieldLabel
        htmlFor={fieldId}
        name={name}
        required={required}
        description={schema.description}
        type={schema.type}
      />
      <textarea
        id={fieldId}
        value={text}
        onChange={(e) => handleTextChange(e.target.value)}
        aria-invalid={parseError !== null}
        spellCheck={false}
        className="font-mono"
        style={{
          ...TEXTAREA_STYLE,
          borderColor:
            parseError !== null
              ? "color-mix(in srgb, var(--status-warn) 50%, transparent)"
              : "var(--border-soft)",
        }}
      />
      {parseError !== null && (
        <p
          className="font-mono"
          style={{ color: "var(--status-warn)", fontSize: 10 }}
        >
          {parseError}
        </p>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Public component: SchemaField
// ---------------------------------------------------------------------------

export interface SchemaFieldProps {
  name: string;
  schema: JSONSchema;
  required: boolean;
  value: unknown;
  onChange: (name: string, value: unknown) => void;
}

/**
 * Renders a single JSON Schema property as a mock-styled form field.
 *
 * - string  -> <input type=text>
 * - integer | number -> <input type=number>
 * - boolean -> <button role=switch> toggle
 * - object | array -> JSON textarea with live parse validation
 * - unknown type -> fallback <input type=text>
 */
export function SchemaField({
  name,
  schema,
  required,
  value,
  onChange,
}: SchemaFieldProps) {
  const fieldId = `schema-field-${name}`;

  if (schema.type === "string") {
    return (
      <div className="flex flex-col" style={{ gap: 5 }}>
        <FieldLabel
          htmlFor={fieldId}
          name={name}
          required={required}
          description={schema.description}
        />
        <input
          id={fieldId}
          type="text"
          value={typeof value === "string" ? value : ""}
          onChange={(e) => onChange(name, e.target.value)}
          className="font-mono"
          style={INPUT_STYLE}
        />
      </div>
    );
  }

  if (schema.type === "integer" || schema.type === "number") {
    return (
      <div className="flex flex-col" style={{ gap: 5 }}>
        <FieldLabel
          htmlFor={fieldId}
          name={name}
          required={required}
          description={schema.description}
        />
        <input
          id={fieldId}
          type="number"
          value={typeof value === "number" && !Number.isNaN(value) ? value : ""}
          onChange={(e) => {
            const parsed = e.target.valueAsNumber;
            onChange(name, Number.isNaN(parsed) ? "" : parsed);
          }}
          className="font-mono"
          style={INPUT_STYLE}
        />
      </div>
    );
  }

  if (schema.type === "boolean") {
    const checked = Boolean(value);
    return (
      <div className="flex items-center" style={{ gap: 10 }}>
        <button
          id={fieldId}
          type="button"
          role="switch"
          aria-checked={checked}
          onClick={() => onChange(name, !checked)}
          className="font-mono uppercase"
          style={{
            height: 26,
            padding: "0 12px",
            fontSize: 9.5,
            letterSpacing: "0.1em",
            borderRadius: 3,
            cursor: "pointer",
            color: checked ? "var(--text-on-accent)" : "var(--text-muted)",
            background: checked ? "var(--accent)" : "var(--surface-sunk)",
            border: `1px solid ${
              checked ? "var(--accent)" : "var(--border-soft)"
            }`,
          }}
        >
          {checked ? "on" : "off"}
        </button>
        <FieldLabel
          htmlFor={fieldId}
          name={name}
          required={required}
          description={schema.description}
        />
      </div>
    );
  }

  if (schema.type === "object" || schema.type === "array") {
    return (
      <JsonTextareaField
        name={name}
        schema={schema}
        required={required}
        value={value}
        onChange={onChange}
      />
    );
  }

  // Fallback for unknown/unsupported types
  return (
    <div className="flex flex-col" style={{ gap: 5 }}>
      <FieldLabel
        htmlFor={fieldId}
        name={name}
        required={required}
        description={schema.description}
        type={schema.type ?? "unknown"}
      />
      <input
        id={fieldId}
        type="text"
        value={String(value ?? "")}
        onChange={(e) => onChange(name, e.target.value)}
        className="font-mono"
        style={INPUT_STYLE}
      />
    </div>
  );
}
