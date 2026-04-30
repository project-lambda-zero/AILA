/**
 * SchemaField — recursive JSON Schema → form field renderer.
 *
 * Handles: string, integer, number, boolean, object, array.
 * Uses existing shadcn UI primitives: Input, Textarea.
 * No external form library required.
 */

import { useState } from "react";

import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import type { JSONSchema } from "./tools-types";

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
    <div className="flex flex-col gap-1">
      <label htmlFor={fieldId} className="font-mono text-xs text-foreground">
        {name}
        {required && <span className="text-destructive ml-0.5">*</span>}
        {schema.description && (
          <span className="font-mono text-xs text-muted-foreground ml-1.5">
            {schema.description}
          </span>
        )}
        <span className="font-mono text-[10px] text-muted-foreground ml-1.5 uppercase tracking-wider">
          ({schema.type})
        </span>
      </label>
      <Textarea
        id={fieldId}
        value={text}
        onChange={(e) => handleTextChange(e.target.value)}
        aria-invalid={parseError !== null}
        className="font-mono text-xs min-h-[80px]"
        spellCheck={false}
      />
      {parseError !== null && (
        <p className="font-mono text-xs text-destructive">{parseError}</p>
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
 * Renders a single JSON Schema property as a form field.
 *
 * - string  → <Input type="text">
 * - integer | number → <Input type="number">
 * - boolean → native checkbox
 * - object | array → JSON <Textarea> with live parse validation
 * - unknown type → fallback <Input type="text">
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
      <div className="flex flex-col gap-1">
        <label htmlFor={fieldId} className="font-mono text-xs text-foreground">
          {name}
          {required && <span className="text-destructive ml-0.5">*</span>}
          {schema.description && (
            <span className="font-mono text-xs text-muted-foreground ml-1.5">
              {schema.description}
            </span>
          )}
        </label>
        <Input
          id={fieldId}
          type="text"
          value={typeof value === "string" ? value : ""}
          onChange={(e) => onChange(name, e.target.value)}
          className="font-mono text-xs"
        />
      </div>
    );
  }

  if (schema.type === "integer" || schema.type === "number") {
    return (
      <div className="flex flex-col gap-1">
        <label htmlFor={fieldId} className="font-mono text-xs text-foreground">
          {name}
          {required && <span className="text-destructive ml-0.5">*</span>}
          {schema.description && (
            <span className="font-mono text-xs text-muted-foreground ml-1.5">
              {schema.description}
            </span>
          )}
        </label>
        <Input
          id={fieldId}
          type="number"
          value={typeof value === "number" && !Number.isNaN(value) ? value : ""}
          onChange={(e) => {
            const parsed = e.target.valueAsNumber;
            onChange(name, Number.isNaN(parsed) ? "" : parsed);
          }}
          className="font-mono text-xs"
        />
      </div>
    );
  }

  if (schema.type === "boolean") {
    const checked = Boolean(value);
    return (
      <div className="flex items-center gap-2">
        <input
          id={fieldId}
          type="checkbox"
          checked={checked}
          onChange={(e) => onChange(name, e.target.checked)}
          className="h-4 w-4 rounded border-input accent-accent"
        />
        <label htmlFor={fieldId} className="font-mono text-xs text-foreground cursor-pointer">
          {name}
          {required && <span className="text-destructive ml-0.5">*</span>}
          {schema.description && (
            <span className="font-mono text-xs text-muted-foreground ml-1.5">
              {schema.description}
            </span>
          )}
        </label>
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
    <div className="flex flex-col gap-1">
      <label htmlFor={fieldId} className="font-mono text-xs text-foreground">
        {name}
        {required && <span className="text-destructive ml-0.5">*</span>}
        {schema.description && (
          <span className="font-mono text-xs text-muted-foreground ml-1.5">
            {schema.description}
          </span>
        )}
        <span className="font-mono text-[10px] text-muted-foreground ml-1.5 uppercase tracking-wider">
          ({schema.type})
        </span>
      </label>
      <Input
        id={fieldId}
        type="text"
        value={String(value ?? "")}
        onChange={(e) => onChange(name, e.target.value)}
        className="font-mono text-xs"
      />
    </div>
  );
}
