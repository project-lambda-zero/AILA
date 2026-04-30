/**
 * Types for the Admin Tools Console (/admin/tools).
 *
 * These mirror the backend Pydantic schemas in src/aila/api/schemas/tools.py.
 * Backend POST /tools/{key} uses `kwargs` as the field name for tool inputs.
 */

export interface ToolSummary {
  tool_key: string;
  name: string;
  description: string;
  module_id: string;
}

export interface JSONSchema {
  type: "string" | "integer" | "number" | "boolean" | "object" | "array";
  description?: string;
  enum?: unknown[];
  default?: unknown;
  properties?: Record<string, JSONSchema>;
  items?: JSONSchema;
}

export interface ToolInputsSchema {
  type: "object";
  properties: Record<string, JSONSchema>;
  required?: string[];
}

export interface ToolDetail extends ToolSummary {
  inputs: ToolInputsSchema | Record<string, unknown>;
  output_type: string;
}

export interface ToolInvokeRequest {
  /** Backend field name is `kwargs` — passed directly to tool.forward(**kwargs). */
  kwargs: Record<string, unknown>;
}

export interface ToolInvokeResponse {
  tool_key: string;
  result: unknown | null;
  error: string | null;
}
