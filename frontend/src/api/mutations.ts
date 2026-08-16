/**
 * Typed create/update mutations + list-endpoint option loader.
 *
 * The console's generic FieldForm (frontend/src/console/pages/FieldForm.tsx)
 * calls useResourceMutation to POST/PATCH JSON via apiFetch (with the
 * `{data}` envelope unwrap + Bearer auth + 401 handling already in the
 * client). useFieldOptions powers a select whose choices come from a list
 * endpoint (e.g. /vr/workspaces, /systems) -- one hook, several envelope
 * shapes normalized to {value,label}.
 */
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import type { QueryKey } from "@tanstack/react-query";

import { apiFetch } from "./client";

export type MutationMethod = "POST" | "PATCH" | "PUT";

export interface ResourceMutationOptions {
  /** Full path relative to the API root. May contain no template markers -- the
   * caller substitutes {id}/{scope} before passing the string in. */
  endpoint: string;
  method: MutationMethod;
  /** react-query key to invalidate on success (usually ["datapage", endpoint]). */
  invalidateKey?: QueryKey;
}

export function useResourceMutation<TPayload extends Record<string, unknown>>(
  opts: ResourceMutationOptions,
) {
  const qc = useQueryClient();
  return useMutation<unknown, Error, TPayload>({
    mutationFn: (payload: TPayload) =>
      apiFetch<unknown>(opts.endpoint, {
        method: opts.method,
        body: JSON.stringify(payload),
      }),
    onSuccess: () => {
      if (opts.invalidateKey) {
        void qc.invalidateQueries({ queryKey: opts.invalidateKey });
      }
    },
  });
}

/** Common list-envelope wrapper keys the API uses. Kept in sync with the set
 * DataPage.toRows accepts so option loaders and tables agree. */
const LIST_KEYS = [
  "items",
  "results",
  "rows",
  "entries",
  "records",
  "data",
  "findings",
  "investigations",
  "targets",
  "workspaces",
  "keys",
  "tasks",
  "subsystems",
  "months",
  "nodes",
];

/** Pick a stable value + label from a row of unknown shape. `valueField` /
 * `labelField` overrides let callers pin a specific field when the row doesn't
 * carry `id` / `name` (e.g. disclosure tracks use `track_id` / `display_name`). */
function pickOption(
  row: Record<string, unknown>,
  valueField?: string,
  labelField?: string,
): { value: string; label: string } | null {
  const rawVal = valueField
    ? row[valueField]
    : row.id ??
      row.action_id ??
      row.track_id ??
      row.tag_key ??
      row.key_id ??
      row.session_id ??
      row.provider_name ??
      row.instance_id ??
      row.username;
  if (rawVal === undefined || rawVal === null || rawVal === "") return null;
  const value = String(rawVal);
  const rawLabel = labelField
    ? row[labelField]
    : row.name ??
      row.display_name ??
      row.title ??
      row.username ??
      row.provider_name ??
      row.tag_key ??
      row.action_id ??
      row.track_id ??
      value;
  const label = rawLabel === undefined || rawLabel === null ? value : String(rawLabel);
  return { value, label };
}

export interface FieldOption {
  value: string;
  label: string;
}

export interface FieldOptionsSpec {
  endpoint?: string;
  valueField?: string;
  labelField?: string;
}

/** Fetch a list endpoint and map each row to {value,label}. Empty options
 * (missing endpoint, still loading) return `[]` so the caller renders a
 * disabled/placeholder select without extra branching. */
export function useFieldOptions(spec: FieldOptionsSpec) {
  const endpoint = spec.endpoint ?? "";
  const q = useQuery({
    queryKey: ["field-options", endpoint, spec.valueField ?? "", spec.labelField ?? ""],
    queryFn: async (): Promise<FieldOption[]> => {
      const raw = await apiFetch<unknown>(endpoint);
      let arr: unknown[] = [];
      if (Array.isArray(raw)) arr = raw;
      else if (raw && typeof raw === "object") {
        const obj = raw as Record<string, unknown>;
        const k = LIST_KEYS.find((name) => Array.isArray(obj[name]));
        if (k) arr = obj[k] as unknown[];
      }
      const out: FieldOption[] = [];
      for (const row of arr) {
        if (!row || typeof row !== "object") continue;
        const opt = pickOption(row as Record<string, unknown>, spec.valueField, spec.labelField);
        if (opt) out.push(opt);
      }
      return out;
    },
    enabled: Boolean(endpoint),
    staleTime: 30_000,
  });
  return q;
}
