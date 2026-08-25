/**
 * React Query hooks for per-persona sibling model routing (#151, req 31).
 *
 * Backend: `platform/routing/persona_model.py` reads the ConfigRegistry key
 * `platform.persona_model_role_map`. The stored value is a JSON string whose
 * shape is a nested map `{module_id: {persona_voice: model_role}}`. The
 * sentinel module_id `"__global__"` is the fallback bucket -- resolution for
 * (module_id, persona) is `nested[module_id][persona]` else
 * `nested["__global__"][persona]` else base task_type. A legacy flat
 * `{persona: model_role}` value is promoted under `"__global__"` at read time.
 * An EMPTY map is byte-identical to the prior behavior (every persona keeps
 * the default model), so the feature is opt-in.
 *
 * This module surfaces two endpoints for the admin editor:
 *   GET  /platform/agents/persona-registry -> [PersonaRegistryModule]
 *   GET  /config/platform/persona_model_role_map -> ConfigEntryResponse
 *   PUT  /config/platform/persona_model_role_map  {value, value_type:"str"}
 * (PUT is admin-gated server-side; the registry read is operator-gated.)
 */
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import type { UseMutationResult, UseQueryResult } from "@tanstack/react-query";

import { apiFetch } from "./client";

/** Subset of the backend `ConfigEntryResponse` the editor reads. */
export interface PersonaRoutingConfig {
  namespace: string;
  key: string;
  value: string;
  value_type: string;
  effective_value: string;
  effective_source: "env" | "db" | "default";
  overridden_by_env: boolean;
  env_key: string;
  updated_at: string | null;
}

/** One persona binding as returned by the registry endpoint. `role` is null
 *  when the module has no `persona_role_map` (e.g. malware routes per-voice).
 *  `task_type_options` is the module-wide finite list of legal task_types the
 *  router can emit; the select is bounded to exactly this list. */
export interface PersonaRegistryPersona {
  voice: string;
  role: string | null;
  task_type_options: string[];
}

/** One registered module as returned by the registry endpoint. A module with
 *  no operator-routable personas (forensics, hello_world, _template) appears
 *  with `personas: []`. */
export interface PersonaRegistryModule {
  module_id: string;
  module_label: string;
  personas: PersonaRegistryPersona[];
}

export const CONFIG_PATH = "/config/platform/persona_model_role_map";
export const QUERY_KEY = ["config", "platform", "persona_model_role_map"] as const;

const REGISTRY_PATH = "/platform/agents/persona-registry";
const REGISTRY_QUERY_KEY = ["platform", "agents", "persona-registry"] as const;

/** Parse the stored JSON value into a nested `{module_id: {persona:
 *  model_role}}` map. A legacy flat `{persona: model_role}` value is wrapped
 *  under the `"__global__"` sentinel so the resolver's fallback bucket sees
 *  it. Invalid, empty, or malformed values resolve to an empty map --
 *  byte-identical to how the backend treats it (off). Blank inner values are
 *  dropped so a half-filled row never counts as an active override. */
export function parsePersonaMap(
  raw: string | null | undefined,
): Record<string, Record<string, string>> {
  const text = (raw ?? "").trim();
  if (text === "") return {};
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return {};
  }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) return {};
  const entries = Object.entries(parsed as Record<string, unknown>);
  if (entries.length === 0) return {};

  // Legacy flat shape: every top-level value is a string.
  const allStrings = entries.every(([, v]) => typeof v === "string");
  if (allStrings) {
    const flat: Record<string, string> = {};
    for (const [persona, rawValue] of entries) {
      const value = typeof rawValue === "string" ? rawValue.trim() : "";
      if (value !== "") flat[persona] = value;
    }
    return Object.keys(flat).length === 0 ? {} : { __global__: flat };
  }

  // Nested shape: top-level values are objects (module_id -> bucket).
  const out: Record<string, Record<string, string>> = {};
  for (const [moduleId, inner] of entries) {
    if (inner === null || typeof inner !== "object" || Array.isArray(inner)) continue;
    const bucket: Record<string, string> = {};
    for (const [persona, rawValue] of Object.entries(inner as Record<string, unknown>)) {
      const value = typeof rawValue === "string" ? rawValue.trim() : "";
      if (value !== "") bucket[persona] = value;
    }
    if (Object.keys(bucket).length > 0) out[moduleId] = bucket;
  }
  return out;
}

/** Read the current persona-model-routing config entry (env > db > default). */
export function usePersonaRoutingConfig(): UseQueryResult<PersonaRoutingConfig> {
  return useQuery<PersonaRoutingConfig>({
    queryKey: QUERY_KEY,
    queryFn: () => apiFetch<PersonaRoutingConfig>(CONFIG_PATH),
    staleTime: 15_000,
    refetchOnWindowFocus: false,
  });
}

/** Read the persona registry. Returns one entry per registered module; a
 *  module with no operator-routable personas is included with `personas: []`
 *  so the page shows every module honestly. `apiFetch` unwraps the
 *  `DataEnvelope.data`, so the resolved type is the module array directly. */
export function usePersonaRegistry(): UseQueryResult<PersonaRegistryModule[]> {
  return useQuery<PersonaRegistryModule[]>({
    queryKey: REGISTRY_QUERY_KEY,
    queryFn: () => apiFetch<PersonaRegistryModule[]>(REGISTRY_PATH),
    staleTime: 60_000,
    refetchOnWindowFocus: false,
  });
}

/** Write the nested `{module_id: {persona: model_role}}` map. An empty map is
 *  persisted as the empty string, which the backend resolves as "off" -- so
 *  toggling the feature off is a real write, not a special case. Empty inner
 *  values and empty buckets are dropped before serialization. Invalidates
 *  the read on success. */
export function useUpdatePersonaRouting(): UseMutationResult<
  PersonaRoutingConfig,
  Error,
  Record<string, Record<string, string>>
> {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (nested: Record<string, Record<string, string>>) => {
      const cleaned: Record<string, Record<string, string>> = {};
      for (const [moduleId, inner] of Object.entries(nested)) {
        const bucket: Record<string, string> = {};
        for (const [persona, rawValue] of Object.entries(inner)) {
          const value = typeof rawValue === "string" ? rawValue.trim() : "";
          if (value !== "") bucket[persona] = value;
        }
        if (Object.keys(bucket).length > 0) cleaned[moduleId] = bucket;
      }
      const value = Object.keys(cleaned).length > 0 ? JSON.stringify(cleaned) : "";
      return apiFetch<PersonaRoutingConfig>(CONFIG_PATH, {
        method: "PUT",
        body: JSON.stringify({ value, value_type: "str" }),
      });
    },
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: QUERY_KEY });
    },
  });
}
