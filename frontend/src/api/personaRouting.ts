/**
 * React Query hooks for per-persona sibling model routing (#151).
 *
 * Backend: `platform/routing/persona_model.py` reads the ConfigRegistry key
 * `platform.persona_model_role_map` -- a JSON object mapping a sibling persona
 * voice (halvar/maddie/yuki/renzo/noor/wei) to a model_role (task_type that
 * resolves through `llm_model_{role}`). It is read live at the shared turn
 * dispatch (`platform/agents/turn_runner.py`) that the VR, malware, and
 * forensics reasoning loops all run through. An EMPTY map is byte-identical to
 * the prior behavior (every persona keeps the default model), so the feature
 * is opt-in: it does nothing until an operator maps at least one persona here.
 *
 * This module surfaces that single config key for the agents-page editor:
 *   GET /config/platform/persona_model_role_map -> ConfigEntryResponse
 *   PUT /config/platform/persona_model_role_map  {value, value_type:"str"}
 * (PUT is admin-gated server-side.)
 */
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import type { UseMutationResult, UseQueryResult } from "@tanstack/react-query";

import { apiFetch } from "./client";

/** The six real sibling persona voices (`PersonaVoice`, platform
 *  `contracts/enums.py`). These are the valid keys for the routing map; the
 *  synthetic voices (unspecified/merge_result/fork_unnamed) are structural
 *  markers, never operator-routable. */
export const PERSONA_VOICES = ["halvar", "maddie", "yuki", "renzo", "noor", "wei"] as const;
export type PersonaVoice = (typeof PERSONA_VOICES)[number];

/** Human-readable role each core persona plays, shown next to the input so an
 *  operator maps models to the debate role, not an opaque codename. Mirrors the
 *  persona -> role split in the module persona routers. */
export const PERSONA_ROLE_LABEL: Record<PersonaVoice, string> = {
  halvar: "researcher",
  noor: "researcher",
  renzo: "implementer",
  wei: "implementer",
  maddie: "critic",
  yuki: "critic",
};

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

const CONFIG_PATH = "/config/platform/persona_model_role_map";
const QUERY_KEY = ["config", "platform", "persona_model_role_map"] as const;

/** Parse the stored JSON value into a persona -> model_role map. Invalid or
 *  empty JSON resolves to an empty map -- byte-identical to how the backend
 *  treats it (off). Blank values are dropped so a half-filled row never counts
 *  as an active override. */
export function parsePersonaMap(raw: string | null | undefined): Record<string, string> {
  const text = (raw ?? "").trim();
  if (text === "") return {};
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return {};
  }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) return {};
  const out: Record<string, string> = {};
  for (const [key, rawValue] of Object.entries(parsed as Record<string, unknown>)) {
    const value = typeof rawValue === "string" ? rawValue.trim() : "";
    if (value !== "") out[key] = value;
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

/** Write the persona -> model_role map. An empty map is persisted as the empty
 *  string, which the backend resolves as "off" -- so toggling the feature off
 *  is a real write, not a special case. Invalidates the read on success. */
export function useUpdatePersonaRouting(): UseMutationResult<
  PersonaRoutingConfig,
  Error,
  Record<string, string>
> {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (map: Record<string, string>) => {
      const value = Object.keys(map).length > 0 ? JSON.stringify(map) : "";
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
