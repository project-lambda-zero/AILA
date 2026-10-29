/**
 * Platform onboarding (#246). Backs:
 *   GET /config/platform/schema -> usePlatformSchema
 *   PUT /config/platform/{key}  -> useSetPlatformConfig
 *
 * The schema payload is narrowed once at the boundary into typed entries; a
 * malformed payload throws so the wizard shows an honest error instead of a
 * partially rendered list.
 */

import type { UseMutationResult, UseQueryResult } from "@tanstack/react-query";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { apiFetch } from "./client";
import { asRecord, readBool, readRecordArray, readStr, readStrArray } from "./parse";

export type OnboardingCategory = "capability" | "infra" | "operational";
export type ConfigSource = "env" | "db" | "default";
export type ConfigValueType = "str" | "int" | "float" | "bool";

const CATEGORIES = { capability: true, infra: true, operational: true } satisfies Record<OnboardingCategory, true>;
const SOURCES = { env: true, db: true, default: true } satisfies Record<ConfigSource, true>;
const VALUE_TYPES = { str: true, int: true, float: true, bool: true } satisfies Record<ConfigValueType, true>;

function isCategory(v: string): v is OnboardingCategory {
  return Object.hasOwn(CATEGORIES, v);
}
function isSource(v: string): v is ConfigSource {
  return Object.hasOwn(SOURCES, v);
}
function isValueType(v: string): v is ConfigValueType {
  return Object.hasOwn(VALUE_TYPES, v);
}

export interface OnboardingPrerequisite {
  name: string;
  ok: boolean;
  detail: string;
}

export interface OnboardingEntry {
  key: string;
  category: OnboardingCategory;
  valueType: ConfigValueType;
  /** Null for secret keys: their values never leave the server. */
  defaultValue: string | null;
  effectiveValue: string | null;
  effectiveSource: ConfigSource;
  overriddenByEnv: boolean;
  envKey: string;
  description: string;
  prerequisite: OnboardingPrerequisite | null;
  readOnly: boolean;
  secret: boolean;
  isSet: boolean;
  choices: string[] | null;
}

export interface PlatformSchema {
  onboardingCompleted: boolean;
  entries: OnboardingEntry[];
}

/** Mirrors the backend bool parse (ConfigRegistry accepts true/1/yes). */
export function isTruthyConfig(raw: string | null): boolean {
  return raw !== null && ["true", "1", "yes"].includes(raw.trim().toLowerCase());
}

function malformed(what: string): Error {
  return new Error(`GET /config/platform/schema returned a malformed ${what}`);
}

function parsePrerequisite(raw: unknown): OnboardingPrerequisite | null {
  if (raw === null || raw === undefined) return null;
  const o = asRecord(raw);
  const name = o ? readStr(o, "name") : null;
  const ok = o ? readBool(o, "ok") : null;
  const detail = o ? readStr(o, "detail") : null;
  if (name === null || ok === null || detail === null) throw malformed("prerequisite");
  return { name, ok, detail };
}

function parseEntry(o: Record<string, unknown>): OnboardingEntry {
  const key = readStr(o, "key");
  const category = readStr(o, "category");
  const valueType = readStr(o, "value_type");
  const source = readStr(o, "effective_source");
  const overriddenByEnv = readBool(o, "overridden_by_env");
  const envKey = readStr(o, "env_key");
  const description = readStr(o, "description");
  const readOnly = readBool(o, "read_only");
  const secret = readBool(o, "secret");
  const isSet = readBool(o, "is_set");
  if (
    key === null ||
    category === null ||
    !isCategory(category) ||
    valueType === null ||
    !isValueType(valueType) ||
    source === null ||
    !isSource(source) ||
    overriddenByEnv === null ||
    envKey === null ||
    description === null ||
    readOnly === null ||
    secret === null ||
    isSet === null
  ) {
    throw malformed(`entry ${key ?? "(unnamed)"}`);
  }
  return {
    key,
    category,
    valueType,
    defaultValue: readStr(o, "default_value"),
    effectiveValue: readStr(o, "effective_value"),
    effectiveSource: source,
    overriddenByEnv,
    envKey,
    description,
    prerequisite: parsePrerequisite(o.prerequisite),
    readOnly,
    secret,
    isSet,
    choices: Array.isArray(o.choices) ? readStrArray(o, "choices") : null,
  };
}

function parseSchema(raw: unknown): PlatformSchema {
  const o = asRecord(raw);
  const completed = o ? readBool(o, "onboarding_completed") : null;
  if (o === null || completed === null) throw malformed("payload");
  return { onboardingCompleted: completed, entries: readRecordArray(o, "entries").map(parseEntry) };
}

export const PLATFORM_SCHEMA_KEY = ["config", "platform", "schema"] as const;

/** God-tier admin only; pass `enabled=false` for everyone else so the console
 *  never fires a request the backend will reject. */
export function usePlatformSchema(enabled: boolean): UseQueryResult<PlatformSchema> {
  return useQuery<PlatformSchema>({
    queryKey: PLATFORM_SCHEMA_KEY,
    queryFn: async () => parseSchema(await apiFetch<unknown>("/config/platform/schema")),
    enabled,
    staleTime: 30_000,
    refetchOnWindowFocus: false,
  });
}

export interface PlatformConfigWrite {
  key: string;
  value: string;
  valueType: ConfigValueType;
}

/** What the PUT response tells the wizard about the write's liveness. */
export interface PlatformConfigWriteResult {
  key: string;
  overriddenByEnv: boolean;
  envKey: string;
}

function parseWriteResult(raw: unknown): PlatformConfigWriteResult {
  const o = asRecord(raw);
  const key = o ? readStr(o, "key") : null;
  const overriddenByEnv = o ? readBool(o, "overridden_by_env") : null;
  const envKey = o ? readStr(o, "env_key") : null;
  if (key === null || overriddenByEnv === null || envKey === null) {
    throw new Error("PUT /config/platform returned a malformed entry");
  }
  return { key, overriddenByEnv, envKey };
}

/** Write one platform key, then refetch the schema so every control shows the
 *  value the registry actually resolves (and sandbox views pick up changes). */
export function useSetPlatformConfig(): UseMutationResult<PlatformConfigWriteResult, Error, PlatformConfigWrite> {
  const qc = useQueryClient();
  return useMutation<PlatformConfigWriteResult, Error, PlatformConfigWrite>({
    mutationFn: async ({ key, value, valueType }) =>
      parseWriteResult(
        await apiFetch<unknown>(`/config/platform/${encodeURIComponent(key)}`, {
          method: "PUT",
          body: JSON.stringify({ value, value_type: valueType }),
        }),
      ),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: PLATFORM_SCHEMA_KEY });
      void qc.invalidateQueries({ queryKey: ["sandbox"] });
    },
  });
}
