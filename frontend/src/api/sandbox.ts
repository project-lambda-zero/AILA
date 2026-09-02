/**
 * React Query hooks + narrowed TS interfaces for the platform-owned
 * sandbox / isolation admin surface. Backs:
 *   GET /platform/sandbox/status  -> useSandboxStatus
 *   GET /config/platform          -> useSandboxConfig  (client-filtered)
 *   PUT /config/platform/{key}    -> useUpdateSandboxConfig
 *   POST /platform/sandbox/exec   -> useSandboxExec    (mutation)
 *   POST /platform/sandbox/probe  -> useSandboxProbe   (mutation)
 *   GET /platform/sandbox/history -> useSandboxHistory
 *
 * All shapes are hand-written from the backend contracts so a change on
 * either side surfaces as a TS build error, not a silent runtime mismatch.
 * Envelope unwrapping is done by `apiFetch` -- these interfaces describe
 * the payload after `{ data: ... }` is peeled.
 */

import type { UseMutationResult, UseQueryResult } from "@tanstack/react-query";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { apiFetch } from "./client";

/* -------------------------------- status --------------------------------- */

/** One row inside `SandboxStatus.checks[]`. `ok` is a hard boolean; the
 *  operator UI paints the row green / amber accordingly. `detail` is a
 *  short human-readable reason and MUST render as prose. */
export interface SandboxStatusCheck {
  name: string;
  ok: boolean;
  detail: string;
}

/** GET /platform/sandbox/status payload. Backend guarantees the fields
 *  are always populated; when the backend is `none` the checks[] still
 *  come back honestly (missing binary, missing rootfs, ...). */
export interface SandboxStatus {
  backend: string;
  provisioned: boolean;
  ssh_host: string;
  /** null when reachability could not be probed (e.g. host not configured
   *  or SSH probe skipped for the current backend). */
  ssh_reachable: boolean | null;
  /** server os.name, e.g. "nt" | "posix". */
  host_os: string;
  checks: SandboxStatusCheck[];
}

/* --------------------------------- config -------------------------------- */

/** One row of the GET /config/platform paginated list. Mirrors the
 *  ConfigEntryResponse fields the sandbox editor reads or writes. The
 *  full record has more fields (env_key, default_value, etc.) but the
 *  editor only touches these. */
export interface SandboxConfigRow {
  namespace: string;
  key: string;
  value: string;
  value_type: "str" | "int" | "float" | "bool";
  effective_value: string;
  effective_source: "env" | "db" | "default";
  overridden_by_env: boolean;
  env_key: string;
  env_value: string | null;
  default_value: string | null;
}

/** Envelope of GET /config/platform. */
interface ConfigListEnvelope {
  total: number;
  page: number;
  page_size: number;
  pages: number;
  items: SandboxConfigRow[];
}

/** Body of PUT /config/platform/{key}. */
export interface ConfigUpdateRequest {
  value: string;
  value_type: "str" | "int" | "float" | "bool";
}

/* ---------------------------------- exec --------------------------------- */

/** Body of POST /platform/sandbox/exec. 1:1 with SandboxSpec on the
 *  service side; the router body is a thin projection so the fields
 *  match exactly. */
export interface SandboxSpec {
  argv: string[];
  stdin?: string;
  env?: Record<string, string>;
  input_files?: Record<string, string>;
  timeout_s?: number;
  network?: boolean;
  vcpu?: number;
  mem_mb?: number;
  workdir?: string;
  output_globs?: string[];
}

/** Response of POST /platform/sandbox/exec. Mirrors SandboxResultResponse. */
export interface SandboxResult {
  backend: string;
  exit_code: number | null;
  stdout: string;
  stderr: string;
  output_files: Record<string, string>;
  duration_s: number;
  timed_out: boolean;
  oom: boolean;
  truncated: boolean;
}

/* -------------------------------- hooks ---------------------------------- */

/** Live sandbox backend health. Kept fresh but not aggressive: the
 *  underlying probe hits an SSH host and shells out to `command -v`,
 *  which is cheap but not free. */
export function useSandboxStatus(): UseQueryResult<SandboxStatus> {
  return useQuery<SandboxStatus>({
    queryKey: ["sandbox", "status"],
    queryFn: () => apiFetch<SandboxStatus>("/platform/sandbox/status"),
    staleTime: 15_000,
    refetchOnWindowFocus: false,
  });
}

/** Filtered view of GET /config/platform: only rows whose key starts with
 *  `sandbox_`. `page_size=250` (backend maximum) is enough to hold all
 *  15 sandbox_* keys plus every other platform key with headroom; the
 *  list endpoint is paginated but the total platform key count is under
 *  the cap, so a single-page fetch is honest here. */
export function useSandboxConfig(): UseQueryResult<SandboxConfigRow[]> {
  return useQuery<SandboxConfigRow[]>({
    queryKey: ["sandbox", "config"],
    queryFn: async () => {
      const env = await apiFetch<ConfigListEnvelope>(
        "/config/platform?page=1&page_size=250",
      );
      return env.items.filter((row) => row.key.startsWith("sandbox_"));
    },
    staleTime: 10_000,
    refetchOnWindowFocus: false,
  });
}

/** Write one platform config key. On success we invalidate both the
 *  config list (so the row reflects the new value + source) AND the
 *  sandbox status (backend / ssh_host changes flip provisioning). */
export function useUpdateSandboxConfig(): UseMutationResult<
  SandboxConfigRow,
  Error,
  { key: string; body: ConfigUpdateRequest }
> {
  const qc = useQueryClient();
  return useMutation<SandboxConfigRow, Error, { key: string; body: ConfigUpdateRequest }>({
    mutationFn: ({ key, body }) =>
      apiFetch<SandboxConfigRow>(`/config/platform/${encodeURIComponent(key)}`, {
        method: "PUT",
        body: JSON.stringify(body),
      }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["sandbox", "config"] });
      void qc.invalidateQueries({ queryKey: ["sandbox", "status"] });
    },
  });
}

/** One-shot exec. Kept as a mutation (not a query) because the request
 *  body carries the whole command and every submit is a distinct action;
 *  the caller keeps the last SandboxResult in local state and paints
 *  honest loading / error views directly from the mutation. A 503 from
 *  the backend means "no sandbox backend provisioned" and a 502 means
 *  the backend was tried and its transport failed -- both surface as
 *  ApiError with their status preserved for the caller to distinguish. */
export function useSandboxExec(): UseMutationResult<SandboxResult, Error, SandboxSpec> {
  const qc = useQueryClient();
  return useMutation<SandboxResult, Error, SandboxSpec>({
    mutationFn: (spec) =>
      apiFetch<SandboxResult>("/platform/sandbox/exec", {
        method: "POST",
        body: JSON.stringify(spec),
      }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["sandbox", "history"] });
    },
  });
}

/* --------------------------------- probe --------------------------------- */

/** Response of POST /platform/sandbox/probe: a live SSH reachability
 *  and tooling check that the operator drives on demand. */
export interface SandboxProbe {
  ok: boolean;
  detail: string;
  duration_ms: number;
  tool_installed?: boolean;
  tool_missing?: boolean;
  installed_path?: string | null;
}

/** One-shot probe. Flips the ssh_reachable chip in the health panel from
 *  the last cached value to the live result without waiting on the
 *  status query's staleness window. */
export function useSandboxProbe(): UseMutationResult<SandboxProbe, Error, void> {
  return useMutation<SandboxProbe, Error, void>({
    mutationFn: () =>
      apiFetch<SandboxProbe>("/platform/sandbox/probe", { method: "POST" }),
  });
}

export interface SandboxTargetPayload {
  system_id?: string | null;
  system_name?: string | null;
  host: string;
  username?: string;
  port?: number;
  backend?: string | null;
}

/** Atomically bind a target host / fleet system and trigger an immediate probe. */
export function useSetSandboxTarget(): UseMutationResult<SandboxProbe, Error, SandboxTargetPayload> {
  const qc = useQueryClient();
  return useMutation<SandboxProbe, Error, SandboxTargetPayload>({
    mutationFn: (payload) =>
      apiFetch<SandboxProbe>("/platform/sandbox/target", {
        method: "POST",
        body: JSON.stringify(payload),
      }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["sandbox", "status"] });
      void qc.invalidateQueries({ queryKey: ["sandbox", "config"] });
    },
  });
}

export interface SandboxBootstrapResult {
  ok: boolean;
  detail: string;
  output: string;
  duration_ms: number;
}

/** Automated installation of sandbox tooling (nsjail / firecracker) on the remote host. */
export function useBootstrapSandboxTooling(): UseMutationResult<SandboxBootstrapResult, Error, { tool?: string }> {
  const qc = useQueryClient();
  return useMutation<SandboxBootstrapResult, Error, { tool?: string }>({
    mutationFn: ({ tool = "nsjail" }) =>
      apiFetch<SandboxBootstrapResult>("/platform/sandbox/install", {
        method: "POST",
        body: JSON.stringify({ tool }),
      }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["sandbox", "status"] });
    },
  });
}

/* --------------------------------- history ------------------------------- */

/** One row of GET /platform/sandbox/history. Stdin/stdout/stderr are
 *  intentionally NOT stored server-side, so the history row only carries
 *  argv + outcome metadata. */
export interface SandboxHistoryRow {
  id: string;
  actor_user_id: string | null;
  argv: string[];
  exit_code: number | null;
  duration_s: number;
  timed_out: boolean;
  oom: boolean;
  truncated: boolean;
  created_at: string;
}

/** Recent sandbox exec history, DESC by created_at, capped at 20 rows. */
export function useSandboxHistory(): UseQueryResult<SandboxHistoryRow[]> {
  return useQuery<SandboxHistoryRow[]>({
    queryKey: ["sandbox", "history"],
    queryFn: () => apiFetch<SandboxHistoryRow[]>("/platform/sandbox/history?limit=20"),
    staleTime: 5_000,
    refetchOnWindowFocus: false,
  });
}
