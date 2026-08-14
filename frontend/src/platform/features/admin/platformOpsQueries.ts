/**
 * Platform Ops data layer.
 *
 * TanStack Query hooks for the three god-tier admin endpoints surfaced
 * on `/admin/platform-ops`:
 *
 *   POST /platform/sandbox/exec              -- one-shot sandbox exec
 *   POST /platform/eval/corpus/export        -- enqueue corpus export
 *   GET  /platform/eval/corpus/stats         -- latest manifest counts
 *   POST /admin/journal/deadletter/replay    -- drain journal deadletters
 *
 * Every response is wrapped in the platform-wide DataEnvelope; the
 * hooks unwrap `.data` so callers work with plain contract types.
 */
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { authorizedRequestJson } from "@platform/api/http";

// ---------------------------------------------------------------------------
// Envelope -- mirrors aila.api.schemas.envelope.DataEnvelope.
// ---------------------------------------------------------------------------

interface DataEnvelope<T> {
  data: T;
  error: string | null;
  meta: Record<string, unknown>;
}

// ---------------------------------------------------------------------------
// Sandbox -- mirrors aila/api/routers/platform_sandbox.py
// ---------------------------------------------------------------------------

export interface SandboxExecRequest {
  argv: string[];
  stdin?: string | null;
  timeout_s: number;
  network: boolean;
}

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

export function useSandboxExec() {
  return useMutation({
    mutationFn: (body: SandboxExecRequest) =>
      authorizedRequestJson<DataEnvelope<SandboxResult>>(
        "/platform/sandbox/exec",
        { method: "POST", body },
      ),
  });
}

// ---------------------------------------------------------------------------
// Corpus -- mirrors aila/api/routers/platform_corpus.py
// ---------------------------------------------------------------------------

export interface CorpusExportResponse {
  task_id: string;
  status: string;
  modules: string[] | null;
  lookback_days: number | null;
}

export interface CorpusStatsResponse {
  has_corpus: boolean;
  corpus_dir: string;
  sft_path: string | null;
  dpo_path: string | null;
  manifest_path: string | null;
  generated_at: string | null;
  sft_count: number;
  dpo_count: number;
  investigations: number;
  module_breakdown: Record<string, number>;
  modules: string[];
  min_turns: number;
  max_field_chars: number;
  skipped_short_branches: number;
  skipped_unparseable_decisions: number;
  detail: string | null;
}

export const platformOpsQueryKeys = {
  all: ["platform", "platform-ops"] as const,
  corpusStats: () => [...platformOpsQueryKeys.all, "corpus-stats"] as const,
};

export function useCorpusStats() {
  return useQuery({
    queryKey: platformOpsQueryKeys.corpusStats(),
    queryFn: () =>
      authorizedRequestJson<DataEnvelope<CorpusStatsResponse>>(
        "/platform/eval/corpus/stats",
      ),
    select: (env) => env.data,
  });
}

export function useCorpusExport() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: () =>
      authorizedRequestJson<DataEnvelope<CorpusExportResponse>>(
        "/platform/eval/corpus/export",
        { method: "POST", body: {} },
      ),
    onSuccess: () => {
      // Manifest only refreshes once the enqueued worker finishes, but
      // an eager refetch is cheap and picks up a fast run if the operator
      // was already sitting on the tab.
      void queryClient.invalidateQueries({
        queryKey: platformOpsQueryKeys.corpusStats(),
      });
    },
  });
}

// ---------------------------------------------------------------------------
// Journal deadletter replay -- mirrors aila/api/routers/admin_journal_replay.py
// ---------------------------------------------------------------------------

export interface ReplayResponseEntry {
  deadletter_id: string;
  chain_id: string;
  team_id: string | null;
  replayed: boolean;
  journal_id: string | null;
  seq: number | null;
  error: string | null;
}

export interface ReplayResponse {
  scanned: number;
  replayed: number;
  failed: number;
  entries: ReplayResponseEntry[];
}

export function useJournalDeadletterReplay() {
  return useMutation({
    mutationFn: () =>
      authorizedRequestJson<DataEnvelope<ReplayResponse>>(
        "/admin/journal/deadletter/replay",
        { method: "POST", body: {} },
      ),
  });
}
