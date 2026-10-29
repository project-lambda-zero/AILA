/**
 * React-query hooks for the VR fuzz surface, backing the merged
 * FuzzCampaignDetail component:
 *
 *   GET  /vr/fuzz/proposals?target_id=&offset=&limit=  -> DataEnvelope[VRFuzzCampaignProposalSummary]
 *   GET  /vr/fuzz/crashes?campaign_id=&offset=&limit=  -> DataEnvelope[VRFuzzCrashSummary]
 *   GET  /vr/fuzz/campaigns/{id}/telemetry             -> DataEnvelope[list[FuzzTelemetryPoint]]
 *   POST /vr/fuzz/proposals/{id}/accept | /reject      (operator decision)
 *   POST /vr/fuzz/crashes/{id}/triage                  (append a CrashTriageEvent)
 *
 * apiFetch peels the { data: [...] } envelope so each hook returns the row
 * array directly. Fields mirror the backend Pydantic contracts at
 *   src/aila/modules/vr/contracts/fuzz_proposal.py
 *   src/aila/modules/vr/contracts/fuzz.py (VRFuzzCrashSummary)
 * and only the fields the UI actually renders are typed here.
 */

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import type { UseMutationResult, UseQueryResult } from "@tanstack/react-query";

import { apiFetch } from "./client";

/** Mirrors VRFuzzCampaignProposalSummary (subset the detail body renders). */
export interface FuzzProposalRow {
  id: string;
  target_id: string;
  workspace_id: string;
  investigation_id: string | null;
  outcome_id: string | null;
  profile: string;
  rationale: string;
  confidence: string;
  status: string;
  suggested_engine_id: string | null;
  suggested_strategy_id: string | null;
  suggested_duration_hours: number | null;
  harness_source: string | null;
  harness_language: string | null;
  harness_build_command: string | null;
  harness_target_path: string | null;
  accepted_campaign_id: string | null;
  created_at: string | null;
  updated_at: string | null;
}

/** Mirrors CrashTriageVerdict (src/aila/modules/vr/contracts/fuzz.py). */
export const CRASH_TRIAGE_VERDICTS = [
  "untriaged",
  "security_relevant",
  "likely_harmless",
  "duplicate",
  "needs_manual_review",
] as const;
export type CrashTriageVerdict = (typeof CRASH_TRIAGE_VERDICTS)[number];

/** Mirrors CrashTriageEvent; one entry of VRFuzzCrashSummary.triage_chain. */
export interface CrashTriageEvent {
  at: string;
  actor: string;
  verdict: CrashTriageVerdict;
  reason: string;
  notes: string;
}

/** Mirrors VRFuzzCrashSummary (subset the detail body renders). */
export interface FuzzCrashRow {
  id: string;
  campaign_id: string;
  stack_hash: string;
  crash_type: string | null;
  severity: string;
  triage_verdict: CrashTriageVerdict;
  triage_reason: string | null;
  stack_trace: string | null;
  reproducer_head_hex: string | null;
  reproducer_head_truncated_size: number | null;
  triage_chain: CrashTriageEvent[];
  created_at: string | null;
}

/** Mirrors FuzzTelemetryPoint. */
export interface FuzzTelemetryPoint {
  id: string;
  campaign_id: string;
  measured_at: string;
  execs_per_sec: number | null;
  total_execs: number | null;
  corpus_size: number | null;
  coverage_pct: number | null;
  crashes_found: number | null;
}

/** Mirrors FuzzProposalDecideAccept. Every key is optional; only the
 * operator-set overrides are sent (the model forbids extra keys and resolves
 * unset ones from the proposal, target profile, and project defaults). */
export interface FuzzProposalAcceptBody {
  name?: string;
  engine_id?: string;
  strategy_id?: string;
  engine_config?: Record<string, unknown>;
  strategy_config?: Record<string, unknown>;
  duration_hours?: number;
  analysis_system_id?: number;
  auto_launch?: boolean;
  skip_prepare?: boolean;
  decision_reason?: string;
}

/** Mirrors the router-local _ProposalAcceptResponse. */
export interface FuzzProposalAcceptResult {
  proposal_id: string;
  campaign_id: string;
  workdir: string;
  harness_path: string | null;
  seeds_written: number;
  dictionary_written: boolean;
  auto_launched: boolean;
  build_log: string;
}

const LIMIT = 200;

/** GET /vr/fuzz/proposals?target_id=<id>&offset=0&limit=200. */
export function useFuzzProposals(
  targetId: string,
): UseQueryResult<FuzzProposalRow[]> {
  return useQuery({
    queryKey: ["vr", "fuzz", "proposals", targetId],
    queryFn: () =>
      apiFetch<FuzzProposalRow[]>(
        `/vr/fuzz/proposals?target_id=${encodeURIComponent(targetId)}&offset=0&limit=${LIMIT}`,
      ),
    enabled: Boolean(targetId),
    staleTime: 15_000,
  });
}

/** GET /vr/fuzz/crashes?campaign_id=<id>&offset=0&limit=200. */
export function useFuzzCrashes(
  campaignId: string,
): UseQueryResult<FuzzCrashRow[]> {
  return useQuery({
    queryKey: ["vr", "fuzz", "crashes", campaignId],
    queryFn: () =>
      apiFetch<FuzzCrashRow[]>(
        `/vr/fuzz/crashes?campaign_id=${encodeURIComponent(campaignId)}&offset=0&limit=${LIMIT}`,
      ),
    enabled: Boolean(campaignId),
    staleTime: 15_000,
  });
}

/** GET /vr/fuzz/campaigns/<id>/telemetry, oldest first. Polls every 10s while
 * `live` (the campaign is running) so the chart follows the fuzzer. */
export function useFuzzTelemetry(
  campaignId: string,
  live: boolean,
): UseQueryResult<FuzzTelemetryPoint[]> {
  return useQuery({
    queryKey: ["vr", "fuzz", "telemetry", campaignId],
    queryFn: () =>
      apiFetch<FuzzTelemetryPoint[]>(
        `/vr/fuzz/campaigns/${encodeURIComponent(campaignId)}/telemetry`,
      ),
    enabled: Boolean(campaignId),
    refetchInterval: live ? 10_000 : false,
    staleTime: 5_000,
  });
}

/** POST /vr/fuzz/proposals/<id>/accept. Refreshes the proposal list and the
 * campaigns table (accept creates a campaign row). */
export function useAcceptFuzzProposal(
  targetId: string,
): UseMutationResult<FuzzProposalAcceptResult, Error, { proposalId: string; body: FuzzProposalAcceptBody }> {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ proposalId, body }) =>
      apiFetch<FuzzProposalAcceptResult>(
        `/vr/fuzz/proposals/${encodeURIComponent(proposalId)}/accept`,
        { method: "POST", body: JSON.stringify(body) },
      ),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["vr", "fuzz", "proposals", targetId] });
      void qc.invalidateQueries({ queryKey: ["datapage", "/vr/fuzz/campaigns"] });
    },
  });
}

/** POST /vr/fuzz/proposals/<id>/reject with the required decision reason. */
export function useRejectFuzzProposal(
  targetId: string,
): UseMutationResult<FuzzProposalRow, Error, { proposalId: string; decisionReason: string }> {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ proposalId, decisionReason }) =>
      apiFetch<FuzzProposalRow>(
        `/vr/fuzz/proposals/${encodeURIComponent(proposalId)}/reject`,
        { method: "POST", body: JSON.stringify({ decision_reason: decisionReason }) },
      ),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["vr", "fuzz", "proposals", targetId] });
    },
  });
}

/** POST /vr/fuzz/crashes/<id>/triage: appends one CrashTriageEvent; the
 * latest event sets the crash's current verdict + reason. */
export function useTriageFuzzCrash(
  campaignId: string,
): UseMutationResult<FuzzCrashRow, Error, { crashId: string; event: CrashTriageEvent }> {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ crashId, event }) =>
      apiFetch<FuzzCrashRow>(
        `/vr/fuzz/crashes/${encodeURIComponent(crashId)}/triage`,
        { method: "POST", body: JSON.stringify(event) },
      ),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["vr", "fuzz", "crashes", campaignId] });
    },
  });
}
