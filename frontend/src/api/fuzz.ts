/**
 * React-query hooks for the VR fuzz surface, backing the merged
 * FuzzCampaignDetail component. Two thin list GETs:
 *
 *   GET /vr/fuzz/proposals?target_id=&offset=&limit=  -> DataEnvelope[VRFuzzCampaignProposalSummary]
 *   GET /vr/fuzz/crashes?campaign_id=&offset=&limit=  -> DataEnvelope[VRFuzzCrashSummary]
 *
 * apiFetch peels the { data: [...] } envelope so each hook returns the row
 * array directly. Fields mirror the backend Pydantic contracts at
 *   src/aila/modules/vr/contracts/fuzz_proposal.py
 *   src/aila/modules/vr/contracts/fuzz.py (VRFuzzCrashSummary)
 * and only the fields the UI actually renders are typed here.
 */

import { useQuery } from "@tanstack/react-query";
import type { UseQueryResult } from "@tanstack/react-query";

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

/** Mirrors VRFuzzCrashSummary (subset the detail body renders). */
export interface FuzzCrashRow {
  id: string;
  campaign_id: string;
  stack_hash: string | null;
  verdict: string | null;
  severity: string | null;
  stack_trace: string | null;
  reproducer_head_hex: string | null;
  reproducer_head_truncated_size: number | null;
  created_at: string | null;
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
