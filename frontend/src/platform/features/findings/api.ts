import { useQuery } from "@tanstack/react-query";
import { authorizedRequestJson } from "@platform/api/http";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface FindingDetail {
  id: number;
  cve_id: string;
  package: string;
  host: string;
  severity: string;
  score: number;
  status: string;
  workflow_state: string;
  fixed_version: string | null;
  nvd_url: string;
  rationale: string;
  is_kev: boolean;
  compliance_tags: string[];
  details: {
    facts?: string;
    inference?: string;
    recommended_action?: string;
    uncertainty?: string;
    advisory_provenance?: string;
    intel_provenance?: string;
    installed_version?: string;
    distribution?: string | null;
    vendor_statuses?: string[];
    vendor_urgencies?: string[];
    vendor_fix_states?: string[];
    [key: string]: unknown;
  };
  last_scanned_at: string | null;
  created_at: string | null;
}

export interface CveIntelMetric {
  metric: string;
  code: string;
  value: string;
  explanation: string;
  weight: "high" | "medium" | "low";
}

export interface CveIntel {
  cve_id: string;
  description: string;
  base_severity: string | null;
  cvss_score: number | null;
  cvss_vector: string | null;
  attack_vector: string | null;
  privileges_required: string | null;
  user_interaction: string | null;
  epss_score: number | null;
  epss_percentile: number | null;
  kev_listed: boolean;
  kev_date_added: string | null;
  nvd_url: string;
  published_at: string | null;
  notes: string[];
  cvss_breakdown: CveIntelMetric[];
}

export interface EvidenceNode {
  id: string;
  type: string;
  label: string;
  metadata: Record<string, unknown>;
}

export interface EvidenceEdge {
  from_id: string;
  to_id: string;
  label: string;
}

export interface EvidenceChain {
  finding_id: number;
  nodes: EvidenceNode[];
  edges: EvidenceEdge[];
}

interface DataEnvelope<T> {
  data: T;
  meta?: unknown;
}

// ---------------------------------------------------------------------------
// Hook
// ---------------------------------------------------------------------------

/**
 * useEvidenceChain — fetch the provenance graph for a finding (UX-05).
 *
 * Calls GET /findings/{id}/evidence-chain.
 * Returns nodes and edges for ReactFlow rendering.
 */
export function useEvidenceChain(findingId: number | null) {
  return useQuery({
    queryKey: ["findings", "evidence-chain", findingId],
    queryFn: () =>
      authorizedRequestJson<DataEnvelope<EvidenceChain>>(
        `/findings/${findingId}/evidence-chain`,
      ),
    enabled: findingId !== null && findingId > 0,
    staleTime: 60_000,
  });
}

/**
 * useFindingDetail — fetch full scoring detail for a single finding.
 *
 * Calls GET /vulnerability/findings/{id}.
 * Returns FindingDetail including parsed details_json blob.
 */
export function useFindingDetail(findingId: number | null) {
  return useQuery({
    queryKey: ["vulnerability", "finding-detail", findingId],
    queryFn: () =>
      authorizedRequestJson<DataEnvelope<FindingDetail>>(
        `/vulnerability/findings/${findingId}`,
      ),
    enabled: findingId !== null && findingId > 0,
    staleTime: 30_000,
  });
}

/**
 * useCveIntel — fetch CVE intelligence with CVSS breakdown.
 *
 * Calls GET /vulnerability/cves/{cve_id}.
 * Returns description, CVSS vector + breakdown, EPSS, KEV.
 */
export function useCveIntel(cveId: string | null) {
  return useQuery({
    queryKey: ["vulnerability", "cve-intel", cveId],
    queryFn: () =>
      authorizedRequestJson<DataEnvelope<CveIntel>>(
        `/vulnerability/cves/${encodeURIComponent(cveId!)}`,
      ),
    enabled: !!cveId && cveId.startsWith("CVE-"),
    staleTime: 300_000,
  });
}
