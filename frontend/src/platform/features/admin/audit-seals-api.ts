/**
 * API layer for cryptographic audit-seal admin views.
 *
 * Wired endpoints (all require admin role, enforced server-side):
 *   GET  /audit/seals?run_id=&include_content=&page=&page_size=
 *   GET  /audit/seals/export?since=&until=&include_content=&page=&page_size=
 *
 * Notes:
 * - `/seals` requires `run_id`; the UI blocks the request until one is supplied.
 * - Content fields are only returned when include_content=true.
 * - The HMAC key is a server-side secret (SecretStore). The client CANNOT
 *   recompute the seal_hash; UI must not claim to "verify HMAC". The linkage
 *   check in AuditLogsPage is a pure structural check (hashes present +
 *   evidence_validation_pass), not a cryptographic verification.
 */

import { authorizedRequestJson, authorizedRequestBlob } from "@platform/api/http";
import type { BlobResponsePayload } from "@platform/api/http";

// ---------------------------------------------------------------------------
// Response types (mirror AuditSealResponse / PaginatedResponse[AuditSealResponse])
// ---------------------------------------------------------------------------

export interface AuditSeal {
  id: number | null;
  run_id: string;
  seal_hash: string;
  input_hash: string;
  output_hash: string;
  model_id: string;
  task_type: string;
  timestamp: string;
  classification: string | null;
  confidence: string | null;
  evidence_validation_pass: boolean | null;
  content_stored: boolean;
  prompt_content: string | null;
  response_content: string | null;
  created_at: string | null;
}

export interface AuditSealListResponse {
  total: number;
  page: number;
  page_size: number;
  pages: number;
  items: AuditSeal[];
}

export interface SealListParams {
  runId: string;
  includeContent: boolean;
  page: number;
  pageSize: number;
}

export interface SealExportParams {
  since: string;
  until: string;
  includeContent: boolean;
}

// ---------------------------------------------------------------------------
// Fetchers
// ---------------------------------------------------------------------------

export async function fetchAuditSeals(
  params: SealListParams,
): Promise<AuditSealListResponse> {
  const qs = new URLSearchParams();
  qs.set("run_id", params.runId);
  qs.set("include_content", params.includeContent ? "true" : "false");
  qs.set("page", String(params.page));
  qs.set("page_size", String(params.pageSize));
  return authorizedRequestJson<AuditSealListResponse>(
    `/audit/seals?${qs.toString()}`,
    { method: "GET" },
  );
}

/**
 * Trigger a server-side export of seals within a date range. Returns a Blob
 * payload; callers pipe it through `saveBlobResponse` to download.
 *
 * The backend currently returns JSON (AuditSealListResponse) with a
 * Content-Disposition; treating the payload as a blob keeps the download
 * flow uniform regardless of the future content-type.
 */
export async function exportAuditSeals(
  params: SealExportParams,
): Promise<BlobResponsePayload> {
  const qs = new URLSearchParams();
  qs.set("since", params.since);
  qs.set("until", params.until);
  qs.set("include_content", params.includeContent ? "true" : "false");
  return authorizedRequestBlob(`/audit/seals/export?${qs.toString()}`, {
    method: "GET",
  });
}

// ---------------------------------------------------------------------------
// Linkage integrity check (NOT HMAC verification)
// ---------------------------------------------------------------------------

export interface SealLinkageResult {
  total: number;
  missingInputHash: number;
  missingOutputHash: number;
  missingSealHash: number;
  evidenceFail: number;
  evidenceUnknown: number;
  ok: boolean;
}

/**
 * Structural hash-linkage check across a list of seals.
 *
 * This is intentionally NOT an HMAC recomputation: the HMAC key is a
 * server-held secret, so the client cannot re-derive `seal_hash`. What we
 * CAN check is that every row exposes the pieces the seal chain depends on:
 * input_hash, output_hash, seal_hash, and evidence_validation_pass. Label
 * the affordance accordingly in the UI.
 */
export function checkSealLinkage(seals: AuditSeal[]): SealLinkageResult {
  let missingInputHash = 0;
  let missingOutputHash = 0;
  let missingSealHash = 0;
  let evidenceFail = 0;
  let evidenceUnknown = 0;
  for (const s of seals) {
    if (!s.input_hash) missingInputHash += 1;
    if (!s.output_hash) missingOutputHash += 1;
    if (!s.seal_hash) missingSealHash += 1;
    if (s.evidence_validation_pass === false) evidenceFail += 1;
    if (s.evidence_validation_pass === null) evidenceUnknown += 1;
  }
  const ok =
    missingInputHash === 0 &&
    missingOutputHash === 0 &&
    missingSealHash === 0 &&
    evidenceFail === 0;
  return {
    total: seals.length,
    missingInputHash,
    missingOutputHash,
    missingSealHash,
    evidenceFail,
    evidenceUnknown,
    ok,
  };
}
